package federatedsaml

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

type metadataSourceFunction func(context.Context, MetadataLoadRequest, int) (MetadataDocument, error)

func (function metadataSourceFunction) LoadSAMLMetadata(ctx context.Context, request MetadataLoadRequest, maximum int) (MetadataDocument, error) {
	return function(ctx, request, maximum)
}

func TestLoadMetadataUsesOnlyBoundedProviderSource(t *testing.T) {
	certificate := testCertificate(t, 105)
	document := testMetadataDocument("https://idp.example.test/entity", "https://idp.example.test/sso", "", certificate)
	called := false
	request := MetadataLoadRequest{
		Provider: testConfiguration(MetadataSnapshot{}).Provider, BindingID: testID(3),
		ExpectedEntityID: "https://idp.example.test/entity", Revision: 11,
		MaximumValidUntil: fixtureTime.Add(48 * time.Hour),
	}
	source := metadataSourceFunction(func(_ context.Context, observed MetadataLoadRequest, maximum int) (MetadataDocument, error) {
		called = true
		if observed.Provider != request.Provider || observed.BindingID != request.BindingID || maximum != DefaultLimits().MaxMetadataBytes {
			t.Fatalf("unexpected source request: %v max=%d", observed, maximum)
		}
		return MetadataDocument{Document: document, RetrievedAt: fixtureTime}, nil
	})
	snapshot, err := LoadMetadata(context.Background(), source, request, DefaultLimits(), time.Second)
	if err != nil || !called || snapshot.Revision() != request.Revision {
		t.Fatalf("LoadMetadata() = %v, %v, called=%v", snapshot, err, called)
	}

	leaking := metadataSourceFunction(func(context.Context, MetadataLoadRequest, int) (MetadataDocument, error) {
		return MetadataDocument{}, errors.New("SECRET hostile source URL")
	})
	if _, err = LoadMetadata(context.Background(), leaking, request, DefaultLimits(), time.Second); !errors.Is(err, ErrInvalidMetadata) || strings.Contains(err.Error(), "SECRET") {
		t.Fatalf("source failure was not safely categorized: %v", err)
	}
}

func TestCompileMetadataAndRollover(t *testing.T) {
	certificateOne := testCertificate(t, 101)
	certificateTwo := testCertificate(t, 102)
	previous := compileTestMetadata(t, 1, "https://idp.example.test/entity", "https://idp.example.test/sso", "https://idp.example.test/slo", certificateOne)
	if previous.Revision() != 1 || previous.EntityID() != "https://idp.example.test/entity" ||
		previous.SSORedirectURL() != "https://idp.example.test/sso" || len(previous.Certificates()) != 1 {
		t.Fatalf("unexpected metadata snapshot: %v", previous)
	}
	der := previous.CertificateDER()
	der[0][0] ^= 0xff
	if der[0][0] == previous.CertificateDER()[0][0] {
		t.Fatal("CertificateDER did not return a defensive copy")
	}

	overlap := compileTestMetadata(t, 2, previous.EntityID(), previous.SSORedirectURL(), previous.SLORedirectURL(), certificateOne, certificateTwo)
	assessment, err := AssessMetadataRollover(previous, overlap)
	if err != nil || assessment.Decision != RolloverAutomatic || assessment.OverlappingFingerprints != 1 || assessment.AddedFingerprints != 1 {
		t.Fatalf("overlap assessment = %#v, %v", assessment, err)
	}
	nonoverlap := compileTestMetadata(t, 3, previous.EntityID(), previous.SSORedirectURL(), previous.SLORedirectURL(), certificateTwo)
	assessment, err = AssessMetadataRollover(previous, nonoverlap)
	if err != nil || assessment.Decision != RolloverProtectedApproval || assessment.OverlappingFingerprints != 0 {
		t.Fatalf("non-overlap assessment = %#v, %v", assessment, err)
	}
	endpointChange := compileTestMetadata(t, 4, previous.EntityID(), "https://idp.example.test/new-sso", previous.SLORedirectURL(), certificateOne, certificateTwo)
	assessment, err = AssessMetadataRollover(previous, endpointChange)
	if err != nil || assessment.Decision != RolloverProtectedApproval {
		t.Fatalf("endpoint-change assessment = %#v, %v", assessment, err)
	}
	entityChange := compileTestMetadata(t, 5, "https://other-idp.example.test/entity", previous.SSORedirectURL(), previous.SLORedirectURL(), certificateOne)
	if _, err = AssessMetadataRollover(previous, entityChange); !errors.Is(err, ErrMetadataRolloverRejected) {
		t.Fatalf("entity change error = %v", err)
	}
}

func TestCompileMetadataRejectsHostileCorpus(t *testing.T) {
	certificate := testCertificate(t, 103)
	base := string(testMetadataDocument("https://idp.example.test/entity", "https://idp.example.test/sso", "https://idp.example.test/slo", certificate))
	tests := map[string]string{
		"doctype":                     `<!DOCTYPE x [<!ENTITY steal SYSTEM "file:///secret">]>` + base,
		"duplicate certificate":       string(testMetadataDocument("https://idp.example.test/entity", "https://idp.example.test/sso", "https://idp.example.test/slo", certificate, certificate)),
		"encryption-only certificate": strings.Replace(base, `use="signing"`, `use="encryption"`, 1),
		"duplicate ID":                strings.Replace(strings.Replace(base, `<md:EntityDescriptor `, `<md:EntityDescriptor ID="_duplicate" `, 1), `<md:IDPSSODescriptor `, `<md:IDPSSODescriptor ID="_duplicate" `, 1),
		"HTTP endpoint":               strings.Replace(base, "https://idp.example.test/sso", "http://idp.example.test/sso", 1),
		"endpoint query":              strings.Replace(base, "https://idp.example.test/sso", "https://idp.example.test/sso?SECRET=raw", 1),
		"unknown extension":           strings.Replace(base, `</md:IDPSSODescriptor>`, `<evil:Extension xmlns:evil="urn:evil"/></md:IDPSSODescriptor>`, 1),
		"entity mismatch":             strings.Replace(base, "https://idp.example.test/entity", "https://other.example.test/entity", 1),
	}
	for name, document := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := CompileMetadata(MetadataCompilationRequest{
				Document: []byte(document), ExpectedEntityID: "https://idp.example.test/entity", Revision: 1,
				RetrievedAt: fixtureTime, MaximumValidUntil: fixtureTime.Add(48 * time.Hour),
			}, DefaultLimits())
			if !errors.Is(err, ErrInvalidMetadata) {
				t.Fatalf("CompileMetadata() error = %v", err)
			}
			if err != nil && strings.Contains(err.Error(), "SECRET") {
				t.Fatalf("error leaked hostile input: %v", err)
			}
		})
	}
}

func TestCompileMetadataRejectsNonCanonicalRevisionEnvelope(t *testing.T) {
	certificate := testCertificate(t, 104)
	document := testMetadataDocument("https://idp.example.test/entity", "https://idp.example.test/sso", "", certificate)
	tests := []MetadataCompilationRequest{
		{Document: document, ExpectedEntityID: "https://idp.example.test/entity", Revision: 0, RetrievedAt: fixtureTime, MaximumValidUntil: fixtureTime.Add(48 * time.Hour)},
		{Document: document, ExpectedEntityID: "https://idp.example.test/entity", Revision: 1, RetrievedAt: fixtureTime.Local(), MaximumValidUntil: fixtureTime.Add(48 * time.Hour)},
		{Document: document, ExpectedEntityID: "https://idp.example.test/entity", Revision: 1, RetrievedAt: fixtureTime, MaximumValidUntil: fixtureTime.Add(400 * 24 * time.Hour)},
	}
	for index, request := range tests {
		if _, err := CompileMetadata(request, DefaultLimits()); !errors.Is(err, ErrInvalidMetadata) {
			t.Fatalf("case %d error = %v", index, err)
		}
	}
}

func TestCompileMetadataAllowsFutureRolloverOnlyWithCurrentKey(t *testing.T) {
	current := testCertificate(t, 106)
	future := makeTestCertificate(t, 107, fixtureTime.Add(time.Hour), fixtureTime.Add(365*24*time.Hour))
	request := func(certificates ...[]byte) MetadataCompilationRequest {
		return MetadataCompilationRequest{
			Document:         testMetadataDocument("https://idp.example.test/entity", "https://idp.example.test/sso", "", certificates...),
			ExpectedEntityID: "https://idp.example.test/entity", Revision: 1,
			RetrievedAt: fixtureTime, MaximumValidUntil: fixtureTime.Add(48 * time.Hour),
		}
	}
	if _, err := CompileMetadata(request(future), DefaultLimits()); !errors.Is(err, ErrInvalidMetadata) {
		t.Fatalf("future-only metadata error = %v", err)
	}
	if snapshot, err := CompileMetadata(request(current, future), DefaultLimits()); err != nil || len(snapshot.Certificates()) != 2 {
		t.Fatalf("overlap metadata = %v, %v", snapshot, err)
	}
}
