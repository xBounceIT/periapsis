package federatedsaml

import (
	"compress/flate"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"sync"
	"testing"
)

func TestStartCallbackAndAtomicConsumption(t *testing.T) {
	fixture := newTestFixture(t)
	parsed, err := url.Parse(fixture.start.RedirectURL())
	if err != nil {
		t.Fatalf("redirect parse: %v", err)
	}
	query := parsed.Query()
	if parsed.Scheme != "https" || parsed.Host != "idp.example.test" || parsed.Path != "/sso" ||
		len(query) != 4 || query.Get("RelayState") != fixture.relay ||
		query.Get("SigAlg") != string(RedirectECDSASHA256) || query.Get("Signature") == "" {
		t.Fatalf("unexpected redirect artifact: %v", fixture.start)
	}
	compressed, err := base64.StdEncoding.Strict().DecodeString(query.Get("SAMLRequest"))
	if err != nil {
		t.Fatalf("decode AuthnRequest: %v", err)
	}
	reader := flate.NewReader(strings.NewReader(string(compressed)))
	document, err := io.ReadAll(reader)
	closeErr := reader.Close()
	if err != nil || closeErr != nil || !strings.Contains(string(document), `ProtocolBinding="`+samlHTTPPOSTBinding+`"`) ||
		!strings.Contains(string(document), `Comparison="exact"`) || !strings.Contains(string(document), fixture.config.ACSURL) {
		t.Fatalf("unexpected AuthnRequest: %q, %v, %v", document, err, closeErr)
	}
	fixture.signer.mu.Lock()
	if len(fixture.signer.requests) != 1 || strings.Contains(string(fixture.signer.requests[0].Payload), "Signature=") ||
		!strings.Contains(string(fixture.signer.requests[0].Payload), "RelayState=") {
		t.Fatalf("unexpected signer request: %v", fixture.signer.requests)
	}
	fixture.signer.mu.Unlock()
	pending := fixture.repo.current()
	begin := fixture.repo.createRequest().Begin
	if pending.ReturnPath != "/incidents?view=mine" || pending.State != TransactionPending || pending.Version != 1 ||
		pending.RequestID == "" || pending.ID != fixture.start.TransactionID() ||
		pending.MaterialID != begin.OperationRunID || !validUUIDv7(pending.MaterialID) ||
		!compareDigest(pending.BrowserDigest, digestOpaque(fixture.start.BrowserHandle())) {
		t.Fatalf("unexpected pending transaction: %v", pending)
	}

	validated, err := fixture.kernel.ValidateCallback(context.Background(), callbackRequest(fixture, validResponseDocument(fixture)))
	if err != nil {
		t.Fatalf("ValidateCallback() error = %v", err)
	}
	jit := validated.JIT()
	if jit.Issuer() != fixture.config.Metadata.EntityID() || jit.SubjectSource() != SubjectPersistentNameID ||
		jit.SubjectValue() != "subject-secret-value" || jit.AuthnContextClassRef() != "urn:test:mfa" ||
		!jit.ValidUntil().Equal(fixtureTime.Add(5*60*1e9)) {
		t.Fatalf("unexpected JIT artifact: %v", jit)
	}
	groups := jit.Groups()
	if fmt.Sprint(groups) != "[alpha-secret-group zeta-secret-group]" {
		t.Fatalf("groups = %v", groups)
	}
	groups[0] = "mutated"
	if jit.Groups()[0] != "alpha-secret-group" {
		t.Fatal("JIT groups accessor did not make a defensive copy")
	}
	evidence := jit.AssuranceEvidence()
	if evidence == nil || evidence.Level != 2 || evidence.Source.ProviderID != fixture.config.Provider.ProviderID ||
		evidence.Source.BindingID != fixture.config.BindingID || evidence.TrustRuleRevision == nil || *evidence.TrustRuleRevision != 12 {
		t.Fatalf("unexpected assurance evidence: %#v", evidence)
	}
	consumer := &atomicConsumer{}
	result, err := fixture.kernel.Consume(context.Background(), validated, consumer)
	if err != nil || result.Category != ConsumerSuccess || consumer.calls != 1 ||
		consumer.request.ReturnPath != "/incidents?view=mine" || !consumer.request.HasSessionIndex ||
		consumer.request.ResponseID != "_response" || consumer.request.AssertionID != "_assertion" ||
		consumer.request.MaterialID != pending.MaterialID {
		t.Fatalf("Consume() = %#v, %v, request=%v", result, err, consumer.request)
	}
	if _, err = fixture.kernel.Consume(context.Background(), validated, consumer); !errors.Is(err, ErrConsumptionRejected) || consumer.calls != 1 {
		t.Fatalf("second Consume() error = %v, calls=%d", err, consumer.calls)
	}
}

func TestConsumeAllowsExactlyOneConcurrentWinner(t *testing.T) {
	fixture := newTestFixture(t)
	validated, err := fixture.kernel.ValidateCallback(context.Background(), callbackRequest(fixture, validResponseDocument(fixture)))
	if err != nil {
		t.Fatalf("ValidateCallback() error = %v", err)
	}
	consumer := &atomicConsumer{}
	const contenders = 64
	var wait sync.WaitGroup
	wait.Add(contenders)
	successes := make(chan struct{}, contenders)
	for range contenders {
		go func() {
			defer wait.Done()
			if result, consumeErr := fixture.kernel.Consume(context.Background(), validated, consumer); consumeErr == nil && result.Category == ConsumerSuccess {
				successes <- struct{}{}
			}
		}()
	}
	wait.Wait()
	close(successes)
	if len(successes) != 1 || consumer.calls != 1 {
		t.Fatalf("successes=%d consumer calls=%d", len(successes), consumer.calls)
	}
}

func TestAtomicConsumerRejectsResponseAssertionAndSessionReplay(t *testing.T) {
	fixture := newTestFixture(t)
	document := validResponseDocument(fixture)
	first, err := fixture.kernel.ValidateCallback(context.Background(), callbackRequest(fixture, document))
	if err != nil {
		t.Fatalf("first ValidateCallback() error = %v", err)
	}
	second, err := fixture.kernel.ValidateCallback(context.Background(), callbackRequest(fixture, document))
	if err != nil {
		t.Fatalf("second ValidateCallback() error = %v", err)
	}
	consumer := &replayConsumer{seen: make(map[string]struct{})}
	var wait sync.WaitGroup
	wait.Add(2)
	results := make(chan AuthenticationConsumerCategory, 2)
	for _, artifact := range []*ValidatedAuthentication{first, second} {
		go func(candidate *ValidatedAuthentication) {
			defer wait.Done()
			result, _ := fixture.kernel.Consume(context.Background(), candidate, consumer)
			results <- result.Category
		}(artifact)
	}
	wait.Wait()
	close(results)
	counts := map[AuthenticationConsumerCategory]int{}
	for category := range results {
		counts[category]++
	}
	if counts[ConsumerSuccess] != 1 || counts[ConsumerReplay] != 1 || consumer.calls != 2 {
		t.Fatalf("categories=%v calls=%d", counts, consumer.calls)
	}
}

func TestValidateCallbackRejectsWrappingAndSemanticCorpus(t *testing.T) {
	fixture := newTestFixture(t)
	valid := string(validResponseDocument(fixture))
	pending := fixture.repo.current()
	duplicateAttribute := `<saml:Attribute Name="department" NameFormat="urn:test:attribute"><saml:AttributeValue>shadow</saml:AttributeValue></saml:Attribute>`
	tests := map[string]string{
		"duplicate ID":                strings.Replace(valid, `_assertion`, `_response`, 1),
		"second assertion wrapping":   strings.Replace(valid, `</samlp:Response>`, string(validAssertionDocument(fixture, true))+`</samlp:Response>`, 1),
		"missing response signature":  strings.Replace(valid, `<ds:Signature/>`, ``, 1),
		"missing assertion signature": replaceNth(valid, `<ds:Signature/>`, ``, 2),
		"wrong destination":           strings.Replace(valid, `Destination="`+fixture.config.ACSURL+`"`, `Destination="https://sp.example.test/wrong"`, 1),
		"wrong recipient":             strings.Replace(valid, `Recipient="`+fixture.config.ACSURL+`"`, `Recipient="https://sp.example.test/wrong"`, 1),
		"wrong InResponseTo":          strings.Replace(valid, `InResponseTo="`+pending.RequestID+`"`, `InResponseTo="_attacker"`, 1),
		"wrong response issuer":       strings.Replace(valid, fixture.config.Metadata.EntityID(), "https://attacker.test/SECRET", 1),
		"wrong audience":              strings.Replace(valid, `<saml:Audience>`+fixture.config.SPEntityID+`</saml:Audience>`, `<saml:Audience>https://attacker.test/SECRET</saml:Audience>`, 1),
		"non-success status":          strings.Replace(valid, samlSuccessStatus, "urn:oasis:names:tc:SAML:2.0:status:Responder", 1),
		"non-bearer confirmation":     strings.Replace(valid, samlBearerConfirmation, "urn:oasis:names:tc:SAML:2.0:cm:holder-of-key", 1),
		"expired conditions":          strings.Replace(valid, fixtureTime.Add(10*60*1e9).Format("2006-01-02T15:04:05Z07:00"), fixtureTime.Add(-timeMinute).Format("2006-01-02T15:04:05Z07:00"), 1),
		"transient subject":           strings.Replace(valid, samlPersistentNameID, "urn:oasis:names:tc:SAML:2.0:nameid-format:transient", 1),
		"unrequested AuthnContext":    strings.Replace(valid, "urn:test:mfa", "urn:test:unknown", 1),
		"duplicate attribute":         strings.Replace(valid, `</saml:AttributeStatement>`, duplicateAttribute+`</saml:AttributeStatement>`, 1),
		"signature in value":          strings.Replace(valid, `department-secret</saml:AttributeValue>`, `department-secret<ds:Signature/></saml:AttributeValue>`, 1),
		"external entity":             `<!DOCTYPE x [<!ENTITY steal SYSTEM "file:///SECRET">]>` + valid,
		"two roots":                   valid + `<samlp:Response xmlns:samlp="` + samlProtocolNamespace + `"/>`,
	}
	for name, document := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := fixture.kernel.ValidateCallback(context.Background(), callbackRequest(fixture, []byte(document))); err == nil {
				t.Fatal("ValidateCallback() unexpectedly succeeded")
			} else if strings.Contains(err.Error(), "SECRET") || strings.Contains(err.Error(), "attacker") {
				t.Fatalf("error leaked hostile input: %v", err)
			}
		})
	}
}

const timeMinute = 60 * 1e9

func TestValidateCallbackRejectsMalformedFormAndBrowserBinding(t *testing.T) {
	fixture := newTestFixture(t)
	base := callbackRequest(fixture, validResponseDocument(fixture))
	tests := map[string]CallbackRequest{
		"wrong media":             {Configuration: fixture.config, MediaType: "multipart/form-data", RawForm: base.RawForm, BrowserHandle: base.BrowserHandle},
		"unknown media parameter": {Configuration: fixture.config, MediaType: "application/x-www-form-urlencoded; boundary=SECRET", RawForm: base.RawForm, BrowserHandle: base.BrowserHandle},
		"duplicate member":        {Configuration: fixture.config, MediaType: base.MediaType, RawForm: append(append([]byte(nil), base.RawForm...), []byte("&SAMLResponse=duplicate")...), BrowserHandle: base.BrowserHandle},
		"unknown member":          {Configuration: fixture.config, MediaType: base.MediaType, RawForm: append(append([]byte(nil), base.RawForm...), []byte("&ReturnTo=%2FSECRET")...), BrowserHandle: base.BrowserHandle},
		"bad relay":               {Configuration: fixture.config, MediaType: base.MediaType, RawForm: []byte(strings.Replace(string(base.RawForm), url.QueryEscape(fixture.relay), "short", 1)), BrowserHandle: base.BrowserHandle},
		"wrong browser":           {Configuration: fixture.config, MediaType: base.MediaType, RawForm: base.RawForm, BrowserHandle: []byte(strings.Repeat("A", 43))},
	}
	for name, request := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := fixture.kernel.ValidateCallback(context.Background(), request); !errors.Is(err, ErrCallbackRejected) {
				t.Fatalf("ValidateCallback() error = %v", err)
			}
		})
	}
}

func TestValidateCallbackRejectsUnboundSignatureProof(t *testing.T) {
	tests := map[string]func(*SignatureVerificationResult){
		"wrong reference":       func(proof *SignatureVerificationResult) { proof.ReferenceURI = "#_attacker" },
		"external dereference":  func(proof *SignatureVerificationResult) { proof.ExternalDereferenceCount = 1 },
		"ambiguous certificate": func(proof *SignatureVerificationResult) { proof.MatchingCertificateCount = 2 },
		"transform parameter":   func(proof *SignatureVerificationResult) { proof.TransformParameterCount = 1 },
		"key type mismatch":     func(proof *SignatureVerificationResult) { proof.SignatureAlgorithm = string(RedirectRSASHA256) },
		"SHA-1": func(proof *SignatureVerificationResult) {
			proof.SignatureAlgorithm = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			fixture := newTestFixture(t)
			fixture.verifier.mutate = mutate
			if _, err := fixture.kernel.ValidateCallback(context.Background(), callbackRequest(fixture, validResponseDocument(fixture))); !errors.Is(err, ErrSignatureRejected) {
				t.Fatalf("ValidateCallback() error = %v", err)
			}
		})
	}
}

func TestImmutableAttributeSubjectAndStaleTrustEvidence(t *testing.T) {
	fixture := newTestFixture(t)
	fixture.config.Subject = SubjectPolicy{Source: SubjectImmutableAttribute, AttributeName: "department", AttributeNameFormat: "urn:test:attribute"}
	fixture.config.TrustRules[0].MaxAge = timeMinute
	restartFixture(t, &fixture)
	validated, err := fixture.kernel.ValidateCallback(context.Background(), callbackRequest(fixture, validResponseDocument(fixture)))
	if err != nil {
		t.Fatalf("ValidateCallback() error = %v", err)
	}
	jit := validated.JIT()
	if jit.SubjectSource() != SubjectImmutableAttribute || jit.SubjectName() != "department" ||
		jit.SubjectFormat() != "urn:test:attribute" || jit.SubjectValue() != "department-secret" {
		t.Fatalf("unexpected immutable subject: %v", jit)
	}
	if jit.AssuranceEvidence() != nil {
		t.Fatalf("stale exact AuthnContext elevated assurance: %#v", jit.AssuranceEvidence())
	}
}

func TestSignaturePolicyConsumesExactlyConfiguredObject(t *testing.T) {
	fixture := newTestFixture(t)
	fixture.config.SignaturePolicy = SignedAssertion
	restartFixture(t, &fixture)
	assertionOnly := responseDocument(fixture, false, validAssertionDocument(fixture, true))
	if _, err := fixture.kernel.ValidateCallback(context.Background(), callbackRequest(fixture, assertionOnly)); err != nil {
		t.Fatalf("assertion-only policy error = %v", err)
	}
	if _, err := fixture.kernel.ValidateCallback(context.Background(), callbackRequest(fixture, responseDocument(fixture, true, validAssertionDocument(fixture, true)))); !errors.Is(err, ErrSignatureRejected) {
		t.Fatalf("unexpected response signature error = %v", err)
	}

	fixture = newTestFixture(t)
	fixture.config.SignaturePolicy = SignedResponse
	restartFixture(t, &fixture)
	responseOnly := responseDocument(fixture, true, validAssertionDocument(fixture, false))
	if _, err := fixture.kernel.ValidateCallback(context.Background(), callbackRequest(fixture, responseOnly)); err != nil {
		t.Fatalf("response-only policy error = %v", err)
	}
	if _, err := fixture.kernel.ValidateCallback(context.Background(), callbackRequest(fixture, validResponseDocument(fixture))); !errors.Is(err, ErrSignatureRejected) {
		t.Fatalf("unexpected assertion signature error = %v", err)
	}
}

func TestConsumerCollisionIsFailClosed(t *testing.T) {
	fixture := newTestFixture(t)
	validated, err := fixture.kernel.ValidateCallback(context.Background(), callbackRequest(fixture, validResponseDocument(fixture)))
	if err != nil {
		t.Fatalf("ValidateCallback() error = %v", err)
	}
	consumer := consumerFunction(func(context.Context, ConsumptionRequest) (ConsumptionResult, error) {
		return ConsumptionResult{Category: ConsumerCollision}, nil
	})
	result, err := fixture.kernel.Consume(context.Background(), validated, consumer)
	if result.Category != ConsumerCollision || !errors.Is(err, ErrConsumptionRejected) {
		t.Fatalf("Consume() = %#v, %v", result, err)
	}
}

func TestStartRejectsUnsafeReturnAndExistingSession(t *testing.T) {
	fixture := newTestFixture(t)
	for _, request := range []StartRequest{
		{Configuration: fixture.config, ReturnPath: "https://attacker.test/"},
		{Configuration: fixture.config, ReturnPath: "//attacker.test/"},
		{Configuration: fixture.config, ReturnPath: "/safe%5Cattacker"},
		{Configuration: fixture.config, ReturnPath: "/safe?value=%0DSECRET"},
		{Configuration: fixture.config, ReturnPath: "/safe", HasLiveSession: true},
	} {
		if _, err := fixture.kernel.StartAuthentication(context.Background(), request); !errors.Is(err, ErrAuthenticationStart) {
			t.Fatalf("StartAuthentication() error = %v", err)
		}
	}
}

func TestStartAtomicallyReplacesPreviousBrowserBinding(t *testing.T) {
	fixture := newTestFixture(t)
	previous := fixture.start.BrowserHandle()
	if _, err := fixture.kernel.StartAuthentication(context.Background(), StartRequest{
		Begin: testAuthenticationBegin(2), Configuration: fixture.config, ReturnPath: "/incidents", PreviousBrowserHandle: previous,
	}); err != nil {
		t.Fatalf("StartAuthentication() error = %v", err)
	}
	create := fixture.repo.createRequest()
	if !create.HasPreviousBrowserBinding || !compareDigest(create.PreviousBrowserDigest, digestOpaque(previous)) {
		t.Fatalf("previous browser binding was not atomically pinned: %v", create)
	}
}

func replaceNth(value, old, replacement string, occurrence int) string {
	index := -1
	offset := 0
	for range occurrence {
		found := strings.Index(value[offset:], old)
		if found < 0 {
			return value
		}
		index = offset + found
		offset = index + len(old)
	}
	return value[:index] + replacement + value[index+len(old):]
}

type consumerFunction func(context.Context, ConsumptionRequest) (ConsumptionResult, error)

func (function consumerFunction) ConsumeSAML(ctx context.Context, request ConsumptionRequest) (ConsumptionResult, error) {
	return function(ctx, request)
}

type replayConsumer struct {
	mu    sync.Mutex
	seen  map[string]struct{}
	calls int
}

func (consumer *replayConsumer) ConsumeSAML(_ context.Context, request ConsumptionRequest) (ConsumptionResult, error) {
	consumer.mu.Lock()
	defer consumer.mu.Unlock()
	consumer.calls++
	keys := []string{"response:" + request.ResponseID, "assertion:" + request.AssertionID}
	if request.HasSessionIndex {
		keys = append(keys, string(request.SessionIndexDigest[:]))
	}
	for _, key := range keys {
		if _, duplicate := consumer.seen[key]; duplicate {
			return ConsumptionResult{Category: ConsumerReplay}, nil
		}
	}
	for _, key := range keys {
		consumer.seen[key] = struct{}{}
	}
	return ConsumptionResult{Category: ConsumerSuccess}, nil
}
