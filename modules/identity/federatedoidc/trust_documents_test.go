package federatedoidc

import (
	"context"
	"errors"
	"testing"

	"github.com/periapsis-im/periapsis/modules/identity/federatedhttp"
)

func TestValidateTrustDocumentRecordsReconstructsExactPair(t *testing.T) {
	t.Parallel()

	client, request, records := validTrustDocumentRecords(t)
	keyCount, err := client.ValidateTrustDocumentRecords(records, request, testJWKSRev)
	if err != nil || keyCount != 3 {
		t.Fatalf("ValidateTrustDocumentRecords() = %d, %v", keyCount, err)
	}
	if records.Discovery.Request.Policy.ClientAuthentication != ClientSecretBasic ||
		len(records.Discovery.Request.Policy.SigningAlgorithms) != 3 ||
		records.Discovery.Request.Policy.SigningAlgorithms[0] != SigningES256 {
		t.Fatalf("fetcher did not return canonical request policy: %#v", records.Discovery.Request.Policy)
	}
}

func TestValidateTrustDocumentRecordsRejectsFetcherDrift(t *testing.T) {
	t.Parallel()

	tests := map[string]func(*TrustDocumentRecords){
		"request policy": func(value *TrustDocumentRecords) {
			value.Discovery.Request.Policy.ClientAuthentication = ClientSecretPost
		},
		"discovery digest and body": func(value *TrustDocumentRecords) {
			value.Discovery.Document[0] ^= 0xff
		},
		"embedded discovery parent": func(value *TrustDocumentRecords) {
			value.JWKS.Discovery.issuer = "https://other.example/tenant"
		},
		"JWKS digest and body": func(value *TrustDocumentRecords) {
			value.JWKS.Digest[0] ^= 0xff
		},
		"reported key count": func(value *TrustDocumentRecords) {
			value.KeyCount++
		},
	}
	for name, mutate := range tests {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			client, request, records := validTrustDocumentRecords(t)
			mutate(&records)
			if count, err := client.ValidateTrustDocumentRecords(records, request, testJWKSRev); !errors.Is(err, ErrInvalidSnapshot) || count != 0 {
				t.Fatalf("ValidateTrustDocumentRecords() = %d, %v", count, err)
			}
		})
	}
}

func validTrustDocumentRecords(t *testing.T) (*Client, DiscoveryRequest, TrustDocumentRecords) {
	t.Helper()
	client, _ := newTrustTestClient(t, []federatedhttp.Result{
		successfulResult(federatedhttp.DocumentOIDCDiscovery, validDiscoveryDocument(t)),
		successfulResult(federatedhttp.DocumentOIDCJWKS, validJWKSDocument(t)),
	}, nil)
	request := validDiscoveryRequest()
	records, err := client.FetchTrustDocuments(context.Background(), request, testJWKSRev)
	if err != nil {
		t.Fatalf("FetchTrustDocuments() error = %v", err)
	}
	return client, request, records
}
