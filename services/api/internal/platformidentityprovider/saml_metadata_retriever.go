package platformidentityprovider

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/periapsis-im/periapsis/modules/identity/federatedhttp"
)

type HardenedSAMLMetadataRetriever struct {
	http *federatedhttp.Client
}

func NewHardenedSAMLMetadataRetriever(client *federatedhttp.Client) (*HardenedSAMLMetadataRetriever, error) {
	if client == nil {
		return nil, errors.New("federated HTTP client is required")
	}
	return &HardenedSAMLMetadataRetriever{http: client}, nil
}

func (retriever *HardenedSAMLMetadataRetriever) RetrieveSAMLMetadata(
	ctx context.Context,
	location string,
	maximumBytes int,
) (SAMLMetadataDocument, error) {
	if retriever == nil || retriever.http == nil || ctx == nil || ctx.Err() != nil ||
		maximumBytes < 1 || maximumBytes > maximumSAMLMetadataBytes {
		return SAMLMetadataDocument{}, errors.New("SAML metadata retrieval is unavailable")
	}
	target, err := retriever.http.CompileTarget(federatedhttp.DocumentSAMLMetadata, location)
	if err != nil {
		return SAMLMetadataDocument{}, errors.New("SAML metadata target was rejected")
	}
	result, err := retriever.http.Fetch(ctx, target, nil)
	defer clear(result.Body)
	if err != nil || result.Category != federatedhttp.CategorySuccess ||
		result.Kind != federatedhttp.DocumentSAMLMetadata || len(result.Body) == 0 ||
		len(result.Body) > maximumBytes || result.Digest != sha256.Sum256(result.Body) ||
		!validSAMLAdministrationInstant(result.Cache.RetrievedAt) {
		return SAMLMetadataDocument{}, errors.New("SAML metadata retrieval failed")
	}
	return SAMLMetadataDocument{
		Document: append([]byte(nil), result.Body...), RetrievedAt: result.Cache.RetrievedAt,
	}, nil
}

// RetrieveTenantSAMLMetadata exposes the same hardened fetch boundary without
// coupling the tenant identity-provider package to platform administration
// models. The returned document is a fresh caller-owned buffer.
func (retriever *HardenedSAMLMetadataRetriever) RetrieveTenantSAMLMetadata(
	ctx context.Context,
	location string,
	maximumBytes int,
) ([]byte, time.Time, error) {
	document, err := retriever.RetrieveSAMLMetadata(ctx, location, maximumBytes)
	if err != nil {
		return nil, time.Time{}, err
	}
	return document.Document, document.RetrievedAt, nil
}

func (retriever *HardenedSAMLMetadataRetriever) String() string {
	return fmt.Sprintf(
		"platformidentityprovider.HardenedSAMLMetadataRetriever{configured:%t,network_policy:[REDACTED]}",
		retriever != nil && retriever.http != nil,
	)
}

func (retriever *HardenedSAMLMetadataRetriever) GoString() string { return retriever.String() }

var _ SAMLMetadataRetriever = (*HardenedSAMLMetadataRetriever)(nil)
