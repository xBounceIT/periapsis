package httpserver

import (
	"context"
	"errors"
	"fmt"
	"regexp"

	"github.com/periapsis-im/periapsis/services/api/internal/platformsamladapter"
)

var (
	errTenantSAMLMetadataInvalid      = errors.New("tenant SAML metadata locator is invalid")
	errTenantSAMLMetadataNotFound     = errors.New("tenant SAML metadata was not found")
	tenantSAMLMetadataSlugPattern     = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	tenantSAMLMetadataLoginKeyPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{2,63}$`)
)

type TenantSAMLMetadataService interface {
	Metadata(context.Context, string, string) (platformsamladapter.TenantSAMLMetadataDocument, error)
}

// RuntimeTenantSAMLMetadata resolves an anonymous locator through one
// certificate-only SECURITY DEFINER projection, verifies every live
// tenant/provider/binding coordinate, and renders deterministic SP metadata.
type RuntimeTenantSAMLMetadata struct {
	source       platformsamladapter.TenantSAMLMetadataSource
	publicOrigin string
}

func NewRuntimeTenantSAMLMetadata(
	source platformsamladapter.TenantSAMLMetadataSource,
	publicOrigin string,
) (*RuntimeTenantSAMLMetadata, error) {
	if source == nil || publicOrigin == "" {
		return nil, errFederatedTransportUnavailable
	}
	return &RuntimeTenantSAMLMetadata{source: source, publicOrigin: publicOrigin}, nil
}

func (service *RuntimeTenantSAMLMetadata) String() string {
	return fmt.Sprintf(
		"httpserver.RuntimeTenantSAMLMetadata{configured:%t,publicOnly:true}",
		service != nil && service.source != nil && service.publicOrigin != "",
	)
}

func (service *RuntimeTenantSAMLMetadata) GoString() string { return service.String() }

func (service *RuntimeTenantSAMLMetadata) Metadata(
	ctx context.Context,
	tenantSlug string,
	loginKey string,
) (platformsamladapter.TenantSAMLMetadataDocument, error) {
	if service == nil || service.source == nil || service.publicOrigin == "" || ctx == nil || ctx.Err() != nil {
		return platformsamladapter.TenantSAMLMetadataDocument{}, errFederatedTransportUnavailable
	}
	if !tenantSAMLMetadataSlugPattern.MatchString(tenantSlug) ||
		!tenantSAMLMetadataLoginKeyPattern.MatchString(loginKey) {
		return platformsamladapter.TenantSAMLMetadataDocument{}, errTenantSAMLMetadataInvalid
	}
	projection, found, err := service.source.LoadTenantSAMLMetadata(ctx, tenantSlug, loginKey)
	defer clearTenantSAMLMetadataProjection(&projection)
	if err != nil || ctx.Err() != nil {
		return platformsamladapter.TenantSAMLMetadataDocument{}, errFederatedTransportUnavailable
	}
	if !found {
		return platformsamladapter.TenantSAMLMetadataDocument{}, errTenantSAMLMetadataNotFound
	}
	if projection.TenantSlug != tenantSlug || projection.LoginKey != loginKey || projection.PublicOrigin != "" {
		return platformsamladapter.TenantSAMLMetadataDocument{}, errFederatedTransportUnavailable
	}
	projection.PublicOrigin = service.publicOrigin
	document, err := platformsamladapter.BuildTenantSAMLMetadata(projection)
	if errors.Is(err, platformsamladapter.ErrProtocolRejected) {
		clear(document.Document)
		return platformsamladapter.TenantSAMLMetadataDocument{}, errTenantSAMLMetadataNotFound
	}
	if err != nil || document.ContentType != platformsamladapter.SAMLMetadataContentType || len(document.Document) == 0 {
		clear(document.Document)
		return platformsamladapter.TenantSAMLMetadataDocument{}, errFederatedTransportUnavailable
	}
	return document, nil
}

func clearTenantSAMLMetadataProjection(projection *platformsamladapter.TenantSAMLMetadataProjection) {
	if projection == nil {
		return
	}
	for index := range projection.Certificates {
		clear(projection.Certificates[index].CertificateDER)
	}
	*projection = platformsamladapter.TenantSAMLMetadataProjection{}
}

type unavailableTenantSAMLMetadataService struct{}

func (unavailableTenantSAMLMetadataService) Metadata(
	context.Context,
	string,
	string,
) (platformsamladapter.TenantSAMLMetadataDocument, error) {
	return platformsamladapter.TenantSAMLMetadataDocument{}, errFederatedTransportUnavailable
}
