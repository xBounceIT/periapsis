package federatedsaml

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net/url"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
)

type localLogoutObservation interface {
	LocalLogoutObservedAt() time.Time
}

// BuildLogoutRequest creates an optional outbound SLO artifact only after the
// caller proves that the local session has already been revoked.
func (kernel *Kernel) BuildLogoutRequest(ctx context.Context, request LogoutBuildRequest) (LogoutRequest, error) {
	if kernel == nil || request.Confirmation == nil || !validEntityID(request.SessionID) ||
		request.Configuration.Authority != kernel.authority ||
		!validEntityID(request.MaterialID) ||
		request.ProtectedMaterial.KeyVersion == 0 || len(request.ProtectedMaterial.Ciphertext) == 0 ||
		len(request.ProtectedMaterial.Ciphertext) > maximumProtectedMaterialBytes {
		return LogoutRequest{}, ErrLogoutArtifactRejected
	}
	now, err := canonicalNow(kernel.now)
	if err != nil {
		return LogoutRequest{}, ErrLogoutArtifactRejected
	}
	configuration, _, err := normalizeConfiguration(request.Configuration, now, kernel.limits)
	if err != nil || configuration.Metadata.sloRedirectURL == "" {
		return LogoutRequest{}, ErrLogoutArtifactRejected
	}
	return kernel.buildLogoutRequest(ctx, storedLogoutConfiguration(configuration), request.SessionID,
		request.MaterialID, request.ProtectedMaterial, request.Confirmation, now)
}

// BuildStoredLogoutRequest creates an outbound SLO artifact from the exact
// session-time projection. The projection is intentionally independent of
// current provider readiness and metadata freshness.
func (kernel *Kernel) BuildStoredLogoutRequest(
	ctx context.Context,
	request StoredLogoutBuildRequest,
) (LogoutRequest, error) {
	configuration := request.Configuration
	if kernel == nil || request.Confirmation == nil || !validEntityID(request.SessionID) ||
		!validEntityID(request.MaterialID) || request.ProtectedMaterial.KeyVersion == 0 ||
		len(request.ProtectedMaterial.Ciphertext) == 0 ||
		len(request.ProtectedMaterial.Ciphertext) > maximumProtectedMaterialBytes ||
		configuration.Authority != kernel.authority ||
		!validCeremonyContext(configuration.Authority, configuration.Provider,
			configuration.MaterialBindingID, configuration.PlatformLoginRevision) ||
		!validBoundedString(configuration.SPEntityID, maximumEntityIDBytes) ||
		!validPersistentRevision(configuration.SPKeyRevision) ||
		!validRedirectAlgorithm(configuration.RedirectSignatureAlgorithm) {
		return LogoutRequest{}, ErrLogoutArtifactRejected
	}
	canonicalSLO, validSLO := canonicalHTTPSURL(configuration.SLORedirectURL, maximumEndpointBytes)
	if !validSLO || canonicalSLO != configuration.SLORedirectURL {
		return LogoutRequest{}, ErrLogoutArtifactRejected
	}
	now, err := canonicalNow(kernel.now)
	if err != nil {
		return LogoutRequest{}, ErrLogoutArtifactRejected
	}
	return kernel.buildLogoutRequest(ctx, configuration, request.SessionID, request.MaterialID,
		request.ProtectedMaterial, request.Confirmation, now)
}

func storedLogoutConfiguration(configuration Configuration) StoredLogoutConfiguration {
	return StoredLogoutConfiguration{
		Authority: configuration.Authority, Provider: configuration.Provider,
		MaterialBindingID: configuration.BindingID, PlatformLoginRevision: configuration.PlatformLoginRevision,
		SPEntityID: configuration.SPEntityID, SLORedirectURL: configuration.Metadata.sloRedirectURL,
		SPKeyRevision:              configuration.SPKeyRevision,
		RedirectSignatureAlgorithm: configuration.RedirectSignatureAlgorithm,
	}
}

func (kernel *Kernel) buildLogoutRequest(
	ctx context.Context,
	configuration StoredLogoutConfiguration,
	sessionID identity.EntityID,
	materialID identity.EntityID,
	protectedMaterial ProtectedSessionMaterial,
	confirmation LocalLogoutConfirmation,
	now time.Time,
) (LogoutRequest, error) {
	if confirmation.SAMLProvider() != configuration.Provider ||
		confirmation.SAMLBindingID() != configuration.MaterialBindingID ||
		confirmation.LocalSessionID() != sessionID {
		return LogoutRequest{}, ErrLogoutArtifactRejected
	}
	revokedAt := confirmation.LocalSessionRevokedAt()
	observedAt := now
	if observation, ok := confirmation.(localLogoutObservation); ok {
		observedAt = observation.LocalLogoutObservedAt()
		if !validInstant(observedAt) || observedAt.Before(now.Add(-5*time.Minute)) ||
			observedAt.After(now.Add(5*time.Minute)) {
			return LogoutRequest{}, ErrLogoutArtifactRejected
		}
	}
	if !validInstant(revokedAt) || revokedAt.After(observedAt) || observedAt.Sub(revokedAt) > 15*time.Minute {
		return LogoutRequest{}, ErrLogoutArtifactRejected
	}
	bounded, cancel, err := operationContext(ctx, kernel.operationTimeout)
	if err != nil {
		return LogoutRequest{}, errors.Join(ErrLogoutArtifactRejected, err)
	}
	defer cancel()
	protectedCiphertext := append([]byte(nil), protectedMaterial.Ciphertext...)
	defer clear(protectedCiphertext)
	material, err := kernel.sessionProtector.OpenSAMLSession(bounded, SessionMaterialContext{
		Authority: configuration.Authority, Provider: configuration.Provider, BindingID: configuration.MaterialBindingID,
		MaterialID: materialID, PlatformLoginRevision: configuration.PlatformLoginRevision,
	}, ProtectedSessionMaterial{
		KeyVersion: protectedMaterial.KeyVersion,
		Ciphertext: protectedCiphertext,
	})
	if err != nil || !validBoundedString(material.NameID, maximumAttributeValueBytes) ||
		material.NameIDFormat != samlPersistentNameID ||
		!validBoundedString(material.SessionIndex, maximumSessionIndexBytes) {
		return LogoutRequest{}, ErrLogoutArtifactRejected
	}
	opaque, err := randomOpaque(kernel.random)
	if err != nil {
		return LogoutRequest{}, ErrLogoutArtifactRejected
	}
	requestID := "_" + base64.RawURLEncoding.EncodeToString(opaque)
	document, err := buildLogoutDocument(configuration.SPEntityID, configuration.SLORedirectURL, requestID, now, material)
	if err != nil {
		return LogoutRequest{}, ErrLogoutArtifactRejected
	}
	compressed, err := deflateRequest(document)
	if err != nil || len(compressed) > maximumSignedPayloadBytes {
		return LogoutRequest{}, ErrLogoutArtifactRejected
	}
	signedQuery := "SAMLRequest=" + url.QueryEscape(base64.StdEncoding.EncodeToString(compressed)) +
		"&SigAlg=" + url.QueryEscape(string(configuration.RedirectSignatureAlgorithm))
	signature, err := kernel.redirectSigner.SignRedirect(bounded, RedirectSignRequest{
		Authority: configuration.Authority, Provider: configuration.Provider, BindingID: configuration.MaterialBindingID,
		PlatformLoginRevision: configuration.PlatformLoginRevision,
		KeyRevision:           configuration.SPKeyRevision, Algorithm: configuration.RedirectSignatureAlgorithm,
		LogoutMaterialID: materialID,
		Payload:          []byte(signedQuery),
	})
	if err != nil || len(signature) == 0 || len(signature) > maximumSignatureBytes {
		return LogoutRequest{}, ErrLogoutArtifactRejected
	}
	redirectURL := configuration.SLORedirectURL + "?" + signedQuery +
		"&Signature=" + url.QueryEscape(base64.StdEncoding.EncodeToString(signature))
	if len(redirectURL) > maximumRedirectBytes {
		return LogoutRequest{}, ErrLogoutArtifactRejected
	}
	return LogoutRequest{redirectURL: redirectURL, requestID: requestID, issuedAt: now, valid: true}, nil
}

func buildLogoutDocument(spEntityID, sloRedirectURL, requestID string, issuedAt time.Time, material SessionMaterial) ([]byte, error) {
	if !validXMLID(requestID) {
		return nil, errors.New("logout request rejected")
	}
	var result bytes.Buffer
	result.WriteString(`<samlp:LogoutRequest xmlns:samlp="`)
	escapeXML(&result, samlProtocolNamespace)
	result.WriteString(`" xmlns:saml="`)
	escapeXML(&result, samlAssertionNamespace)
	result.WriteString(`" ID="`)
	escapeXML(&result, requestID)
	result.WriteString(`" Version="2.0" IssueInstant="`)
	escapeXML(&result, issuedAt.Format(time.RFC3339Nano))
	result.WriteString(`" Destination="`)
	escapeXML(&result, sloRedirectURL)
	result.WriteString(`"><saml:Issuer>`)
	escapeXML(&result, spEntityID)
	result.WriteString(`</saml:Issuer><saml:NameID Format="`)
	escapeXML(&result, material.NameIDFormat)
	result.WriteString(`">`)
	escapeXML(&result, material.NameID)
	result.WriteString(`</saml:NameID><samlp:SessionIndex>`)
	escapeXML(&result, material.SessionIndex)
	result.WriteString(`</samlp:SessionIndex></samlp:LogoutRequest>`)
	if result.Len() > maximumSignedPayloadBytes {
		return nil, errors.New("logout request rejected")
	}
	return result.Bytes(), nil
}
