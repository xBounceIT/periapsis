package federatedsaml

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"net/url"
	"time"
)

func (kernel *Kernel) StartAuthentication(ctx context.Context, request StartRequest) (AuthorizationStart, error) {
	if kernel == nil || kernel.transactions == nil || !validAuthenticationBegin(request.Begin) ||
		request.Configuration.Authority != kernel.authority ||
		request.HasLiveSession || !validReturnPath(request.ReturnPath) ||
		len(request.PreviousBrowserHandle) != 0 && !validBrowserHandle(request.PreviousBrowserHandle) {
		return AuthorizationStart{}, ErrAuthenticationStart
	}
	now, err := canonicalNow(kernel.now)
	if err != nil {
		return AuthorizationStart{}, ErrAuthenticationStart
	}
	configuration, configurationDigest, err := normalizeConfiguration(request.Configuration, now, kernel.limits)
	if err != nil {
		return AuthorizationStart{}, ErrAuthenticationStart
	}
	transactionBytes, err := randomOpaque(kernel.random)
	if err != nil {
		return AuthorizationStart{}, ErrAuthenticationStart
	}
	requestOpaque, err := randomOpaque(kernel.random)
	if err != nil {
		return AuthorizationStart{}, ErrAuthenticationStart
	}
	relayOpaque, err := randomOpaque(kernel.random)
	if err != nil {
		return AuthorizationStart{}, ErrAuthenticationStart
	}
	browserOpaque, err := randomOpaque(kernel.random)
	if err != nil {
		return AuthorizationStart{}, ErrAuthenticationStart
	}
	generated := map[[sha256.Size]byte]struct{}{}
	for _, opaque := range [][]byte{transactionBytes, requestOpaque, relayOpaque, browserOpaque} {
		digest := digestOpaque(opaque)
		if _, duplicate := generated[digest]; duplicate {
			return AuthorizationStart{}, ErrAuthenticationStart
		}
		generated[digest] = struct{}{}
	}
	requestID := "_" + base64.RawURLEncoding.EncodeToString(requestOpaque)
	relayState := base64.RawURLEncoding.EncodeToString(relayOpaque)
	browserHandle := []byte(base64.RawURLEncoding.EncodeToString(browserOpaque))
	if len(request.PreviousBrowserHandle) != 0 && compareDigest(digestOpaque(request.PreviousBrowserHandle), digestOpaque(browserHandle)) {
		return AuthorizationStart{}, ErrAuthenticationStart
	}
	authnRequest, err := buildAuthnRequest(configuration, requestID, now)
	if err != nil {
		return AuthorizationStart{}, ErrAuthenticationStart
	}
	compressed, err := deflateRequest(authnRequest)
	if err != nil || len(compressed) > maximumSignedPayloadBytes {
		return AuthorizationStart{}, ErrAuthenticationStart
	}
	encoded := base64.StdEncoding.EncodeToString(compressed)
	signedQuery := "SAMLRequest=" + url.QueryEscape(encoded) + "&RelayState=" + url.QueryEscape(relayState) +
		"&SigAlg=" + url.QueryEscape(string(configuration.RedirectSignatureAlgorithm))
	if len(signedQuery) > maximumRedirectBytes {
		return AuthorizationStart{}, ErrAuthenticationStart
	}
	bounded, cancel, err := operationContext(ctx, kernel.operationTimeout)
	if err != nil {
		return AuthorizationStart{}, errors.Join(ErrAuthenticationStart, err)
	}
	defer cancel()
	signature, err := kernel.redirectSigner.SignRedirect(bounded, RedirectSignRequest{
		Authority: configuration.Authority, Provider: configuration.Provider, BindingID: configuration.BindingID,
		PlatformLoginRevision: configuration.PlatformLoginRevision,
		KeyRevision:           configuration.SPKeyRevision, Algorithm: configuration.RedirectSignatureAlgorithm,
		Payload: []byte(signedQuery),
	})
	if err != nil || len(signature) == 0 || len(signature) > maximumSignatureBytes {
		return AuthorizationStart{}, ErrAuthenticationStart
	}
	redirectURL := configuration.Metadata.ssoRedirectURL + "?" + signedQuery +
		"&Signature=" + url.QueryEscape(base64.StdEncoding.EncodeToString(signature))
	if len(redirectURL) > maximumRedirectBytes {
		return AuthorizationStart{}, ErrAuthenticationStart
	}
	var transactionID TransactionID
	copy(transactionID[:], transactionBytes)
	expiresAt := now.Add(kernel.transactionTTL)
	pending := PendingTransaction{
		ID: transactionID, MaterialID: request.Begin.OperationRunID,
		RequestID: requestID, RelayStateDigest: digestOpaque([]byte(relayState)),
		BrowserDigest: digestOpaque(browserHandle), Pins: transactionPins(configuration, configurationDigest),
		CreatedAt: now, ExpiresAt: expiresAt, ReturnPath: request.ReturnPath,
		State: TransactionPending, Version: 1,
	}
	createRequest := CreateTransactionRequest{Begin: request.Begin, Current: pending}
	if len(request.PreviousBrowserHandle) != 0 {
		createRequest.PreviousBrowserDigest = digestOpaque(request.PreviousBrowserHandle)
		createRequest.HasPreviousBrowserBinding = true
	}
	if err := kernel.transactions.CreateReplacing(bounded, createRequest); err != nil {
		return AuthorizationStart{}, ErrTransactionPersistence
	}
	return AuthorizationStart{
		transactionID: transactionID, redirectURL: redirectURL,
		browserHandle: browserHandle, expiresAt: expiresAt, valid: true,
	}, nil
}

func validBrowserHandle(value []byte) bool {
	if len(value) != base64.RawURLEncoding.EncodedLen(minimumOpaqueBytes) {
		return false
	}
	decoded := make([]byte, minimumOpaqueBytes)
	defer clear(decoded)
	written, err := base64.RawURLEncoding.Strict().Decode(decoded, value)
	canonical := make([]byte, base64.RawURLEncoding.EncodedLen(minimumOpaqueBytes))
	defer clear(canonical)
	base64.RawURLEncoding.Encode(canonical, decoded)
	return err == nil && written == len(decoded) && validOpaque(decoded) && bytes.Equal(canonical, value)
}

func buildAuthnRequest(configuration Configuration, requestID string, issuedAt time.Time) ([]byte, error) {
	if !validXMLID(requestID) {
		return nil, errors.New("request rejected")
	}
	var result bytes.Buffer
	result.WriteString(`<samlp:AuthnRequest xmlns:samlp="`)
	escapeXML(&result, samlProtocolNamespace)
	result.WriteString(`" xmlns:saml="`)
	escapeXML(&result, samlAssertionNamespace)
	result.WriteString(`" ID="`)
	escapeXML(&result, requestID)
	result.WriteString(`" Version="2.0" IssueInstant="`)
	escapeXML(&result, issuedAt.Format(time.RFC3339Nano))
	result.WriteString(`" Destination="`)
	escapeXML(&result, configuration.Metadata.ssoRedirectURL)
	result.WriteString(`" AssertionConsumerServiceURL="`)
	escapeXML(&result, configuration.ACSURL)
	result.WriteString(`" ProtocolBinding="`)
	escapeXML(&result, samlHTTPPOSTBinding)
	result.WriteString(`"><saml:Issuer>`)
	escapeXML(&result, configuration.SPEntityID)
	result.WriteString(`</saml:Issuer><samlp:NameIDPolicy AllowCreate="true"`)
	if configuration.Subject.Source == SubjectPersistentNameID {
		result.WriteString(` Format="`)
		escapeXML(&result, samlPersistentNameID)
		result.WriteString(`"`)
	}
	result.WriteString(`/><samlp:RequestedAuthnContext Comparison="` + samlExactAuthnContextCompare + `">`)
	for _, classRef := range configuration.RequestedAuthnContexts {
		result.WriteString(`<saml:AuthnContextClassRef>`)
		escapeXML(&result, classRef)
		result.WriteString(`</saml:AuthnContextClassRef>`)
	}
	result.WriteString(`</samlp:RequestedAuthnContext></samlp:AuthnRequest>`)
	if result.Len() > maximumSignedPayloadBytes {
		return nil, errors.New("request rejected")
	}
	return result.Bytes(), nil
}

func escapeXML(destination *bytes.Buffer, value string) {
	_ = xml.EscapeText(destination, []byte(value))
}

func deflateRequest(document []byte) ([]byte, error) {
	var result bytes.Buffer
	writer, err := flate.NewWriter(&result, flate.BestCompression)
	if err != nil {
		return nil, err
	}
	if _, err = writer.Write(document); err != nil {
		_ = writer.Close()
		return nil, err
	}
	if err = writer.Close(); err != nil {
		return nil, err
	}
	return result.Bytes(), nil
}
