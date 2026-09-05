package httpserver

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"strconv"
	"unicode/utf8"

	"github.com/periapsis-im/periapsis/services/api/internal/contract"
)

const (
	maximumPlatformIdentityProviderBodyBytes = 1 << 20
	maximumPlatformOIDCSecretBodyBytes       = 64 << 10
	maximumPlatformOIDCClientSecretBytes     = 8 * 1024
)

var (
	platformOIDCCreateConfigurationFields = []string{
		"issuer", "clientId", "redirectUri", "tenantRedirectUri", "postLogoutRedirectUri", "extraScopes",
		"allowRefreshToken", "useUserInfo",
	}
	platformSAMLCreateConfigurationFields = []string{
		"expectedEntityId", "spEntityId", "acsUrl", "redirectSignatureAlgorithm",
		"signaturePolicy", "encryptionPolicy", "requestedAuthnContexts", "subjectSource",
		"subjectAttributeName", "subjectAttributeNameFormat", "clockSkewNanoseconds",
		"maxAuthenticationAgeNanoseconds",
	}
)

func decodePlatformAuthProviderCreateBody(
	r *http.Request,
	destination *contract.PlatformAuthProviderCreateRequest,
) error {
	raw, err := decodePlatformIdentityProviderJSONBody(r, destination)
	if err != nil {
		return err
	}
	object, err := exactTenantLDAPJSONObject(
		raw,
		[]string{"kind", "key", "displayName", "description", "configuration"},
		[]string{"kind", "key", "displayName", "configuration"},
	)
	if err != nil {
		return err
	}
	if err := requirePlatformIdentityProviderJSONTypes(
		object,
		[]string{"kind", "key", "displayName"},
		nil,
		nil,
		nil,
	); err != nil {
		return err
	}
	if description, present := object["description"]; present {
		if _, ok := description.(string); !ok {
			return errors.New("platform provider description must be a string")
		}
	}
	kind, ok := object["kind"].(string)
	if !ok {
		return errors.New("platform provider kind must be a string")
	}
	switch kind {
	case "oidc":
		configuration, configurationErr := exactTenantLDAPJSONObject(
			object["configuration"],
			platformOIDCCreateConfigurationFields,
			platformOIDCCreateConfigurationFields,
		)
		if configurationErr != nil {
			return configurationErr
		}
		err = requirePlatformIdentityProviderJSONTypes(
			configuration,
			[]string{"issuer", "clientId", "redirectUri", "tenantRedirectUri", "postLogoutRedirectUri"},
			[]string{"allowRefreshToken", "useUserInfo"},
			[]string{"extraScopes"},
			nil,
		)
	case "saml":
		configuration, configurationErr := exactTenantLDAPJSONObject(
			object["configuration"],
			platformSAMLCreateConfigurationFields,
			[]string{
				"expectedEntityId", "spEntityId", "acsUrl", "redirectSignatureAlgorithm",
				"signaturePolicy", "encryptionPolicy", "requestedAuthnContexts", "subjectSource",
				"clockSkewNanoseconds", "maxAuthenticationAgeNanoseconds",
			},
		)
		if configurationErr != nil {
			return configurationErr
		}
		if err := requirePlatformIdentityProviderJSONTypes(
			configuration,
			[]string{
				"expectedEntityId", "spEntityId", "acsUrl", "redirectSignatureAlgorithm",
				"signaturePolicy", "encryptionPolicy", "subjectSource",
			},
			nil,
			[]string{"requestedAuthnContexts"},
			[]string{"clockSkewNanoseconds", "maxAuthenticationAgeNanoseconds"},
		); err != nil {
			return err
		}
		subjectSource, subjectOK := configuration["subjectSource"].(string)
		_, subjectNamePresent := configuration["subjectAttributeName"]
		_, subjectFormatPresent := configuration["subjectAttributeNameFormat"]
		if !subjectOK || subjectSource == "persistent_nameid" &&
			(subjectNamePresent || subjectFormatPresent) ||
			subjectSource == "immutable_attribute" &&
				(!subjectNamePresent || !subjectFormatPresent) {
			return errors.New("platform SAML subject source is inconsistent")
		}
		if subjectSource != "persistent_nameid" && subjectSource != "immutable_attribute" {
			return errors.New("platform SAML subject source is invalid")
		}
		if subjectSource == "immutable_attribute" {
			err = requirePlatformIdentityProviderJSONTypes(
				configuration,
				[]string{"subjectAttributeName", "subjectAttributeNameFormat"},
				nil,
				nil,
				nil,
			)
		}
	default:
		return errors.New("platform provider kind is unsupported")
	}
	return err
}

func decodePlatformAuthProviderUpdateBody(
	r *http.Request,
	destination *contract.PlatformAuthProviderUpdateRequest,
) error {
	raw, err := decodePlatformIdentityProviderJSONBody(r, destination)
	if err != nil {
		return err
	}
	object, err := exactTenantLDAPJSONObject(
		raw,
		[]string{"key", "displayName", "description", "expectedVersion"},
		[]string{"key", "displayName", "description", "expectedVersion"},
	)
	if err != nil {
		return err
	}
	return requirePlatformIdentityProviderJSONTypes(
		object,
		[]string{"key", "displayName", "description"},
		nil,
		nil,
		[]string{"expectedVersion"},
	)
}

func decodePlatformAuthProviderArchiveBody(
	r *http.Request,
	destination *contract.PlatformAuthProviderArchiveRequest,
) error {
	raw, err := decodePlatformIdentityProviderJSONBody(r, destination)
	if err != nil {
		return err
	}
	object, err := exactTenantLDAPJSONObject(raw, []string{"expectedVersion"}, []string{"expectedVersion"})
	if err != nil {
		return err
	}
	return requirePlatformIdentityProviderJSONTypes(object, nil, nil, nil, []string{"expectedVersion"})
}

func decodePlatformAuthProviderActivationBody(
	r *http.Request,
	destination *contract.PlatformAuthProviderActivationRequest,
) error {
	raw, err := decodePlatformIdentityProviderJSONBody(r, destination)
	if err != nil {
		return err
	}
	object, err := exactTenantLDAPJSONObject(
		raw,
		[]string{"expectedVersion", "accountMode"},
		[]string{"expectedVersion", "accountMode"},
	)
	if err != nil {
		return err
	}
	return requirePlatformIdentityProviderJSONTypes(
		object, []string{"accountMode"}, nil, nil, []string{"expectedVersion"},
	)
}

func decodePlatformAuthProviderDeactivationBody(
	r *http.Request,
	destination *contract.PlatformAuthProviderDeactivationRequest,
) error {
	raw, err := decodePlatformIdentityProviderJSONBody(r, destination)
	if err != nil {
		return err
	}
	object, err := exactTenantLDAPJSONObject(raw, []string{"expectedVersion"}, []string{"expectedVersion"})
	if err != nil {
		return err
	}
	return requirePlatformIdentityProviderJSONTypes(object, nil, nil, nil, []string{"expectedVersion"})
}

func decodePlatformOIDCDirectLoginBody(
	r *http.Request,
	destination *contract.PlatformOIDCDirectLoginCommandRequest,
) error {
	raw, err := decodePlatformIdentityProviderJSONBody(r, destination)
	if err != nil {
		return err
	}
	object, err := exactTenantLDAPJSONObject(raw, []string{"expectedVersion"}, []string{"expectedVersion"})
	if err != nil {
		return err
	}
	return requirePlatformIdentityProviderJSONTypes(object, nil, nil, nil, []string{"expectedVersion"})
}

func requirePlatformIdentityProviderJSONTypes(
	object map[string]any,
	stringFields []string,
	booleanFields []string,
	stringArrayFields []string,
	integerFields []string,
) error {
	for _, field := range stringFields {
		if _, ok := object[field].(string); !ok {
			return errors.New("platform identity-provider string field is invalid")
		}
	}
	for _, field := range booleanFields {
		if _, ok := object[field].(bool); !ok {
			return errors.New("platform identity-provider boolean field is invalid")
		}
	}
	for _, field := range stringArrayFields {
		values, ok := object[field].([]any)
		if !ok {
			return errors.New("platform identity-provider string-array field is invalid")
		}
		for _, value := range values {
			if _, ok := value.(string); !ok {
				return errors.New("platform identity-provider string-array item is invalid")
			}
		}
	}
	for _, field := range integerFields {
		value, ok := object[field].(float64)
		if !ok || math.Trunc(value) != value {
			return errors.New("platform identity-provider integer field is invalid")
		}
	}
	return nil
}

func decodePlatformIdentityProviderJSONBody(r *http.Request, destination any) (any, error) {
	mediaType, err := requestMediaType(r)
	if err != nil || mediaType != "application/json" {
		return nil, errors.New("unsupported platform identity-provider content type")
	}
	if r == nil || r.Body == nil {
		return nil, errors.New("platform identity-provider request body is missing")
	}
	defer r.Body.Close()
	body, err := io.ReadAll(io.LimitReader(r.Body, maximumPlatformIdentityProviderBodyBytes+1))
	if err != nil || len(body) == 0 || len(body) > maximumPlatformIdentityProviderBodyBytes || !utf8.Valid(body) {
		clear(body)
		return nil, errors.New("platform identity-provider request body is invalid")
	}
	defer clear(body)
	if err := validateTenantLDAPJSONTokens(body); err != nil {
		return nil, err
	}
	var raw any
	if err := unmarshalExactJSON(body, &raw); err != nil {
		return nil, err
	}
	if err := unmarshalExactJSON(body, destination); err != nil {
		return nil, err
	}
	return raw, nil
}

func unmarshalExactJSON(document []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return errors.New("platform identity-provider request body does not match the contract")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("platform identity-provider request body must contain one JSON value")
	}
	return nil
}

func decodePlatformOIDCClientSecret(
	r *http.Request,
) (secret []byte, expectedVersion int64, err error) {
	mediaType, mediaErr := requestMediaType(r)
	if mediaErr != nil || mediaType != "application/json" || r == nil || r.Body == nil {
		return nil, 0, errors.New("unsupported platform OIDC secret content type")
	}
	defer r.Body.Close()
	buffer := make([]byte, maximumPlatformOIDCSecretBodyBytes+1)
	used := 0
	for used < len(buffer) {
		read, readErr := r.Body.Read(buffer[used:])
		used += read
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				break
			}
			clear(buffer)
			return nil, 0, errors.New("platform OIDC secret body could not be read")
		}
		if read == 0 {
			clear(buffer)
			return nil, 0, errors.New("platform OIDC secret body made no progress")
		}
	}
	if used == 0 || used > maximumPlatformOIDCSecretBodyBytes {
		clear(buffer)
		return nil, 0, errors.New("platform OIDC secret body is invalid")
	}
	return decodePlatformOIDCClientSecretDocument(buffer[:used])
}

func decodePlatformOIDCClientSecretDocument(
	document []byte,
) (secret []byte, expectedVersion int64, err error) {
	defer clear(document[:cap(document)])
	defer func() {
		if err != nil {
			clear(secret)
			secret = nil
		}
	}()
	if !utf8.Valid(document) {
		return nil, 0, errors.New("platform OIDC secret body is not UTF-8 JSON")
	}
	parser := tenantLDAPSecretParser{source: document}
	parser.skipWhitespace()
	if !parser.consume('{') {
		return nil, 0, errors.New("platform OIDC secret body must be an object")
	}
	seenSecret := false
	seenVersion := false
	for member := 0; ; member++ {
		parser.skipWhitespace()
		if parser.consume('}') {
			break
		}
		if member >= 2 {
			return nil, 0, errors.New("platform OIDC secret body contains extra fields")
		}
		key, parseErr := parser.stringBytes(32)
		if parseErr != nil {
			return nil, 0, parseErr
		}
		parser.skipWhitespace()
		if !parser.consume(':') {
			clear(key)
			return nil, 0, errors.New("platform OIDC secret member is missing a colon")
		}
		parser.skipWhitespace()
		switch {
		case bytes.Equal(key, []byte("clientSecret")):
			if seenSecret {
				clear(key)
				return nil, 0, errors.New("platform OIDC secret body contains a duplicate field")
			}
			secret, parseErr = parser.stringBytes(maximumPlatformOIDCClientSecretBytes)
			seenSecret = true
		case bytes.Equal(key, []byte("expectedVersion")):
			if seenVersion {
				clear(key)
				return nil, 0, errors.New("platform OIDC secret body contains a duplicate field")
			}
			expectedVersion, parseErr = parsePlatformOIDCSecretVersion(&parser)
			seenVersion = true
		default:
			clear(key)
			return nil, 0, errors.New("platform OIDC secret body contains an unknown field")
		}
		clear(key)
		if parseErr != nil {
			return nil, 0, parseErr
		}
		parser.skipWhitespace()
		if parser.consume('}') {
			break
		}
		if !parser.consume(',') {
			return nil, 0, errors.New("platform OIDC secret body is malformed")
		}
		parser.skipWhitespace()
		if parser.index >= len(parser.source) || parser.source[parser.index] == '}' {
			return nil, 0, errors.New("platform OIDC secret body contains a trailing comma")
		}
	}
	parser.skipWhitespace()
	if parser.index != len(parser.source) || !seenSecret || !seenVersion || len(secret) == 0 {
		return nil, 0, errors.New("platform OIDC secret body is incomplete")
	}
	return secret, expectedVersion, nil
}

func parsePlatformOIDCSecretVersion(parser *tenantLDAPSecretParser) (int64, error) {
	start := parser.index
	for parser.index < len(parser.source) && parser.source[parser.index] >= '0' && parser.source[parser.index] <= '9' {
		parser.index++
	}
	if parser.index == start || parser.source[start] == '0' {
		return 0, errors.New("platform OIDC expectedVersion is invalid")
	}
	version, err := strconv.ParseInt(string(parser.source[start:parser.index]), 10, 64)
	if err != nil || version < 1 {
		return 0, errors.New("platform OIDC expectedVersion is invalid")
	}
	return version, nil
}
