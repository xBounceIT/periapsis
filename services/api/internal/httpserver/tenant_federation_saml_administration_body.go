package httpserver

import (
	"errors"
	"net/http"
	"unicode/utf8"

	"github.com/periapsis-im/periapsis/services/api/internal/contract"
	"github.com/periapsis-im/periapsis/services/api/internal/identityprovider"
)

type tenantFederationSAMLMetadataBody struct {
	metadataURL       *string
	metadataXML       []byte
	approveTrustReset bool
	reason            string
}

func (body *tenantFederationSAMLMetadataBody) destroy() {
	if body == nil {
		return
	}
	clear(body.metadataXML)
	*body = tenantFederationSAMLMetadataBody{}
}

func decodeTenantFederationSAMLMetadataBody(r *http.Request) (tenantFederationSAMLMetadataBody, error) {
	document, err := readPlatformSAMLAdministrationBody(r)
	if err != nil {
		return tenantFederationSAMLMetadataBody{}, err
	}
	return decodeTenantFederationSAMLMetadataDocument(document)
}

func decodeTenantFederationSAMLMetadataDocument(
	document []byte,
) (result tenantFederationSAMLMetadataBody, err error) {
	defer clear(document[:cap(document)])
	defer func() {
		if err != nil {
			result.destroy()
		}
	}()
	if !utf8.Valid(document) {
		return tenantFederationSAMLMetadataBody{}, errors.New("tenant SAML metadata body is not UTF-8 JSON")
	}
	parser := tenantLDAPSecretParser{source: document}
	parser.skipWhitespace()
	if !parser.consume('{') {
		return tenantFederationSAMLMetadataBody{}, errors.New("tenant SAML metadata body must be an object")
	}
	var source string
	seen := make(map[string]struct{}, 5)
	for member := 0; ; member++ {
		parser.skipWhitespace()
		if parser.consume('}') {
			break
		}
		if member >= 5 {
			return tenantFederationSAMLMetadataBody{}, errors.New("tenant SAML metadata body contains extra fields")
		}
		key, parseErr := parser.stringBytes(32)
		if parseErr != nil {
			return tenantFederationSAMLMetadataBody{}, parseErr
		}
		keyText := string(key)
		clear(key)
		if _, duplicate := seen[keyText]; duplicate {
			return tenantFederationSAMLMetadataBody{}, errors.New("tenant SAML metadata body contains a duplicate field")
		}
		seen[keyText] = struct{}{}
		parser.skipWhitespace()
		if !parser.consume(':') {
			return tenantFederationSAMLMetadataBody{}, errors.New("tenant SAML metadata member is missing a colon")
		}
		parser.skipWhitespace()
		switch keyText {
		case "source":
			value, valueErr := parser.stringBytes(8)
			if valueErr != nil {
				return tenantFederationSAMLMetadataBody{}, valueErr
			}
			source = string(value)
			clear(value)
		case "metadataUrl":
			value, valueErr := parser.stringBytes(4096)
			if valueErr != nil {
				return tenantFederationSAMLMetadataBody{}, valueErr
			}
			location := string(value)
			clear(value)
			result.metadataURL = &location
		case "metadataXml":
			result.metadataXML, parseErr = parser.stringBytes(maximumFederationSAMLMetadataHTTPBytes)
		case "approveTrustReset":
			result.approveTrustReset, parseErr = parsePlatformSAMLBoolean(&parser)
		case "reason":
			value, valueErr := parser.stringBytes(maximumFederationAuditReasonHTTPBytes)
			if valueErr != nil {
				return tenantFederationSAMLMetadataBody{}, valueErr
			}
			result.reason = string(value)
			clear(value)
		default:
			return tenantFederationSAMLMetadataBody{}, errors.New("tenant SAML metadata body contains an unknown field")
		}
		if parseErr != nil {
			return tenantFederationSAMLMetadataBody{}, parseErr
		}
		parser.skipWhitespace()
		if parser.consume('}') {
			break
		}
		if !parser.consume(',') {
			return tenantFederationSAMLMetadataBody{}, errors.New("tenant SAML metadata body is malformed")
		}
		parser.skipWhitespace()
		if parser.index >= len(parser.source) || parser.source[parser.index] == '}' {
			return tenantFederationSAMLMetadataBody{}, errors.New("tenant SAML metadata body contains a trailing comma")
		}
	}
	parser.skipWhitespace()
	_, sourceSeen := seen["source"]
	_, approvalSeen := seen["approveTrustReset"]
	_, reasonSeen := seen["reason"]
	_, urlSeen := seen["metadataUrl"]
	_, xmlSeen := seen["metadataXml"]
	if parser.index != len(parser.source) || !sourceSeen || !approvalSeen || !reasonSeen ||
		urlSeen == xmlSeen || source == "url" && !urlSeen || source == "xml" && !xmlSeen ||
		source != "url" && source != "xml" ||
		urlSeen && (result.metadataURL == nil || *result.metadataURL == "") ||
		xmlSeen && len(result.metadataXML) == 0 {
		return tenantFederationSAMLMetadataBody{}, errors.New("tenant SAML metadata body is incomplete")
	}
	return result, nil
}

const (
	maximumFederationSAMLMetadataHTTPBytes = 512 * 1024
	// OpenAPI maxLength and the domain boundary count Unicode scalar values.
	// Four bytes per scalar is the exact worst-case UTF-8 transport allowance.
	maximumFederationAuditReasonHTTPBytes = 4 * 500
)

func decodeTenantFederationSAMLSPCredentialBody(r *http.Request) (string, error) {
	var body contract.TenantSAMLSPCredentialMutationRequest
	raw, err := decodeTenantLDAPJSONBody(r, &body)
	if err != nil {
		return "", err
	}
	if _, err = exactTenantLDAPJSONObject(raw, []string{"reason"}, []string{"reason"}); err != nil {
		return "", err
	}
	return body.Reason, nil
}

func tenantFederationSAMLInput(body tenantFederationSAMLMetadataBody) identityprovider.FederationReplaceSAMLMetadataInput {
	return identityprovider.FederationReplaceSAMLMetadataInput{
		MetadataURL: body.metadataURL, MetadataXML: body.metadataXML,
		ApproveTrustReset: body.approveTrustReset, Reason: body.reason,
	}
}
