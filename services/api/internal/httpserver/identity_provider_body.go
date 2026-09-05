package httpserver

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/periapsis-im/periapsis/services/api/internal/contract"
)

const (
	maximumTenantLDAPBodyBytes       = 1 << 20
	maximumTenantLDAPSecretBodyBytes = 64 << 10
	maximumTenantLDAPSecretBytes     = 8*1024 - 16
)

var (
	tenantLDAPConfigurationFields = []string{
		"template", "verifyCertificate", "customCaPem", "connectTimeoutMs", "operationTimeoutMs",
		"bindDn", "userBaseDn", "groupBaseDn", "userSearchFilter", "groupSearchFilter", "userDnTemplate",
		"pageSize", "maxPages", "maxEntries", "maxResponseBytes", "referralMode", "maxReferralHops",
		"nestedGroupMode", "maxNestedGroupDepth", "maxGroups", "firstNameAttribute", "lastNameAttribute",
		"displayNameAttribute", "usernameAttribute", "alternateUsernameAttribute", "emailAttribute",
		"immutableSubjectAttribute", "immutableSubjectFormat", "groupMembershipAttribute",
		"posixMemberUidAttribute", "posixGidNumberAttribute", "accountStatusMode", "accountStatusAttribute",
		"accountDisabledValue", "jitMode", "noMatchPolicy", "deprovisionMode", "deprovisionGraceSeconds",
		"syncIntervalSeconds",
	}
	tenantLDAPEndpointFields = []string{
		"priority", "host", "port", "transport", "tlsServerName", "referralAllowed", "enabled",
	}
)

func decodeTenantLDAPCreateBody(
	r *http.Request,
	destination *contract.TenantLDAPAuthProviderCreateRequest,
) error {
	raw, err := decodeTenantLDAPJSONBody(r, destination)
	if err != nil {
		return err
	}
	object, err := exactTenantLDAPJSONObject(
		raw,
		[]string{"kind", "key", "displayName", "description", "configuration", "endpoints"},
		[]string{"kind", "key", "displayName", "configuration", "endpoints"},
	)
	if err != nil {
		return err
	}
	return validateTenantLDAPConfigurationAndEndpoints(object)
}

func decodeTenantLDAPUpdateBody(
	r *http.Request,
	destination *contract.TenantLDAPAuthProviderUpdateRequest,
) error {
	raw, err := decodeTenantLDAPJSONBody(r, destination)
	if err != nil {
		return err
	}
	object, err := exactTenantLDAPJSONObject(
		raw,
		[]string{"key", "displayName", "description", "enabled", "configuration", "endpoints"},
		[]string{"key", "displayName", "description", "enabled", "configuration", "endpoints"},
	)
	if err != nil {
		return err
	}
	return validateTenantLDAPConfigurationAndEndpoints(object)
}

func decodeTenantLDAPReasonBody(r *http.Request, destination any) error {
	raw, err := decodeTenantLDAPJSONBody(r, destination)
	if err != nil {
		return err
	}
	_, err = exactTenantLDAPJSONObject(raw, []string{"reason"}, []string{"reason"})
	return err
}

func validateTenantLDAPConfigurationAndEndpoints(object map[string]any) error {
	configuration, err := exactTenantLDAPJSONObject(
		object["configuration"], tenantLDAPConfigurationFields, tenantLDAPConfigurationFields,
	)
	if err != nil || configuration["syncIntervalSeconds"] != nil {
		return errors.New("LDAP configuration does not contain the exact foundation fields")
	}
	endpoints, ok := object["endpoints"].([]any)
	if !ok {
		return errors.New("LDAP endpoints must be an array")
	}
	for _, endpoint := range endpoints {
		if _, err := exactTenantLDAPJSONObject(endpoint, tenantLDAPEndpointFields, tenantLDAPEndpointFields); err != nil {
			return err
		}
	}
	return nil
}

func decodeTenantLDAPJSONBody(r *http.Request, destination any) (any, error) {
	mediaType, err := requestMediaType(r)
	if err != nil || mediaType != "application/json" {
		return nil, errors.New("unsupported LDAP request content type")
	}
	defer r.Body.Close()
	body, err := io.ReadAll(io.LimitReader(r.Body, maximumTenantLDAPBodyBytes+1))
	if err != nil || len(body) == 0 || len(body) > maximumTenantLDAPBodyBytes || !utf8.Valid(body) {
		clear(body)
		return nil, errors.New("LDAP request body is invalid")
	}
	defer clear(body)
	if err := validateTenantLDAPJSONTokens(body); err != nil {
		return nil, err
	}
	var raw any
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, errors.New("LDAP request body is malformed")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return nil, errors.New("LDAP request body does not match the contract")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, errors.New("LDAP request body must contain one JSON value")
	}
	return raw, nil
}

func validateTenantLDAPJSONTokens(body []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	if err := scanTenantLDAPJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("LDAP request body must contain one JSON value")
	}
	return nil
}

func scanTenantLDAPJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, composite := token.(json.Delim)
	if !composite {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, keyErr := decoder.Token()
			key, ok := keyToken.(string)
			if keyErr != nil || !ok || containsTenantLDAPControlCharacter(key) {
				return errors.New("LDAP request body contains an invalid object key")
			}
			if _, duplicate := seen[key]; duplicate {
				return errors.New("LDAP request body contains a duplicate object key")
			}
			seen[key] = struct{}{}
			if err := scanTenantLDAPJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, closeErr := decoder.Token()
		if closeErr != nil || closing != json.Delim('}') {
			return errors.New("LDAP request body contains an unterminated object")
		}
	case '[':
		for decoder.More() {
			if err := scanTenantLDAPJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, closeErr := decoder.Token()
		if closeErr != nil || closing != json.Delim(']') {
			return errors.New("LDAP request body contains an unterminated array")
		}
	default:
		return errors.New("LDAP request body contains an invalid delimiter")
	}
	return nil
}

func containsTenantLDAPControlCharacter(value string) bool {
	for _, character := range value {
		if unicode.IsControl(character) {
			return true
		}
	}
	return false
}

func exactTenantLDAPJSONObject(value any, allowed, required []string) (map[string]any, error) {
	object, ok := value.(map[string]any)
	if !ok {
		return nil, errors.New("LDAP request member must be an object")
	}
	allowedSet := make(map[string]struct{}, len(allowed))
	for _, field := range allowed {
		allowedSet[field] = struct{}{}
	}
	for field := range object {
		if _, allowedField := allowedSet[field]; !allowedField {
			return nil, errors.New("LDAP request body contains an unknown field")
		}
	}
	for _, field := range required {
		if _, present := object[field]; !present {
			return nil, errors.New("LDAP request body omits a required field")
		}
	}
	return object, nil
}

func decodeTenantLDAPBindSecret(r *http.Request) ([]byte, error) {
	mediaType, err := requestMediaType(r)
	if err != nil || mediaType != "application/json" {
		return nil, errors.New("unsupported LDAP secret content type")
	}
	defer r.Body.Close()
	buffer := make([]byte, maximumTenantLDAPSecretBodyBytes+1)
	used := 0
	for used < len(buffer) {
		read, readErr := r.Body.Read(buffer[used:])
		used += read
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				break
			}
			clear(buffer)
			return nil, errors.New("LDAP secret request body could not be read")
		}
		if read == 0 {
			clear(buffer)
			return nil, errors.New("LDAP secret request body made no progress")
		}
	}
	if used == 0 || used > maximumTenantLDAPSecretBodyBytes {
		clear(buffer)
		return nil, errors.New("LDAP secret request body is invalid")
	}
	return decodeTenantLDAPBindSecretDocument(buffer[:used])
}

func decodeTenantLDAPBindSecretDocument(document []byte) (secret []byte, err error) {
	defer clear(document[:cap(document)])
	if !utf8.Valid(document) {
		return nil, errors.New("LDAP secret request is not UTF-8 JSON")
	}
	parser := tenantLDAPSecretParser{source: document}
	parser.skipWhitespace()
	if !parser.consume('{') {
		return nil, errors.New("LDAP secret request must be an object")
	}
	parser.skipWhitespace()
	key, parseErr := parser.stringBytes(32)
	if parseErr != nil {
		return nil, parseErr
	}
	keyIsSecret := bytes.Equal(key, []byte("secret"))
	clear(key)
	if !keyIsSecret {
		return nil, errors.New("LDAP secret request contains an unknown field")
	}
	parser.skipWhitespace()
	if !parser.consume(':') {
		return nil, errors.New("LDAP secret request is missing a colon")
	}
	parser.skipWhitespace()
	secret, parseErr = parser.stringBytes(maximumTenantLDAPSecretBytes)
	if parseErr != nil {
		return nil, parseErr
	}
	defer func() {
		if err != nil {
			clear(secret)
			secret = nil
		}
	}()
	if len(secret) == 0 {
		return nil, errors.New("LDAP bind secret is empty")
	}
	parser.skipWhitespace()
	if !parser.consume('}') {
		return nil, errors.New("LDAP secret request contains extra or duplicate fields")
	}
	parser.skipWhitespace()
	if parser.index != len(parser.source) {
		return nil, errors.New("LDAP secret request contains trailing data")
	}
	return secret, nil
}

type tenantLDAPSecretParser struct {
	source []byte
	index  int
}

func (p *tenantLDAPSecretParser) skipWhitespace() {
	for p.index < len(p.source) {
		switch p.source[p.index] {
		case ' ', '\t', '\r', '\n':
			p.index++
		default:
			return
		}
	}
}

func (p *tenantLDAPSecretParser) consume(value byte) bool {
	if p.index >= len(p.source) || p.source[p.index] != value {
		return false
	}
	p.index++
	return true
}

func (p *tenantLDAPSecretParser) stringBytes(maximum int) ([]byte, error) {
	if !p.consume('"') {
		return nil, errors.New("LDAP secret request member must be a JSON string")
	}
	result := make([]byte, 0, maximum)
	fail := func(message string) ([]byte, error) {
		clear(result)
		return nil, errors.New(message)
	}
	for p.index < len(p.source) {
		character := p.source[p.index]
		p.index++
		switch character {
		case '"':
			if !utf8.Valid(result) {
				return fail("LDAP secret JSON string is invalid UTF-8")
			}
			return result, nil
		case '\\':
			if p.index >= len(p.source) {
				return fail("LDAP secret JSON escape is truncated")
			}
			escaped := p.source[p.index]
			p.index++
			switch escaped {
			case '"', '\\', '/':
				result = append(result, escaped)
			case 'b':
				result = append(result, '\b')
			case 'f':
				result = append(result, '\f')
			case 'n':
				result = append(result, '\n')
			case 'r':
				result = append(result, '\r')
			case 't':
				result = append(result, '\t')
			case 'u':
				codeUnit, ok := p.hexCodeUnit()
				if !ok {
					return fail("LDAP secret JSON unicode escape is invalid")
				}
				runeValue := rune(codeUnit)
				if utf16.IsSurrogate(runeValue) {
					if runeValue < 0xD800 || runeValue > 0xDBFF || p.index+2 > len(p.source) ||
						p.source[p.index] != '\\' || p.source[p.index+1] != 'u' {
						return fail("LDAP secret JSON surrogate is invalid")
					}
					p.index += 2
					low, lowOK := p.hexCodeUnit()
					if !lowOK {
						return fail("LDAP secret JSON surrogate is invalid")
					}
					runeValue = utf16.DecodeRune(runeValue, rune(low))
					if runeValue == unicode.ReplacementChar {
						return fail("LDAP secret JSON surrogate is invalid")
					}
				}
				result = utf8.AppendRune(result, runeValue)
			default:
				return fail("LDAP secret JSON escape is invalid")
			}
		default:
			if character < 0x20 {
				return fail("LDAP secret JSON contains an unescaped control byte")
			}
			result = append(result, character)
		}
		if len(result) > maximum {
			return fail("LDAP bind secret exceeds the byte limit")
		}
	}
	return fail("LDAP secret JSON string is unterminated")
}

func (p *tenantLDAPSecretParser) hexCodeUnit() (uint16, bool) {
	if p.index+4 > len(p.source) {
		return 0, false
	}
	var result uint16
	for range 4 {
		value := p.source[p.index]
		p.index++
		result <<= 4
		switch {
		case value >= '0' && value <= '9':
			result |= uint16(value - '0')
		case value >= 'a' && value <= 'f':
			result |= uint16(value-'a') + 10
		case value >= 'A' && value <= 'F':
			result |= uint16(value-'A') + 10
		default:
			return 0, false
		}
	}
	return result, true
}
