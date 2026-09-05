package httpserver

import (
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"unicode/utf8"

	"github.com/periapsis-im/periapsis/services/api/internal/contract"
)

const (
	maximumPlatformSAMLAdministrationBodyBytes = 2 << 20
	maximumPlatformSAMLMetadataBytes           = 512 * 1024
	maximumPlatformSAMLPrivateKeyBytes         = 128*1024 - 16
	maximumPlatformSAMLCertificateBytes        = 64 * 1024
	maximumPlatformSAMLCertificates            = 8
)

type platformSAMLMetadataBody struct {
	metadataURL       *string
	metadataXML       []byte
	approveTrustReset bool
	expectedVersion   int64
}

func (body *platformSAMLMetadataBody) destroy() {
	if body == nil {
		return
	}
	clearPlatformSAMLBytes(body.metadataXML)
	*body = platformSAMLMetadataBody{}
}

func decodePlatformSAMLMetadataBody(r *http.Request) (platformSAMLMetadataBody, error) {
	document, err := readPlatformSAMLAdministrationBody(r)
	if err != nil {
		return platformSAMLMetadataBody{}, err
	}
	return decodePlatformSAMLMetadataDocument(document)
}

func decodePlatformSAMLMetadataDocument(document []byte) (result platformSAMLMetadataBody, err error) {
	defer clear(document[:cap(document)])
	defer func() {
		if err != nil {
			result.destroy()
		}
	}()
	if !utf8.Valid(document) {
		return platformSAMLMetadataBody{}, errors.New("platform SAML metadata body is not UTF-8 JSON")
	}
	parser := tenantLDAPSecretParser{source: document}
	parser.skipWhitespace()
	if !parser.consume('{') {
		return platformSAMLMetadataBody{}, errors.New("platform SAML metadata body must be an object")
	}
	var source string
	seen := make(map[string]struct{}, 5)
	for member := 0; ; member++ {
		parser.skipWhitespace()
		if parser.consume('}') {
			break
		}
		if member >= 4 {
			return platformSAMLMetadataBody{}, errors.New("platform SAML metadata body contains extra fields")
		}
		key, parseErr := parser.stringBytes(32)
		if parseErr != nil {
			return platformSAMLMetadataBody{}, parseErr
		}
		keyText := string(key)
		clear(key)
		if _, duplicate := seen[keyText]; duplicate {
			return platformSAMLMetadataBody{}, errors.New("platform SAML metadata body contains a duplicate field")
		}
		seen[keyText] = struct{}{}
		parser.skipWhitespace()
		if !parser.consume(':') {
			return platformSAMLMetadataBody{}, errors.New("platform SAML metadata member is missing a colon")
		}
		parser.skipWhitespace()
		switch keyText {
		case "source":
			value, valueErr := parser.stringBytes(8)
			if valueErr != nil {
				return platformSAMLMetadataBody{}, valueErr
			}
			source = string(value)
			clear(value)
		case "expectedVersion":
			result.expectedVersion, parseErr = parsePlatformOIDCSecretVersion(&parser)
		case "metadataUrl":
			value, valueErr := parser.stringBytes(4096)
			if valueErr != nil {
				return platformSAMLMetadataBody{}, valueErr
			}
			location := string(value)
			clear(value)
			result.metadataURL = &location
		case "metadataXml":
			result.metadataXML, parseErr = parser.stringBytes(maximumPlatformSAMLMetadataBytes)
		case "approveTrustReset":
			result.approveTrustReset, parseErr = parsePlatformSAMLBoolean(&parser)
		default:
			return platformSAMLMetadataBody{}, errors.New("platform SAML metadata body contains an unknown field")
		}
		if parseErr != nil {
			return platformSAMLMetadataBody{}, parseErr
		}
		parser.skipWhitespace()
		if parser.consume('}') {
			break
		}
		if !parser.consume(',') {
			return platformSAMLMetadataBody{}, errors.New("platform SAML metadata body is malformed")
		}
		parser.skipWhitespace()
		if parser.index >= len(parser.source) || parser.source[parser.index] == '}' {
			return platformSAMLMetadataBody{}, errors.New("platform SAML metadata body contains a trailing comma")
		}
	}
	parser.skipWhitespace()
	_, sourceSeen := seen["source"]
	_, versionSeen := seen["expectedVersion"]
	_, approvalSeen := seen["approveTrustReset"]
	_, urlSeen := seen["metadataUrl"]
	_, xmlSeen := seen["metadataXml"]
	if parser.index != len(parser.source) || !sourceSeen || !versionSeen || !approvalSeen ||
		urlSeen == xmlSeen || source == "url" && !urlSeen || source == "xml" && !xmlSeen ||
		source != "url" && source != "xml" ||
		urlSeen && (result.metadataURL == nil || *result.metadataURL == "") ||
		xmlSeen && len(result.metadataXML) == 0 {
		return platformSAMLMetadataBody{}, errors.New("platform SAML metadata body is incomplete")
	}
	return result, nil
}

func decodePlatformSAMLSPKeyBody(r *http.Request) (privateKey []byte, certificates [][]byte, expectedVersion int64, err error) {
	document, err := readPlatformSAMLAdministrationBody(r)
	if err != nil {
		return nil, nil, 0, err
	}
	return decodePlatformSAMLSPKeyDocument(document)
}

func decodePlatformSAMLSPKeyDocument(document []byte) (privateKey []byte, certificates [][]byte, expectedVersion int64, err error) {
	defer clear(document[:cap(document)])
	defer func() {
		if err != nil {
			clearPlatformSAMLBytes(privateKey)
			clearPlatformSAMLByteSlices(certificates)
			privateKey = nil
			certificates = nil
		}
	}()
	if !utf8.Valid(document) {
		return nil, nil, 0, errors.New("platform SAML SP-key body is not UTF-8 JSON")
	}
	parser := tenantLDAPSecretParser{source: document}
	parser.skipWhitespace()
	if !parser.consume('{') {
		return nil, nil, 0, errors.New("platform SAML SP-key body must be an object")
	}
	seen := make(map[string]struct{}, 3)
	var encodedKey []byte
	var encodedCertificates [][]byte
	defer clearPlatformSAMLBytes(encodedKey)
	defer clearPlatformSAMLByteSlices(encodedCertificates)
	for member := 0; ; member++ {
		parser.skipWhitespace()
		if parser.consume('}') {
			break
		}
		if member >= 3 {
			return nil, nil, 0, errors.New("platform SAML SP-key body contains extra fields")
		}
		key, parseErr := parser.stringBytes(32)
		if parseErr != nil {
			return nil, nil, 0, parseErr
		}
		keyText := string(key)
		clear(key)
		if _, duplicate := seen[keyText]; duplicate {
			return nil, nil, 0, errors.New("platform SAML SP-key body contains a duplicate field")
		}
		seen[keyText] = struct{}{}
		parser.skipWhitespace()
		if !parser.consume(':') {
			return nil, nil, 0, errors.New("platform SAML SP-key member is missing a colon")
		}
		parser.skipWhitespace()
		switch keyText {
		case "expectedVersion":
			expectedVersion, parseErr = parsePlatformOIDCSecretVersion(&parser)
		case "privateKeyPkcs8":
			encodedKey, parseErr = parser.stringBytes(base64.StdEncoding.EncodedLen(maximumPlatformSAMLPrivateKeyBytes))
		case "certificates":
			encodedCertificates, parseErr = parsePlatformSAMLStringArray(
				&parser,
				base64.StdEncoding.EncodedLen(maximumPlatformSAMLCertificateBytes),
				maximumPlatformSAMLCertificates,
			)
		default:
			return nil, nil, 0, errors.New("platform SAML SP-key body contains an unknown field")
		}
		if parseErr != nil {
			return nil, nil, 0, parseErr
		}
		parser.skipWhitespace()
		if parser.consume('}') {
			break
		}
		if !parser.consume(',') {
			return nil, nil, 0, errors.New("platform SAML SP-key body is malformed")
		}
		parser.skipWhitespace()
		if parser.index >= len(parser.source) || parser.source[parser.index] == '}' {
			return nil, nil, 0, errors.New("platform SAML SP-key body contains a trailing comma")
		}
	}
	parser.skipWhitespace()
	if parser.index != len(parser.source) || len(seen) != 3 || len(encodedKey) == 0 || len(encodedCertificates) == 0 {
		return nil, nil, 0, errors.New("platform SAML SP-key body is incomplete")
	}
	privateKey, err = decodeCanonicalPlatformSAMLBase64(encodedKey, maximumPlatformSAMLPrivateKeyBytes)
	if err != nil {
		return nil, nil, 0, err
	}
	certificates = make([][]byte, len(encodedCertificates))
	for index := range encodedCertificates {
		certificates[index], err = decodeCanonicalPlatformSAMLBase64(
			encodedCertificates[index], maximumPlatformSAMLCertificateBytes,
		)
		if err != nil {
			return nil, nil, 0, err
		}
		for previous := 0; previous < index; previous++ {
			if bytes.Equal(certificates[previous], certificates[index]) {
				return nil, nil, 0, errors.New("platform SAML SP-key certificates contain a duplicate")
			}
		}
	}
	return privateKey, certificates, expectedVersion, nil
}

func decodePlatformSAMLSPKeyClearBody(r *http.Request, destination *contract.PlatformSAMLSPKeyClearRequest) error {
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

func readPlatformSAMLAdministrationBody(r *http.Request) ([]byte, error) {
	if r == nil || r.Body == nil {
		return nil, errors.New("platform SAML administration body is missing")
	}
	mediaType, err := requestMediaType(r)
	if err != nil || mediaType != "application/json" {
		return nil, errors.New("unsupported platform SAML administration content type")
	}
	defer r.Body.Close()
	buffer := make([]byte, maximumPlatformSAMLAdministrationBodyBytes+1)
	used := 0
	for used < len(buffer) {
		read, readErr := r.Body.Read(buffer[used:])
		used += read
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				break
			}
			clear(buffer)
			return nil, errors.New("platform SAML administration body could not be read")
		}
		if read == 0 {
			clear(buffer)
			return nil, errors.New("platform SAML administration body made no progress")
		}
	}
	if used == 0 || used > maximumPlatformSAMLAdministrationBodyBytes {
		clear(buffer)
		return nil, errors.New("platform SAML administration body is invalid")
	}
	return buffer[:used], nil
}

func parsePlatformSAMLBoolean(parser *tenantLDAPSecretParser) (bool, error) {
	if parser.index+4 <= len(parser.source) && bytes.Equal(parser.source[parser.index:parser.index+4], []byte("true")) {
		parser.index += 4
		return true, nil
	}
	if parser.index+5 <= len(parser.source) && bytes.Equal(parser.source[parser.index:parser.index+5], []byte("false")) {
		parser.index += 5
		return false, nil
	}
	return false, errors.New("platform SAML boolean member is invalid")
}

func parsePlatformSAMLStringArray(parser *tenantLDAPSecretParser, maximumBytes, maximumItems int) ([][]byte, error) {
	if !parser.consume('[') {
		return nil, errors.New("platform SAML certificate member must be an array")
	}
	values := make([][]byte, 0, maximumItems)
	fail := func(message string) ([][]byte, error) {
		clearPlatformSAMLByteSlices(values)
		return nil, errors.New(message)
	}
	parser.skipWhitespace()
	if parser.consume(']') {
		return fail("platform SAML certificate array is empty")
	}
	for {
		if len(values) >= maximumItems {
			return fail("platform SAML certificate array exceeds the item limit")
		}
		value, err := parser.stringBytes(maximumBytes)
		if err != nil {
			clearPlatformSAMLByteSlices(values)
			return nil, err
		}
		if len(value) == 0 {
			clear(value)
			return fail("platform SAML certificate encoding is empty")
		}
		values = append(values, value)
		parser.skipWhitespace()
		if parser.consume(']') {
			return values, nil
		}
		if !parser.consume(',') {
			return fail("platform SAML certificate array is malformed")
		}
		parser.skipWhitespace()
		if parser.index >= len(parser.source) || parser.source[parser.index] == ']' {
			return fail("platform SAML certificate array contains a trailing comma")
		}
	}
}

func decodeCanonicalPlatformSAMLBase64(encoded []byte, maximumDecodedBytes int) ([]byte, error) {
	if len(encoded) == 0 || len(encoded)%4 != 0 || len(encoded) > base64.StdEncoding.EncodedLen(maximumDecodedBytes) {
		return nil, errors.New("platform SAML material is not bounded canonical base64")
	}
	decoded := make([]byte, base64.StdEncoding.DecodedLen(len(encoded)))
	used, err := base64.StdEncoding.Strict().Decode(decoded, encoded)
	if err != nil || used == 0 || used > maximumDecodedBytes {
		clearPlatformSAMLBytes(decoded)
		return nil, errors.New("platform SAML material is not bounded canonical base64")
	}
	decoded = decoded[:used]
	canonical := make([]byte, base64.StdEncoding.EncodedLen(len(decoded)))
	base64.StdEncoding.Encode(canonical, decoded)
	valid := bytes.Equal(canonical, encoded)
	clearPlatformSAMLBytes(canonical)
	if !valid {
		clearPlatformSAMLBytes(decoded)
		return nil, errors.New("platform SAML material is not bounded canonical base64")
	}
	return decoded, nil
}

func clearPlatformSAMLByteSlices(values [][]byte) {
	for index := range values {
		clearPlatformSAMLBytes(values[index])
	}
}

func clearPlatformSAMLBytes(value []byte) {
	clear(value[:cap(value)])
}
