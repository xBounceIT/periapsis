package httpserver

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"unicode/utf8"

	"github.com/periapsis-im/periapsis/services/api/internal/contract"
)

const maximumPlatformLocalAccountBodyBytes = 8 * 1024

type platformLocalAccountActivationBody struct {
	ExpectedRevision int64
	CeremonyToken    []byte
	NewPassword      []byte
	FactorProof      []byte
}

type platformLocalAccountPasswordBody struct {
	ExpectedRevision int64
	NewPassword      []byte
}

func decodePlatformLocalAccountInviteBody(
	r *http.Request,
	destination *contract.PlatformLocalAccountInviteRequest,
) error {
	raw, err := decodePlatformLocalAccountJSONBody(r, destination)
	if err != nil {
		return err
	}
	object, err := exactTenantLDAPJSONObject(
		raw,
		[]string{"displayName", "loginIdentifier", "protectedRecoveryPrincipal"},
		[]string{"displayName", "loginIdentifier", "protectedRecoveryPrincipal"},
	)
	if err != nil {
		return err
	}
	return requirePlatformIdentityProviderJSONTypes(
		object,
		[]string{"displayName", "loginIdentifier"},
		[]string{"protectedRecoveryPrincipal"},
		nil,
		nil,
	)
}

func decodePlatformLocalAccountTransitionBody(
	r *http.Request,
	destination *contract.PlatformLocalAccountTransitionRequest,
) error {
	raw, err := decodePlatformLocalAccountJSONBody(r, destination)
	if err != nil {
		return err
	}
	object, err := exactTenantLDAPJSONObject(raw, []string{"expectedRevision"}, []string{"expectedRevision"})
	if err != nil {
		return err
	}
	return requirePlatformIdentityProviderJSONTypes(object, nil, nil, nil, []string{"expectedRevision"})
}

func decodePlatformLocalAccountJSONBody(r *http.Request, destination any) (any, error) {
	document, err := readPlatformLocalAccountBody(r)
	if err != nil {
		return nil, err
	}
	defer clear(document[:cap(document)])
	if !utf8.Valid(document) || validateTenantLDAPJSONTokens(document) != nil {
		return nil, errors.New("platform local-account request body is invalid")
	}
	var raw any
	if unmarshalExactJSON(document, &raw) != nil || unmarshalExactJSON(document, destination) != nil {
		return nil, errors.New("platform local-account request body does not match the contract")
	}
	return raw, nil
}

func decodePlatformLocalAccountActivationBody(
	r *http.Request,
) (body platformLocalAccountActivationBody, err error) {
	document, readErr := readPlatformLocalAccountBody(r)
	if readErr != nil {
		return body, readErr
	}
	defer clear(document[:cap(document)])
	defer func() {
		if err != nil {
			body.clear()
		}
	}()
	if !utf8.Valid(document) {
		return body, errors.New("platform local-account activation body is not UTF-8 JSON")
	}
	parser := tenantLDAPSecretParser{source: document}
	parser.skipWhitespace()
	if !parser.consume('{') {
		return body, errors.New("platform local-account activation body must be an object")
	}
	var seen uint8
	for member := 0; ; member++ {
		parser.skipWhitespace()
		if parser.consume('}') {
			break
		}
		if member >= 4 {
			return body, errors.New("platform local-account activation body contains extra fields")
		}
		key, parseErr := parser.stringBytes(32)
		if parseErr != nil {
			return body, parseErr
		}
		parser.skipWhitespace()
		if !parser.consume(':') {
			clear(key)
			return body, errors.New("platform local-account activation member is missing a colon")
		}
		parser.skipWhitespace()
		switch {
		case bytes.Equal(key, []byte("expectedRevision")):
			parseErr = rejectDuplicatePlatformLocalAccountField(seen, 1)
			if parseErr == nil {
				body.ExpectedRevision, parseErr = parsePlatformOIDCSecretVersion(&parser)
				seen |= 1
			}
		case bytes.Equal(key, []byte("ceremonyToken")):
			parseErr = rejectDuplicatePlatformLocalAccountField(seen, 2)
			if parseErr == nil {
				body.CeremonyToken, parseErr = parser.stringBytes(43)
				seen |= 2
			}
		case bytes.Equal(key, []byte("newPassword")):
			parseErr = rejectDuplicatePlatformLocalAccountField(seen, 4)
			if parseErr == nil {
				body.NewPassword, parseErr = parser.stringBytes(1024)
				seen |= 4
			}
		case bytes.Equal(key, []byte("factorProof")):
			parseErr = rejectDuplicatePlatformLocalAccountField(seen, 8)
			if parseErr == nil {
				body.FactorProof, parseErr = parser.stringBytes(8)
				seen |= 8
			}
		default:
			parseErr = errors.New("platform local-account activation body contains an unknown field")
		}
		clear(key)
		if parseErr != nil {
			return body, parseErr
		}
		if err := consumePlatformLocalAccountMemberEnd(&parser); err != nil {
			return body, err
		}
		if parser.source[parser.index-1] == '}' {
			break
		}
	}
	parser.skipWhitespace()
	if parser.index != len(parser.source) || seen != 15 {
		return body, errors.New("platform local-account activation body is incomplete")
	}
	return body, nil
}

func decodePlatformLocalAccountPasswordBody(
	r *http.Request,
) (body platformLocalAccountPasswordBody, err error) {
	document, readErr := readPlatformLocalAccountBody(r)
	if readErr != nil {
		return body, readErr
	}
	defer clear(document[:cap(document)])
	defer func() {
		if err != nil {
			body.clear()
		}
	}()
	if !utf8.Valid(document) {
		return body, errors.New("platform local-account password body is not UTF-8 JSON")
	}
	parser := tenantLDAPSecretParser{source: document}
	parser.skipWhitespace()
	if !parser.consume('{') {
		return body, errors.New("platform local-account password body must be an object")
	}
	var seen uint8
	for member := 0; ; member++ {
		parser.skipWhitespace()
		if parser.consume('}') {
			break
		}
		if member >= 2 {
			return body, errors.New("platform local-account password body contains extra fields")
		}
		key, parseErr := parser.stringBytes(32)
		if parseErr != nil {
			return body, parseErr
		}
		parser.skipWhitespace()
		if !parser.consume(':') {
			clear(key)
			return body, errors.New("platform local-account password member is missing a colon")
		}
		parser.skipWhitespace()
		switch {
		case bytes.Equal(key, []byte("expectedRevision")):
			parseErr = rejectDuplicatePlatformLocalAccountField(seen, 1)
			if parseErr == nil {
				body.ExpectedRevision, parseErr = parsePlatformOIDCSecretVersion(&parser)
				seen |= 1
			}
		case bytes.Equal(key, []byte("newPassword")):
			parseErr = rejectDuplicatePlatformLocalAccountField(seen, 2)
			if parseErr == nil {
				body.NewPassword, parseErr = parser.stringBytes(1024)
				seen |= 2
			}
		default:
			parseErr = errors.New("platform local-account password body contains an unknown field")
		}
		clear(key)
		if parseErr != nil {
			return body, parseErr
		}
		if err := consumePlatformLocalAccountMemberEnd(&parser); err != nil {
			return body, err
		}
		if parser.source[parser.index-1] == '}' {
			break
		}
	}
	parser.skipWhitespace()
	if parser.index != len(parser.source) || seen != 3 {
		return body, errors.New("platform local-account password body is incomplete")
	}
	return body, nil
}

func readPlatformLocalAccountBody(r *http.Request) ([]byte, error) {
	if r == nil || r.Body == nil {
		return nil, errors.New("unsupported platform local-account content type")
	}
	mediaType, err := requestMediaType(r)
	if err != nil || mediaType != "application/json" {
		return nil, errors.New("unsupported platform local-account content type")
	}
	defer r.Body.Close()
	buffer := make([]byte, maximumPlatformLocalAccountBodyBytes+1)
	used := 0
	for used < len(buffer) {
		read, readErr := r.Body.Read(buffer[used:])
		used += read
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				break
			}
			clear(buffer)
			return nil, errors.New("platform local-account request body could not be read")
		}
		if read == 0 {
			clear(buffer)
			return nil, errors.New("platform local-account request body made no progress")
		}
	}
	if used == 0 || used > maximumPlatformLocalAccountBodyBytes {
		clear(buffer)
		return nil, errors.New("platform local-account request body is invalid")
	}
	return buffer[:used], nil
}

func rejectDuplicatePlatformLocalAccountField(seen, field uint8) error {
	if seen&field != 0 {
		return errors.New("platform local-account request body contains a duplicate field")
	}
	return nil
}

func consumePlatformLocalAccountMemberEnd(parser *tenantLDAPSecretParser) error {
	parser.skipWhitespace()
	if parser.consume('}') {
		return nil
	}
	if !parser.consume(',') {
		return errors.New("platform local-account request body is malformed")
	}
	parser.skipWhitespace()
	if parser.index >= len(parser.source) || parser.source[parser.index] == '}' {
		return errors.New("platform local-account request body contains a trailing comma")
	}
	return nil
}

func (body *platformLocalAccountActivationBody) clear() {
	if body == nil {
		return
	}
	clear(body.CeremonyToken)
	clear(body.NewPassword)
	clear(body.FactorProof)
	*body = platformLocalAccountActivationBody{}
}

func (body *platformLocalAccountPasswordBody) clear() {
	if body == nil {
		return
	}
	clear(body.NewPassword)
	*body = platformLocalAccountPasswordBody{}
}
