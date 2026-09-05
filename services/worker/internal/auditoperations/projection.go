package auditoperations

import (
	"bytes"
	"encoding/json"
	"io"
	"regexp"
	"strings"
	"unicode"

	"github.com/google/uuid"
)

const (
	maximumProjectionBytes = 256 * 1024
	maximumJSONDepth       = 32
	maximumJSONNodes       = 8_192
)

var (
	objectKeyPattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9./_-]*$`)
	stableKindPattern = regexp.MustCompile(`^[a-z][a-z0-9_.:+-]{0,63}$`)
	prohibitedKeys    = map[string]struct{}{
		"accesstoken": {}, "accesstokendigest": {}, "apikey": {}, "apikeydigest": {},
		"assertion": {}, "authorization": {}, "bindpassword": {}, "clientassertion": {},
		"clientsecret": {}, "cookie": {}, "credential": {}, "credentials": {},
		"csrfsecret": {}, "csrfsecretdigest": {}, "csrftoken": {}, "encryptionkey": {},
		"idtoken": {}, "idtokendigest": {}, "keymaterial": {}, "passphrase": {},
		"password": {}, "passwordphc": {}, "privatekey": {}, "privatekeyciphertext": {},
		"recoverycode": {}, "recoverycodes": {}, "refreshtoken": {}, "refreshtokendigest": {},
		"samlassertion": {}, "secret": {}, "secretciphertext": {}, "sessiontoken": {},
		"token": {}, "tokendigest": {}, "totpsecret": {},
	}
	safeSensitiveBooleanKeys = map[string]struct{}{
		"authorizationinitialized": {}, "bindsecretconfigured": {},
		"passwordconfigured": {}, "privatekeyconfigured": {},
		"secretmaterialarchived": {}, "secretmaterialincluded": {},
	}
	safeSensitiveIdentifierKeys = map[string]struct{}{
		"apikeyid": {}, "bindsecretid": {}, "credentialid": {}, "fencetoken": {},
		"predecessorcredentialid": {}, "replacementcredentialid": {}, "secretid": {},
	}
	safeSensitiveIntegerKeys = map[string]struct{}{
		"authorizationrevision": {}, "bindsecretkeyversion": {}, "bindsecretversion": {},
		"credentialkeyversion": {}, "credentialversion": {}, "secretversion": {},
	}
	safeSensitiveKindKeys = map[string]struct{}{
		"bindsecretalgorithm": {}, "credentialkind": {}, "secretkind": {}, "tokenkind": {},
	}
	sensitiveKeyFragments = []string{
		"accesstoken", "apikey", "assertion", "bindpassword", "clientassertion",
		"clientsecret", "cookie", "credential", "csrfsecret", "csrftoken",
		"encryptionkey", "idtoken", "keymaterial", "passphrase", "password",
		"privatekey", "recoverycode", "refreshtoken", "samlassertion", "secret",
		"sessiontoken", "token", "totpsecret",
	}
	tenantProjectionKeys = projectionKeySet(
		"projectionVersion", "stream", "tenantId", "sequence", "id", "occurredAt",
		"actorType", "actorUserId", "actorServiceAccountId", "impersonatedByUserId",
		"action", "resourceType", "resourceId", "requestId", "correlationId",
		"ipAddress", "userAgent", "authenticationMethod", "outcome", "reason",
		"before", "after", "metadata", "previousHash", "eventHash",
	)
	platformProjectionKeys = projectionKeySet(
		"projectionVersion", "stream", "sequence", "id", "occurredAt", "actorType",
		"actorUserId", "action", "resourceType", "resourceId", "requestId",
		"correlationId", "ipAddress", "userAgent", "authenticationMethod", "outcome",
		"reason", "before", "after", "metadata", "previousHash", "eventHash",
	)
)

func canonicalProjection(raw json.RawMessage, stream Stream, tenantID uuid.UUID, sequence int64) ([]byte, error) {
	if !stream.Valid() || sequence < 1 || len(raw) < 2 || len(raw) > maximumProjectionBytes || !json.Valid(raw) {
		return nil, ErrInvalidProjection
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var document map[string]any
	if err := decoder.Decode(&document); err != nil || document == nil {
		return nil, ErrInvalidProjection
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, ErrInvalidProjection
	}
	allowed := platformProjectionKeys
	if stream == TenantStream {
		allowed = tenantProjectionKeys
	}
	for key := range document {
		if _, ok := allowed[key]; !ok {
			return nil, ErrInvalidProjection
		}
	}
	version, versionOK := document["projectionVersion"].(json.Number)
	projectedStream, streamOK := document["stream"].(string)
	projectedSequence, sequenceOK := document["sequence"].(json.Number)
	versionValue, versionErr := version.Int64()
	sequenceValue, sequenceErr := projectedSequence.Int64()
	if !versionOK || versionErr != nil || versionValue != 1 || !streamOK || projectedStream != string(stream) ||
		!sequenceOK || sequenceErr != nil || sequenceValue != sequence {
		return nil, ErrInvalidProjection
	}
	if stream == TenantStream {
		projectedTenant, ok := document["tenantId"].(string)
		if !ok || projectedTenant != tenantID.String() || !validUUIDv7(tenantID) {
			return nil, ErrInvalidProjection
		}
	} else if tenantID != uuid.Nil {
		return nil, ErrInvalidProjection
	}
	nodes := 0
	if !safeJSONValue(document, 1, &nodes) {
		return nil, ErrInvalidProjection
	}
	canonical, err := json.Marshal(document)
	if err != nil || len(canonical) > maximumProjectionBytes {
		return nil, ErrInvalidProjection
	}
	return canonical, nil
}

func safeJSONValue(value any, depth int, nodes *int) bool {
	*nodes++
	if depth > maximumJSONDepth || *nodes > maximumJSONNodes {
		return false
	}
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			canonical := canonicalJSONKey(key)
			if prohibitedJSONKey(canonical) || !validSafeSensitiveValue(canonical, child) ||
				!safeJSONValue(child, depth+1, nodes) {
				return false
			}
		}
	case []any:
		for _, child := range typed {
			if !safeJSONValue(child, depth+1, nodes) {
				return false
			}
		}
	case string, json.Number, bool, nil:
		return true
	default:
		return false
	}
	return true
}

func prohibitedJSONKey(value string) bool {
	if safeSensitiveKey(value) {
		return false
	}
	if _, prohibited := prohibitedKeys[value]; prohibited {
		return true
	}
	for _, fragment := range sensitiveKeyFragments {
		if strings.Contains(value, fragment) {
			return true
		}
	}
	return false
}

func safeSensitiveKey(value string) bool {
	for _, catalog := range []map[string]struct{}{
		safeSensitiveBooleanKeys, safeSensitiveIdentifierKeys,
		safeSensitiveIntegerKeys, safeSensitiveKindKeys,
	} {
		if _, ok := catalog[value]; ok {
			return true
		}
	}
	return false
}

func validSafeSensitiveValue(key string, value any) bool {
	if _, expected := safeSensitiveBooleanKeys[key]; expected {
		_, ok := value.(bool)
		return ok
	}
	if _, expected := safeSensitiveIdentifierKeys[key]; expected {
		if value == nil {
			return true
		}
		identifier, ok := value.(string)
		if !ok {
			return false
		}
		parsed, err := uuid.Parse(identifier)
		return err == nil && validUUIDv7(parsed)
	}
	if _, expected := safeSensitiveIntegerKeys[key]; expected {
		number, ok := value.(json.Number)
		integer, err := number.Int64()
		return ok && err == nil && integer >= 0
	}
	if _, expected := safeSensitiveKindKeys[key]; expected {
		kind, ok := value.(string)
		return ok && stableKindPattern.MatchString(kind)
	}
	return true
}

func canonicalJSONKey(value string) string {
	var result strings.Builder
	for _, character := range strings.ToLower(value) {
		if unicode.IsLetter(character) || unicode.IsDigit(character) {
			result.WriteRune(character)
		}
	}
	return result.String()
}

func projectionKeySet(keys ...string) map[string]struct{} {
	result := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		result[key] = struct{}{}
	}
	return result
}

func validUUIDv7(value uuid.UUID) bool {
	return value != uuid.Nil && value.Version() == 7 && value.String() != ""
}

func validObjectKey(stream Stream, tenantID uuid.UUID, value string) bool {
	if !stream.Valid() || len(value) > 1024 || !objectKeyPattern.MatchString(value) || strings.Contains(value, "//") ||
		strings.Contains(value, "..") {
		return false
	}
	if stream == PlatformStream {
		return tenantID == uuid.Nil && strings.HasPrefix(value, "platform/audit/")
	}
	return validUUIDv7(tenantID) && strings.HasPrefix(value, "tenants/"+tenantID.String()+"/audit/")
}
