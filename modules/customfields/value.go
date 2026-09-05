package customfields

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/mail"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/net/idna"
)

type Presence uint8

const (
	PresenceMissing Presence = iota
	PresenceNull
	PresencePresent
)

type InputValue struct {
	provided bool
	raw      json.RawMessage
}

func MissingInputValue() InputValue { return InputValue{} }

func JSONInputValue(raw json.RawMessage) InputValue {
	return InputValue{provided: true, raw: slices.Clone(raw)}
}

func NullInputValue() InputValue { return JSONInputValue(json.RawMessage("null")) }

func (value InputValue) Provided() bool           { return value.provided }
func (value InputValue) RawJSON() json.RawMessage { return slices.Clone(value.raw) }

type Value struct {
	presence  Presence
	dataType  DataType
	canonical json.RawMessage
	text      *string
	integer   *int64
	boolean   *bool
	instant   *time.Time
	keys      []Key
	reference *EntityID
}

func (value Value) Presence() Presence             { return value.presence }
func (value Value) DataType() DataType             { return value.dataType }
func (value Value) CanonicalJSON() json.RawMessage { return slices.Clone(value.canonical) }
func (value Value) Text() (string, bool) {
	if value.text == nil {
		return "", false
	}
	return *value.text, true
}
func (value Value) Integer() (int64, bool) {
	if value.integer == nil {
		return 0, false
	}
	return *value.integer, true
}
func (value Value) Boolean() (bool, bool) {
	if value.boolean == nil {
		return false, false
	}
	return *value.boolean, true
}
func (value Value) DateTime() (*time.Time, bool) {
	if value.instant == nil {
		return nil, false
	}
	result := *value.instant
	return &result, true
}
func (value Value) Keys() []Key { return slices.Clone(value.keys) }
func (value Value) Reference() (*EntityID, bool) {
	if value.reference == nil {
		return nil, false
	}
	result := *value.reference
	return &result, true
}
func (value Value) String() string {
	return fmt.Sprintf("customfields.Value{presence:%d,type:%s,value:[REDACTED]}", value.presence, value.dataType)
}
func (value Value) GoString() string { return value.String() }

func (value Value) clone() Value {
	result := value
	result.canonical = slices.Clone(value.canonical)
	result.keys = slices.Clone(value.keys)
	if value.text != nil {
		text := *value.text
		result.text = &text
	}
	if value.integer != nil {
		integer := *value.integer
		result.integer = &integer
	}
	if value.boolean != nil {
		boolean := *value.boolean
		result.boolean = &boolean
	}
	if value.instant != nil {
		instant := *value.instant
		result.instant = &instant
	}
	if value.reference != nil {
		reference := *value.reference
		result.reference = &reference
	}
	return result
}

type ValidationContext struct {
	TenantID      EntityID
	ObjectType    ObjectType
	Audience      Audience
	Phase         WritePhase
	TransitionKey Key
}

type FieldError struct {
	Field Key
	Code  string
}

func (fieldError FieldError) Error() string {
	return fmt.Sprintf("custom field %q: %s", fieldError.Field.String(), fieldError.Code)
}

func (fieldError FieldError) Unwrap() error { return ErrInvalidValidationInput }

func (definition Definition) Validate(input InputValue, context ValidationContext) (Value, *FieldError) {
	if context.TenantID != definition.tenantID || context.ObjectType != definition.objectType ||
		!validAudience(context.Audience) || !validWritePhase(context.Phase) ||
		(context.Phase == PhaseTransition) != validKey(context.TransitionKey.value) {
		fieldError := definition.fieldError("invalid_context")
		return Value{}, &fieldError
	}
	required := definition.requiredFor(context.Phase, context.TransitionKey)
	if !input.provided {
		// A caller must not learn about or activate a hidden/archived field by
		// omitting it. System writes remain editable and therefore still apply
		// defaults and required-field policy.
		if !definition.CanEdit(context.Audience, context.Phase) {
			return Value{presence: PresenceMissing, dataType: definition.dataType}, nil
		}
		if (context.Phase == PhaseCreate || context.Phase == PhaseBulkImport) &&
			definition.defaultValue.presence != PresenceMissing {
			return definition.defaultValue.clone(), nil
		}
		if required {
			fieldError := definition.fieldError("required")
			return Value{}, &fieldError
		}
		return Value{presence: PresenceMissing, dataType: definition.dataType}, nil
	}
	if !definition.CanEdit(context.Audience, context.Phase) {
		fieldError := definition.fieldError("edit_denied")
		return Value{}, &fieldError
	}
	value, fieldError := definition.validateValue(input, required)
	if fieldError != nil {
		return Value{}, fieldError
	}
	return value, nil
}

func (definition Definition) validateValue(input InputValue, required bool) (Value, *FieldError) {
	if !input.provided {
		return Value{presence: PresenceMissing, dataType: definition.dataType}, nil
	}
	if len(input.raw) == 0 || len(input.raw) > maximumJSONBytes || !utf8.Valid(input.raw) {
		fieldError := definition.fieldError("malformed")
		return Value{}, &fieldError
	}
	if bytes.Equal(bytes.TrimSpace(input.raw), []byte("null")) {
		if required {
			fieldError := definition.fieldError("required")
			return Value{}, &fieldError
		}
		if !definition.nullable {
			fieldError := definition.fieldError("null_not_allowed")
			return Value{}, &fieldError
		}
		return Value{presence: PresenceNull, dataType: definition.dataType, canonical: json.RawMessage("null")}, nil
	}

	value, code := definition.canonicalPresentValue(input.raw)
	if code != "" {
		fieldError := definition.fieldError(code)
		return Value{}, &fieldError
	}
	if required && value.semanticallyEmpty() {
		fieldError := definition.fieldError("empty_not_allowed")
		return Value{}, &fieldError
	}
	return value, nil
}

func (definition Definition) canonicalPresentValue(raw json.RawMessage) (Value, string) {
	switch definition.dataType {
	case TypeShortText, TypeLongText:
		text, ok := decodeJSONString(raw)
		multiline := definition.dataType == TypeLongText
		maximum := 1_024
		if multiline {
			maximum = maximumCanonicalTextBytes
		}
		if !ok || !validText(text, maximum, true, multiline) || !definition.textWithinConstraints(text) {
			return Value{}, "invalid_text"
		}
		return textValue(definition.dataType, text), ""
	case TypeInteger, TypeDuration:
		integer, ok := decodeInteger(raw)
		if !ok || definition.dataType == TypeDuration && integer < 0 || !definition.numberWithinConstraints(strconv.FormatInt(integer, 10)) {
			return Value{}, "invalid_integer"
		}
		return integerValue(definition.dataType, integer), ""
	case TypeDecimal:
		decimal, ok := decodeDecimal(raw)
		if !ok || !definition.numberWithinConstraints(decimal) {
			return Value{}, "invalid_decimal"
		}
		return decimalValue(decimal), ""
	case TypeBoolean:
		boolean, ok := decodeBoolean(raw)
		if !ok {
			return Value{}, "invalid_boolean"
		}
		return booleanValue(boolean), ""
	case TypeDate:
		text, ok := decodeJSONString(raw)
		date, err := time.Parse("2006-01-02", text)
		if !ok || err != nil || date.Format("2006-01-02") != text {
			return Value{}, "invalid_date"
		}
		return textValue(TypeDate, text), ""
	case TypeDateTime:
		text, ok := decodeJSONString(raw)
		instant, err := time.Parse(time.RFC3339Nano, text)
		if !ok || err != nil || instant.Nanosecond()%1_000 != 0 {
			return Value{}, "invalid_datetime"
		}
		instant = instant.UTC()
		canonical := instant.Format(time.RFC3339Nano)
		return Value{
			presence: PresencePresent, dataType: TypeDateTime, canonical: mustMarshal(canonical), instant: &instant,
		}, ""
	case TypeSingleSelect:
		text, ok := decodeJSONString(raw)
		key, err := NewKey(text)
		if !ok || err != nil || !definition.liveOption(key) {
			return Value{}, "invalid_option"
		}
		return Value{presence: PresencePresent, dataType: TypeSingleSelect, canonical: mustMarshal(text), keys: []Key{key}}, ""
	case TypeMultiSelect:
		keys, ok := decodeKeyArray(raw, maximumOptions)
		if !ok {
			return Value{}, "invalid_options"
		}
		for _, key := range keys {
			if !definition.liveOption(key) {
				return Value{}, "invalid_option"
			}
		}
		texts := make([]string, len(keys))
		for index, key := range keys {
			texts[index] = key.String()
		}
		return Value{presence: PresencePresent, dataType: TypeMultiSelect, canonical: mustMarshal(texts), keys: keys}, ""
	case TypeURL:
		text, ok := decodeJSONString(raw)
		canonical, ok := canonicalURL(text)
		if !ok || !definition.textWithinConstraints(canonical) {
			return Value{}, "invalid_url"
		}
		return textValue(TypeURL, canonical), ""
	case TypeEmail:
		text, ok := decodeJSONString(raw)
		canonical, ok := canonicalEmail(text)
		if !ok || !definition.textWithinConstraints(canonical) {
			return Value{}, "invalid_email"
		}
		return textValue(TypeEmail, canonical), ""
	case TypeIP:
		text, ok := decodeJSONString(raw)
		address, err := netip.ParseAddr(text)
		if !ok || err != nil || address.Is4In6() || address.Zone() != "" {
			return Value{}, "invalid_ip"
		}
		return textValue(TypeIP, address.String()), ""
	case TypeCIDR:
		text, ok := decodeJSONString(raw)
		prefix, err := netip.ParsePrefix(text)
		if !ok || err != nil || prefix.Addr().Is4In6() || prefix.Addr().Zone() != "" {
			return Value{}, "invalid_cidr"
		}
		return textValue(TypeCIDR, prefix.Masked().String()), ""
	case TypeUser, TypeOperatorTeam, TypeCustomerContact, TypeAssetReference, TypeIOCReference:
		text, ok := decodeJSONString(raw)
		reference, err := ParseEntityID(text)
		if !ok || err != nil {
			return Value{}, "invalid_reference"
		}
		return Value{
			presence: PresencePresent, dataType: definition.dataType,
			canonical: mustMarshal(reference.String()), reference: &reference,
		}, ""
	case TypeStructuredJSON:
		canonical, ok := canonicalJSONObject(raw)
		if !definition.allowStructuredJSON || !ok {
			return Value{}, "invalid_json"
		}
		return Value{presence: PresencePresent, dataType: TypeStructuredJSON, canonical: canonical}, ""
	default:
		return Value{}, "invalid_type"
	}
}

func (definition Definition) fieldError(code string) FieldError {
	return FieldError{Field: definition.key, Code: code}
}

func (definition Definition) textWithinConstraints(value string) bool {
	length := uint32(utf8.RuneCountInString(value))
	if definition.constraints.minimumLength != nil && length < *definition.constraints.minimumLength ||
		definition.constraints.maximumLength != nil && length > *definition.constraints.maximumLength ||
		definition.constraints.compiled != nil && !definition.constraints.compiled.MatchString(value) {
		return false
	}
	return true
}

func (definition Definition) numberWithinConstraints(value string) bool {
	return (definition.constraints.minimum == "" || compareDecimal(value, definition.constraints.minimum) >= 0) &&
		(definition.constraints.maximum == "" || compareDecimal(value, definition.constraints.maximum) <= 0)
}

func (definition Definition) liveOption(key Key) bool {
	for _, option := range definition.options {
		if option.key == key {
			return !option.archived
		}
	}
	return false
}

func (value Value) semanticallyEmpty() bool {
	if value.presence != PresencePresent {
		return true
	}
	if value.text != nil {
		return *value.text == ""
	}
	return value.dataType == TypeMultiSelect && len(value.keys) == 0
}

func textValue(dataType DataType, text string) Value {
	return Value{presence: PresencePresent, dataType: dataType, canonical: mustMarshal(text), text: &text}
}

func integerValue(dataType DataType, integer int64) Value {
	return Value{
		presence: PresencePresent, dataType: dataType,
		canonical: json.RawMessage(strconv.FormatInt(integer, 10)), integer: &integer,
	}
}

func decimalValue(decimal string) Value {
	return Value{presence: PresencePresent, dataType: TypeDecimal, canonical: json.RawMessage(decimal), text: &decimal}
}

func booleanValue(boolean bool) Value {
	return Value{
		presence: PresencePresent, dataType: TypeBoolean,
		canonical: json.RawMessage(strconv.FormatBool(boolean)), boolean: &boolean,
	}
}

func decodeJSONString(raw json.RawMessage) (string, bool) {
	var value string
	return value, decodeExactlyOne(raw, &value)
}

func decodeBoolean(raw json.RawMessage) (bool, bool) {
	var value bool
	return value, decodeExactlyOne(raw, &value)
}

func decodeInteger(raw json.RawMessage) (int64, bool) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if decoder.Decode(&value) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return 0, false
	}
	number, ok := value.(json.Number)
	if !ok {
		return 0, false
	}
	integer, err := strconv.ParseInt(string(number), 10, 64)
	return integer, err == nil
}

func decodeDecimal(raw json.RawMessage) (string, bool) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if decoder.Decode(&value) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return "", false
	}
	number, ok := value.(json.Number)
	if !ok {
		return "", false
	}
	return canonicalDecimal(string(number), false)
}

func decodeExactlyOne(raw json.RawMessage, destination any) bool {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if decoder.Decode(destination) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return false
	}
	return true
}

func decodeKeyArray(raw json.RawMessage, maximum int) ([]Key, bool) {
	var values []string
	if !decodeExactlyOne(raw, &values) || len(values) > maximum {
		return nil, false
	}
	keys := make([]Key, len(values))
	for index, value := range values {
		key, err := NewKey(value)
		if err != nil {
			return nil, false
		}
		keys[index] = key
	}
	slices.SortFunc(keys, func(left, right Key) int {
		return strings.Compare(left.value, right.value)
	})
	for index := 1; index < len(keys); index++ {
		if keys[index-1] == keys[index] {
			return nil, false
		}
	}
	return keys, true
}

func canonicalDecimal(value string, optional bool) (string, bool) {
	if value == "" {
		return "", optional
	}
	if len(value) > 256 {
		return "", false
	}
	start := 0
	if value[0] == '-' {
		start = 1
		if len(value) == 1 {
			return "", false
		}
	}
	dot := -1
	for index := start; index < len(value); index++ {
		if value[index] == '.' && dot == -1 {
			dot = index
			continue
		}
		if value[index] < '0' || value[index] > '9' {
			return "", false
		}
	}
	integerEnd := len(value)
	if dot >= 0 {
		integerEnd = dot
		if dot == start || dot == len(value)-1 {
			return "", false
		}
	}
	if integerEnd-start > 1 && value[start] == '0' {
		return "", false
	}
	if dot >= 0 {
		value = strings.TrimRight(value, "0")
		value = strings.TrimSuffix(value, ".")
	}
	if value == "-0" {
		value = "0"
	}
	return value, true
}

func compareDecimal(left, right string) int {
	leftNumber, leftOK := new(big.Rat).SetString(left)
	rightNumber, rightOK := new(big.Rat).SetString(right)
	if !leftOK || !rightOK {
		panic("compareDecimal called with invalid canonical decimal")
	}
	return leftNumber.Cmp(rightNumber)
}

func canonicalURL(value string) (string, bool) {
	if !validText(value, 8*1024, false, false) {
		return "", false
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "http" && parsed.Scheme != "https" ||
		parsed.Host == "" || parsed.User != nil || parsed.Opaque != "" {
		return "", false
	}
	hostname := parsed.Hostname()
	if hostname == "" || strings.ContainsAny(hostname, " \t\r\n") {
		return "", false
	}
	port := parsed.Port()
	if port != "" {
		parsedPort, portErr := strconv.ParseUint(port, 10, 16)
		if portErr != nil || parsedPort == 0 {
			return "", false
		}
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	hostname = strings.ToLower(hostname)
	if address, addressErr := netip.ParseAddr(hostname); addressErr == nil {
		if address.Is4In6() || address.Zone() != "" {
			return "", false
		}
		hostname = address.String()
	} else {
		hostname, err = idna.Lookup.ToASCII(strings.TrimSuffix(hostname, "."))
		if err != nil || hostname == "" || len(hostname) > 253 {
			return "", false
		}
		hostname = strings.ToLower(hostname)
	}
	if port == "80" && parsed.Scheme == "http" || port == "443" && parsed.Scheme == "https" {
		port = ""
	}
	parsed.Host = hostname
	if strings.Contains(hostname, ":") {
		parsed.Host = "[" + hostname + "]"
	}
	if port != "" {
		parsed.Host = net.JoinHostPort(hostname, port)
	}
	return parsed.String(), true
}

func canonicalEmail(value string) (string, bool) {
	if !validText(value, 320, false, false) {
		return "", false
	}
	address, err := mail.ParseAddress(value)
	if err != nil || address.Address != value || address.Name != "" || strings.Count(value, "@") != 1 {
		return "", false
	}
	parts := strings.SplitN(value, "@", 2)
	if parts[0] == "" || parts[1] == "" || !isASCII(parts[0]) || !isASCII(parts[1]) {
		return "", false
	}
	return parts[0] + "@" + strings.ToLower(parts[1]), true
}

func isASCII(value string) bool {
	for index := 0; index < len(value); index++ {
		if value[index] > 0x7f {
			return false
		}
	}
	return true
}

func canonicalJSONObject(raw json.RawMessage) (json.RawMessage, bool) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	count := 0
	value, ok := decodeJSONValue(decoder, 0, &count)
	if !ok || decoder.Decode(&struct{}{}) != io.EOF {
		return nil, false
	}
	if _, object := value.(map[string]any); !object {
		return nil, false
	}
	canonical, err := json.Marshal(value)
	return canonical, err == nil && len(canonical) <= maximumJSONBytes
}

func decodeJSONValue(decoder *json.Decoder, depth int, count *int) (any, bool) {
	if depth > maximumJSONDepth || *count >= maximumJSONValues {
		return nil, false
	}
	*count++
	token, err := decoder.Token()
	if err != nil {
		return nil, false
	}
	switch typed := token.(type) {
	case nil, bool, string:
		if text, textOK := typed.(string); textOK && !validText(text, maximumCanonicalTextBytes, true, true) {
			return nil, false
		}
		return typed, true
	case json.Number:
		canonical, ok := canonicalDecimal(string(typed), false)
		if !ok {
			return nil, false
		}
		return json.Number(canonical), true
	case json.Delim:
		switch typed {
		case '{':
			object := make(map[string]any)
			for decoder.More() {
				keyToken, keyErr := decoder.Token()
				key, keyOK := keyToken.(string)
				if keyErr != nil || !keyOK || !validText(key, 256, false, false) {
					return nil, false
				}
				if _, duplicate := object[key]; duplicate {
					return nil, false
				}
				child, childOK := decodeJSONValue(decoder, depth+1, count)
				if !childOK {
					return nil, false
				}
				object[key] = child
			}
			closing, closeErr := decoder.Token()
			return object, closeErr == nil && closing == json.Delim('}')
		case '[':
			array := make([]any, 0)
			for decoder.More() {
				child, childOK := decodeJSONValue(decoder, depth+1, count)
				if !childOK {
					return nil, false
				}
				array = append(array, child)
			}
			closing, closeErr := decoder.Token()
			return array, closeErr == nil && closing == json.Delim(']')
		}
	}
	return nil, false
}

func mustMarshal(value any) json.RawMessage {
	encoded, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return encoded
}
