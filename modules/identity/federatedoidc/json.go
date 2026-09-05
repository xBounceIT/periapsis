package federatedoidc

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"unicode/utf8"
)

type jsonStatistics struct {
	values        int
	objectMembers int
	arrayItems    int
}

func validateBoundedJSONObject(document []byte, maximumBytes int, limits Limits) error {
	if len(document) < 2 || len(document) > maximumBytes || !utf8.Valid(document) {
		return errors.New("bounded JSON rejected")
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.UseNumber()
	statistics := jsonStatistics{}
	topLevelObject, err := scanJSONValue(decoder, 1, limits, &statistics)
	if err != nil || !topLevelObject {
		return errors.New("bounded JSON rejected")
	}
	if _, err = decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("bounded JSON rejected")
	}
	return nil
}

func scanJSONValue(
	decoder *json.Decoder,
	depth int,
	limits Limits,
	statistics *jsonStatistics,
) (bool, error) {
	if decoder == nil || statistics == nil || depth > limits.MaxJSONDepth {
		return false, errors.New("bounded JSON rejected")
	}
	token, err := decoder.Token()
	if err != nil {
		return false, errors.New("bounded JSON rejected")
	}
	statistics.values++
	if statistics.values > limits.MaxJSONValues {
		return false, errors.New("bounded JSON rejected")
	}
	switch value := token.(type) {
	case json.Delim:
		switch value {
		case '{':
			seen := make(map[string]struct{})
			for decoder.More() {
				keyToken, keyErr := decoder.Token()
				key, ok := keyToken.(string)
				if keyErr != nil || !ok || len(key) > limits.MaxJSONStringBytes {
					return false, errors.New("bounded JSON rejected")
				}
				statistics.objectMembers++
				if statistics.objectMembers > limits.MaxJSONObjectMembers {
					return false, errors.New("bounded JSON rejected")
				}
				if _, duplicate := seen[key]; duplicate {
					return false, errors.New("bounded JSON rejected")
				}
				seen[key] = struct{}{}
				if _, valueErr := scanJSONValue(decoder, depth+1, limits, statistics); valueErr != nil {
					return false, valueErr
				}
			}
			closing, closeErr := decoder.Token()
			if closeErr != nil || closing != json.Delim('}') {
				return false, errors.New("bounded JSON rejected")
			}
			return depth == 1, nil
		case '[':
			for decoder.More() {
				statistics.arrayItems++
				if statistics.arrayItems > limits.MaxJSONArrayItems {
					return false, errors.New("bounded JSON rejected")
				}
				if _, valueErr := scanJSONValue(decoder, depth+1, limits, statistics); valueErr != nil {
					return false, valueErr
				}
			}
			closing, closeErr := decoder.Token()
			if closeErr != nil || closing != json.Delim(']') {
				return false, errors.New("bounded JSON rejected")
			}
			return false, nil
		default:
			return false, errors.New("bounded JSON rejected")
		}
	case string:
		if len(value) > limits.MaxJSONStringBytes {
			return false, errors.New("bounded JSON rejected")
		}
	case json.Number:
		if len(value.String()) > 64 {
			return false, errors.New("bounded JSON rejected")
		}
	case bool, nil:
	default:
		return false, errors.New("bounded JSON rejected")
	}
	return false, nil
}

func decodeObject(document []byte) (map[string]json.RawMessage, error) {
	var result map[string]json.RawMessage
	if err := json.Unmarshal(document, &result); err != nil || result == nil {
		return nil, errors.New("JSON object rejected")
	}
	return result, nil
}

func decodeStringMember(
	object map[string]json.RawMessage,
	name string,
	required bool,
	maximumBytes int,
) (string, bool, error) {
	raw, present := object[name]
	if !present {
		if required {
			return "", false, errors.New("JSON member rejected")
		}
		return "", false, nil
	}
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) < 2 || trimmed[0] != '"' {
		return "", false, errors.New("JSON member rejected")
	}
	var value string
	if json.Unmarshal(trimmed, &value) != nil || len(value) == 0 || len(value) > maximumBytes || !utf8.ValidString(value) {
		return "", false, errors.New("JSON member rejected")
	}
	return value, true, nil
}

func decodeStringArrayMember(
	object map[string]json.RawMessage,
	name string,
	required bool,
	maximumItems int,
	maximumStringBytes int,
) ([]string, bool, error) {
	raw, present := object[name]
	if !present {
		if required {
			return nil, false, errors.New("JSON member rejected")
		}
		return nil, false, nil
	}
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) < 2 || trimmed[0] != '[' {
		return nil, false, errors.New("JSON member rejected")
	}
	var values []json.RawMessage
	if json.Unmarshal(trimmed, &values) != nil || len(values) == 0 || len(values) > maximumItems {
		return nil, false, errors.New("JSON member rejected")
	}
	result := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, valueRaw := range values {
		valueTrimmed := bytes.TrimSpace(valueRaw)
		if len(valueTrimmed) < 2 || valueTrimmed[0] != '"' {
			return nil, false, errors.New("JSON member rejected")
		}
		var value string
		if json.Unmarshal(valueTrimmed, &value) != nil || value == "" || len(value) > maximumStringBytes ||
			!utf8.ValidString(value) {
			return nil, false, errors.New("JSON member rejected")
		}
		if _, duplicate := seen[value]; duplicate {
			return nil, false, errors.New("JSON member rejected")
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result, true, nil
}

func containsString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}
