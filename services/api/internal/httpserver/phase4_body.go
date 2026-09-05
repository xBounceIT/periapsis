package httpserver

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
)

const (
	maximumPhase4BodyBytes  = 1 << 20
	maximumPhase4JSONDepth  = 32
	maximumPhase4JSONValues = 4096
)

// decodePhase4Body preserves explicit JSON null for custom fields and custody
// operations while rejecting duplicate members, missing required members,
// unknown members, excessive depth/count, trailing data, and invalid UTF-8.
func decodePhase4Body(r *http.Request, destination any) error {
	mediaType, err := requestMediaType(r)
	if err != nil || mediaType != "application/json" {
		return errors.New("unsupported Phase 4 request content type")
	}
	defer r.Body.Close()
	body, err := io.ReadAll(io.LimitReader(r.Body, maximumPhase4BodyBytes+1))
	if err != nil || len(body) == 0 || len(body) > maximumPhase4BodyBytes || !utf8.Valid(body) {
		clear(body)
		return errors.New("Phase 4 request body is invalid")
	}
	defer clear(body)
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	count := 0
	if err := scanPhase4JSONValue(decoder, 0, &count); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("Phase 4 request body must contain one JSON value")
	}
	var raw any
	if err := json.Unmarshal(body, &raw); err != nil {
		return errors.New("Phase 4 request body does not match the exact contract shape")
	}
	if err := validatePhase4JSONShape(raw, reflect.TypeOf(destination)); err != nil {
		return fmt.Errorf("Phase 4 request body does not match the exact contract shape: %w", err)
	}
	strict := json.NewDecoder(bytes.NewReader(body))
	strict.DisallowUnknownFields()
	if err := strict.Decode(destination); err != nil {
		return errors.New("Phase 4 request body does not match the contract")
	}
	if err := strict.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("Phase 4 request body must contain one JSON value")
	}
	return nil
}

func scanPhase4JSONValue(decoder *json.Decoder, depth int, count *int) error {
	return scanBoundedJSONValue(decoder, depth, count, maximumPhase4JSONValues)
}

func scanBoundedJSONValue(decoder *json.Decoder, depth int, count *int, maximumValues int) error {
	if depth > maximumPhase4JSONDepth || *count >= maximumValues {
		return errors.New("Phase 4 request body exceeds structural bounds")
	}
	*count++
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
			if keyErr != nil || !ok || invalidPhase4JSONKey(key) {
				return errors.New("Phase 4 request body contains an invalid object key")
			}
			if _, duplicate := seen[key]; duplicate {
				return errors.New("Phase 4 request body contains a duplicate object key")
			}
			seen[key] = struct{}{}
			if err := scanBoundedJSONValue(decoder, depth+1, count, maximumValues); err != nil {
				return err
			}
		}
		closing, closeErr := decoder.Token()
		if closeErr != nil || closing != json.Delim('}') {
			return errors.New("Phase 4 request body contains an unterminated object")
		}
	case '[':
		for decoder.More() {
			if err := scanBoundedJSONValue(decoder, depth+1, count, maximumValues); err != nil {
				return err
			}
		}
		closing, closeErr := decoder.Token()
		if closeErr != nil || closing != json.Delim(']') {
			return errors.New("Phase 4 request body contains an unterminated array")
		}
	default:
		return errors.New("Phase 4 request body contains an invalid delimiter")
	}
	return nil
}

func invalidPhase4JSONKey(value string) bool {
	if value == "" || len(value) > 256 {
		return true
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return true
		}
	}
	return false
}

func validatePhase4JSONShape(value any, destinationType reflect.Type) error {
	for destinationType.Kind() == reflect.Pointer {
		destinationType = destinationType.Elem()
	}
	if destinationType == reflect.TypeOf(slaRawJSON{}) {
		return nil
	}
	if destinationType == reflect.TypeOf(uuid.UUID{}) || destinationType == reflect.TypeOf(time.Time{}) {
		if _, ok := value.(string); !ok {
			return errors.New("expected JSON string")
		}
		return nil
	}
	if destinationType.PkgPath() == "github.com/periapsis-im/periapsis/services/api/internal/contract" &&
		(strings.HasPrefix(destinationType.Name(), "CustomFieldValue") || destinationType.Name() == "AlertCreator") {
		return nil
	}
	switch destinationType.Kind() {
	case reflect.Struct:
		object, ok := value.(map[string]any)
		if !ok {
			return errors.New("expected JSON object")
		}
		fields := make(map[string]reflect.StructField, destinationType.NumField())
		for index := 0; index < destinationType.NumField(); index++ {
			field := destinationType.Field(index)
			if !field.IsExported() {
				continue
			}
			name := strings.Split(field.Tag.Get("json"), ",")[0]
			if name == "" {
				name = field.Name
			}
			if name != "-" {
				fields[name] = field
			}
		}
		for name, field := range fields {
			item, present := object[name]
			optional := strings.Contains(field.Tag.Get("json"), "omitempty")
			if !present {
				if !optional {
					return errors.New("required JSON member is absent")
				}
				continue
			}
			if item == nil && field.Type.Kind() != reflect.Pointer {
				return errors.New("required JSON member is null")
			}
			if item != nil {
				if err := validatePhase4JSONShape(item, field.Type); err != nil {
					return fmt.Errorf("member %q: %w", name, err)
				}
			}
		}
		for name := range object {
			if _, known := fields[name]; !known {
				return errors.New("unknown JSON member")
			}
		}
	case reflect.Array, reflect.Slice:
		items, ok := value.([]any)
		if !ok {
			return errors.New("expected JSON array")
		}
		for _, item := range items {
			if err := validatePhase4JSONShape(item, destinationType.Elem()); err != nil {
				return err
			}
		}
	case reflect.Map:
		object, ok := value.(map[string]any)
		if !ok {
			return errors.New("expected JSON object")
		}
		for _, item := range object {
			if item != nil && destinationType.Elem().Kind() != reflect.Interface {
				if err := validatePhase4JSONShape(item, destinationType.Elem()); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
