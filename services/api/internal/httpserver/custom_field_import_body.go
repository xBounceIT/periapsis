package httpserver

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"unicode/utf8"
)

const (
	customFieldImportMaximumBodyBytes  = 32 * 1024 * 1024
	customFieldImportMaximumJSONValues = 2_000_000
	customFieldImportMaximumCellBytes  = 64 * 1024
)

type customFieldImportRequestBody struct {
	ObjectType       string                     `json:"objectType"`
	Mode             string                     `json:"mode"`
	Rows             []customFieldImportRowBody `json:"rows"`
	RetentionSeconds *int64                     `json:"retentionSeconds,omitempty"`
}

type customFieldImportRowBody struct {
	TargetID        string                       `json:"targetId"`
	ExpectedVersion uint64                       `json:"expectedVersion"`
	Fields          []customFieldImportFieldBody `json:"fields"`
}

type customFieldImportFieldBody struct {
	Key     string
	Value   json.RawMessage
	Present bool
}

func (field *customFieldImportFieldBody) UnmarshalJSON(document []byte) error {
	if field == nil {
		return errors.New("custom-field import field destination is required")
	}
	var object map[string]json.RawMessage
	decoder := json.NewDecoder(bytes.NewReader(document))
	if err := decoder.Decode(&object); err != nil || object == nil {
		return errors.New("custom-field import field must be an object")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("custom-field import field has trailing data")
	}
	keyDocument, hasKey := object["key"]
	valueDocument, hasValue := object["value"]
	if !hasKey || len(object) != 1 && !(len(object) == 2 && hasValue) {
		return errors.New("custom-field import field shape is invalid")
	}
	var key string
	if err := json.Unmarshal(keyDocument, &key); err != nil {
		return errors.New("custom-field import field key is invalid")
	}
	if hasValue && (len(valueDocument) == 0 || len(valueDocument) > customFieldImportMaximumCellBytes) {
		return errors.New("custom-field import field value is too large")
	}
	field.Key, field.Present = key, hasValue
	field.Value = append(field.Value[:0], valueDocument...)
	return nil
}

func decodeCustomFieldImportRequestBody(
	request *http.Request,
	destination *customFieldImportRequestBody,
) error {
	if request == nil || destination == nil {
		return errors.New("custom-field import request body is unavailable")
	}
	mediaType, err := requestMediaType(request)
	if err != nil || mediaType != "application/json" {
		return errors.New("custom-field import request content type is unsupported")
	}
	defer request.Body.Close()
	body, err := io.ReadAll(io.LimitReader(request.Body, customFieldImportMaximumBodyBytes+1))
	if err != nil || len(body) == 0 || len(body) > customFieldImportMaximumBodyBytes || !utf8.Valid(body) {
		clear(body)
		return errors.New("custom-field import request body is invalid")
	}
	defer clear(body)
	scanner := json.NewDecoder(bytes.NewReader(body))
	scanner.UseNumber()
	values := 0
	if err := scanBoundedJSONValue(scanner, 0, &values, customFieldImportMaximumJSONValues); err != nil {
		return err
	}
	if _, err := scanner.Token(); !errors.Is(err, io.EOF) {
		return errors.New("custom-field import request must contain one JSON value")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return errors.New("custom-field import request does not match the contract")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("custom-field import request must contain one JSON value")
	}
	return nil
}
