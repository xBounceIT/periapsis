package httpserver

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
	application "github.com/periapsis-im/periapsis/services/api/internal/ticketing"
)

type ticketExportOptional[T any] struct {
	Value   T
	Present bool
}

func (field *ticketExportOptional[T]) UnmarshalJSON(data []byte) error {
	if field == nil || bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		return errors.New("optional ticket-export values cannot be null")
	}
	var value T
	if err := decodeStrictJSON(data, &value); err != nil {
		return err
	}
	field.Value, field.Present = value, true
	return nil
}

type ticketExportRequestBody struct {
	Kind             string                      `json:"kind"`
	Comments         string                      `json:"comments"`
	Source           ticketExportSourceBody      `json:"source"`
	MaximumRows      ticketExportOptional[int64] `json:"maximumRows,omitempty"`
	MaximumBytes     ticketExportOptional[int64] `json:"maximumBytes,omitempty"`
	RetentionSeconds ticketExportOptional[int64] `json:"retentionSeconds,omitempty"`
}

type ticketExportSourceBody struct {
	Source    string                                          `json:"source"`
	Spec      ticketExportOptional[savedViewSpecBody]         `json:"spec,omitempty"`
	SavedView ticketExportOptional[ticketExportSavedViewBody] `json:"savedView,omitempty"`
}

type ticketExportSavedViewBody struct {
	ID                 uuid.UUID `json:"id"`
	ExpectedRevision   int64     `json:"expectedRevision"`
	ExpectedSpecSHA256 string    `json:"expectedSpecSha256"`
}

type ticketExportCancelBody struct {
	Kind             string `json:"kind"`
	ExpectedRevision int64  `json:"expectedRevision"`
}

func decodeTicketExportBody(r *http.Request, destination any) error {
	mediaType, err := requestMediaType(r)
	if err != nil || mediaType != "application/json" {
		return errors.New("unsupported ticket-export request content type")
	}
	defer r.Body.Close()
	body, err := io.ReadAll(io.LimitReader(r.Body, maximumPhase4BodyBytes+1))
	if err != nil || len(body) == 0 || len(body) > maximumPhase4BodyBytes || !utf8.Valid(body) {
		clear(body)
		return errors.New("ticket-export request body is invalid")
	}
	defer clear(body)
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	count := 0
	if err := scanPhase4JSONValue(decoder, 0, &count); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("ticket-export request body must contain one JSON value")
	}
	if err := validateTicketExportJSONShape(body, destination); err != nil {
		return err
	}
	strict := json.NewDecoder(bytes.NewReader(body))
	strict.DisallowUnknownFields()
	if err := strict.Decode(destination); err != nil {
		return errors.New("ticket-export request body does not match the contract")
	}
	if err := strict.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("ticket-export request body must contain one JSON value")
	}
	return nil
}

func validateTicketExportJSONShape(body []byte, destination any) error {
	var raw any
	if err := json.Unmarshal(body, &raw); err != nil {
		return errors.New("ticket-export request body does not match the contract")
	}
	if err := rejectTicketExportNulls(raw); err != nil {
		return err
	}
	root, err := ticketExportJSONObject(raw)
	if err != nil {
		return err
	}
	switch destination.(type) {
	case *ticketExportRequestBody:
		if err := requireTicketExportMembers(root, "kind", "comments", "source"); err != nil {
			return err
		}
		source, err := ticketExportJSONObject(root["source"])
		if err != nil {
			return err
		}
		if err := requireTicketExportMembers(source, "source"); err != nil {
			return err
		}
		switch source["source"] {
		case "inline":
			if err := requireTicketExportMembers(source, "spec"); err != nil {
				return err
			}
			return validateTicketExportSpecShape(source["spec"])
		case "saved_view":
			if err := requireTicketExportMembers(source, "savedView"); err != nil {
				return err
			}
			savedView, err := ticketExportJSONObject(source["savedView"])
			if err != nil {
				return err
			}
			return requireTicketExportMembers(
				savedView, "id", "expectedRevision", "expectedSpecSha256",
			)
		}
	case *ticketExportCancelBody:
		return requireTicketExportMembers(root, "kind", "expectedRevision")
	}
	return errors.New("unsupported ticket-export request body")
}

func rejectTicketExportNulls(value any) error {
	if value == nil {
		return errors.New("ticket-export request values cannot be null")
	}
	switch value := value.(type) {
	case []any:
		for _, item := range value {
			if err := rejectTicketExportNulls(item); err != nil {
				return err
			}
		}
	case map[string]any:
		for _, item := range value {
			if err := rejectTicketExportNulls(item); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateTicketExportSpecShape(value any) error {
	spec, err := ticketExportJSONObject(value)
	if err != nil {
		return err
	}
	if err := requireTicketExportMembers(spec, "filters", "sort", "columns"); err != nil {
		return err
	}
	filters, err := ticketExportJSONObject(spec["filters"])
	if err != nil {
		return err
	}
	if err := requireTicketExportMembers(
		filters, "states", "severities", "priorities", "queue", "custom",
	); err != nil {
		return err
	}
	custom, ok := filters["custom"].([]any)
	if !ok {
		return errors.New("ticket-export custom filters must be an array")
	}
	for _, value := range custom {
		filter, err := ticketExportJSONObject(value)
		if err != nil {
			return err
		}
		if err := requireTicketExportMembers(
			filter, "definitionId", "expectedDefinitionVersion", "operator", "value",
		); err != nil {
			return err
		}
	}
	sort, err := ticketExportJSONObject(spec["sort"])
	if err != nil {
		return err
	}
	if err := requireTicketExportMembers(sort, "source", "direction", "nulls"); err != nil {
		return err
	}
	columns, ok := spec["columns"].([]any)
	if !ok {
		return errors.New("ticket-export columns must be an array")
	}
	for _, value := range columns {
		column, err := ticketExportJSONObject(value)
		if err != nil {
			return err
		}
		if err := requireTicketExportMembers(column, "source", "visible", "pin"); err != nil {
			return err
		}
	}
	return nil
}

func ticketExportJSONObject(value any) (map[string]any, error) {
	object, ok := value.(map[string]any)
	if !ok {
		return nil, errors.New("ticket-export request member must be an object")
	}
	return object, nil
}

func requireTicketExportMembers(object map[string]any, names ...string) error {
	for _, name := range names {
		if value, present := object[name]; !present || value == nil {
			return errors.New("ticket-export request is missing a required member")
		}
	}
	return nil
}

func ticketExportRequestInput(
	body ticketExportRequestBody,
	idempotencyKey string,
) (application.AsyncExportRequestInput, error) {
	comments, err := ticketExportComments(body.Comments)
	if err != nil {
		return application.AsyncExportRequestInput{}, err
	}
	source, err := ticketExportSourceInput(body.Source)
	if err != nil {
		return application.AsyncExportRequestInput{}, err
	}
	input := application.AsyncExportRequestInput{
		Audience: kernel.TicketExportAudienceOperator, Comments: comments,
		Source: source, IdempotencyKey: idempotencyKey,
	}
	if body.MaximumRows.Present {
		value := body.MaximumRows.Value
		if value < 1 || value > int64(kernel.TicketExportOperatorMaximumRows) {
			return application.AsyncExportRequestInput{}, application.ErrInvalidInput
		}
		input.MaximumRows = uint32(value)
	}
	if body.MaximumBytes.Present {
		value := body.MaximumBytes.Value
		if value < 1 || uint64(value) > kernel.TicketExportOperatorMaximumBytes {
			return application.AsyncExportRequestInput{}, application.ErrInvalidInput
		}
		input.MaximumBytes = uint64(value)
	}
	if body.RetentionSeconds.Present {
		value := body.RetentionSeconds.Value
		minimum := int64(kernel.TicketExportMinimumRetention / time.Second)
		maximum := int64(kernel.TicketExportMaximumRetention / time.Second)
		if value < minimum || value > maximum {
			return application.AsyncExportRequestInput{}, application.ErrInvalidInput
		}
		input.Retention = time.Duration(value) * time.Second
	}
	return input, nil
}

func ticketExportComments(value string) (kernel.TicketExportCommentScope, error) {
	switch value {
	case "none":
		return kernel.TicketExportCommentsNone, nil
	case "public":
		return kernel.TicketExportCommentsPublic, nil
	case "public_and_private":
		return kernel.TicketExportCommentsPublicAndPrivate, nil
	default:
		return 0, application.ErrInvalidInput
	}
}

func ticketExportSourceInput(body ticketExportSourceBody) (application.AsyncExportSourceInput, error) {
	switch body.Source {
	case "inline":
		if !body.Spec.Present || body.SavedView.Present {
			return application.AsyncExportSourceInput{}, application.ErrInvalidInput
		}
		spec, err := savedViewSpecInput(body.Spec.Value)
		if err != nil {
			return application.AsyncExportSourceInput{}, err
		}
		return application.AsyncExportSourceInput{Inline: &spec}, nil
	case "saved_view":
		if body.Spec.Present || !body.SavedView.Present || body.SavedView.Value.ID == uuid.Nil ||
			body.SavedView.Value.ExpectedRevision < 1 ||
			body.SavedView.Value.ExpectedRevision > maximumResourceVersion {
			return application.AsyncExportSourceInput{}, application.ErrInvalidInput
		}
		digest, err := ticketExportSHA256(body.SavedView.Value.ExpectedSpecSHA256)
		if err != nil {
			return application.AsyncExportSourceInput{}, err
		}
		return application.AsyncExportSourceInput{SavedView: &application.AsyncExportSavedViewSourceInput{
			ID: body.SavedView.Value.ID, ExpectedRevision: uint64(body.SavedView.Value.ExpectedRevision),
			ExpectedSpecDigest: digest,
		}}, nil
	default:
		return application.AsyncExportSourceInput{}, application.ErrInvalidInput
	}
}

func ticketExportSHA256(value string) ([sha256.Size]byte, error) {
	var result [sha256.Size]byte
	if len(value) != hex.EncodedLen(len(result)) || value != strings.ToLower(value) {
		return result, application.ErrInvalidInput
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != len(result) {
		return result, application.ErrInvalidInput
	}
	copy(result[:], decoded)
	clear(decoded)
	if result == ([sha256.Size]byte{}) {
		return result, application.ErrInvalidInput
	}
	return result, nil
}
