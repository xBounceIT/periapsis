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
	application "github.com/periapsis-im/periapsis/services/api/internal/ticketing"
)

type ticketBulkOptional[T any] struct {
	Value   T
	Present bool
}

func (field *ticketBulkOptional[T]) UnmarshalJSON(data []byte) error {
	if field == nil || bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		return errors.New("optional ticket-bulk values cannot be null")
	}
	var value T
	if err := decodeStrictJSON(data, &value); err != nil {
		return err
	}
	field.Value, field.Present = value, true
	return nil
}

func decodeTicketBulkBody(r *http.Request, destination any) error {
	mediaType, err := requestMediaType(r)
	if err != nil || mediaType != "application/json" {
		return errors.New("unsupported ticket-bulk request content type")
	}
	defer r.Body.Close()
	body, err := io.ReadAll(io.LimitReader(r.Body, maximumPhase4BodyBytes+1))
	if err != nil || len(body) == 0 || len(body) > maximumPhase4BodyBytes || !utf8.Valid(body) {
		clear(body)
		return errors.New("ticket-bulk request body is invalid")
	}
	defer clear(body)
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	count := 0
	if err := scanPhase4JSONValue(decoder, 0, &count); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("ticket-bulk request body must contain one JSON value")
	}
	strict := json.NewDecoder(bytes.NewReader(body))
	strict.DisallowUnknownFields()
	if err := strict.Decode(destination); err != nil {
		return errors.New("ticket-bulk request body does not match the contract")
	}
	if err := strict.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("ticket-bulk request body must contain one JSON value")
	}
	return nil
}

type ticketBulkRequestBody struct {
	Kind             string                    `json:"kind"`
	Selection        ticketBulkSelectionBody   `json:"selection"`
	Mutation         ticketBulkMutationBody    `json:"mutation"`
	RetentionSeconds ticketBulkOptional[int64] `json:"retentionSeconds,omitempty"`
}

type ticketBulkSelectionBody struct {
	Source  string                                     `json:"source"`
	Targets ticketBulkOptional[[]ticketBulkTargetBody] `json:"targets,omitempty"`
	Query   ticketBulkOptional[ticketBulkQueryBody]    `json:"query,omitempty"`
}

type ticketBulkTargetBody struct {
	ID              uuid.UUID `json:"id"`
	ExpectedVersion int64     `json:"expectedVersion"`
}

type ticketBulkQueryBody struct {
	Source    string                                      `json:"source"`
	Spec      ticketBulkOptional[savedViewSpecBody]       `json:"spec,omitempty"`
	SavedView ticketBulkOptional[ticketBulkSavedViewBody] `json:"savedView,omitempty"`
}

type ticketBulkSavedViewBody struct {
	ID                 uuid.UUID `json:"id"`
	ExpectedRevision   int64     `json:"expectedRevision"`
	ExpectedSpecSHA256 string    `json:"expectedSpecSha256"`
}

type ticketBulkMutationBody struct {
	Action     string                        `json:"action"`
	Transition ticketBulkOptional[string]    `json:"transition,omitempty"`
	To         ticketBulkOptional[string]    `json:"to,omitempty"`
	TeamID     ticketBulkOptional[uuid.UUID] `json:"teamId,omitempty"`
	AssigneeID ticketBulkOptional[uuid.UUID] `json:"assigneeId,omitempty"`
}

type ticketBulkCancelBody struct {
	Kind             string `json:"kind"`
	ExpectedRevision int64  `json:"expectedRevision"`
}

func ticketBulkRequestInput(body ticketBulkRequestBody, idempotencyKey string) (application.TicketBulkRequestInput, error) {
	selection, err := ticketBulkSelectionInput(body.Selection)
	if err != nil {
		return application.TicketBulkRequestInput{}, err
	}
	mutation, err := ticketBulkMutationInput(body.Mutation)
	if err != nil {
		return application.TicketBulkRequestInput{}, err
	}
	input := application.TicketBulkRequestInput{
		Selection: selection, Mutation: mutation, IdempotencyKey: idempotencyKey,
	}
	if body.RetentionSeconds.Present {
		seconds := body.RetentionSeconds.Value
		if seconds < 300 || seconds > 2_592_000 {
			return application.TicketBulkRequestInput{}, application.ErrInvalidInput
		}
		input.Retention = time.Duration(seconds) * time.Second
	}
	return input, nil
}

func ticketBulkSelectionInput(body ticketBulkSelectionBody) (application.TicketBulkSelectionInput, error) {
	switch body.Source {
	case "explicit":
		if !body.Targets.Present || body.Query.Present || len(body.Targets.Value) == 0 || len(body.Targets.Value) > 1_000 {
			return application.TicketBulkSelectionInput{}, application.ErrInvalidInput
		}
		targets := make([]application.TicketBulkTargetInput, len(body.Targets.Value))
		for index, target := range body.Targets.Value {
			if target.ExpectedVersion <= 0 || target.ExpectedVersion > 2_147_483_647 {
				return application.TicketBulkSelectionInput{}, application.ErrInvalidInput
			}
			targets[index] = application.TicketBulkTargetInput{
				ID: target.ID, ExpectedVersion: uint64(target.ExpectedVersion),
			}
		}
		return application.TicketBulkSelectionInput{Explicit: targets}, nil
	case "query":
		if body.Targets.Present || !body.Query.Present {
			return application.TicketBulkSelectionInput{}, application.ErrInvalidInput
		}
		query, err := ticketBulkQueryInput(body.Query.Value)
		if err != nil {
			return application.TicketBulkSelectionInput{}, err
		}
		return application.TicketBulkSelectionInput{Query: &query}, nil
	default:
		return application.TicketBulkSelectionInput{}, application.ErrInvalidInput
	}
}

func ticketBulkQueryInput(body ticketBulkQueryBody) (application.TicketBulkQuerySourceInput, error) {
	switch body.Source {
	case "inline":
		if !body.Spec.Present || body.SavedView.Present {
			return application.TicketBulkQuerySourceInput{}, application.ErrInvalidInput
		}
		spec, err := savedViewSpecInput(body.Spec.Value)
		if err != nil {
			return application.TicketBulkQuerySourceInput{}, err
		}
		return application.TicketBulkQuerySourceInput{Inline: &spec}, nil
	case "saved_view":
		if body.Spec.Present || !body.SavedView.Present || body.SavedView.Value.ExpectedRevision <= 0 ||
			body.SavedView.Value.ExpectedRevision > 2_147_483_647 {
			return application.TicketBulkQuerySourceInput{}, application.ErrInvalidInput
		}
		digest, err := ticketBulkSHA256(body.SavedView.Value.ExpectedSpecSHA256)
		if err != nil {
			return application.TicketBulkQuerySourceInput{}, err
		}
		return application.TicketBulkQuerySourceInput{SavedView: &application.TicketBulkSavedViewSourceInput{
			ID: body.SavedView.Value.ID, ExpectedRevision: uint64(body.SavedView.Value.ExpectedRevision),
			ExpectedSpecDigest: digest,
		}}, nil
	default:
		return application.TicketBulkQuerySourceInput{}, application.ErrInvalidInput
	}
}

func ticketBulkMutationInput(body ticketBulkMutationBody) (application.TicketBulkMutationInput, error) {
	input := application.TicketBulkMutationInput{Action: body.Action}
	if body.Transition.Present {
		input.Transition = body.Transition.Value
	}
	if body.To.Present {
		input.To = body.To.Value
	}
	if body.TeamID.Present {
		input.TeamID = body.TeamID.Value
	}
	if body.AssigneeID.Present {
		value := body.AssigneeID.Value
		input.AssigneeID = &value
	}
	switch body.Action {
	case "transition":
		if !body.Transition.Present || !body.To.Present || body.TeamID.Present || body.AssigneeID.Present {
			return application.TicketBulkMutationInput{}, application.ErrInvalidInput
		}
	case "assign", "transfer":
		if body.Transition.Present || body.To.Present || !body.TeamID.Present {
			return application.TicketBulkMutationInput{}, application.ErrInvalidInput
		}
	case "claim":
		if body.Transition.Present || body.To.Present || !body.TeamID.Present || body.AssigneeID.Present {
			return application.TicketBulkMutationInput{}, application.ErrInvalidInput
		}
	case "release":
		if body.Transition.Present || body.To.Present || body.TeamID.Present || body.AssigneeID.Present {
			return application.TicketBulkMutationInput{}, application.ErrInvalidInput
		}
	default:
		return application.TicketBulkMutationInput{}, application.ErrInvalidInput
	}
	return input, nil
}

func ticketBulkSHA256(value string) ([sha256.Size]byte, error) {
	var result [sha256.Size]byte
	if len(value) != hex.EncodedLen(len(result)) || value != strings.ToLower(value) {
		return result, application.ErrInvalidInput
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != len(result) {
		return result, application.ErrInvalidInput
	}
	copy(result[:], decoded)
	if result == ([sha256.Size]byte{}) {
		return result, application.ErrInvalidInput
	}
	return result, nil
}
