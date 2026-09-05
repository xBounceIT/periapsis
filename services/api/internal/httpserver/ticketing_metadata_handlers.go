package httpserver

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
	"github.com/periapsis-im/periapsis/services/api/internal/contract"
	applicationticketing "github.com/periapsis-im/periapsis/services/api/internal/ticketing"
)

var alertMetadataRequestFields = [...]string{
	"title", "description", "severity", "priority", "category",
	"classification", "customerVisible", "tags",
}

var caseMetadataRequestFields = [...]string{
	"title", "description", "summary", "severity", "priority", "category",
	"classification", "customerVisible", "tags",
}

func (h *Handler) ReplaceTenantAlertMetadata(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	alertID contract.AlertId,
	params contract.ReplaceTenantAlertMetadataParams,
) {
	actor, expectedVersion, idempotencyKey, ok := h.ticketMetadataMutationRequest(w, r, params.IfMatch, params.IdempotencyKey)
	if !ok {
		return
	}
	var body contract.ReplaceTenantAlertMetadataJSONRequestBody
	if err := decodeRequiredMetadataBody(r, &body, alertMetadataRequestFields[:]); err != nil ||
		!body.Severity.Valid() || !body.Priority.Valid() {
		writeDomainError(w, r, applicationticketing.ErrInvalidInput)
		return
	}
	input, err := alertMetadataInput(body, expectedVersion, idempotencyKey)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	result, err := h.ticketing.ReplaceAlertMetadata(
		r.Context(), actor, uuid.UUID(tenantID), uuid.UUID(alertID), input,
	)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	mapped, err := mapAlertMetadata(result.Metadata, uuid.UUID(tenantID), uuid.UUID(alertID), expectedVersion)
	if err != nil || !setVersionETag(w, int64(result.Metadata.Version)) {
		writeDomainError(w, r, applicationticketing.ErrUnavailable)
		return
	}
	writeSensitiveJSON(w, http.StatusOK, mapped)
}

func (h *Handler) ReplaceTenantCaseMetadata(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	caseID contract.CaseId,
	params contract.ReplaceTenantCaseMetadataParams,
) {
	actor, expectedVersion, idempotencyKey, ok := h.ticketMetadataMutationRequest(w, r, params.IfMatch, params.IdempotencyKey)
	if !ok {
		return
	}
	var body contract.ReplaceTenantCaseMetadataJSONRequestBody
	if err := decodeRequiredMetadataBody(r, &body, caseMetadataRequestFields[:]); err != nil ||
		!body.Severity.Valid() || !body.Priority.Valid() {
		writeDomainError(w, r, applicationticketing.ErrInvalidInput)
		return
	}
	input, err := caseMetadataInput(body, expectedVersion, idempotencyKey)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	result, err := h.ticketing.ReplaceCaseMetadata(
		r.Context(), actor, uuid.UUID(tenantID), uuid.UUID(caseID), input,
	)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	mapped, err := mapCaseMetadata(result.Metadata, uuid.UUID(tenantID), uuid.UUID(caseID), expectedVersion)
	if err != nil || !setVersionETag(w, int64(result.Metadata.Version)) {
		writeDomainError(w, r, applicationticketing.ErrUnavailable)
		return
	}
	writeSensitiveJSON(w, http.StatusOK, mapped)
}

func (h *Handler) ticketMetadataMutationRequest(
	w http.ResponseWriter,
	r *http.Request,
	ifMatch contract.IfMatch,
	parameterKey contract.IdempotencyKey,
) (applicationticketing.Actor, uint64, string, bool) {
	actor, expectedVersion, ok := h.ticketingMutationPrecondition(w, r, ifMatch)
	if !ok {
		return applicationticketing.Actor{}, 0, "", false
	}
	if expectedVersion >= 2_147_483_647 {
		writeDomainError(w, r, applicationticketing.ErrInvalidInput)
		return applicationticketing.Actor{}, 0, "", false
	}
	idempotencyKey, err := requestIdempotencyKey(r)
	if err != nil || string(parameterKey) != idempotencyKey {
		writeDomainError(w, r, applicationticketing.ErrInvalidInput)
		return applicationticketing.Actor{}, 0, "", false
	}
	return actor, expectedVersion, idempotencyKey, true
}

func alertMetadataInput(
	body contract.AlertMetadataReplaceRequest,
	expectedVersion uint64,
	idempotencyKey string,
) (applicationticketing.MetadataReplaceInput, error) {
	tags, err := canonicalStrings(body.Tags)
	if err != nil {
		return applicationticketing.MetadataReplaceInput{}, err
	}
	return applicationticketing.MetadataReplaceInput{
		EditableMetadata: applicationticketing.EditableMetadata{
			Title: body.Title, Description: body.Description,
			Severity: string(body.Severity), Priority: string(body.Priority), Category: body.Category,
			Classification: body.Classification, CustomerVisible: body.CustomerVisible, Tags: tags,
		},
		ExpectedVersion: expectedVersion,
		IdempotencyKey:  idempotencyKey,
	}, nil
}

func caseMetadataInput(
	body contract.CaseMetadataReplaceRequest,
	expectedVersion uint64,
	idempotencyKey string,
) (applicationticketing.MetadataReplaceInput, error) {
	tags, err := canonicalStrings(body.Tags)
	if err != nil {
		return applicationticketing.MetadataReplaceInput{}, err
	}
	return applicationticketing.MetadataReplaceInput{
		EditableMetadata: applicationticketing.EditableMetadata{
			Title: body.Title, Description: body.Description, Summary: body.Summary,
			Severity: string(body.Severity), Priority: string(body.Priority), Category: body.Category,
			Classification: body.Classification, CustomerVisible: body.CustomerVisible, Tags: tags,
		},
		ExpectedVersion: expectedVersion,
		IdempotencyKey:  idempotencyKey,
	}, nil
}

func mapAlertMetadata(value applicationticketing.TicketMetadata, tenantID, alertID uuid.UUID, expectedVersion uint64) (contract.AlertMetadata, error) {
	if value.Kind != kernel.AggregateAlert || value.TenantID != tenantID || value.TicketID != alertID ||
		value.Version != expectedVersion+1 || value.Version > 2_147_483_647 || value.UpdatedAt.IsZero() ||
		value.Summary != "" {
		return contract.AlertMetadata{}, errors.New("invalid Alert metadata result")
	}
	severity := contract.AlertSeverity(value.Severity)
	priority := contract.TicketPriority(value.Priority)
	if !severity.Valid() || !priority.Valid() {
		return contract.AlertMetadata{}, errors.New("invalid Alert metadata result")
	}
	return contract.AlertMetadata{
		Id: value.TicketID, Title: value.Title, Description: value.Description,
		Severity: severity, Priority: priority, Category: value.Category,
		Classification: value.Classification, CustomerVisible: value.CustomerVisible,
		Tags: append([]string{}, value.Tags...), Version: int64(value.Version), UpdatedAt: value.UpdatedAt.UTC(),
	}, nil
}

func mapCaseMetadata(value applicationticketing.TicketMetadata, tenantID, caseID uuid.UUID, expectedVersion uint64) (contract.CaseMetadata, error) {
	if value.Kind != kernel.AggregateCase || value.TenantID != tenantID || value.TicketID != caseID ||
		value.Version != expectedVersion+1 || value.Version > 2_147_483_647 || value.UpdatedAt.IsZero() {
		return contract.CaseMetadata{}, errors.New("invalid Case metadata result")
	}
	severity := contract.AlertSeverity(value.Severity)
	priority := contract.TicketPriority(value.Priority)
	if !severity.Valid() || !priority.Valid() {
		return contract.CaseMetadata{}, errors.New("invalid Case metadata result")
	}
	return contract.CaseMetadata{
		Id: value.TicketID, Title: value.Title, Description: value.Description, Summary: value.Summary,
		Severity: severity, Priority: priority, Category: value.Category,
		Classification: value.Classification, CustomerVisible: value.CustomerVisible,
		Tags: append([]string{}, value.Tags...), Version: int64(value.Version), UpdatedAt: value.UpdatedAt.UTC(),
	}, nil
}

// decodeRequiredMetadataBody retains the contract's distinction between an
// omitted required nullable property and an explicit JSON null. The generated
// Go pointer alone cannot represent that distinction after unmarshalling.
func decodeRequiredMetadataBody(r *http.Request, destination any, requiredFields []string) error {
	if r == nil || r.Body == nil {
		return errors.New("request body is missing")
	}
	mediaType, err := requestMediaType(r)
	if err != nil || mediaType != "application/json" {
		return errors.New("unsupported request content type")
	}
	original := r.Body
	body, err := io.ReadAll(io.LimitReader(original, (1<<20)+1))
	closeErr := original.Close()
	if err != nil || closeErr != nil || len(body) == 0 || len(body) > 1<<20 || !utf8.Valid(body) {
		return errors.New("request body is invalid")
	}
	if err := validateMetadataJSONTokens(body, requiredFields); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("request body must contain one JSON value")
	}
	return nil
}

func validateMetadataJSONTokens(body []byte, requiredFields []string) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') {
		return errors.New("request body must be an object")
	}
	allowed := make(map[string]struct{}, len(requiredFields))
	for _, field := range requiredFields {
		allowed[field] = struct{}{}
	}
	seen := make(map[string]struct{}, len(allowed))
	for decoder.More() {
		keyToken, keyErr := decoder.Token()
		key, ok := keyToken.(string)
		if keyErr != nil || !ok || containsJSONControlCharacter(key) {
			return errors.New("request body contains an invalid object key")
		}
		if _, duplicate := seen[key]; duplicate {
			return errors.New("request body contains a duplicate object key")
		}
		if _, expected := allowed[key]; !expected {
			return errors.New("request body contains an unknown field")
		}
		seen[key] = struct{}{}
		switch key {
		case "description", "summary":
			value, valueErr := decoder.Token()
			text, ok := value.(string)
			if valueErr != nil || !ok || containsDisallowedMetadataMultilineControl(text) {
				return errors.New("request body contains an invalid multiline field")
			}
		case "classification":
			value, valueErr := decoder.Token()
			if valueErr != nil {
				return valueErr
			}
			if value != nil {
				classification, ok := value.(string)
				if !ok || containsJSONControlCharacter(classification) {
					return errors.New("request body contains an invalid classification")
				}
			}
		case "customerVisible":
			value, valueErr := decoder.Token()
			if _, ok := value.(bool); valueErr != nil || !ok {
				return errors.New("request body contains an invalid visibility")
			}
		case "tags":
			opening, openingErr := decoder.Token()
			if openingErr != nil || opening != json.Delim('[') {
				return errors.New("request body contains invalid tags")
			}
			for decoder.More() {
				value, valueErr := decoder.Token()
				tag, ok := value.(string)
				if valueErr != nil || !ok || containsJSONControlCharacter(tag) {
					return errors.New("request body contains invalid tags")
				}
			}
			closing, closingErr := decoder.Token()
			if closingErr != nil || closing != json.Delim(']') {
				return errors.New("request body contains invalid tags")
			}
		case "title", "severity", "priority", "category":
			value, valueErr := decoder.Token()
			text, ok := value.(string)
			if valueErr != nil || !ok || containsJSONControlCharacter(text) {
				return errors.New("request body contains an invalid single-line field")
			}
		}
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim('}') {
		return errors.New("request body contains an unterminated object")
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("request body must contain one JSON value")
	}
	if len(seen) != len(allowed) {
		return errors.New("request body omits a required field")
	}
	return nil
}

func containsDisallowedMetadataMultilineControl(value string) bool {
	for _, character := range value {
		if unicode.IsControl(character) && character != '\t' && character != '\n' && character != '\r' {
			return true
		}
	}
	return false
}
