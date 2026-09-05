package httpserver

import (
	"net/http"
	"slices"
	"strconv"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
	"github.com/periapsis-im/periapsis/services/api/internal/contract"
	applicationticketing "github.com/periapsis-im/periapsis/services/api/internal/ticketing"
)

type escalationRequestBody struct {
	ExpectedVersion int64                          `json:"expectedVersion"`
	Reason          string                         `json:"reason"`
	RelationType    contract.AlertCaseRelationType `json:"relationType"`
	Sources         []escalationSourceBody         `json:"sources"`
	Target          escalationTargetBody           `json:"target"`
}

type escalationSourceBody struct {
	AlertID         uuid.UUID                   `json:"alertId"`
	ExpectedVersion int64                       `json:"expectedVersion"`
	CopySelection   escalationCopySelectionBody `json:"copySelection"`
}

type escalationCopySelectionBody struct {
	Fields           *[]contract.EscalationCopyField `json:"fields,omitempty"`
	CustomFieldKeys  *[]contract.CustomFieldKey      `json:"customFieldKeys,omitempty"`
	IOCIDs           *[]uuid.UUID                    `json:"iocIds,omitempty"`
	AssetIDs         *[]uuid.UUID                    `json:"assetIds,omitempty"`
	AttachmentIDs    *[]uuid.UUID                    `json:"attachmentIds,omitempty"`
	ContactIDs       *[]uuid.UUID                    `json:"contactIds,omitempty"`
	PublicCommentIDs *[]uuid.UUID                    `json:"publicCommentIds,omitempty"`
}

type escalationTargetBody struct {
	Mode            string                      `json:"mode"`
	Case            *contract.CaseCreateRequest `json:"case,omitempty"`
	CaseID          *uuid.UUID                  `json:"caseId,omitempty"`
	ExpectedVersion *int64                      `json:"expectedVersion,omitempty"`
}

func (h *Handler) EscalateTenantAlertToCase(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	alertID contract.AlertId,
	params contract.EscalateTenantAlertToCaseParams,
) {
	h.handleAlertCaseLink(
		w, r, tenantID, alertID, params.IfMatch,
		string(params.IdempotencyKey), false,
	)
}

func (h *Handler) LinkTenantAlertToExistingCase(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	alertID contract.AlertId,
	params contract.LinkTenantAlertToExistingCaseParams,
) {
	h.handleAlertCaseLink(
		w, r, tenantID, alertID, params.IfMatch,
		string(params.IdempotencyKey), true,
	)
}

func (h *Handler) handleAlertCaseLink(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	alertID contract.AlertId,
	ifMatch contract.IfMatch,
	parameterIdempotencyKey string,
	existingCaseOnly bool,
) {
	actor, expected, ok := h.ticketingMutationPrecondition(w, r, ifMatch)
	if !ok {
		return
	}
	idempotencyKey, err := requestIdempotencyKey(r)
	if err != nil || parameterIdempotencyKey != idempotencyKey {
		writeDomainError(w, r, applicationticketing.ErrInvalidInput)
		return
	}
	var body escalationRequestBody
	if err := decodeAuthorizationBody(r, &body, "application/json"); err != nil ||
		!bodyVersionMatches(body.ExpectedVersion, expected) || !body.RelationType.Valid() {
		writeDomainError(w, r, applicationticketing.ErrInvalidInput)
		return
	}
	input, createsCase, err := escalationInput(body, uuid.UUID(alertID), expected, idempotencyKey)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	if existingCaseOnly && createsCase {
		writeDomainError(w, r, applicationticketing.ErrInvalidInput)
		return
	}
	var result applicationticketing.EscalationResult
	if existingCaseOnly {
		result, err = h.ticketing.Link(r.Context(), actor, uuid.UUID(tenantID), input)
	} else {
		result, err = h.ticketing.Escalate(r.Context(), actor, uuid.UUID(tenantID), input)
	}
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	alert, alertErr := mapTicketView(result.Alert)
	caseProjection, caseErr := mapTicketView(result.Case)
	if alertErr != nil || caseErr != nil || !setVersionETag(w, int64(result.Alert.Record.Snapshot.Version())) {
		writeDomainError(w, r, applicationticketing.ErrUnavailable)
		return
	}
	links := make([]any, 0, len(result.Links))
	for _, link := range result.Links {
		links = append(links, mapLink(link.Link, applicationticketing.ProjectionOperator))
	}
	status := http.StatusOK
	if createsCase {
		status = http.StatusCreated
		caseID := uuid.UUID(result.Case.Record.Snapshot.ID().Bytes())
		w.Header().Set("Location", "/api/v1/tenants/"+uuid.UUID(tenantID).String()+"/cases/"+caseID.String())
	}
	writeSensitiveJSON(w, status, map[string]any{
		"alert": alert, "case": caseProjection, "links": links, "sideEffects": result.Effects,
	})
}

func (h *Handler) UnlinkTenantAlertFromCase(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	alertID contract.AlertId,
	params contract.UnlinkTenantAlertFromCaseParams,
) {
	actor, expected, ok := h.ticketingMutationPrecondition(w, r, params.IfMatch)
	if !ok {
		return
	}
	idempotencyKey, err := requestIdempotencyKey(r)
	if err != nil || string(params.IdempotencyKey) != idempotencyKey {
		writeDomainError(w, r, applicationticketing.ErrInvalidInput)
		return
	}
	var body contract.AlertCaseUnlinkRequest
	if err := decodeAuthorizationBody(r, &body, "application/json"); err != nil ||
		!bodyVersionMatches(int64(body.ExpectedVersion), expected) {
		writeDomainError(w, r, applicationticketing.ErrInvalidInput)
		return
	}
	receipt, err := h.ticketing.Unlink(
		r.Context(), actor, uuid.UUID(tenantID), uuid.UUID(alertID),
		applicationticketing.UnlinkInput{
			CaseID: body.CaseId, ExpectedVersion: expected,
			ExpectedCaseVersion: uint64(body.ExpectedCaseVersion),
			Reason:              string(body.Reason), IdempotencyKey: idempotencyKey,
		},
	)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	if !setVersionETag(w, int64(receipt.AlertVersion)) {
		writeDomainError(w, r, applicationticketing.ErrUnavailable)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set(idempotentReplayHeader, strconv.FormatBool(receipt.Replayed))
	writeSensitiveJSON(w, http.StatusOK, contract.AlertCaseUnlinkReceipt{
		TenantId: receipt.TenantID, AlertId: receipt.AlertID,
		CaseId: receipt.CaseID, LinkId: receipt.LinkID,
		PreviousAlertVersion: int64(receipt.PreviousAlertVersion),
		AlertVersion:         int64(receipt.AlertVersion),
		PreviousCaseVersion:  int64(receipt.PreviousCaseVersion),
		CaseVersion:          int64(receipt.CaseVersion),
		RetractedAt:          receipt.RetractedAt.UTC(), Replayed: receipt.Replayed,
	})
}

func escalationInput(body escalationRequestBody, pathAlertID uuid.UUID, expected uint64, idempotencyKey string) (applicationticketing.EscalationInput, bool, error) {
	input := applicationticketing.EscalationInput{
		PathAlertID: pathAlertID, ExpectedVersion: expected, Relation: string(body.RelationType),
		Reason: body.Reason, IdempotencyKey: idempotencyKey,
	}
	for _, source := range body.Sources {
		if source.ExpectedVersion < 1 {
			return applicationticketing.EscalationInput{}, false, applicationticketing.ErrInvalidInput
		}
		selection, err := escalationSelection(source.CopySelection)
		if err != nil {
			return applicationticketing.EscalationInput{}, false, err
		}
		input.Sources = append(input.Sources, applicationticketing.EscalationSourceInput{
			AlertID: source.AlertID, ExpectedVersion: uint64(source.ExpectedVersion), Selection: selection,
		})
	}
	switch body.Target.Mode {
	case "create_case":
		if body.Target.Case == nil || body.Target.CaseID != nil || body.Target.ExpectedVersion != nil ||
			!body.Target.Case.Severity.Valid() || !body.Target.Case.Priority.Valid() {
			return applicationticketing.EscalationInput{}, false, applicationticketing.ErrInvalidInput
		}
		created, err := createCaseInput(*body.Target.Case, idempotencyKey)
		if err != nil {
			return applicationticketing.EscalationInput{}, false, err
		}
		input.Target.NewCase = &created
		if err := applicationticketing.ValidateEscalationInput(input); err != nil {
			return applicationticketing.EscalationInput{}, false, err
		}
		return input, true, nil
	case "existing_case":
		if body.Target.Case != nil || body.Target.CaseID == nil || body.Target.ExpectedVersion == nil || *body.Target.ExpectedVersion < 1 {
			return applicationticketing.EscalationInput{}, false, applicationticketing.ErrInvalidInput
		}
		input.Target.ExistingCaseID = body.Target.CaseID
		input.Target.ExistingCaseVersion = uint64(*body.Target.ExpectedVersion)
		if err := applicationticketing.ValidateEscalationInput(input); err != nil {
			return applicationticketing.EscalationInput{}, false, err
		}
		return input, false, nil
	default:
		return applicationticketing.EscalationInput{}, false, applicationticketing.ErrInvalidInput
	}
}

func escalationSelection(body escalationCopySelectionBody) (applicationticketing.CopySelection, error) {
	selection := applicationticketing.CopySelection{ItemIDs: make(map[kernel.CopyField][]uuid.UUID)}
	if body.Fields != nil {
		for _, value := range *body.Fields {
			if !value.Valid() {
				return applicationticketing.CopySelection{}, applicationticketing.ErrInvalidInput
			}
			field, ok := copyField(string(value))
			if !ok {
				return applicationticketing.CopySelection{}, applicationticketing.ErrInvalidInput
			}
			selection.Fields = append(selection.Fields, field)
		}
	}
	if body.CustomFieldKeys != nil {
		for _, value := range *body.CustomFieldKeys {
			key, err := kernel.NewKey(value)
			if err != nil {
				return applicationticketing.CopySelection{}, applicationticketing.ErrInvalidInput
			}
			selection.CustomFields = append(selection.CustomFields, key)
		}
		if len(*body.CustomFieldKeys) > 0 {
			selection.Fields = append(selection.Fields, kernel.CopyCustomFields)
		}
	}
	copyIDs := func(field kernel.CopyField, values *[]uuid.UUID) {
		if values != nil && len(*values) > 0 {
			selection.ItemIDs[field] = slices.Clone(*values)
			selection.Fields = append(selection.Fields, field)
		}
	}
	copyIDs(kernel.CopyIOCs, body.IOCIDs)
	copyIDs(kernel.CopyAssets, body.AssetIDs)
	copyIDs(kernel.CopyAttachments, body.AttachmentIDs)
	copyIDs(kernel.CopyContacts, body.ContactIDs)
	if body.PublicCommentIDs != nil {
		selection.PublicCommentIDs = slices.Clone(*body.PublicCommentIDs)
		if len(*body.PublicCommentIDs) > 0 {
			selection.Fields = append(selection.Fields, kernel.CopyPublicComments)
		}
	}
	return selection, nil
}

func copyField(value string) (kernel.CopyField, bool) {
	switch value {
	case "title":
		return kernel.CopyTitle, true
	case "description":
		return kernel.CopyDescription, true
	case "severity":
		return kernel.CopySeverity, true
	case "priority":
		return kernel.CopyPriority, true
	case "category":
		return kernel.CopyCategory, true
	case "tags":
		return kernel.CopyTags, true
	case "custom_fields":
		return kernel.CopyCustomFields, true
	case "iocs":
		return kernel.CopyIOCs, true
	case "assets":
		return kernel.CopyAssets, true
	case "attachments":
		return kernel.CopyAttachments, true
	case "contacts":
		return kernel.CopyContacts, true
	case "public_comments":
		return kernel.CopyPublicComments, true
	default:
		return 0, false
	}
}
