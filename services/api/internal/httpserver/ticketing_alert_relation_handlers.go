package httpserver

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/google/uuid"
	"github.com/periapsis-im/periapsis/services/api/internal/contract"
	applicationticketing "github.com/periapsis-im/periapsis/services/api/internal/ticketing"
)

func (h *Handler) ListTenantAlertRelations(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	alertID contract.AlertId,
	params contract.ListTenantAlertRelationsParams,
) {
	actor, ok := h.ticketingReadActor(w, r)
	if !ok {
		return
	}
	page, err := h.ticketing.AlertRelations(
		r.Context(), actor, uuid.UUID(tenantID), uuid.UUID(alertID),
		cursorPageInput(params.After, params.Limit),
	)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	mapped, err := mapAlertRelationPage(page)
	if err != nil {
		writeDomainError(w, r, applicationticketing.ErrUnavailable)
		return
	}
	writeSensitiveJSON(w, http.StatusOK, mapped)
}

func (h *Handler) CreateTenantAlertRelation(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	alertID contract.AlertId,
	params contract.CreateTenantAlertRelationParams,
) {
	actor, expected, ok := h.ticketingMutationPrecondition(w, r, params.IfMatch)
	if !ok {
		return
	}
	key, err := requestIdempotencyKey(r)
	if err != nil || string(params.IdempotencyKey) != key {
		writeDomainError(w, r, applicationticketing.ErrInvalidInput)
		return
	}
	var body contract.AlertRelationCreateRequest
	if err := decodeAuthorizationBody(r, &body, "application/json"); err != nil ||
		!bodyVersionMatches(int64(body.ExpectedVersion), expected) ||
		body.ExpectedTargetVersion < 1 || !body.RelationType.Valid() {
		writeDomainError(w, r, applicationticketing.ErrInvalidInput)
		return
	}
	receipt, err := h.ticketing.CreateAlertRelation(
		r.Context(), actor, uuid.UUID(tenantID), uuid.UUID(alertID),
		applicationticketing.AlertRelationCreateInput{
			TargetAlertID:         body.TargetAlertId,
			RelationType:          applicationticketing.AlertRelationType(body.RelationType),
			ExpectedVersion:       expected,
			ExpectedTargetVersion: uint64(body.ExpectedTargetVersion),
			Reason:                string(body.Reason),
			IdempotencyKey:        key,
		},
	)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	writeAlertRelationReceipt(w, r, receipt)
}

func (h *Handler) RetractTenantAlertRelation(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	alertID contract.AlertId,
	relationID contract.AlertRelationId,
	params contract.RetractTenantAlertRelationParams,
) {
	actor, expected, ok := h.ticketingMutationPrecondition(w, r, params.IfMatch)
	if !ok {
		return
	}
	key, err := requestIdempotencyKey(r)
	if err != nil || string(params.IdempotencyKey) != key {
		writeDomainError(w, r, applicationticketing.ErrInvalidInput)
		return
	}
	var body contract.AlertRelationRetractionRequest
	if err := decodeAuthorizationBody(r, &body, "application/json"); err != nil ||
		!bodyVersionMatches(int64(body.ExpectedVersion), expected) ||
		body.ExpectedRelatedAlertVersion < 1 {
		writeDomainError(w, r, applicationticketing.ErrInvalidInput)
		return
	}
	receipt, err := h.ticketing.RetractAlertRelation(
		r.Context(), actor, uuid.UUID(tenantID), uuid.UUID(alertID), uuid.UUID(relationID),
		applicationticketing.AlertRelationRetractionInput{
			RelatedAlertID:              body.RelatedAlertId,
			ExpectedVersion:             expected,
			ExpectedRelatedAlertVersion: uint64(body.ExpectedRelatedAlertVersion),
			Reason:                      string(body.Reason),
			IdempotencyKey:              key,
		},
	)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	writeAlertRelationReceipt(w, r, receipt)
}

func writeAlertRelationReceipt(
	w http.ResponseWriter,
	r *http.Request,
	receipt applicationticketing.AlertRelationMutationReceipt,
) {
	if !setVersionETag(w, int64(receipt.AlertVersion)) {
		writeDomainError(w, r, applicationticketing.ErrUnavailable)
		return
	}
	relationType := contract.AlertRelationType(receipt.RelationType)
	if !relationType.Valid() {
		writeDomainError(w, r, applicationticketing.ErrUnavailable)
		return
	}
	w.Header().Set(idempotentReplayHeader, strconv.FormatBool(receipt.Replayed))
	writeSensitiveJSON(w, http.StatusOK, contract.AlertRelationMutationReceipt{
		TenantId: receipt.TenantID, AlertId: receipt.AlertID,
		RelatedAlertId: receipt.RelatedAlertID, RelationId: receipt.RelationID,
		RelationType:         relationType,
		PreviousAlertVersion: int64(receipt.PreviousAlertVersion), AlertVersion: int64(receipt.AlertVersion),
		PreviousRelatedAlertVersion: int64(receipt.PreviousRelatedAlertVersion),
		RelatedAlertVersion:         int64(receipt.RelatedAlertVersion),
		OccurredAt:                  receipt.OccurredAt.UTC(), Replayed: receipt.Replayed,
	})
}

func mapAlertRelationPage(page applicationticketing.AlertRelationPage) (contract.AlertRelationList, error) {
	items := make([]contract.AlertRelation, len(page.Items))
	for index, item := range page.Items {
		mapped, err := mapAlertRelation(item)
		if err != nil {
			return contract.AlertRelationList{}, err
		}
		items[index] = mapped
	}
	return contract.AlertRelationList{Items: items, NextCursor: page.NextCursor}, nil
}

func mapAlertRelation(record applicationticketing.AlertRelationRecord) (contract.AlertRelation, error) {
	relationType := contract.AlertRelationType(record.Relation.Type)
	direction := contract.AlertRelationDirection(record.Direction)
	status := contract.AlertRelationStatusActive
	if !relationType.Valid() || !direction.Valid() {
		return contract.AlertRelation{}, errors.New("invalid Alert relation enum")
	}
	result := contract.AlertRelation{
		Id: record.Relation.ID, TenantId: record.Relation.TenantID,
		SourceAlertId: record.Relation.SourceAlertID, TargetAlertId: record.Relation.TargetAlertID,
		RelationType: relationType, Direction: direction, Status: status,
		Reason:                contract.CommandReason(record.Relation.Reason),
		PreviousSourceVersion: int64(record.Relation.PreviousSourceVersion),
		SourceVersion:         int64(record.Relation.SourceVersion),
		PreviousTargetVersion: int64(record.Relation.PreviousTargetVersion),
		TargetVersion:         int64(record.Relation.TargetVersion),
		LinkedAt:              record.Relation.LinkedAt.UTC(),
		RelatedAlert: contract.RelatedAlertSummary{
			Id: uuid.UUID(record.Related.Snapshot.ID().Bytes()), Number: record.Related.Number,
			Title: record.Related.Title, Severity: contract.AlertSeverity(record.Related.Severity),
			StateKey: contract.WorkflowStateKey(record.Related.Snapshot.State().String()),
			Version:  int64(record.Related.Snapshot.Version()), UpdatedAt: record.Related.UpdatedAt.UTC(),
		},
	}
	if !result.RelatedAlert.Severity.Valid() {
		return contract.AlertRelation{}, errors.New("invalid related Alert severity")
	}
	if retraction := record.Relation.Retraction; retraction != nil {
		result.Status = contract.AlertRelationStatusRetracted
		result.Retraction = &contract.AlertRelationRetraction{
			Reason:                contract.CommandReason(retraction.Reason),
			PreviousSourceVersion: int64(retraction.PreviousSourceVersion),
			SourceVersion:         int64(retraction.SourceVersion),
			PreviousTargetVersion: int64(retraction.PreviousTargetVersion),
			TargetVersion:         int64(retraction.TargetVersion),
			RetractedAt:           retraction.RetractedAt.UTC(),
		}
	}
	return result, nil
}
