package httpserver

import (
	"context"
	"net/http"
	"strconv"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/dfir"
	"github.com/periapsis-im/periapsis/services/api/internal/contract"
	application "github.com/periapsis-im/periapsis/services/api/internal/dfir"
)

type dfirSharedResourceService interface {
	ChangeIndicatorLink(context.Context, application.Actor, uuid.UUID, application.SharedResourceLinkCommand) (application.MutationResult[kernel.Indicator], error)
	ChangeAssetLink(context.Context, application.Actor, uuid.UUID, application.SharedResourceLinkCommand) (application.MutationResult[kernel.Asset], error)
}

func (h *Handler) LinkTenantCaseDfirIndicator(w http.ResponseWriter, r *http.Request, tenantID contract.TenantId, rootID contract.CaseId, resourceID uuid.UUID, _ contract.LinkTenantCaseDfirIndicatorParams) {
	h.changeDfirSharedLink(w, r, uuid.UUID(tenantID), kernel.EntityCase, uuid.UUID(rootID), kernel.EntityIOC, resourceID, true)
}

func (h *Handler) UnlinkTenantCaseDfirIndicator(w http.ResponseWriter, r *http.Request, tenantID contract.TenantId, rootID contract.CaseId, resourceID uuid.UUID, _ contract.UnlinkTenantCaseDfirIndicatorParams) {
	h.changeDfirSharedLink(w, r, uuid.UUID(tenantID), kernel.EntityCase, uuid.UUID(rootID), kernel.EntityIOC, resourceID, false)
}

func (h *Handler) LinkTenantCaseDfirAsset(w http.ResponseWriter, r *http.Request, tenantID contract.TenantId, rootID contract.CaseId, resourceID uuid.UUID, _ contract.LinkTenantCaseDfirAssetParams) {
	h.changeDfirSharedLink(w, r, uuid.UUID(tenantID), kernel.EntityCase, uuid.UUID(rootID), kernel.EntityAsset, resourceID, true)
}

func (h *Handler) UnlinkTenantCaseDfirAsset(w http.ResponseWriter, r *http.Request, tenantID contract.TenantId, rootID contract.CaseId, resourceID uuid.UUID, _ contract.UnlinkTenantCaseDfirAssetParams) {
	h.changeDfirSharedLink(w, r, uuid.UUID(tenantID), kernel.EntityCase, uuid.UUID(rootID), kernel.EntityAsset, resourceID, false)
}

func (h *Handler) LinkTenantAlertDfirIndicator(w http.ResponseWriter, r *http.Request, tenantID contract.TenantId, rootID contract.AlertId, resourceID uuid.UUID, _ contract.LinkTenantAlertDfirIndicatorParams) {
	h.changeDfirSharedLink(w, r, uuid.UUID(tenantID), kernel.EntityAlert, uuid.UUID(rootID), kernel.EntityIOC, resourceID, true)
}

func (h *Handler) UnlinkTenantAlertDfirIndicator(w http.ResponseWriter, r *http.Request, tenantID contract.TenantId, rootID contract.AlertId, resourceID uuid.UUID, _ contract.UnlinkTenantAlertDfirIndicatorParams) {
	h.changeDfirSharedLink(w, r, uuid.UUID(tenantID), kernel.EntityAlert, uuid.UUID(rootID), kernel.EntityIOC, resourceID, false)
}

func (h *Handler) LinkTenantAlertDfirAsset(w http.ResponseWriter, r *http.Request, tenantID contract.TenantId, rootID contract.AlertId, resourceID uuid.UUID, _ contract.LinkTenantAlertDfirAssetParams) {
	h.changeDfirSharedLink(w, r, uuid.UUID(tenantID), kernel.EntityAlert, uuid.UUID(rootID), kernel.EntityAsset, resourceID, true)
}

func (h *Handler) UnlinkTenantAlertDfirAsset(w http.ResponseWriter, r *http.Request, tenantID contract.TenantId, rootID contract.AlertId, resourceID uuid.UUID, _ contract.UnlinkTenantAlertDfirAssetParams) {
	h.changeDfirSharedLink(w, r, uuid.UUID(tenantID), kernel.EntityAlert, uuid.UUID(rootID), kernel.EntityAsset, resourceID, false)
}

func (h *Handler) changeDfirSharedLink(w http.ResponseWriter, r *http.Request, tenant uuid.UUID, rootKind kernel.EntityKind, rootUUID uuid.UUID, resourceKind kernel.EntityKind, resourceUUID uuid.UUID, linked bool) {
	actor, audit, key, ok := h.dfirMutationContext(w, r, tenant)
	if !ok {
		return
	}
	var eventUUID uuid.UUID
	var expectedVersion int64
	if linked {
		var body contract.DfirSharedResourceLinkRequest
		if decodePhase4Body(r, &body) != nil {
			writeDomainError(w, r, application.ErrInvalidInput)
			return
		}
		eventUUID, expectedVersion = uuid.UUID(body.LinkId), int64(body.ExpectedVersion)
	} else {
		var body contract.DfirSharedResourceUnlinkRequest
		if decodePhase4Body(r, &body) != nil {
			writeDomainError(w, r, application.ErrInvalidInput)
			return
		}
		eventUUID, expectedVersion = uuid.UUID(body.UnlinkId), int64(body.ExpectedVersion)
	}
	if !dfirResourcePrecondition(w, r, expectedVersion) {
		return
	}
	rootID, rootErr := dfirEntityID(rootUUID)
	resourceID, resourceErr := dfirEntityID(resourceUUID)
	eventID, eventErr := dfirEntityID(eventUUID)
	if rootErr != nil || resourceErr != nil || eventErr != nil {
		writeDomainError(w, r, application.ErrInvalidInput)
		return
	}
	service, available := h.dfir.(dfirSharedResourceService)
	if !available {
		writeDomainError(w, r, application.ErrUnavailable)
		return
	}
	command := application.SharedResourceLinkCommand{
		RootKind: rootKind, RootID: rootID, ResourceID: resourceID, EventID: eventID,
		ExpectedVersion: uint64(expectedVersion), Linked: linked,
		Envelope: application.MutationEnvelope{IdempotencyKey: key, Audit: audit},
	}
	var mapped any
	var err error
	var replayed bool
	version := uint64(expectedVersion) + 1
	if resourceKind == kernel.EntityIOC {
		result, callErr := service.ChangeIndicatorLink(r.Context(), actor.dfir, tenant, command)
		if callErr != nil {
			writeDomainError(w, r, callErr)
			return
		}
		replayed = result.Replayed
		if rootKind == kernel.EntityCase {
			mapped, err = mapDfirIndicator(result.Resource, rootUUID, version)
		} else {
			mapped, err = mapDfirAlertIndicator(result.Resource, rootUUID, version)
		}
	} else {
		result, callErr := service.ChangeAssetLink(r.Context(), actor.dfir, tenant, command)
		if callErr != nil {
			writeDomainError(w, r, callErr)
			return
		}
		replayed = result.Replayed
		if rootKind == kernel.EntityCase {
			mapped, err = mapDfirAsset(result.Resource, rootUUID, version)
		} else {
			mapped, err = mapDfirAlertAsset(result.Resource, rootUUID, version)
		}
	}
	if err != nil || !setDfirResourceVersionETag(w, contract.DfirResourceVersion(version)) {
		writeDomainError(w, r, application.ErrUnavailable)
		return
	}
	w.Header().Set(idempotentReplayHeader, strconv.FormatBool(replayed))
	writeSensitiveJSON(w, http.StatusOK, mapped)
}
