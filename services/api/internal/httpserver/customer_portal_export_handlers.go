package httpserver

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/google/uuid"

	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
	"github.com/periapsis-im/periapsis/services/api/internal/contract"
	application "github.com/periapsis-im/periapsis/services/api/internal/ticketing"
)

func (h *Handler) ExportCustomerPortalAlert(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	alertID contract.AlertId,
) {
	h.exportCustomerPortalTicket(w, r, uuid.UUID(tenantID), kernel.AggregateAlert, uuid.UUID(alertID))
}

func (h *Handler) ExportCustomerPortalCase(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	caseID contract.CaseId,
) {
	h.exportCustomerPortalTicket(w, r, uuid.UUID(tenantID), kernel.AggregateCase, uuid.UUID(caseID))
}

func (h *Handler) exportCustomerPortalTicket(
	w http.ResponseWriter,
	r *http.Request,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	resourceID uuid.UUID,
) {
	w.Header().Set("Cache-Control", "no-store")
	actor, ok := h.ticketingReadActor(w, r)
	if !ok {
		return
	}
	projection, err := h.ticketing.ExportPortal(r.Context(), actor, tenantID, kind, resourceID)
	if err != nil {
		writeCustomerPortalExportError(w, r, err)
		return
	}
	if err := writeCustomerPortalExport(w, kind, projection); err != nil {
		writeCustomerPortalExportError(w, r, err)
	}
}

func writeCustomerPortalExport(
	w http.ResponseWriter,
	kind kernel.AggregateKind,
	projection application.CustomerPortalExport,
) error {
	if projection.Kind != kind {
		return application.ErrUnavailable
	}
	payload, err := application.RenderCustomerPortalCSV(projection)
	if err != nil {
		return err
	}
	var filename string
	switch kind {
	case kernel.AggregateAlert:
		filename = "periapsis-customer-alert.csv"
	case kernel.AggregateCase:
		filename = "periapsis-customer-case.csv"
	default:
		return application.ErrUnavailable
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	w.Header().Set("Content-Length", strconv.Itoa(len(payload)))
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(payload)
	return nil
}

func writeCustomerPortalExportError(w http.ResponseWriter, r *http.Request, err error) {
	w.Header().Set("Cache-Control", "no-store")
	if errors.Is(err, application.ErrExportLimit) {
		writeProblem(
			w, r, http.StatusRequestEntityTooLarge, "export_too_large", "Export too large",
			"The customer-safe export exceeds the synchronous download limit.",
		)
		return
	}
	writeDomainError(w, r, err)
}
