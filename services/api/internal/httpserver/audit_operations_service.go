package httpserver

import (
	"context"
	"reflect"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/services/api/internal/auditoperations"
	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
)

// AuditOperationsService is the human-only audit export and retention
// boundary. Its concrete implementation repeats live authorization inside
// the guarded database ABI for every call, including status and download.
type AuditOperationsService interface {
	CreateTenantExport(context.Context, authentication.Session, uuid.UUID, auditoperations.CreateExportInput) (auditoperations.ExportMutationResult, error)
	CreatePlatformExport(context.Context, authentication.Session, auditoperations.CreateExportInput) (auditoperations.ExportMutationResult, error)
	GetTenantExport(context.Context, authentication.Session, uuid.UUID, uuid.UUID, authentication.EventContext) (auditoperations.ExportJob, error)
	GetPlatformExport(context.Context, authentication.Session, uuid.UUID, authentication.EventContext) (auditoperations.ExportJob, error)
	CancelTenantExport(context.Context, authentication.Session, uuid.UUID, auditoperations.CancelExportInput) (auditoperations.ExportMutationResult, error)
	CancelPlatformExport(context.Context, authentication.Session, auditoperations.CancelExportInput) (auditoperations.ExportMutationResult, error)
	DownloadTenantExport(context.Context, authentication.Session, uuid.UUID, uuid.UUID, authentication.EventContext) (auditoperations.Download, error)
	DownloadPlatformExport(context.Context, authentication.Session, uuid.UUID, authentication.EventContext) (auditoperations.Download, error)
	GetTenantRetention(context.Context, authentication.Session, uuid.UUID, authentication.EventContext) (auditoperations.RetentionState, error)
	GetPlatformRetention(context.Context, authentication.Session, authentication.EventContext) (auditoperations.RetentionState, error)
	UpdateTenantRetention(context.Context, authentication.Session, uuid.UUID, auditoperations.UpdateRetentionInput) (auditoperations.RetentionMutationResult, error)
	UpdatePlatformRetention(context.Context, authentication.Session, auditoperations.UpdateRetentionInput) (auditoperations.RetentionMutationResult, error)
	PlaceTenantLegalHold(context.Context, authentication.Session, uuid.UUID, auditoperations.PlaceLegalHoldInput) (auditoperations.LegalHoldMutationResult, error)
	PlacePlatformLegalHold(context.Context, authentication.Session, auditoperations.PlaceLegalHoldInput) (auditoperations.LegalHoldMutationResult, error)
	ReleaseTenantLegalHold(context.Context, authentication.Session, uuid.UUID, auditoperations.ReleaseLegalHoldInput) (auditoperations.LegalHoldMutationResult, error)
	ReleasePlatformLegalHold(context.Context, authentication.Session, auditoperations.ReleaseLegalHoldInput) (auditoperations.LegalHoldMutationResult, error)
}

type unavailableAuditOperationsService struct{}

func (unavailableAuditOperationsService) CreateTenantExport(context.Context, authentication.Session, uuid.UUID, auditoperations.CreateExportInput) (auditoperations.ExportMutationResult, error) {
	return auditoperations.ExportMutationResult{}, auditoperations.ErrUnavailable
}
func (unavailableAuditOperationsService) CreatePlatformExport(context.Context, authentication.Session, auditoperations.CreateExportInput) (auditoperations.ExportMutationResult, error) {
	return auditoperations.ExportMutationResult{}, auditoperations.ErrUnavailable
}
func (unavailableAuditOperationsService) GetTenantExport(context.Context, authentication.Session, uuid.UUID, uuid.UUID, authentication.EventContext) (auditoperations.ExportJob, error) {
	return auditoperations.ExportJob{}, auditoperations.ErrUnavailable
}
func (unavailableAuditOperationsService) GetPlatformExport(context.Context, authentication.Session, uuid.UUID, authentication.EventContext) (auditoperations.ExportJob, error) {
	return auditoperations.ExportJob{}, auditoperations.ErrUnavailable
}
func (unavailableAuditOperationsService) CancelTenantExport(context.Context, authentication.Session, uuid.UUID, auditoperations.CancelExportInput) (auditoperations.ExportMutationResult, error) {
	return auditoperations.ExportMutationResult{}, auditoperations.ErrUnavailable
}
func (unavailableAuditOperationsService) CancelPlatformExport(context.Context, authentication.Session, auditoperations.CancelExportInput) (auditoperations.ExportMutationResult, error) {
	return auditoperations.ExportMutationResult{}, auditoperations.ErrUnavailable
}
func (unavailableAuditOperationsService) DownloadTenantExport(context.Context, authentication.Session, uuid.UUID, uuid.UUID, authentication.EventContext) (auditoperations.Download, error) {
	return auditoperations.Download{}, auditoperations.ErrUnavailable
}
func (unavailableAuditOperationsService) DownloadPlatformExport(context.Context, authentication.Session, uuid.UUID, authentication.EventContext) (auditoperations.Download, error) {
	return auditoperations.Download{}, auditoperations.ErrUnavailable
}
func (unavailableAuditOperationsService) GetTenantRetention(context.Context, authentication.Session, uuid.UUID, authentication.EventContext) (auditoperations.RetentionState, error) {
	return auditoperations.RetentionState{}, auditoperations.ErrUnavailable
}
func (unavailableAuditOperationsService) GetPlatformRetention(context.Context, authentication.Session, authentication.EventContext) (auditoperations.RetentionState, error) {
	return auditoperations.RetentionState{}, auditoperations.ErrUnavailable
}
func (unavailableAuditOperationsService) UpdateTenantRetention(context.Context, authentication.Session, uuid.UUID, auditoperations.UpdateRetentionInput) (auditoperations.RetentionMutationResult, error) {
	return auditoperations.RetentionMutationResult{}, auditoperations.ErrUnavailable
}
func (unavailableAuditOperationsService) UpdatePlatformRetention(context.Context, authentication.Session, auditoperations.UpdateRetentionInput) (auditoperations.RetentionMutationResult, error) {
	return auditoperations.RetentionMutationResult{}, auditoperations.ErrUnavailable
}
func (unavailableAuditOperationsService) PlaceTenantLegalHold(context.Context, authentication.Session, uuid.UUID, auditoperations.PlaceLegalHoldInput) (auditoperations.LegalHoldMutationResult, error) {
	return auditoperations.LegalHoldMutationResult{}, auditoperations.ErrUnavailable
}
func (unavailableAuditOperationsService) PlacePlatformLegalHold(context.Context, authentication.Session, auditoperations.PlaceLegalHoldInput) (auditoperations.LegalHoldMutationResult, error) {
	return auditoperations.LegalHoldMutationResult{}, auditoperations.ErrUnavailable
}
func (unavailableAuditOperationsService) ReleaseTenantLegalHold(context.Context, authentication.Session, uuid.UUID, auditoperations.ReleaseLegalHoldInput) (auditoperations.LegalHoldMutationResult, error) {
	return auditoperations.LegalHoldMutationResult{}, auditoperations.ErrUnavailable
}
func (unavailableAuditOperationsService) ReleasePlatformLegalHold(context.Context, authentication.Session, auditoperations.ReleaseLegalHoldInput) (auditoperations.LegalHoldMutationResult, error) {
	return auditoperations.LegalHoldMutationResult{}, auditoperations.ErrUnavailable
}

func auditOperationsServiceIsNil(service AuditOperationsService) bool {
	if service == nil {
		return true
	}
	value := reflect.ValueOf(service)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

var _ AuditOperationsService = unavailableAuditOperationsService{}
