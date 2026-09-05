package dfir

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/dfir"
)

var alertInvestigationReadCapabilities = [...]Capability{
	CapabilityEvidenceRead,
	CapabilityTaskRead,
	CapabilityRelationshipRead,
}

type AlertInvestigationService struct {
	repository AlertInvestigationRepository
	bucket     string
	clock      func() time.Time
}

type AlertInvestigationServiceConfig struct {
	Bucket string
	Clock  func() time.Time
}

type alertCallbackCapture[T any] struct {
	mutex sync.Mutex
	calls int
	value T
}

func (capture *alertCallbackCapture[T]) begin() {
	capture.mutex.Lock()
	defer capture.mutex.Unlock()
	capture.calls++
}

func (capture *alertCallbackCapture[T]) complete(value T) {
	capture.mutex.Lock()
	defer capture.mutex.Unlock()
	capture.value = value
}

func (capture *alertCallbackCapture[T]) snapshot() (T, int) {
	capture.mutex.Lock()
	defer capture.mutex.Unlock()
	return capture.value, capture.calls
}

func NewAlertInvestigationService(
	repository AlertInvestigationRepository,
	config AlertInvestigationServiceConfig,
) (*AlertInvestigationService, error) {
	if repository == nil || !validObjectBucket(config.Bucket) {
		return nil, errors.New("complete Alert DFIR dependencies and valid storage configuration are required")
	}
	if config.Clock == nil {
		config.Clock = time.Now
	}
	return &AlertInvestigationService{repository: repository, bucket: config.Bucket, clock: config.Clock}, nil
}

func (service *AlertInvestigationService) Workspace(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	alertID kernel.EntityID,
) (AlertInvestigationWorkspace, error) {
	if err := initialAlertInvestigationContext(ctx); err != nil {
		return AlertInvestigationWorkspace{}, err
	}
	if !validActor(actor, tenantID) || actor.Kind != PrincipalHuman || alertID == (kernel.EntityID{}) {
		return AlertInvestigationWorkspace{}, ErrForbidden
	}
	if _, _, err := actorEntities(actor); err != nil {
		return AlertInvestigationWorkspace{}, ErrForbidden
	}
	accesses := make(WorkspaceAccess, len(alertInvestigationReadCapabilities))
	for _, capability := range alertInvestigationReadCapabilities {
		access, err := service.resolveAccess(ctx, actor, tenantID, alertID, capability, false)
		if err != nil {
			return AlertInvestigationWorkspace{}, err
		}
		accesses[capability] = access
	}
	if err := ctx.Err(); err != nil {
		return AlertInvestigationWorkspace{}, err
	}
	workspace, err := service.repository.LoadAlertInvestigationWorkspace(ctx, actor, tenantID, alertID, accesses)
	if err != nil {
		return AlertInvestigationWorkspace{}, repositoryError(err)
	}
	if err := ctx.Err(); err != nil {
		return AlertInvestigationWorkspace{}, err
	}
	if !validAlertInvestigationWorkspace(workspace, tenantID, alertID) {
		return AlertInvestigationWorkspace{}, ErrUnavailable
	}
	workspace.Evidence = slices.Clone(workspace.Evidence)
	workspace.Tasks = slices.Clone(workspace.Tasks)
	workspace.Relationships = slices.Clone(workspace.Relationships)
	return workspace, nil
}

func (service *AlertInvestigationService) authorizeMutation(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	alertID kernel.EntityID,
	capability Capability,
	envelope MutationEnvelope,
) (Access, kernel.EntityID, error) {
	if err := initialAlertInvestigationContext(ctx); err != nil {
		return Access{}, kernel.EntityID{}, err
	}
	if !validActor(actor, tenantID) || actor.Kind != PrincipalHuman || alertID == (kernel.EntityID{}) {
		return Access{}, kernel.EntityID{}, ErrForbidden
	}
	if !validEnvelope(envelope) || !validAlertAuditText(envelope.Audit.UserAgent) ||
		envelope.Audit.AuthenticationMethod != actor.AuthenticationMethod {
		return Access{}, kernel.EntityID{}, ErrInvalidInput
	}
	_, actorID, err := actorEntities(actor)
	if err != nil {
		return Access{}, kernel.EntityID{}, ErrForbidden
	}
	access, err := service.resolveAccess(ctx, actor, tenantID, alertID, capability, true)
	if err != nil {
		return Access{}, kernel.EntityID{}, err
	}
	return access, actorID, nil
}

func (service *AlertInvestigationService) resolveAccess(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	alertID kernel.EntityID,
	capability Capability,
	manage bool,
) (Access, error) {
	access, err := service.repository.ResolveAlertAccess(
		ctx, actor, tenantID, capability, AlertResourceScope{AlertID: alertID},
	)
	if err != nil {
		return Access{}, repositoryError(err)
	}
	if err := ctx.Err(); err != nil {
		return Access{}, err
	}
	if !validAccess(actor, access, manage) || access.Audience != kernel.AudienceOperator {
		return Access{}, ErrForbidden
	}
	return access, nil
}

func alertActorUserEntity(actor Actor) (kernel.EntityID, error) {
	identifier, err := kernel.NewEntityID([16]byte(actor.UserID))
	if err != nil {
		return kernel.EntityID{}, ErrForbidden
	}
	return identifier, nil
}

func initialAlertInvestigationContext(ctx context.Context) error {
	if ctx == nil {
		return ErrInvalidInput
	}
	return ctx.Err()
}

func (service *AlertInvestigationService) currentTime() (time.Time, error) {
	now := service.clock().UTC().Truncate(time.Microsecond)
	if !validAlertInstant(now) {
		return time.Time{}, ErrUnavailable
	}
	return now, nil
}

func validAlertInvestigationWorkspace(
	workspace AlertInvestigationWorkspace,
	tenantID uuid.UUID,
	alertID kernel.EntityID,
) bool {
	if len(workspace.Evidence) > maximumWorkspaceResources || len(workspace.Tasks) > maximumWorkspaceResources ||
		len(workspace.Relationships) > maximumWorkspaceRelationships {
		return false
	}
	tenant, err := kernel.NewEntityID([16]byte(tenantID))
	if err != nil {
		return false
	}
	seen := make(map[kernel.EntityID]struct{}, maximumWorkspaceResources)
	for _, evidence := range workspace.Evidence {
		if !validAlertEvidenceProjection(evidence, tenant, alertID, evidence.ID()) ||
			!uniqueWorkspaceID(seen, evidence.ID()) {
			return false
		}
	}
	clear(seen)
	for _, task := range workspace.Tasks {
		if task.TenantID() != tenant || task.AlertID() != alertID || task.Version() == 0 ||
			!validAlertTaskProjection(task) || !uniqueWorkspaceID(seen, task.ID()) {
			return false
		}
	}
	clear(seen)
	for _, relationship := range workspace.Relationships {
		if relationship.TenantID() != tenant || relationship.AlertID() != alertID ||
			!validAlertRelationshipProjection(relationship) || !uniqueWorkspaceID(seen, relationship.ID()) {
			return false
		}
	}
	return true
}

func validAlertTaskProjection(task kernel.AlertTask) bool {
	restored, err := kernel.NewAlertTask(task.Snapshot())
	return err == nil && sameFingerprint(alertTaskFingerprint(restored, 0), alertTaskFingerprint(task, 0))
}

func validAlertRelationshipProjection(relationship kernel.AlertRelationship) bool {
	restored, err := kernel.NewAlertRelationship(relationship.Snapshot())
	return err == nil && sameFingerprint(
		alertRelationshipFingerprint(restored, 0), alertRelationshipFingerprint(relationship, 0),
	)
}

func validAlertMutationVersion(expected uint64) bool {
	return expected > 0 && expected < kernel.MaximumAlertResourceVersion
}

func validAlertAuditText(value string) bool {
	return validAlertSingleLineText(value, 1_024, true)
}

func validAlertSingleLineText(value string, maximum int, optional bool) bool {
	if value == "" {
		return optional
	}
	if len(value) > maximum || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) || character == '\u2028' || character == '\u2029' ||
			character == '\u200e' || character == '\u200f' ||
			character >= '\u202a' && character <= '\u202e' ||
			character >= '\u2066' && character <= '\u2069' {
			return false
		}
	}
	return true
}

func validAlertInstant(value time.Time) bool {
	if value.IsZero() || value.Location() != time.UTC || value.Nanosecond()%1_000 != 0 {
		return false
	}
	_, err := value.MarshalJSON()
	return err == nil
}

func validOptionalAlertInstant(value *time.Time) bool {
	return value == nil || validAlertInstant(*value)
}

func alertInvestigationMutationError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return err
	case errors.Is(err, ErrInvalidInput), errors.Is(err, ErrForbidden), errors.Is(err, ErrNotFound),
		errors.Is(err, ErrConflict), errors.Is(err, ErrPreconditionFailed), errors.Is(err, ErrUnavailable):
		return err
	case errors.Is(err, kernel.ErrEvidenceConflict), errors.Is(err, kernel.ErrTaskConflict),
		errors.Is(err, kernel.ErrRelationshipConflict):
		return ErrPreconditionFailed
	case errors.Is(err, kernel.ErrEvidenceRetention):
		return ErrConflict
	case errors.Is(err, kernel.ErrInvalidEvidence), errors.Is(err, kernel.ErrInvalidTask),
		errors.Is(err, kernel.ErrInvalidRelationship):
		return ErrInvalidInput
	default:
		return repositoryError(err)
	}
}
