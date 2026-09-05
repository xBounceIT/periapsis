package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/mfa"
	"github.com/periapsis-im/periapsis/services/api/internal/mfapolicy"
	"github.com/periapsis-im/periapsis/services/api/internal/postgres/dbsql"
)

const maximumMFAPolicyProjectionBytes = 128 * 1024
const mfaPolicyInstantLayout = "2006-01-02T15:04:05.000Z"

// MFAPolicyRepository adapts the protected MFA-policy JSON ABI. Every method
// installs transaction-local actor (and tenant, when applicable) context; a
// mutation result is decoded and validated by the service callback before the
// transaction containing the policy, audit event, and replay receipt commits.
type MFAPolicyRepository struct {
	begin transactionBeginner
}

var _ mfapolicy.Repository = (*MFAPolicyRepository)(nil)

func NewMFAPolicyRepository(pool *pgxpool.Pool) *MFAPolicyRepository {
	return &MFAPolicyRepository{begin: poolTransactionBeginner(pool)}
}

func (repository *MFAPolicyRepository) ListPlatform(
	ctx context.Context,
	params mfapolicy.ListParams,
) ([]mfa.PolicyDocument, error) {
	return withMFAPolicyTransaction(ctx, repository, params.SessionParams, uuid.Nil,
		func(queries *dbsql.Queries) ([]mfa.PolicyDocument, error) {
			documents, err := queries.ListPlatformMFAPolicies(ctx, dbsql.ListPlatformMFAPoliciesParams{
				SessionID:            toDatabaseUUID(params.SessionID),
				AuthenticationMethod: params.AuthenticationMethod,
				AfterPolicyID:        mfaPolicyCursorID(params.After),
				AfterRevision:        mfaPolicyCursorRevision(params.After),
				PageSize:             params.Limit,
				IncludeRetired:       params.IncludeRetired,
			})
			if err != nil {
				return nil, err
			}
			return decodeMFAPolicyDocuments(documents, uuid.Nil)
		})
}

func (repository *MFAPolicyRepository) ListTenant(
	ctx context.Context,
	params mfapolicy.ListParams,
) ([]mfa.PolicyDocument, error) {
	return withMFAPolicyTransaction(ctx, repository, params.SessionParams, params.TenantID,
		func(queries *dbsql.Queries) ([]mfa.PolicyDocument, error) {
			documents, err := queries.ListTenantMFAPolicies(ctx, dbsql.ListTenantMFAPoliciesParams{
				SessionID:            toDatabaseUUID(params.SessionID),
				TenantID:             toDatabaseUUID(params.TenantID),
				AuthenticationMethod: params.AuthenticationMethod,
				AfterPolicyID:        mfaPolicyCursorID(params.After),
				AfterRevision:        mfaPolicyCursorRevision(params.After),
				PageSize:             params.Limit,
				IncludeRetired:       params.IncludeRetired,
			})
			if err != nil {
				return nil, err
			}
			return decodeMFAPolicyDocuments(documents, params.TenantID)
		})
}

func (repository *MFAPolicyRepository) GetPlatform(
	ctx context.Context,
	params mfapolicy.GetParams,
) (mfa.PolicyDocument, error) {
	return withMFAPolicyTransaction(ctx, repository, params.SessionParams, uuid.Nil,
		func(queries *dbsql.Queries) (mfa.PolicyDocument, error) {
			document, err := queries.GetPlatformMFAPolicy(ctx, dbsql.GetPlatformMFAPolicyParams{
				SessionID:            toDatabaseUUID(params.SessionID),
				AuthenticationMethod: params.AuthenticationMethod,
				PolicyID:             toDatabaseUUID(params.PolicyID),
				Revision:             optionalMFAPolicyRevision(params.Revision),
			})
			if err != nil {
				return mfa.PolicyDocument{}, err
			}
			return decodeMFAPolicyDocument(document, uuid.Nil)
		})
}

func (repository *MFAPolicyRepository) GetTenant(
	ctx context.Context,
	params mfapolicy.GetParams,
) (mfa.PolicyDocument, error) {
	return withMFAPolicyTransaction(ctx, repository, params.SessionParams, params.TenantID,
		func(queries *dbsql.Queries) (mfa.PolicyDocument, error) {
			document, err := queries.GetTenantMFAPolicy(ctx, dbsql.GetTenantMFAPolicyParams{
				SessionID:            toDatabaseUUID(params.SessionID),
				TenantID:             toDatabaseUUID(params.TenantID),
				AuthenticationMethod: params.AuthenticationMethod,
				PolicyID:             toDatabaseUUID(params.PolicyID),
				Revision:             optionalMFAPolicyRevision(params.Revision),
			})
			if err != nil {
				return mfa.PolicyDocument{}, err
			}
			return decodeMFAPolicyDocument(document, params.TenantID)
		})
}

func (repository *MFAPolicyRepository) SimulatePlatform(
	ctx context.Context,
	params mfapolicy.SimulationParams,
) (mfa.PolicySimulation, error) {
	request, err := marshalMFAPolicySimulation(params, false)
	if err != nil {
		return mfa.PolicySimulation{}, mfapolicy.ErrInvalidInput
	}
	return withMFAPolicyTransaction(ctx, repository, params.SessionParams, uuid.Nil,
		func(queries *dbsql.Queries) (mfa.PolicySimulation, error) {
			document, queryErr := queries.SimulatePlatformMFAPolicyChange(
				ctx, dbsql.SimulatePlatformMFAPolicyChangeParams{
					SessionID:            toDatabaseUUID(params.SessionID),
					AuthenticationMethod: params.AuthenticationMethod,
					Request:              request,
				},
			)
			if queryErr != nil {
				return mfa.PolicySimulation{}, queryErr
			}
			return decodeMFAPolicySimulation(document, uuid.Nil)
		})
}

func (repository *MFAPolicyRepository) SimulateTenant(
	ctx context.Context,
	params mfapolicy.SimulationParams,
) (mfa.PolicySimulation, error) {
	request, err := marshalMFAPolicySimulation(params, true)
	if err != nil {
		return mfa.PolicySimulation{}, mfapolicy.ErrInvalidInput
	}
	return withMFAPolicyTransaction(ctx, repository, params.SessionParams, params.TenantID,
		func(queries *dbsql.Queries) (mfa.PolicySimulation, error) {
			document, queryErr := queries.SimulateTenantMFAPolicyChange(
				ctx, dbsql.SimulateTenantMFAPolicyChangeParams{
					SessionID:            toDatabaseUUID(params.SessionID),
					TenantID:             toDatabaseUUID(params.TenantID),
					AuthenticationMethod: params.AuthenticationMethod,
					Request:              request,
				},
			)
			if queryErr != nil {
				return mfa.PolicySimulation{}, queryErr
			}
			return decodeMFAPolicySimulation(document, params.TenantID)
		})
}

func (repository *MFAPolicyRepository) PublishPlatform(
	ctx context.Context,
	params mfapolicy.PublishParams,
) (mfapolicy.MutationResult, error) {
	command, err := marshalMFAPolicyPublish(params)
	if err != nil || params.ValidateResult == nil {
		return mfapolicy.MutationResult{}, mfapolicy.ErrInvalidInput
	}
	return mutateMFAPolicy(ctx, repository, params.SessionParams, uuid.Nil, params.ValidateResult,
		func(queries *dbsql.Queries) ([]byte, error) {
			return queries.PublishPlatformMFAPolicy(ctx, dbsql.PublishPlatformMFAPolicyParams{
				SessionID:            toDatabaseUUID(params.SessionID),
				AuthenticationMethod: params.AuthenticationMethod,
				Command:              command,
			})
		})
}

func (repository *MFAPolicyRepository) PublishTenant(
	ctx context.Context,
	params mfapolicy.PublishParams,
) (mfapolicy.MutationResult, error) {
	command, err := marshalMFAPolicyPublish(params)
	if err != nil || params.ValidateResult == nil {
		return mfapolicy.MutationResult{}, mfapolicy.ErrInvalidInput
	}
	return mutateMFAPolicy(ctx, repository, params.SessionParams, params.TenantID, params.ValidateResult,
		func(queries *dbsql.Queries) ([]byte, error) {
			return queries.PublishTenantMFAPolicy(ctx, dbsql.PublishTenantMFAPolicyParams{
				SessionID:            toDatabaseUUID(params.SessionID),
				TenantID:             toDatabaseUUID(params.TenantID),
				AuthenticationMethod: params.AuthenticationMethod,
				Command:              command,
			})
		})
}

func (repository *MFAPolicyRepository) RetirePlatform(
	ctx context.Context,
	params mfapolicy.RetireParams,
) (mfapolicy.MutationResult, error) {
	command, err := marshalMFAPolicyRetire(params)
	if err != nil || params.ValidateResult == nil {
		return mfapolicy.MutationResult{}, mfapolicy.ErrInvalidInput
	}
	return mutateMFAPolicy(ctx, repository, params.SessionParams, uuid.Nil, params.ValidateResult,
		func(queries *dbsql.Queries) ([]byte, error) {
			return queries.RetirePlatformMFAPolicy(ctx, dbsql.RetirePlatformMFAPolicyParams{
				SessionID:            toDatabaseUUID(params.SessionID),
				AuthenticationMethod: params.AuthenticationMethod,
				Command:              command,
			})
		})
}

func (repository *MFAPolicyRepository) RetireTenant(
	ctx context.Context,
	params mfapolicy.RetireParams,
) (mfapolicy.MutationResult, error) {
	command, err := marshalMFAPolicyRetire(params)
	if err != nil || params.ValidateResult == nil {
		return mfapolicy.MutationResult{}, mfapolicy.ErrInvalidInput
	}
	return mutateMFAPolicy(ctx, repository, params.SessionParams, params.TenantID, params.ValidateResult,
		func(queries *dbsql.Queries) ([]byte, error) {
			return queries.RetireTenantMFAPolicy(ctx, dbsql.RetireTenantMFAPolicyParams{
				SessionID:            toDatabaseUUID(params.SessionID),
				TenantID:             toDatabaseUUID(params.TenantID),
				AuthenticationMethod: params.AuthenticationMethod,
				Command:              command,
			})
		})
}

func mutateMFAPolicy(
	ctx context.Context,
	repository *MFAPolicyRepository,
	session mfapolicy.SessionParams,
	tenantID uuid.UUID,
	validate mfapolicy.MutationResultValidator,
	query func(*dbsql.Queries) ([]byte, error),
) (mfapolicy.MutationResult, error) {
	return withMFAPolicyTransaction(ctx, repository, session, tenantID,
		func(queries *dbsql.Queries) (mfapolicy.MutationResult, error) {
			document, err := query(queries)
			if err != nil {
				return mfapolicy.MutationResult{}, err
			}
			result, err := decodeMFAPolicyMutation(document, tenantID)
			if err != nil {
				return mfapolicy.MutationResult{}, err
			}
			validated, err := validate(result)
			if err != nil {
				return mfapolicy.MutationResult{}, mfapolicy.ErrUnavailable
			}
			return validated, nil
		})
}

func withMFAPolicyTransaction[T any](
	ctx context.Context,
	repository *MFAPolicyRepository,
	session mfapolicy.SessionParams,
	tenantID uuid.UUID,
	work func(*dbsql.Queries) (T, error),
) (T, error) {
	var zero T
	if ctx == nil || repository == nil || repository.begin == nil || work == nil ||
		!mfaPolicyUUIDv7(session.ActorID) || !mfaPolicyUUIDv7(session.SessionID) ||
		!validMFAPolicyAuthenticationMethod(session.AuthenticationMethod) ||
		tenantID != uuid.Nil && !mfaPolicyUUIDv7(tenantID) {
		return zero, mfapolicy.ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	result, err := withinTransaction(ctx, repository.begin, func(tx databaseTransaction) (T, error) {
		queries := dbsql.New(tx)
		if tenantID == uuid.Nil {
			if setErr := setUserContext(ctx, queries, session.ActorID); setErr != nil {
				return zero, setErr
			}
		} else {
			installed, setErr := queries.SetTenantContext(ctx, dbsql.SetTenantContextParams{
				TenantID: toDatabaseUUID(tenantID), UserID: toDatabaseUUID(session.ActorID),
			})
			if setErr != nil || installed.TenantID != tenantID.String() ||
				installed.UserID != session.ActorID.String() {
				if setErr != nil {
					return zero, setErr
				}
				return zero, mfapolicy.ErrUnavailable
			}
		}
		return work(queries)
	})
	if err != nil {
		return zero, mapMFAPolicyDatabaseError(err)
	}
	return result, nil
}

func mapMFAPolicyDatabaseError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, mfapolicy.ErrInvalidInput) || errors.Is(err, mfapolicy.ErrForbidden) ||
		errors.Is(err, mfapolicy.ErrNotFound) || errors.Is(err, mfapolicy.ErrConflict) ||
		errors.Is(err, mfapolicy.ErrRecoveryUnsafe) ||
		errors.Is(err, mfapolicy.ErrPreconditionFailed) || errors.Is(err, mfapolicy.ErrUnavailable) {
		return err
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return mfapolicy.ErrNotFound
	}
	var databaseError *pgconn.PgError
	if !errors.As(err, &databaseError) {
		return mfapolicy.ErrUnavailable
	}
	if databaseError.Code == "40001" {
		if databaseError.Message == "MFA policy create revision conflict" ||
			databaseError.Message == "MFA policy simulation create conflict" {
			return mfapolicy.ErrConflict
		}
		return mfapolicy.ErrPreconditionFailed
	}
	if databaseError.Code == "55000" &&
		databaseError.Message == "MFA policy would violate direct recovery safety" {
		return mfapolicy.ErrRecoveryUnsafe
	}
	switch databaseError.Code {
	case "42501":
		return mfapolicy.ErrForbidden
	case "P0002":
		return mfapolicy.ErrNotFound
	case "55000", "22003", "23505":
		return mfapolicy.ErrConflict
	case "22023", "23514":
		return mfapolicy.ErrInvalidInput
	default:
		return mfapolicy.ErrUnavailable
	}
}

type mfaPolicyTargetWire struct {
	Scope           string     `json:"scope"`
	TenantID        *uuid.UUID `json:"tenantId,omitempty"`
	RoleID          *uuid.UUID `json:"roleId,omitempty"`
	SecurityGroupID *uuid.UUID `json:"securityGroupId,omitempty"`
	Action          string     `json:"action,omitempty"`
}

type mfaPolicyRequirementWire struct {
	Level              string  `json:"level"`
	LocalRequired      bool    `json:"localRequired"`
	FreshnessSeconds   int64   `json:"freshnessSeconds"`
	EnrollmentDeadline *string `json:"enrollmentDeadline"`
}

type mfaPolicyDocumentWire struct {
	ID          uuid.UUID                `json:"id"`
	Revision    int64                    `json:"revision"`
	Target      mfaPolicyTargetWire      `json:"target"`
	Requirement mfaPolicyRequirementWire `json:"requirement"`
	Status      mfa.PolicyStatus         `json:"status"`
	CreatedAt   string                   `json:"createdAt"`
	RetiredAt   *string                  `json:"retiredAt"`
}

type mfaPolicyContextWire struct {
	RoleIDs          []uuid.UUID `json:"roleIds"`
	SecurityGroupIDs []uuid.UUID `json:"securityGroupIds"`
	Action           string      `json:"action"`
}

type mfaPolicyCandidateWire struct {
	Target      mfaPolicyTargetWire      `json:"target"`
	Requirement mfaPolicyRequirementWire `json:"requirement"`
}

type mfaPolicySourceWire struct {
	Source      mfa.PolicySimulationSourceKind `json:"source"`
	PolicyID    *uuid.UUID                     `json:"policyId,omitempty"`
	Revision    *int64                         `json:"revision,omitempty"`
	Target      mfaPolicyTargetWire            `json:"target"`
	Requirement mfaPolicyRequirementWire       `json:"requirement"`
}

type mfaPolicyRecoveryWire struct {
	Safe                         bool                       `json:"safe"`
	EligibleDirectAdministrators int64                      `json:"eligibleDirectAdministrators"`
	ReadyDirectAdministrators    int64                      `json:"readyDirectAdministrators"`
	ReasonCodes                  []mfa.PolicyRecoveryReason `json:"reasonCodes"`
}

type mfaPolicySimulationWire struct {
	Operation mfa.PolicyChangeOperation `json:"operation"`
	Target    mfaPolicyTargetWire       `json:"target"`
	Context   *mfaPolicyContextWire     `json:"context"`
	Current   *mfaPolicyDocumentWire    `json:"current"`
	Candidate *mfaPolicyCandidateWire   `json:"candidate"`
	Effective struct {
		Requirement *mfaPolicyRequirementWire `json:"requirement"`
		Sources     []mfaPolicySourceWire     `json:"sources"`
	} `json:"effective"`
	Recovery mfaPolicyRecoveryWire `json:"recovery"`
}

type mfaPolicyMutationWire struct {
	Policy   mfaPolicyDocumentWire `json:"policy"`
	Replayed bool                  `json:"replayed"`
}

type mfaPolicyAuditWire struct {
	EventID       uuid.UUID `json:"eventId"`
	RequestID     uuid.UUID `json:"requestId"`
	CorrelationID uuid.UUID `json:"correlationId"`
	IPAddress     string    `json:"ipAddress"`
	UserAgent     string    `json:"userAgent"`
}

func marshalMFAPolicySimulation(params mfapolicy.SimulationParams, tenant bool) ([]byte, error) {
	target, err := encodeMFAPolicyTarget(params.Target)
	if err != nil {
		return nil, err
	}
	request := struct {
		Operation        mfa.PolicyChangeOperation `json:"operation"`
		Target           mfaPolicyTargetWire       `json:"target"`
		ExpectedRevision int64                     `json:"expectedRevision"`
		ExpectedPolicyID *uuid.UUID                `json:"expectedPolicyId,omitempty"`
		Requirement      *mfaPolicyRequirementWire `json:"requirement,omitempty"`
		Context          *mfaPolicyContextWire     `json:"context,omitempty"`
	}{Operation: params.Operation, Target: target, ExpectedRevision: params.ExpectedRevision,
		ExpectedPolicyID: params.ExpectedPolicyID}
	if params.Requirement != nil {
		requirement, requirementErr := encodeMFAPolicyRequirement(*params.Requirement)
		if requirementErr != nil {
			return nil, requirementErr
		}
		request.Requirement = &requirement
	}
	if tenant {
		if params.Context == nil {
			return nil, mfapolicy.ErrInvalidInput
		}
		request.Context = encodeMFAPolicyContext(*params.Context)
	} else if params.Context != nil {
		return nil, mfapolicy.ErrInvalidInput
	}
	return json.Marshal(request)
}

func marshalMFAPolicyPublish(params mfapolicy.PublishParams) ([]byte, error) {
	target, err := encodeMFAPolicyTarget(params.Target)
	if err != nil {
		return nil, err
	}
	requirement, err := encodeMFAPolicyRequirement(params.Requirement)
	if err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		CommandID        uuid.UUID                `json:"commandId"`
		Target           mfaPolicyTargetWire      `json:"target"`
		ExpectedRevision int64                    `json:"expectedRevision"`
		ExpectedPolicyID *uuid.UUID               `json:"expectedPolicyId,omitempty"`
		Requirement      mfaPolicyRequirementWire `json:"requirement"`
		Reason           string                   `json:"reason"`
		Audit            mfaPolicyAuditWire       `json:"audit"`
	}{params.CommandID, target, params.ExpectedRevision, params.ExpectedPolicyID,
		requirement, params.Reason, encodeMFAPolicyAudit(params.Audit)})
}

func marshalMFAPolicyRetire(params mfapolicy.RetireParams) ([]byte, error) {
	target, err := encodeMFAPolicyTarget(params.Target)
	if err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		CommandID        uuid.UUID           `json:"commandId"`
		Target           mfaPolicyTargetWire `json:"target"`
		ExpectedRevision int64               `json:"expectedRevision"`
		ExpectedPolicyID uuid.UUID           `json:"expectedPolicyId"`
		Reason           string              `json:"reason"`
		Audit            mfaPolicyAuditWire  `json:"audit"`
	}{params.CommandID, target, params.ExpectedRevision, params.ExpectedPolicyID,
		params.Reason, encodeMFAPolicyAudit(params.Audit)})
}

func encodeMFAPolicyAudit(audit mfapolicy.CommandAudit) mfaPolicyAuditWire {
	return mfaPolicyAuditWire{EventID: audit.EventID, RequestID: audit.Event.RequestID,
		CorrelationID: audit.Event.CorrelationID, IPAddress: audit.Event.RemoteAddress.String(),
		UserAgent: audit.Event.UserAgent}
}

func encodeMFAPolicyTarget(value mfa.AdministrationTarget) (mfaPolicyTargetWire, error) {
	wire := mfaPolicyTargetWire{Action: value.Action}
	switch value.Scope {
	case mfa.PolicyPlatformFloor:
		wire.Scope = "platform_floor"
	case mfa.PolicyTenantBaseline:
		wire.Scope = "tenant_baseline"
	case mfa.PolicySecurityGroup:
		wire.Scope = "security_group"
	case mfa.PolicyRole:
		wire.Scope = "role"
	case mfa.PolicyAction:
		wire.Scope = "action"
	default:
		return mfaPolicyTargetWire{}, mfapolicy.ErrInvalidInput
	}
	if value.TenantID != (identity.EntityID{}) {
		identifier := uuid.UUID(value.TenantID)
		wire.TenantID = &identifier
	}
	if value.RoleID != (identity.EntityID{}) {
		identifier := uuid.UUID(value.RoleID)
		wire.RoleID = &identifier
	}
	if value.SecurityGroupID != (identity.EntityID{}) {
		identifier := uuid.UUID(value.SecurityGroupID)
		wire.SecurityGroupID = &identifier
	}
	return wire, nil
}

func encodeMFAPolicyRequirement(value mfa.PolicyRequirement) (mfaPolicyRequirementWire, error) {
	wire := mfaPolicyRequirementWire{LocalRequired: value.LocalRequired,
		FreshnessSeconds: int64(value.Freshness / time.Second)}
	switch value.Level {
	case identity.AssurancePrimary:
		wire.Level = "primary"
	case identity.AssuranceMFA:
		wire.Level = "mfa"
	case identity.AssurancePhishingResistant:
		wire.Level = "phishing_resistant"
	default:
		return mfaPolicyRequirementWire{}, mfapolicy.ErrInvalidInput
	}
	if value.Freshness < 0 || value.Freshness > 365*24*time.Hour ||
		value.Freshness%time.Second != 0 {
		return mfaPolicyRequirementWire{}, mfapolicy.ErrInvalidInput
	}
	if value.EnrollmentDeadline != nil {
		deadline := value.EnrollmentDeadline.UTC()
		if deadline.Nanosecond()%1_000_000 != 0 {
			return mfaPolicyRequirementWire{}, mfapolicy.ErrInvalidInput
		}
		formatted := deadline.Format(mfaPolicyInstantLayout)
		wire.EnrollmentDeadline = &formatted
	}
	return wire, nil
}

func encodeMFAPolicyContext(value mfa.PolicySimulationContext) *mfaPolicyContextWire {
	return &mfaPolicyContextWire{RoleIDs: mfaPolicyUUIDs(value.RoleIDs),
		SecurityGroupIDs: mfaPolicyUUIDs(value.SecurityGroupIDs), Action: value.Action}
}

func decodeMFAPolicyDocuments(documents [][]byte, tenantID uuid.UUID) ([]mfa.PolicyDocument, error) {
	result := make([]mfa.PolicyDocument, 0, len(documents))
	for _, document := range documents {
		policy, err := decodeMFAPolicyDocument(document, tenantID)
		if err != nil {
			return nil, err
		}
		result = append(result, policy)
	}
	return result, nil
}

func decodeMFAPolicyDocument(document []byte, tenantID uuid.UUID) (mfa.PolicyDocument, error) {
	if err := requireMFAPolicyDocumentShape(document); err != nil {
		return mfa.PolicyDocument{}, err
	}
	var wire mfaPolicyDocumentWire
	if err := decodeMFAPolicyJSON(document, &wire); err != nil {
		return mfa.PolicyDocument{}, err
	}
	return mapMFAPolicyDocument(wire, tenantID)
}

func requireMFAPolicyDocumentShape(document []byte) error {
	object, err := parseMFAPolicyObject(document, "id", "revision", "target", "requirement",
		"status", "createdAt", "retiredAt")
	if err != nil {
		return err
	}
	if err := requireMFAPolicyTargetShape(object["target"]); err != nil {
		return err
	}
	return requireMFAPolicyRequirementShape(object["requirement"])
}

func mapMFAPolicyDocument(wire mfaPolicyDocumentWire, tenantID uuid.UUID) (mfa.PolicyDocument, error) {
	target, err := decodeMFAPolicyTarget(wire.Target)
	if err != nil {
		return mfa.PolicyDocument{}, err
	}
	requirement, err := decodeMFAPolicyRequirement(wire.Requirement)
	if err != nil {
		return mfa.PolicyDocument{}, err
	}
	createdAt, err := decodeMFAPolicyInstant(wire.CreatedAt)
	if err != nil {
		return mfa.PolicyDocument{}, err
	}
	retiredAt, err := decodeOptionalMFAPolicyInstant(wire.RetiredAt)
	if err != nil {
		return mfa.PolicyDocument{}, err
	}
	value := mfa.PolicyDocument{ID: identity.EntityID(wire.ID), Revision: wire.Revision,
		Target: target, Requirement: requirement, Status: wire.Status,
		CreatedAt: createdAt, RetiredAt: retiredAt}
	if mfa.ValidatePolicyDocument(value, identity.EntityID(tenantID)) != nil ||
		!mfaPolicyUUIDv7(wire.ID) {
		return mfa.PolicyDocument{}, mfapolicy.ErrUnavailable
	}
	return mfa.ClonePolicyDocument(value), nil
}

func decodeMFAPolicySimulation(document []byte, tenantID uuid.UUID) (mfa.PolicySimulation, error) {
	if err := requireMFAPolicySimulationShape(document); err != nil {
		return mfa.PolicySimulation{}, err
	}
	var wire mfaPolicySimulationWire
	if err := decodeMFAPolicyJSON(document, &wire); err != nil {
		return mfa.PolicySimulation{}, err
	}
	target, err := decodeMFAPolicyTarget(wire.Target)
	if err != nil {
		return mfa.PolicySimulation{}, err
	}
	value := mfa.PolicySimulation{Operation: wire.Operation, Target: target,
		Recovery: mfa.PolicyRecoverySafety{Safe: wire.Recovery.Safe,
			EligibleDirectAdministrators: wire.Recovery.EligibleDirectAdministrators,
			ReadyDirectAdministrators:    wire.Recovery.ReadyDirectAdministrators,
			ReasonCodes:                  append([]mfa.PolicyRecoveryReason(nil), wire.Recovery.ReasonCodes...)}}
	if wire.Context != nil {
		value.Context = &mfa.PolicySimulationContext{RoleIDs: mfaPolicyEntityIDs(wire.Context.RoleIDs),
			SecurityGroupIDs: mfaPolicyEntityIDs(wire.Context.SecurityGroupIDs), Action: wire.Context.Action}
	}
	if wire.Current != nil {
		current, mapErr := mapMFAPolicyDocument(*wire.Current, tenantID)
		if mapErr != nil {
			return mfa.PolicySimulation{}, mapErr
		}
		value.Current = &current
	}
	if wire.Candidate != nil {
		candidateTarget, targetErr := decodeMFAPolicyTarget(wire.Candidate.Target)
		candidateRequirement, requirementErr := decodeMFAPolicyRequirement(wire.Candidate.Requirement)
		if targetErr != nil || requirementErr != nil {
			return mfa.PolicySimulation{}, mfapolicy.ErrUnavailable
		}
		value.Candidate = &mfa.PolicySimulationCandidate{Target: candidateTarget,
			Requirement: candidateRequirement}
	}
	if wire.Effective.Requirement != nil {
		requirement, requirementErr := decodeMFAPolicyRequirement(*wire.Effective.Requirement)
		if requirementErr != nil {
			return mfa.PolicySimulation{}, requirementErr
		}
		value.Effective.Requirement = &requirement
	}
	value.Effective.Sources = make([]mfa.PolicySimulationSource, 0, len(wire.Effective.Sources))
	for _, sourceWire := range wire.Effective.Sources {
		sourceTarget, targetErr := decodeMFAPolicyTarget(sourceWire.Target)
		sourceRequirement, requirementErr := decodeMFAPolicyRequirement(sourceWire.Requirement)
		if targetErr != nil || requirementErr != nil {
			return mfa.PolicySimulation{}, mfapolicy.ErrUnavailable
		}
		source := mfa.PolicySimulationSource{Source: sourceWire.Source, Target: sourceTarget,
			Requirement: sourceRequirement}
		if sourceWire.PolicyID != nil {
			source.PolicyID = identity.EntityID(*sourceWire.PolicyID)
		}
		if sourceWire.Revision != nil {
			source.Revision = *sourceWire.Revision
		}
		value.Effective.Sources = append(value.Effective.Sources, source)
	}
	if mfa.ValidatePolicySimulation(value, identity.EntityID(tenantID)) != nil {
		return mfa.PolicySimulation{}, mfapolicy.ErrUnavailable
	}
	return mfa.ClonePolicySimulation(value), nil
}

func decodeMFAPolicyMutation(document []byte, tenantID uuid.UUID) (mfapolicy.MutationResult, error) {
	object, err := parseMFAPolicyObject(document, "policy", "replayed")
	if err != nil {
		return mfapolicy.MutationResult{}, err
	}
	if err := requireMFAPolicyDocumentShape(object["policy"]); err != nil {
		return mfapolicy.MutationResult{}, err
	}
	var wire mfaPolicyMutationWire
	if err := decodeMFAPolicyJSON(document, &wire); err != nil {
		return mfapolicy.MutationResult{}, err
	}
	policy, err := mapMFAPolicyDocument(wire.Policy, tenantID)
	if err != nil {
		return mfapolicy.MutationResult{}, err
	}
	return mfapolicy.MutationResult{Policy: policy, Replayed: wire.Replayed}, nil
}

func decodeMFAPolicyTarget(wire mfaPolicyTargetWire) (mfa.AdministrationTarget, error) {
	value := mfa.AdministrationTarget{Action: wire.Action}
	switch wire.Scope {
	case "platform_floor":
		value.Scope = mfa.PolicyPlatformFloor
	case "tenant_baseline":
		value.Scope = mfa.PolicyTenantBaseline
	case "security_group":
		value.Scope = mfa.PolicySecurityGroup
	case "role":
		value.Scope = mfa.PolicyRole
	case "action":
		value.Scope = mfa.PolicyAction
	default:
		return mfa.AdministrationTarget{}, mfapolicy.ErrUnavailable
	}
	if wire.TenantID != nil {
		value.TenantID = identity.EntityID(*wire.TenantID)
	}
	if wire.RoleID != nil {
		value.RoleID = identity.EntityID(*wire.RoleID)
	}
	if wire.SecurityGroupID != nil {
		value.SecurityGroupID = identity.EntityID(*wire.SecurityGroupID)
	}
	return value, nil
}

func decodeMFAPolicyRequirement(wire mfaPolicyRequirementWire) (mfa.PolicyRequirement, error) {
	if wire.FreshnessSeconds < 0 || wire.FreshnessSeconds > 31_536_000 {
		return mfa.PolicyRequirement{}, mfapolicy.ErrUnavailable
	}
	enrollmentDeadline, err := decodeOptionalMFAPolicyInstant(wire.EnrollmentDeadline)
	if err != nil {
		return mfa.PolicyRequirement{}, err
	}
	value := mfa.PolicyRequirement{LocalRequired: wire.LocalRequired,
		Freshness:          time.Duration(wire.FreshnessSeconds) * time.Second,
		EnrollmentDeadline: enrollmentDeadline}
	switch wire.Level {
	case "primary":
		value.Level = identity.AssurancePrimary
	case "mfa":
		value.Level = identity.AssuranceMFA
	case "phishing_resistant":
		value.Level = identity.AssurancePhishingResistant
	default:
		return mfa.PolicyRequirement{}, mfapolicy.ErrUnavailable
	}
	if _, err := mfa.NormalizePolicyRequirement(value); err != nil {
		return mfa.PolicyRequirement{}, mfapolicy.ErrUnavailable
	}
	return value, nil
}

func requireMFAPolicyObject(document []byte, fields ...string) error {
	_, err := parseMFAPolicyObject(document, fields...)
	return err
}

func parseMFAPolicyObject(document []byte, fields ...string) (map[string]json.RawMessage, error) {
	trimmed := bytes.TrimSpace(document)
	if len(trimmed) < 2 || len(trimmed) > maximumMFAPolicyProjectionBytes || trimmed[0] != '{' {
		return nil, mfapolicy.ErrUnavailable
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &object); err != nil || object == nil || len(object) != len(fields) {
		return nil, mfapolicy.ErrUnavailable
	}
	for _, field := range fields {
		if _, present := object[field]; !present {
			return nil, mfapolicy.ErrUnavailable
		}
	}
	return object, nil
}

func requireMFAPolicyTargetShape(document []byte) error {
	_, err := parseMFAPolicyObject(document, "scope")
	if err == nil {
		var scope struct {
			Scope string `json:"scope"`
		}
		if decodeErr := decodeMFAPolicyJSON(document, &scope); decodeErr != nil || scope.Scope != "platform_floor" {
			return mfapolicy.ErrUnavailable
		}
		return nil
	}
	var discriminator struct {
		Scope string `json:"scope"`
	}
	if decodeErr := json.Unmarshal(document, &discriminator); decodeErr != nil {
		return mfapolicy.ErrUnavailable
	}
	switch discriminator.Scope {
	case "tenant_baseline":
		return requireMFAPolicyObject(document, "scope", "tenantId")
	case "role":
		return requireMFAPolicyObject(document, "scope", "tenantId", "roleId")
	case "security_group":
		return requireMFAPolicyObject(document, "scope", "tenantId", "securityGroupId")
	case "action":
		return requireMFAPolicyObject(document, "scope", "tenantId", "action")
	default:
		return mfapolicy.ErrUnavailable
	}
}

func requireMFAPolicyRequirementShape(document []byte) error {
	return requireMFAPolicyObject(document, "level", "localRequired", "freshnessSeconds",
		"enrollmentDeadline")
}

func requireMFAPolicySimulationShape(document []byte) error {
	object, err := parseMFAPolicyObject(document, "operation", "target", "context", "current",
		"candidate", "effective", "recovery")
	if err != nil {
		return err
	}
	if err = requireMFAPolicyTargetShape(object["target"]); err != nil {
		return err
	}
	if !mfaPolicyJSONNull(object["context"]) {
		if err = requireMFAPolicyObject(object["context"], "roleIds", "securityGroupIds", "action"); err != nil {
			return err
		}
	}
	if !mfaPolicyJSONNull(object["current"]) {
		if err = requireMFAPolicyDocumentShape(object["current"]); err != nil {
			return err
		}
	}
	if !mfaPolicyJSONNull(object["candidate"]) {
		candidate, candidateErr := parseMFAPolicyObject(object["candidate"], "target", "requirement")
		if candidateErr != nil {
			return candidateErr
		}
		if err = requireMFAPolicyTargetShape(candidate["target"]); err != nil {
			return err
		}
		if err = requireMFAPolicyRequirementShape(candidate["requirement"]); err != nil {
			return err
		}
	}
	effective, err := parseMFAPolicyObject(object["effective"], "requirement", "sources")
	if err != nil {
		return err
	}
	if !mfaPolicyJSONNull(effective["requirement"]) {
		if err = requireMFAPolicyRequirementShape(effective["requirement"]); err != nil {
			return err
		}
	}
	var sources []json.RawMessage
	if err = json.Unmarshal(effective["sources"], &sources); err != nil || sources == nil {
		return mfapolicy.ErrUnavailable
	}
	for _, sourceDocument := range sources {
		source, sourceErr := parseMFAPolicyObject(sourceDocument, "source", "target", "requirement")
		if sourceErr != nil {
			source, sourceErr = parseMFAPolicyObject(sourceDocument, "source", "policyId", "revision",
				"target", "requirement")
		}
		if sourceErr != nil {
			return sourceErr
		}
		if err = requireMFAPolicyTargetShape(source["target"]); err != nil {
			return err
		}
		if err = requireMFAPolicyRequirementShape(source["requirement"]); err != nil {
			return err
		}
	}
	return requireMFAPolicyObject(object["recovery"], "safe", "eligibleDirectAdministrators",
		"readyDirectAdministrators", "reasonCodes")
}

func mfaPolicyJSONNull(document []byte) bool {
	return bytes.Equal(bytes.TrimSpace(document), []byte("null"))
}

func decodeMFAPolicyJSON(document []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return mfapolicy.ErrUnavailable
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return mfapolicy.ErrUnavailable
	}
	return nil
}

func mfaPolicyCursorID(cursor *mfapolicy.Cursor) pgtype.UUID {
	if cursor == nil {
		return pgtype.UUID{}
	}
	return toDatabaseUUID(cursor.ID)
}

func mfaPolicyCursorRevision(cursor *mfapolicy.Cursor) *int64 {
	if cursor == nil {
		return nil
	}
	return &cursor.Revision
}

func optionalMFAPolicyRevision(revision int64) *int64 {
	if revision == 0 {
		return nil
	}
	return &revision
}

func mfaPolicyUUIDs(values []identity.EntityID) []uuid.UUID {
	result := make([]uuid.UUID, len(values))
	for index, value := range values {
		result[index] = uuid.UUID(value)
	}
	return result
}

func mfaPolicyEntityIDs(values []uuid.UUID) []identity.EntityID {
	result := make([]identity.EntityID, len(values))
	for index, value := range values {
		result[index] = identity.EntityID(value)
	}
	return result
}

func decodeOptionalMFAPolicyInstant(value *string) (*time.Time, error) {
	if value == nil {
		return nil, nil
	}
	result, err := decodeMFAPolicyInstant(*value)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

func decodeMFAPolicyInstant(value string) (time.Time, error) {
	result, err := time.Parse(mfaPolicyInstantLayout, value)
	if err != nil || result.Format(mfaPolicyInstantLayout) != value {
		return time.Time{}, mfapolicy.ErrUnavailable
	}
	return result, nil
}

func validMFAPolicyAuthenticationMethod(value string) bool {
	switch value {
	case "bootstrap_totp", "oidc", "passkey", "recovery_code", "saml", "totp":
		return true
	default:
		return false
	}
}

func mfaPolicyUUIDv7(value uuid.UUID) bool {
	return value != uuid.Nil && value.Version() == 7 && value.Variant() == uuid.RFC4122
}
