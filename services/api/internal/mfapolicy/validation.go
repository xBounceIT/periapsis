package mfapolicy

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/mfa"
	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
)

func normalizeListInput(input ListInput) (ListInput, error) {
	if input.Limit == 0 {
		input.Limit = DefaultPageSize
	}
	if input.Limit < 1 || input.Limit > MaximumPageSize {
		return ListInput{}, ErrInvalidInput
	}
	if input.After != nil && (!validUUIDv7(input.After.ID) || !validRevision(input.After.Revision)) {
		return ListInput{}, ErrInvalidInput
	}
	return input, nil
}

func normalizeSimulationInput(
	input SimulationInput,
	tenantID uuid.UUID,
) (SimulationInput, error) {
	target, err := normalizeInputTarget(input.Target, tenantID)
	if err != nil {
		return SimulationInput{}, err
	}
	input.Target = target
	if tenantID == uuid.Nil {
		if input.Context != nil {
			return SimulationInput{}, ErrInvalidInput
		}
	} else {
		if input.Context == nil {
			return SimulationInput{}, ErrInvalidInput
		}
		contextValue, contextErr := normalizeContext(*input.Context)
		if contextErr != nil {
			return SimulationInput{}, contextErr
		}
		input.Context = &contextValue
		if !simulationTargetApplies(input.Target, contextValue) {
			return SimulationInput{}, ErrInvalidInput
		}
	}
	switch input.Operation {
	case mfa.PolicyPublish:
		if input.Requirement == nil {
			return SimulationInput{}, ErrInvalidInput
		}
		requirement, requirementErr := mfa.NormalizePolicyRequirement(*input.Requirement)
		if requirementErr != nil {
			return SimulationInput{}, ErrInvalidInput
		}
		input.Requirement = &requirement
		if err = validatePublishCAS(input.ExpectedPolicyID, input.ExpectedRevision); err != nil {
			return SimulationInput{}, err
		}
	case mfa.PolicyRetire:
		if input.Requirement != nil || input.ExpectedPolicyID == nil ||
			!validUUIDv7(*input.ExpectedPolicyID) || !validRevision(input.ExpectedRevision) {
			return SimulationInput{}, ErrInvalidInput
		}
	default:
		return SimulationInput{}, ErrInvalidInput
	}
	input.ExpectedPolicyID = cloneUUID(input.ExpectedPolicyID)
	return input, nil
}

func simulationTargetApplies(
	target mfa.AdministrationTarget,
	contextValue mfa.PolicySimulationContext,
) bool {
	switch target.Scope {
	case mfa.PolicyTenantBaseline:
		return true
	case mfa.PolicyRole:
		return slices.Contains(contextValue.RoleIDs, target.RoleID)
	case mfa.PolicySecurityGroup:
		return slices.Contains(contextValue.SecurityGroupIDs, target.SecurityGroupID)
	case mfa.PolicyAction:
		return target.Action == contextValue.Action
	default:
		return false
	}
}

func normalizePublishInput(input PublishInput, tenantID uuid.UUID) (PublishInput, error) {
	if !validUUIDv7(input.CommandID) || !validReason(input.Reason) || !validEvent(input.Event) {
		return PublishInput{}, ErrInvalidInput
	}
	target, err := normalizeInputTarget(input.Target, tenantID)
	if err != nil {
		return PublishInput{}, err
	}
	requirement, err := mfa.NormalizePolicyRequirement(input.Requirement)
	if err != nil || validatePublishCAS(input.ExpectedPolicyID, input.ExpectedRevision) != nil {
		return PublishInput{}, ErrInvalidInput
	}
	input.Target = target
	input.Requirement = requirement
	input.ExpectedPolicyID = cloneUUID(input.ExpectedPolicyID)
	return input, nil
}

func normalizeRetireInput(input RetireInput, tenantID uuid.UUID) (RetireInput, error) {
	if !validUUIDv7(input.CommandID) || !validUUIDv7(input.ExpectedPolicyID) ||
		!validRevision(input.ExpectedRevision) || !validReason(input.Reason) || !validEvent(input.Event) {
		return RetireInput{}, ErrInvalidInput
	}
	target, err := normalizeInputTarget(input.Target, tenantID)
	if err != nil {
		return RetireInput{}, err
	}
	input.Target = target
	return input, nil
}

func normalizeInputTarget(
	target mfa.AdministrationTarget,
	tenantID uuid.UUID,
) (mfa.AdministrationTarget, error) {
	if tenantID == uuid.Nil {
		if _, err := mfa.NormalizeAdministrationTarget(target, identity.EntityID{}); err != nil {
			return mfa.AdministrationTarget{}, ErrInvalidInput
		}
		return target, nil
	}
	if !validUUIDv7(tenantID) || target.TenantID != (identity.EntityID{}) ||
		target.Scope == mfa.PolicyPlatformFloor {
		return mfa.AdministrationTarget{}, ErrInvalidInput
	}
	target.TenantID = identity.EntityID(tenantID)
	if _, err := mfa.NormalizeAdministrationTarget(target, identity.EntityID(tenantID)); err != nil ||
		!validTargetIDs(target) {
		return mfa.AdministrationTarget{}, ErrInvalidInput
	}
	return target, nil
}

func normalizeContext(value mfa.PolicySimulationContext) (mfa.PolicySimulationContext, error) {
	for _, values := range [][]identity.EntityID{value.RoleIDs, value.SecurityGroupIDs} {
		for _, item := range values {
			if !validUUIDv7(uuid.UUID(item)) {
				return mfa.PolicySimulationContext{}, ErrInvalidInput
			}
		}
	}
	value, err := mfa.NormalizePolicySimulationContext(value)
	if err != nil {
		return mfa.PolicySimulationContext{}, ErrInvalidInput
	}
	return value, nil
}

func validatePublishCAS(policyID *uuid.UUID, revision int64) error {
	if revision == 0 {
		if policyID != nil {
			return ErrInvalidInput
		}
		return nil
	}
	if policyID == nil || !validUUIDv7(*policyID) || revision < 1 || revision >= MaximumSafeRevision {
		return ErrInvalidInput
	}
	return nil
}

func validatePage(rows []mfa.PolicyDocument, tenantID uuid.UUID, input ListInput) error {
	if len(rows) > input.Limit+1 {
		return ErrUnavailable
	}
	for index := range rows {
		if validateDocument(rows[index], tenantID) != nil ||
			!input.IncludeRetired && rows[index].Status != mfa.PolicyLive ||
			index > 0 && compareCursor(rows[index-1], rows[index]) >= 0 ||
			input.After != nil && compareDocumentToCursor(rows[index], *input.After) <= 0 {
			return ErrUnavailable
		}
	}
	return nil
}

func validateDocument(value mfa.PolicyDocument, tenantID uuid.UUID) error {
	if !validUUIDv7(uuid.UUID(value.ID)) || !validTargetIDs(value.Target) ||
		mfa.ValidatePolicyDocument(value, identity.EntityID(tenantID)) != nil {
		return ErrUnavailable
	}
	return nil
}

func validateSimulationResult(
	value mfa.PolicySimulation,
	input SimulationInput,
	tenantID uuid.UUID,
) (mfa.PolicySimulation, error) {
	if mfa.ValidatePolicySimulation(value, identity.EntityID(tenantID)) != nil ||
		value.Operation != input.Operation || value.Target != input.Target {
		return mfa.PolicySimulation{}, ErrUnavailable
	}
	if input.Context == nil && value.Context != nil || input.Context != nil &&
		(value.Context == nil || input.Context.Action != value.Context.Action ||
			!slices.Equal(input.Context.RoleIDs, value.Context.RoleIDs) ||
			!slices.Equal(input.Context.SecurityGroupIDs, value.Context.SecurityGroupIDs)) {
		return mfa.PolicySimulation{}, ErrUnavailable
	}
	if value.Current != nil && validateDocument(*value.Current, tenantID) != nil {
		return mfa.PolicySimulation{}, ErrUnavailable
	}
	if input.ExpectedRevision == 0 {
		if value.Current != nil {
			return mfa.PolicySimulation{}, ErrUnavailable
		}
	} else if value.Current == nil || value.Current.Revision != input.ExpectedRevision ||
		uuid.UUID(value.Current.ID) != *input.ExpectedPolicyID {
		return mfa.PolicySimulation{}, ErrUnavailable
	}
	if input.Requirement == nil {
		if value.Candidate != nil {
			return mfa.PolicySimulation{}, ErrUnavailable
		}
	} else if value.Candidate == nil || value.Candidate.Target != input.Target ||
		!requirementsEqual(value.Candidate.Requirement, *input.Requirement) {
		return mfa.PolicySimulation{}, ErrUnavailable
	}
	for _, source := range value.Effective.Sources {
		if source.Source == mfa.PolicySimulationCurrentSource && !validUUIDv7(uuid.UUID(source.PolicyID)) ||
			!validTargetIDs(source.Target) {
			return mfa.PolicySimulation{}, ErrUnavailable
		}
	}
	return mfa.ClonePolicySimulation(value), nil
}

func validatePublishResult(
	value MutationResult,
	input PublishInput,
	tenantID uuid.UUID,
) (MutationResult, error) {
	if validateDocument(value.Policy, tenantID) != nil || value.Policy.Status != mfa.PolicyLive ||
		value.Policy.Target != input.Target || !requirementsEqual(value.Policy.Requirement, input.Requirement) {
		return MutationResult{}, ErrUnavailable
	}
	if input.ExpectedRevision == 0 {
		if value.Policy.Revision != 1 {
			return MutationResult{}, ErrUnavailable
		}
	} else if uuid.UUID(value.Policy.ID) != *input.ExpectedPolicyID ||
		value.Policy.Revision != input.ExpectedRevision+1 {
		return MutationResult{}, ErrUnavailable
	}
	value.Policy = mfa.ClonePolicyDocument(value.Policy)
	return value, nil
}

func validateRetireResult(
	value MutationResult,
	input RetireInput,
	tenantID uuid.UUID,
) (MutationResult, error) {
	if validateDocument(value.Policy, tenantID) != nil || value.Policy.Status != mfa.PolicyRetired ||
		uuid.UUID(value.Policy.ID) != input.ExpectedPolicyID || value.Policy.Revision != input.ExpectedRevision ||
		value.Policy.Target != input.Target {
		return MutationResult{}, ErrUnavailable
	}
	value.Policy = mfa.ClonePolicyDocument(value.Policy)
	return value, nil
}

func validTargetIDs(value mfa.AdministrationTarget) bool {
	for _, id := range []identity.EntityID{value.TenantID, value.RoleID, value.SecurityGroupID} {
		if id != (identity.EntityID{}) && !validUUIDv7(uuid.UUID(id)) {
			return false
		}
	}
	return true
}

func compareCursor(left, right mfa.PolicyDocument) int {
	return mfa.ComparePolicyDocumentCursor(left, right)
}

func compareDocumentToCursor(value mfa.PolicyDocument, cursor Cursor) int {
	if comparison := bytes.Compare(value.ID[:], cursor.ID[:]); comparison != 0 {
		return comparison
	}
	if value.Revision < cursor.Revision {
		return -1
	}
	if value.Revision > cursor.Revision {
		return 1
	}
	return 0
}

func requirementsEqual(left, right mfa.PolicyRequirement) bool {
	return left.Level == right.Level && left.LocalRequired == right.LocalRequired &&
		left.Freshness == right.Freshness && instantsEqual(left.EnrollmentDeadline, right.EnrollmentDeadline)
}

func instantsEqual(left, right *time.Time) bool {
	return left == nil && right == nil || left != nil && right != nil && left.Equal(*right)
}

func validateSession(value authentication.Session) bool {
	return validUUIDv7(value.ID) && validUUIDv7(value.User.ID) && validAuthenticationMethod(value.AuthenticationMethod)
}

func validAuthenticationMethod(value string) bool {
	switch value {
	case "bootstrap_totp", "oidc", "passkey", "recovery_code", "saml", "totp":
		return true
	default:
		return false
	}
}

func validEvent(value authentication.EventContext) bool {
	return validUUIDv7(value.RequestID) && validUUIDv7(value.CorrelationID) &&
		validRemoteAddress(value.RemoteAddress) && validUserAgent(value.UserAgent)
}

func validRemoteAddress(value netip.Addr) bool {
	return value.IsValid() && value.Zone() == ""
}

func validUserAgent(value string) bool {
	if len(value) < 1 || len(value) > 512 || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) || unicode.In(character, unicode.Cf) {
			return false
		}
	}
	return true
}

func validReason(value string) bool {
	if len(value) < 1 || len(value) > 2048 || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range []byte(value) {
		if character < 0x20 || character > 0x7e || character == ',' {
			return false
		}
	}
	return true
}

func validUUIDv7(value uuid.UUID) bool {
	return value != uuid.Nil && value.Version() == 7 && value.Variant() == uuid.RFC4122
}

func validRevision(value int64) bool { return value > 0 && value <= MaximumSafeRevision }

func cloneUUID(value *uuid.UUID) *uuid.UUID {
	if value == nil {
		return nil
	}
	result := *value
	return &result
}

func mapDependencyError(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, context.Canceled):
		return context.Canceled
	case errors.Is(err, context.DeadlineExceeded):
		return context.DeadlineExceeded
	case errors.Is(err, ErrInvalidInput), errors.Is(err, authentication.ErrInvalidInput),
		errors.Is(err, authorization.ErrInvalidInput):
		return ErrInvalidInput
	case errors.Is(err, ErrForbidden), errors.Is(err, authentication.ErrForbidden),
		errors.Is(err, authorization.ErrForbidden), errors.Is(err, authorization.ErrDenied):
		return ErrForbidden
	case errors.Is(err, ErrNotFound), errors.Is(err, authentication.ErrNotFound),
		errors.Is(err, authorization.ErrNotFound):
		return ErrNotFound
	case errors.Is(err, ErrRecoveryUnsafe):
		return ErrRecoveryUnsafe
	case errors.Is(err, ErrPreconditionRequired), errors.Is(err, authorization.ErrPreconditionRequired):
		return ErrPreconditionRequired
	case errors.Is(err, ErrPreconditionFailed), errors.Is(err, authorization.ErrPreconditionFailed):
		return ErrPreconditionFailed
	case errors.Is(err, ErrConflict), errors.Is(err, authentication.ErrConflict),
		errors.Is(err, authorization.ErrConflict):
		return ErrConflict
	default:
		return ErrUnavailable
	}
}

func interfaceIsNil(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
