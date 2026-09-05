package httpserver

import (
	"errors"
	"time"

	"github.com/google/uuid"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/mfa"
	"github.com/periapsis-im/periapsis/services/api/internal/contract"
	"github.com/periapsis-im/periapsis/services/api/internal/mfapolicy"
)

func platformMFAPolicyTarget(value contract.PlatformMfaPolicyTargetInput) (mfa.AdministrationTarget, error) {
	if value.Scope != contract.PlatformMfaPolicyTargetInputScopePlatformFloor {
		return mfa.AdministrationTarget{}, errors.New("invalid platform MFA policy target")
	}
	return mfa.AdministrationTarget{Scope: mfa.PolicyPlatformFloor}, nil
}

func tenantMFAPolicyTarget(value contract.TenantMfaPolicyTargetInput) (mfa.AdministrationTarget, error) {
	target := mfa.AdministrationTarget{}
	switch value.Scope {
	case contract.TenantMfaPolicyTargetInputScopeTenantBaseline:
		target.Scope = mfa.PolicyTenantBaseline
	case contract.TenantMfaPolicyTargetInputScopeSecurityGroup:
		target.Scope = mfa.PolicySecurityGroup
		if value.SecurityGroupId != nil {
			target.SecurityGroupID = identity.EntityID(uuid.UUID(*value.SecurityGroupId))
		}
	case contract.TenantMfaPolicyTargetInputScopeRole:
		target.Scope = mfa.PolicyRole
		if value.RoleId != nil {
			target.RoleID = identity.EntityID(uuid.UUID(*value.RoleId))
		}
	case contract.TenantMfaPolicyTargetInputScopeAction:
		target.Scope = mfa.PolicyAction
		if value.Action != nil {
			target.Action = *value.Action
		}
	default:
		return mfa.AdministrationTarget{}, errors.New("invalid tenant MFA policy target")
	}
	return target, nil
}

func mfaPolicyRequirement(value contract.MfaPolicyRequirement) (mfa.PolicyRequirement, error) {
	if value.FreshnessSeconds < 0 ||
		value.FreshnessSeconds > int64(mfa.MaximumPolicyFreshness/time.Second) {
		return mfa.PolicyRequirement{}, errors.New("invalid MFA policy freshness")
	}
	level := identity.AssuranceLevel(0)
	switch value.Level {
	case contract.MfaPolicyLevelPrimary:
		level = identity.AssurancePrimary
	case contract.MfaPolicyLevelMfa:
		level = identity.AssuranceMFA
	case contract.MfaPolicyLevelPhishingResistant:
		level = identity.AssurancePhishingResistant
	default:
		return mfa.PolicyRequirement{}, errors.New("invalid MFA policy level")
	}
	return mfa.PolicyRequirement{
		Level:              level,
		LocalRequired:      value.LocalRequired,
		Freshness:          time.Duration(value.FreshnessSeconds) * time.Second,
		EnrollmentDeadline: cloneMFAPolicyInstant(value.EnrollmentDeadline),
	}, nil
}

func mfaPolicySimulationContext(value contract.MfaPolicySimulationContext) mfa.PolicySimulationContext {
	result := mfa.PolicySimulationContext{
		RoleIDs:          make([]identity.EntityID, len(value.RoleIds)),
		SecurityGroupIDs: make([]identity.EntityID, len(value.SecurityGroupIds)),
		Action:           value.Action,
	}
	for index := range value.RoleIds {
		result.RoleIDs[index] = identity.EntityID(uuid.UUID(value.RoleIds[index]))
	}
	for index := range value.SecurityGroupIds {
		result.SecurityGroupIDs[index] = identity.EntityID(uuid.UUID(value.SecurityGroupIds[index]))
	}
	return result
}

func mapMFAPolicyPage(value mfapolicy.Page) (contract.MfaPolicyPage, error) {
	result := contract.MfaPolicyPage{Items: make([]contract.MfaPolicyDocument, len(value.Items))}
	for index := range value.Items {
		mapped, err := mapMFAPolicyDocument(value.Items[index])
		if err != nil {
			return contract.MfaPolicyPage{}, err
		}
		result.Items[index] = mapped
	}
	if value.NextCursor != nil {
		if !validMFAPolicyUUID(value.NextCursor.ID) || value.NextCursor.Revision < 1 ||
			value.NextCursor.Revision > mfapolicy.MaximumSafeRevision {
			return contract.MfaPolicyPage{}, errors.New("invalid MFA policy page cursor")
		}
		result.NextCursor = &contract.MfaPolicyCursor{
			Id: value.NextCursor.ID, Revision: value.NextCursor.Revision,
		}
	}
	return result, nil
}

func mapMFAPolicyMutation(value mfapolicy.MutationResult) (contract.MfaPolicyMutationResult, error) {
	document, err := mapMFAPolicyDocument(value.Policy)
	if err != nil {
		return contract.MfaPolicyMutationResult{}, err
	}
	return contract.MfaPolicyMutationResult{Policy: document, Replayed: value.Replayed}, nil
}

func mapMFAPolicyDocument(value mfa.PolicyDocument) (contract.MfaPolicyDocument, error) {
	expectedTenant := value.Target.TenantID
	if value.Target.Scope == mfa.PolicyPlatformFloor {
		expectedTenant = identity.EntityID{}
	}
	if !validMFAPolicyUUID(uuid.UUID(value.ID)) || mfa.ValidatePolicyDocument(value, expectedTenant) != nil {
		return contract.MfaPolicyDocument{}, errors.New("invalid MFA policy document")
	}
	target, err := mapMFAPolicyTarget(value.Target)
	if err != nil {
		return contract.MfaPolicyDocument{}, err
	}
	requirement, err := mapMFAPolicyRequirement(value.Requirement)
	if err != nil {
		return contract.MfaPolicyDocument{}, err
	}
	status := contract.MfaPolicyStatus(value.Status)
	if !status.Valid() {
		return contract.MfaPolicyDocument{}, errors.New("invalid MFA policy status")
	}
	return contract.MfaPolicyDocument{
		Id: uuid.UUID(value.ID), Revision: value.Revision, Target: target,
		Requirement: requirement, Status: status, CreatedAt: value.CreatedAt,
		RetiredAt: cloneMFAPolicyInstant(value.RetiredAt),
	}, nil
}

func mapMFAPolicySimulation(value mfa.PolicySimulation) (contract.MfaPolicySimulationResult, error) {
	expectedTenant := value.Target.TenantID
	if value.Target.Scope == mfa.PolicyPlatformFloor {
		expectedTenant = identity.EntityID{}
	}
	if mfa.ValidatePolicySimulation(value, expectedTenant) != nil {
		return contract.MfaPolicySimulationResult{}, errors.New("invalid MFA policy simulation")
	}
	target, err := mapMFAPolicyTarget(value.Target)
	if err != nil {
		return contract.MfaPolicySimulationResult{}, err
	}
	result := contract.MfaPolicySimulationResult{
		Operation: contract.MfaPolicyOperation(value.Operation), Target: target,
		Effective: contract.MfaPolicyEffectiveSimulation{
			Sources: make([]contract.MfaPolicySimulationSource, len(value.Effective.Sources)),
		},
		Recovery: contract.MfaPolicyRecoverySafety{
			Safe:                         value.Recovery.Safe,
			EligibleDirectAdministrators: value.Recovery.EligibleDirectAdministrators,
			ReadyDirectAdministrators:    value.Recovery.ReadyDirectAdministrators,
			ReasonCodes:                  make([]contract.MfaPolicyRecoveryReason, len(value.Recovery.ReasonCodes)),
		},
	}
	if !result.Operation.Valid() {
		return contract.MfaPolicySimulationResult{}, errors.New("invalid MFA policy operation")
	}
	if value.Context != nil {
		result.Context = mapMFAPolicyContext(*value.Context)
	}
	if value.Current != nil {
		current, mapErr := mapMFAPolicyDocument(*value.Current)
		if mapErr != nil {
			return contract.MfaPolicySimulationResult{}, mapErr
		}
		result.Current = &current
	}
	if value.Candidate != nil {
		candidateTarget, targetErr := mapMFAPolicyTarget(value.Candidate.Target)
		candidateRequirement, requirementErr := mapMFAPolicyRequirement(value.Candidate.Requirement)
		if targetErr != nil || requirementErr != nil {
			return contract.MfaPolicySimulationResult{}, errors.New("invalid MFA policy candidate")
		}
		result.Candidate = &contract.MfaPolicySimulationCandidate{
			Target: candidateTarget, Requirement: candidateRequirement,
		}
	}
	if value.Effective.Requirement != nil {
		requirement, mapErr := mapMFAPolicyRequirement(*value.Effective.Requirement)
		if mapErr != nil {
			return contract.MfaPolicySimulationResult{}, mapErr
		}
		result.Effective.Requirement = &requirement
	}
	for index, source := range value.Effective.Sources {
		mapped, mapErr := mapMFAPolicySource(source)
		if mapErr != nil {
			return contract.MfaPolicySimulationResult{}, mapErr
		}
		result.Effective.Sources[index] = mapped
	}
	for index, reason := range value.Recovery.ReasonCodes {
		mapped := contract.MfaPolicyRecoveryReason(reason)
		if !mapped.Valid() {
			return contract.MfaPolicySimulationResult{}, errors.New("invalid MFA policy recovery reason")
		}
		result.Recovery.ReasonCodes[index] = mapped
	}
	return result, nil
}

func mapMFAPolicySource(value mfa.PolicySimulationSource) (contract.MfaPolicySimulationSource, error) {
	target, err := mapMFAPolicyTarget(value.Target)
	if err != nil {
		return contract.MfaPolicySimulationSource{}, err
	}
	requirement, err := mapMFAPolicyRequirement(value.Requirement)
	if err != nil {
		return contract.MfaPolicySimulationSource{}, err
	}
	result := contract.MfaPolicySimulationSource{
		Source: contract.MfaPolicySimulationSourceSource(value.Source),
		Target: target, Requirement: requirement,
	}
	if !result.Source.Valid() {
		return contract.MfaPolicySimulationSource{}, errors.New("invalid MFA policy source")
	}
	if value.Source == mfa.PolicySimulationCurrentSource {
		policyID := uuid.UUID(value.PolicyID)
		revision := value.Revision
		result.PolicyId = &policyID
		result.Revision = &revision
	}
	return result, nil
}

func mapMFAPolicyTarget(value mfa.AdministrationTarget) (contract.MfaPolicyTarget, error) {
	expectedTenant := value.TenantID
	if value.Scope == mfa.PolicyPlatformFloor {
		expectedTenant = identity.EntityID{}
	}
	if _, err := mfa.NormalizeAdministrationTarget(value, expectedTenant); err != nil {
		return contract.MfaPolicyTarget{}, err
	}
	result := contract.MfaPolicyTarget{}
	switch value.Scope {
	case mfa.PolicyPlatformFloor:
		result.Scope = contract.MfaPolicyScopePlatformFloor
	case mfa.PolicyTenantBaseline:
		result.Scope = contract.MfaPolicyScopeTenantBaseline
	case mfa.PolicySecurityGroup:
		result.Scope = contract.MfaPolicyScopeSecurityGroup
		id := uuid.UUID(value.SecurityGroupID)
		result.SecurityGroupId = &id
	case mfa.PolicyRole:
		result.Scope = contract.MfaPolicyScopeRole
		id := uuid.UUID(value.RoleID)
		result.RoleId = &id
	case mfa.PolicyAction:
		result.Scope = contract.MfaPolicyScopeAction
		action := value.Action
		result.Action = &action
	default:
		return contract.MfaPolicyTarget{}, errors.New("invalid MFA policy scope")
	}
	if value.TenantID != (identity.EntityID{}) {
		id := uuid.UUID(value.TenantID)
		result.TenantId = &id
	}
	return result, nil
}

func mapMFAPolicyRequirement(value mfa.PolicyRequirement) (contract.MfaPolicyRequirement, error) {
	if _, err := mfa.NormalizePolicyRequirement(value); err != nil {
		return contract.MfaPolicyRequirement{}, err
	}
	level := contract.MfaPolicyLevel("")
	switch value.Level {
	case identity.AssurancePrimary:
		level = contract.MfaPolicyLevelPrimary
	case identity.AssuranceMFA:
		level = contract.MfaPolicyLevelMfa
	case identity.AssurancePhishingResistant:
		level = contract.MfaPolicyLevelPhishingResistant
	}
	return contract.MfaPolicyRequirement{
		Level: level, LocalRequired: value.LocalRequired,
		FreshnessSeconds:   int64(value.Freshness / time.Second),
		EnrollmentDeadline: cloneMFAPolicyInstant(value.EnrollmentDeadline),
	}, nil
}

func mapMFAPolicyContext(value mfa.PolicySimulationContext) *contract.MfaPolicySimulationContext {
	result := &contract.MfaPolicySimulationContext{
		RoleIds:          make([]uuid.UUID, len(value.RoleIDs)),
		SecurityGroupIds: make([]uuid.UUID, len(value.SecurityGroupIDs)),
		Action:           value.Action,
	}
	for index := range value.RoleIDs {
		result.RoleIds[index] = uuid.UUID(value.RoleIDs[index])
	}
	for index := range value.SecurityGroupIDs {
		result.SecurityGroupIds[index] = uuid.UUID(value.SecurityGroupIDs[index])
	}
	return result
}

func cloneMFAPolicyInstant(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	result := *value
	return &result
}

func validMFAPolicyUUID(value uuid.UUID) bool {
	return value != uuid.Nil && value.Version() == 7 && value.Variant() == uuid.RFC4122
}
