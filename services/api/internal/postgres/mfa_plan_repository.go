package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/mfa"
	"github.com/periapsis-im/periapsis/modules/identity/webauthn"
	"github.com/periapsis-im/periapsis/services/api/internal/mfaauth"
)

const (
	resolveMFAAuthoritySQL = `
with resolved as (
  select app.resolve_mfa_authority_v2(
    $1::uuid, $2::text, $3::text, $4::text, $5::timestamptz, $6::bytea
  ) as value
)
select jsonb_strip_nulls(jsonb_build_object(
  'loadedAt', value -> 'loadedAt',
  'flow', value -> 'flow',
  'tenantId', value -> 'tenantId',
  'userId', value -> 'userId',
  'identityEpoch', value -> 'identityEpoch',
  'sessionId', value -> 'sessionId',
  'sessionFamilyId', value -> 'sessionFamilyId',
  'continuationId', value -> 'continuationId',
  'anchorVersion', value -> 'anchorVersion',
  'anchorExpiresAt', value -> 'anchorExpiresAt',
  'anchorRecoveryRestricted', value -> 'anchorRecoveryRestricted',
  'action', value -> 'action',
  'audience', value -> 'audience',
  'policyContext', value -> 'policyContext',
  'policies', value -> 'policies',
  'baselineEvidence', value -> 'baselineEvidence',
  'totpFactorIds', value -> 'totpFactorIds',
  'recoveryAvailable', value -> 'recoveryAvailable',
  'recoverySetId', value -> 'recoverySetId',
  'recoverySetVersion', value -> 'recoverySetVersion',
  'passkeyUserHandle', value -> 'passkeyUserHandle',
  'passkeyCredentialIds', value -> 'passkeyCredentialIds'
))
from resolved`
	resolvePrimaryPasskeySQL = `select app.resolve_primary_passkey_v1($1::uuid, $2::text, $3::text, $4::timestamptz)`
)

type MFAPlanRepositoryOptions struct {
	Pool               *pgxpool.Pool
	RelyingParty       webauthn.RelyingParty
	RegistrationPolicy webauthn.CeremonyPolicy
	PrimaryPolicy      webauthn.CeremonyPolicy
	StepUpPolicy       webauthn.CeremonyPolicy
	PasskeyEnabled     bool
}

// MFAPlanRepository reloads live authority and factor inventory for every
// start operation. RP/origin and ceremony policy are deployment pins, never
// accepted from the browser or an untrusted database row.
type MFAPlanRepository struct {
	queryer            mfaQueryer
	rp                 webauthn.RelyingParty
	registrationPolicy webauthn.CeremonyPolicy
	primaryPolicy      webauthn.CeremonyPolicy
	stepUpPolicy       webauthn.CeremonyPolicy
	passkeyEnabled     bool
}

var (
	_ mfaauth.LocalStepUpSource      = (*MFAPlanRepository)(nil)
	_ mfaauth.FactorEnrollmentSource = (*MFAPlanRepository)(nil)
	_ mfaauth.PasskeyPlanSource      = (*MFAPlanRepository)(nil)
)

func NewMFAPlanRepository(options MFAPlanRepositoryOptions) (*MFAPlanRepository, error) {
	if options.Pool == nil {
		return nil, errors.New("MFA plan repository requires a database pool")
	}
	passkeyEnabled := options.PasskeyEnabled || options.RelyingParty.ID() != ""
	compiled := webauthn.RelyingParty{}
	if passkeyEnabled {
		var err error
		compiled, err = webauthn.CompileRelyingParty(
			options.RelyingParty.ID(), options.RelyingParty.Origins(), options.RelyingParty.Revision(),
		)
		if err != nil || compiled.ID() != options.RelyingParty.ID() || compiled.Revision() != options.RelyingParty.Revision() {
			return nil, errors.New("MFA plan repository requires a valid relying party")
		}
		for _, policy := range []webauthn.CeremonyPolicy{
			options.RegistrationPolicy, options.PrimaryPolicy, options.StepUpPolicy,
		} {
			if _, err := ceremonyPolicyToWire(policy); err != nil || !policy.RequireUserPresence {
				return nil, errors.New("MFA plan repository requires valid ceremony policies")
			}
		}
	}
	return &MFAPlanRepository{
		queryer: options.Pool, rp: compiled, passkeyEnabled: passkeyEnabled,
		registrationPolicy: options.RegistrationPolicy,
		primaryPolicy:      options.PrimaryPolicy, stepUpPolicy: options.StepUpPolicy,
	}, nil
}

// newMFAPlanRepositoryWithQueryer is intentionally test-only at the package
// boundary; production composition always uses NewMFAPlanRepository.
func newMFAPlanRepositoryWithQueryer(
	queryer mfaQueryer,
	rp webauthn.RelyingParty,
	registrationPolicy, primaryPolicy, stepUpPolicy webauthn.CeremonyPolicy,
) *MFAPlanRepository {
	return &MFAPlanRepository{
		queryer: queryer, rp: rp, passkeyEnabled: rp.ID() != "", registrationPolicy: registrationPolicy,
		primaryPolicy: primaryPolicy, stepUpPolicy: stepUpPolicy,
	}
}

type policyContextWire struct {
	TenantID         string   `json:"tenantId"`
	RoleIDs          []string `json:"roleIds"`
	SecurityGroupIDs []string `json:"securityGroupIds"`
	Action           string   `json:"action"`
}

type assurancePolicyWire struct {
	ID                   string     `json:"id"`
	Revision             int64      `json:"revision"`
	Level                string     `json:"level"`
	LocalRequired        bool       `json:"localRequired"`
	FreshnessNanoseconds int64      `json:"freshnessNanoseconds"`
	EnrollmentDeadline   *time.Time `json:"enrollmentDeadline"`
}

type scopedPolicyWire struct {
	Scope    string              `json:"scope"`
	TenantID string              `json:"tenantId,omitempty"`
	TargetID string              `json:"targetId,omitempty"`
	Action   string              `json:"action,omitempty"`
	Policy   assurancePolicyWire `json:"policy"`
}

type authoritySnapshotInputWire struct {
	LoadedAt                 time.Time               `json:"loadedAt"`
	Flow                     string                  `json:"flow"`
	TenantID                 string                  `json:"tenantId"`
	UserID                   string                  `json:"userId"`
	IdentityEpoch            int64                   `json:"identityEpoch"`
	SessionID                string                  `json:"sessionId,omitempty"`
	SessionFamilyID          string                  `json:"sessionFamilyId,omitempty"`
	ContinuationID           string                  `json:"continuationId,omitempty"`
	AnchorVersion            int64                   `json:"anchorVersion"`
	AnchorExpiresAt          time.Time               `json:"anchorExpiresAt"`
	AnchorRecoveryRestricted bool                    `json:"anchorRecoveryRestricted"`
	Action                   string                  `json:"action"`
	Audience                 string                  `json:"audience"`
	PolicyContext            policyContextWire       `json:"policyContext"`
	Policies                 []scopedPolicyWire      `json:"policies"`
	BaselineEvidence         []assuranceEvidenceWire `json:"baselineEvidence"`
	TOTPFactorIDs            []string                `json:"totpFactorIds"`
	RecoveryAvailable        bool                    `json:"recoveryAvailable"`
	RecoverySetID            string                  `json:"recoverySetId,omitempty"`
	RecoverySetVersion       int64                   `json:"recoverySetVersion"`
	PasskeyUserHandle        []byte                  `json:"passkeyUserHandle,omitempty"`
	PasskeyCredentialIDs     [][]byte                `json:"passkeyCredentialIds"`
}

type primaryPasskeyInputWire struct {
	ReferenceID   string             `json:"referenceId"`
	LoadedAt      time.Time          `json:"loadedAt"`
	TenantID      string             `json:"tenantId"`
	UserID        string             `json:"userId,omitempty"`
	IdentityEpoch int64              `json:"identityEpoch"`
	Action        string             `json:"action"`
	Audience      string             `json:"audience"`
	PolicyContext policyContextWire  `json:"policyContext"`
	Policies      []scopedPolicyWire `json:"policies"`
	Mode          string             `json:"mode"`
	UserHandle    []byte             `json:"userHandle,omitempty"`
	CredentialIDs [][]byte           `json:"credentialIds"`
}

func (repository *MFAPlanRepository) ResolveLocalStepUp(
	ctx context.Context,
	lookup mfaauth.AuthorityLookup,
) (mfaauth.AuthoritySnapshot, error) {
	input, err := repository.resolveAuthority(ctx, lookup)
	if err != nil {
		return mfaauth.AuthoritySnapshot{}, errMFAPersistence
	}
	return mfaauth.NewAuthoritySnapshot(input)
}

func (repository *MFAPlanRepository) ResolveFactorEnrollment(
	ctx context.Context,
	lookup mfaauth.AuthorityLookup,
) (mfaauth.AuthoritySnapshot, error) {
	return repository.ResolveLocalStepUp(ctx, lookup)
}

func (repository *MFAPlanRepository) ResolvePasskeyRegistration(
	ctx context.Context,
	lookup mfaauth.PasskeyLookup,
) (mfaauth.PasskeyRegistrationPlan, error) {
	if lookup.Purpose != webauthn.PurposeRegistration {
		return mfaauth.PasskeyRegistrationPlan{}, errMFAPersistence
	}
	if repository == nil || !repository.passkeyEnabled {
		return mfaauth.PasskeyRegistrationPlan{}, errMFAPersistence
	}
	flow, err := lookupFlowForPurpose(lookup.Purpose)
	if err != nil {
		return mfaauth.PasskeyRegistrationPlan{}, errMFAPersistence
	}
	input, err := repository.resolveAuthorityFields(
		ctx, lookup.ReferenceID, flow, lookup.Action, lookup.Audience, lookup.EvaluatedAt(),
		lookup.ContinuationReceiptDigest,
	)
	if err != nil {
		return mfaauth.PasskeyRegistrationPlan{}, errMFAPersistence
	}
	authority, err := mfaauth.NewAuthoritySnapshot(input)
	if err != nil {
		return mfaauth.PasskeyRegistrationPlan{}, errMFAPersistence
	}
	return mfaauth.NewPasskeyRegistrationPlan(
		lookup.ReferenceID, authority, repository.rp, repository.registrationPolicy,
	)
}

func (repository *MFAPlanRepository) ResolvePasskeyAuthentication(
	ctx context.Context,
	lookup mfaauth.PasskeyLookup,
) (mfaauth.PasskeyAuthenticationPlan, error) {
	if repository == nil || repository.queryer == nil || !repository.passkeyEnabled {
		return mfaauth.PasskeyAuthenticationPlan{}, errMFAPersistence
	}
	if lookup.Purpose == webauthn.PurposePrimaryAuthentication {
		var raw []byte
		if err := repository.queryer.QueryRow(
			ctx, resolvePrimaryPasskeySQL, entityIDWire(lookup.ReferenceID), lookup.Action,
			lookup.Audience, databaseTime(lookup.EvaluatedAt()),
		).Scan(&raw); err != nil {
			return mfaauth.PasskeyAuthenticationPlan{}, errMFAPersistence
		}
		defer clear(raw)
		var wire primaryPasskeyInputWire
		if err := unmarshalMFAWire(raw, &wire); err != nil {
			return mfaauth.PasskeyAuthenticationPlan{}, errMFAPersistence
		}
		input, err := primaryPasskeyInputFromWire(wire, repository.rp, repository.primaryPolicy)
		if err != nil {
			return mfaauth.PasskeyAuthenticationPlan{}, errMFAPersistence
		}
		return mfaauth.NewPrimaryPasskeyPlan(input)
	}
	flow, err := lookupFlowForPurpose(lookup.Purpose)
	if err != nil {
		return mfaauth.PasskeyAuthenticationPlan{}, errMFAPersistence
	}
	input, err := repository.resolveAuthorityFields(
		ctx, lookup.ReferenceID, flow, lookup.Action, lookup.Audience, lookup.EvaluatedAt(),
		lookup.ContinuationReceiptDigest,
	)
	if err != nil {
		return mfaauth.PasskeyAuthenticationPlan{}, errMFAPersistence
	}
	authority, err := mfaauth.NewAuthoritySnapshot(input)
	if err != nil {
		return mfaauth.PasskeyAuthenticationPlan{}, errMFAPersistence
	}
	return mfaauth.NewStepUpPasskeyPlan(
		lookup.ReferenceID, authority, repository.rp, repository.stepUpPolicy,
	)
}

func (repository *MFAPlanRepository) resolveAuthority(
	ctx context.Context,
	lookup mfaauth.AuthorityLookup,
) (mfaauth.AuthoritySnapshotInput, error) {
	flow := ""
	switch lookup.Flow {
	case mfa.FlowPostPrimaryContinuation:
		flow = "continuation"
	case mfa.FlowExistingSession:
		flow = "session"
	default:
		return mfaauth.AuthoritySnapshotInput{}, errMFAPersistence
	}
	return repository.resolveAuthorityFields(
		ctx, lookup.AnchorID, flow, lookup.Action, lookup.Audience, lookup.EvaluatedAt(),
		lookup.ContinuationReceiptDigest,
	)
}

func (repository *MFAPlanRepository) resolveAuthorityFields(
	ctx context.Context,
	referenceID identity.EntityID,
	flow string,
	action string,
	audience string,
	evaluatedAt time.Time,
	continuationReceiptDigest [32]byte,
) (mfaauth.AuthoritySnapshotInput, error) {
	if repository == nil || repository.queryer == nil {
		return mfaauth.AuthoritySnapshotInput{}, errMFAPersistence
	}
	var raw []byte
	if err := repository.queryer.QueryRow(
		ctx, resolveMFAAuthoritySQL, entityIDWire(referenceID), flow, action, audience, databaseTime(evaluatedAt),
		digestArgument(continuationReceiptDigest),
	).Scan(&raw); err != nil {
		return mfaauth.AuthoritySnapshotInput{}, errMFAPersistence
	}
	defer clear(raw)
	var wire authoritySnapshotInputWire
	if err := unmarshalMFAWire(raw, &wire); err != nil {
		return mfaauth.AuthoritySnapshotInput{}, errMFAPersistence
	}
	input, err := authoritySnapshotInputFromWire(wire)
	if err != nil {
		return mfaauth.AuthoritySnapshotInput{}, err
	}
	input.ContinuationReceiptDigest = continuationReceiptDigest
	return input, nil
}

func digestArgument(value [32]byte) []byte {
	if value == ([32]byte{}) {
		return nil
	}
	return append([]byte(nil), value[:]...)
}

func authoritySnapshotInputFromWire(value authoritySnapshotInputWire) (mfaauth.AuthoritySnapshotInput, error) {
	flow := mfa.StepUpFlow(0)
	switch value.Flow {
	case "continuation":
		flow = mfa.FlowPostPrimaryContinuation
	case "session":
		flow = mfa.FlowExistingSession
	default:
		return mfaauth.AuthoritySnapshotInput{}, errInvalidMFAWire
	}
	ids, err := parseAuthorityInputIDs(
		value.TenantID, value.UserID, value.SessionID, value.SessionFamilyID,
		value.ContinuationID, value.RecoverySetID,
	)
	if err != nil || !validMFAJSONRevision(value.IdentityEpoch) ||
		!validMFAJSONSuccessorRevision(value.AnchorVersion) || value.RecoverySetVersion < 0 ||
		value.RecoverySetVersion > 0 && !validMFAJSONSuccessorRevision(value.RecoverySetVersion) {
		return mfaauth.AuthoritySnapshotInput{}, errInvalidMFAWire
	}
	contextValue, err := policyContextFromWire(value.PolicyContext)
	if err != nil {
		return mfaauth.AuthoritySnapshotInput{}, err
	}
	policies, err := scopedPoliciesFromWire(value.Policies)
	if err != nil {
		return mfaauth.AuthoritySnapshotInput{}, err
	}
	evidence, err := evidenceFromWire(value.BaselineEvidence)
	if err != nil {
		return mfaauth.AuthoritySnapshotInput{}, err
	}
	totp, err := parseEntityIDList(value.TOTPFactorIDs)
	if err != nil {
		return mfaauth.AuthoritySnapshotInput{}, err
	}
	return mfaauth.AuthoritySnapshotInput{
		LoadedAt: value.LoadedAt.UTC(), Flow: flow, TenantID: ids[0], UserID: ids[1],
		IdentityEpoch: uint64(value.IdentityEpoch), SessionID: ids[2], SessionFamilyID: ids[3],
		ContinuationID: ids[4], AnchorVersion: uint64(value.AnchorVersion),
		AnchorExpiresAt: value.AnchorExpiresAt.UTC(), AnchorRecoveryRestricted: value.AnchorRecoveryRestricted,
		Action: value.Action, Audience: value.Audience, PolicyContext: contextValue, Policies: policies,
		BaselineEvidence: evidence, TOTPFactorIDs: totp, RecoveryAvailable: value.RecoveryAvailable,
		RecoverySetID: ids[5], RecoverySetVersion: uint64(value.RecoverySetVersion),
		PasskeyUserHandle:    append([]byte(nil), value.PasskeyUserHandle...),
		PasskeyCredentialIDs: cloneWireBytes2D(value.PasskeyCredentialIDs),
	}, nil
}

func primaryPasskeyInputFromWire(
	value primaryPasskeyInputWire,
	rp webauthn.RelyingParty,
	policy webauthn.CeremonyPolicy,
) (mfaauth.PrimaryPasskeyPlanInput, error) {
	referenceID, err := parseEntityIDWire(value.ReferenceID, false)
	if err != nil {
		return mfaauth.PrimaryPasskeyPlanInput{}, err
	}
	tenantID, err := parseEntityIDWire(value.TenantID, false)
	if err != nil {
		return mfaauth.PrimaryPasskeyPlanInput{}, err
	}
	userID, err := parseEntityIDWire(value.UserID, true)
	if err != nil || value.IdentityEpoch < 0 || value.IdentityEpoch > maximumMFAJSONSafeInteger {
		return mfaauth.PrimaryPasskeyPlanInput{}, errInvalidMFAWire
	}
	contextValue, err := policyContextFromWire(value.PolicyContext)
	if err != nil {
		return mfaauth.PrimaryPasskeyPlanInput{}, err
	}
	policies, err := scopedPoliciesFromWire(value.Policies)
	if err != nil {
		return mfaauth.PrimaryPasskeyPlanInput{}, err
	}
	mode, err := authenticationModeFromWire(value.Mode, false)
	if err != nil {
		return mfaauth.PrimaryPasskeyPlanInput{}, err
	}
	return mfaauth.PrimaryPasskeyPlanInput{
		ReferenceID: referenceID, LoadedAt: value.LoadedAt.UTC(), TenantID: tenantID, UserID: userID,
		IdentityEpoch: uint64(value.IdentityEpoch), Action: value.Action, Audience: value.Audience,
		PolicyContext: contextValue, Policies: policies, RP: rp, Policy: policy, Mode: mode,
		UserHandle: append([]byte(nil), value.UserHandle...), CredentialIDs: cloneWireBytes2D(value.CredentialIDs),
	}, nil
}

func policyContextFromWire(value policyContextWire) (mfa.PolicyContext, error) {
	tenantID, err := parseEntityIDWire(value.TenantID, false)
	if err != nil {
		return mfa.PolicyContext{}, err
	}
	roles, err := parseEntityIDList(value.RoleIDs)
	if err != nil {
		return mfa.PolicyContext{}, err
	}
	groups, err := parseEntityIDList(value.SecurityGroupIDs)
	if err != nil {
		return mfa.PolicyContext{}, err
	}
	return mfa.PolicyContext{
		TenantID: tenantID, RoleIDs: roles, SecurityGroupIDs: groups, Action: value.Action,
	}, nil
}

func scopedPoliciesFromWire(values []scopedPolicyWire) ([]mfa.ScopedPolicy, error) {
	result := make([]mfa.ScopedPolicy, len(values))
	for index, value := range values {
		scope, err := policyScopeFromWire(value.Scope)
		if err != nil {
			return nil, err
		}
		tenantID, err := parseEntityIDWire(value.TenantID, true)
		if err != nil {
			return nil, err
		}
		targetID, err := parseEntityIDWire(value.TargetID, true)
		if err != nil {
			return nil, err
		}
		policy, err := assurancePolicyFromWire(value.Policy)
		if err != nil {
			return nil, err
		}
		result[index] = mfa.ScopedPolicy{
			Scope: scope, TenantID: tenantID, TargetID: targetID, Action: value.Action, Policy: policy,
		}
	}
	return result, nil
}

func assurancePolicyFromWire(value assurancePolicyWire) (identity.AssurancePolicy, error) {
	identifier, err := parseEntityIDWire(value.ID, false)
	if err != nil || !validMFAJSONRevision(value.Revision) || value.FreshnessNanoseconds < 0 {
		return identity.AssurancePolicy{}, errInvalidMFAWire
	}
	level, err := assuranceLevelFromWire(value.Level)
	if err != nil {
		return identity.AssurancePolicy{}, err
	}
	return identity.AssurancePolicy{
		ID: identifier, Revision: value.Revision, Level: level, LocalRequired: value.LocalRequired,
		Freshness: time.Duration(value.FreshnessNanoseconds), EnrollmentDeadline: copyTimePointer(value.EnrollmentDeadline),
	}, nil
}

func policyScopeFromWire(value string) (mfa.PolicyScope, error) {
	switch value {
	case "platform_floor":
		return mfa.PolicyPlatformFloor, nil
	case "tenant_baseline":
		return mfa.PolicyTenantBaseline, nil
	case "security_group":
		return mfa.PolicySecurityGroup, nil
	case "role":
		return mfa.PolicyRole, nil
	case "action":
		return mfa.PolicyAction, nil
	default:
		return 0, errInvalidMFAWire
	}
}

func lookupFlowForPurpose(value webauthn.CeremonyPurpose) (string, error) {
	switch value {
	case webauthn.PurposeRegistration:
		// Enrollment may be anchored by either an existing repair session or a
		// post-primary continuation. The protected resolver requires exactly
		// one live match and returns the concrete flow in its snapshot.
		return "enrollment", nil
	case webauthn.PurposeStepUpAuthentication:
		return "session", nil
	case webauthn.PurposeContinuationAuthentication:
		return "continuation", nil
	default:
		return "", errInvalidMFAWire
	}
}

func parseAuthorityInputIDs(values ...string) ([6]identity.EntityID, error) {
	var result [6]identity.EntityID
	for index, value := range values {
		identifier, err := parseEntityIDWire(value, index >= 2)
		if err != nil {
			return [6]identity.EntityID{}, err
		}
		result[index] = identifier
	}
	return result, nil
}

func parseEntityIDList(values []string) ([]identity.EntityID, error) {
	result := make([]identity.EntityID, len(values))
	for index, value := range values {
		identifier, err := parseEntityIDWire(value, false)
		if err != nil {
			return nil, err
		}
		result[index] = identifier
	}
	return result, nil
}
