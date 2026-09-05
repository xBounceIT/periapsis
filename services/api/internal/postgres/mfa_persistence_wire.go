package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/google/uuid"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/mfa"
	"github.com/periapsis-im/periapsis/modules/identity/webauthn"
)

const (
	maximumMFAWireBytes       = 2 * 1024 * 1024
	maximumMFAJSONSafeInteger = int64(9_007_199_254_740_991)
)

var errInvalidMFAWire = errors.New("database returned invalid MFA state")

type assuranceRequirementWire struct {
	Level                string               `json:"level"`
	LocalRequired        bool                 `json:"localRequired"`
	FreshnessNanoseconds int64                `json:"freshnessNanoseconds"`
	EnrollmentDeadline   *time.Time           `json:"enrollmentDeadline"`
	PolicyRevisions      []policyRevisionWire `json:"policyRevisions"`
}

type policyRevisionWire struct {
	PolicyID string `json:"policyId"`
	Revision int64  `json:"revision"`
}

type assuranceEvidenceWire struct {
	Level             string     `json:"level"`
	Kind              string     `json:"kind"`
	Local             bool       `json:"local"`
	ProviderID        string     `json:"providerId,omitempty"`
	BindingID         string     `json:"bindingId,omitempty"`
	AuthenticatedAt   time.Time  `json:"authenticatedAt"`
	ExpiresAt         *time.Time `json:"expiresAt"`
	FactorRevision    *int64     `json:"factorRevision"`
	TrustRuleRevision *int64     `json:"trustRuleRevision"`
}

type stepUpBindingWire struct {
	Flow                     string                   `json:"flow"`
	TenantID                 string                   `json:"tenantId"`
	UserID                   string                   `json:"userId"`
	IdentityEpoch            int64                    `json:"identityEpoch"`
	SessionID                string                   `json:"sessionId,omitempty"`
	SessionFamilyID          string                   `json:"sessionFamilyId,omitempty"`
	ContinuationID           string                   `json:"continuationId,omitempty"`
	AnchorVersion            int64                    `json:"anchorVersion"`
	AnchorExpiresAt          time.Time                `json:"anchorExpiresAt"`
	AnchorRecoveryRestricted bool                     `json:"anchorRecoveryRestricted"`
	Action                   string                   `json:"action"`
	Audience                 string                   `json:"audience"`
	Requirement              assuranceRequirementWire `json:"requirement"`
	BaselineEvidence         []assuranceEvidenceWire  `json:"baselineEvidence"`
}

type webauthnBindingWire struct {
	Purpose                  string                   `json:"purpose"`
	TenantID                 string                   `json:"tenantId"`
	UserID                   string                   `json:"userId,omitempty"`
	IdentityEpoch            int64                    `json:"identityEpoch"`
	SessionID                string                   `json:"sessionId,omitempty"`
	SessionFamilyID          string                   `json:"sessionFamilyId,omitempty"`
	ContinuationID           string                   `json:"continuationId,omitempty"`
	AnchorVersion            int64                    `json:"anchorVersion"`
	AnchorExpiresAt          *time.Time               `json:"anchorExpiresAt"`
	AnchorRecoveryRestricted bool                     `json:"anchorRecoveryRestricted"`
	Action                   string                   `json:"action"`
	Audience                 string                   `json:"audience"`
	Requirement              assuranceRequirementWire `json:"requirement"`
	BaselineEvidence         []assuranceEvidenceWire  `json:"baselineEvidence"`
}

type relyingPartyWire struct {
	ID       string   `json:"id"`
	Origins  []string `json:"origins"`
	Revision int64    `json:"revision"`
}

type ceremonyPolicyWire struct {
	RequireUserPresence bool   `json:"requireUserPresence"`
	UserVerification    string `json:"userVerification"`
	ResidentKey         string `json:"residentKey"`
	Attestation         string `json:"attestation"`
	MetadataRevision    int64  `json:"metadataRevision"`
}

func marshalMFAWire(value any) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) == 0 || len(encoded) > maximumMFAWireBytes {
		return nil, errInvalidMFAWire
	}
	return encoded, nil
}

func unmarshalMFAWire(raw []byte, target any) error {
	if len(raw) == 0 || len(raw) > maximumMFAWireBytes || target == nil {
		return errInvalidMFAWire
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return errInvalidMFAWire
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errInvalidMFAWire
	}
	return nil
}

func queryMFAJSON(ctx context.Context, queryer mfaQueryer, query string, request, response any) error {
	if queryer == nil {
		return errMFAPersistence
	}
	payload, err := marshalMFAWire(request)
	if err != nil {
		return errMFAPersistence
	}
	defer clear(payload)
	var raw []byte
	if err := queryer.QueryRow(ctx, query, payload).Scan(&raw); err != nil {
		return errMFAPersistence
	}
	defer clear(raw)
	if err := unmarshalMFAWire(raw, response); err != nil {
		return errMFAPersistence
	}
	return nil
}

func entityIDWire(value identity.EntityID) string {
	identifier := uuid.UUID(value)
	if identifier == uuid.Nil || identifier.Version() != 7 {
		return ""
	}
	return identifier.String()
}

func parseEntityIDWire(value string, optional bool) (identity.EntityID, error) {
	if value == "" && optional {
		return identity.EntityID{}, nil
	}
	parsed, err := uuid.Parse(value)
	if err != nil {
		return identity.EntityID{}, errInvalidMFAWire
	}
	if parsed == uuid.Nil || parsed.Version() != 7 {
		return identity.EntityID{}, errInvalidMFAWire
	}
	return identity.EntityID(parsed), nil
}

func requirementToWire(value identity.EffectiveAssuranceRequirement) (assuranceRequirementWire, error) {
	level, err := assuranceLevelToWire(value.Level)
	if err != nil || value.Freshness < 0 {
		return assuranceRequirementWire{}, errInvalidMFAWire
	}
	revisions := make([]policyRevisionWire, len(value.PolicyRevisions))
	for index, revision := range value.PolicyRevisions {
		if revision.PolicyID == (identity.EntityID{}) || !validMFAJSONRevision(revision.Revision) {
			return assuranceRequirementWire{}, errInvalidMFAWire
		}
		revisions[index] = policyRevisionWire{PolicyID: entityIDWire(revision.PolicyID), Revision: revision.Revision}
	}
	return assuranceRequirementWire{
		Level: level, LocalRequired: value.LocalRequired,
		FreshnessNanoseconds: int64(value.Freshness), EnrollmentDeadline: copyTimePointer(value.EnrollmentDeadline),
		PolicyRevisions: revisions,
	}, nil
}

func requirementFromWire(value assuranceRequirementWire) (identity.EffectiveAssuranceRequirement, error) {
	level, err := assuranceLevelFromWire(value.Level)
	if err != nil || value.FreshnessNanoseconds < 0 {
		return identity.EffectiveAssuranceRequirement{}, errInvalidMFAWire
	}
	revisions := make([]identity.AssurancePolicyRevision, len(value.PolicyRevisions))
	for index, revision := range value.PolicyRevisions {
		identifier, parseErr := parseEntityIDWire(revision.PolicyID, false)
		if parseErr != nil || !validMFAJSONRevision(revision.Revision) {
			return identity.EffectiveAssuranceRequirement{}, errInvalidMFAWire
		}
		revisions[index] = identity.AssurancePolicyRevision{PolicyID: identifier, Revision: revision.Revision}
	}
	return identity.EffectiveAssuranceRequirement{
		Level: level, LocalRequired: value.LocalRequired,
		Freshness: time.Duration(value.FreshnessNanoseconds), EnrollmentDeadline: copyTimePointer(value.EnrollmentDeadline),
		PolicyRevisions: revisions,
	}, nil
}

func evidenceToWire(values []identity.AssuranceEvidence) ([]assuranceEvidenceWire, error) {
	result := make([]assuranceEvidenceWire, len(values))
	for index, value := range values {
		if !validMFAJSONOptionalRevision(value.FactorRevision) ||
			!validMFAJSONOptionalRevision(value.TrustRuleRevision) {
			return nil, errInvalidMFAWire
		}
		level, err := assuranceLevelToWire(value.Level)
		if err != nil {
			return nil, errInvalidMFAWire
		}
		kind := "factor"
		if value.Kind == identity.AssuranceEvidenceRecovery {
			kind = "recovery"
		} else if value.Kind != identity.AssuranceEvidenceFactor {
			return nil, errInvalidMFAWire
		}
		result[index] = assuranceEvidenceWire{
			Level: level, Kind: kind, Local: value.Source.Local,
			ProviderID: entityIDWire(value.Source.ProviderID), BindingID: entityIDWire(value.Source.BindingID),
			AuthenticatedAt: value.AuthenticatedAt, ExpiresAt: copyTimePointer(value.ExpiresAt),
			FactorRevision: copyInt64Pointer(value.FactorRevision), TrustRuleRevision: copyInt64Pointer(value.TrustRuleRevision),
		}
	}
	return result, nil
}

func evidenceFromWire(values []assuranceEvidenceWire) ([]identity.AssuranceEvidence, error) {
	result := make([]identity.AssuranceEvidence, len(values))
	for index, value := range values {
		if !validMFAJSONOptionalRevision(value.FactorRevision) ||
			!validMFAJSONOptionalRevision(value.TrustRuleRevision) {
			return nil, errInvalidMFAWire
		}
		level, err := assuranceLevelFromWire(value.Level)
		if err != nil {
			return nil, errInvalidMFAWire
		}
		kind := identity.AssuranceEvidenceFactor
		if value.Kind == "recovery" {
			kind = identity.AssuranceEvidenceRecovery
		} else if value.Kind != "factor" {
			return nil, errInvalidMFAWire
		}
		providerID, err := parseEntityIDWire(value.ProviderID, true)
		if err != nil {
			return nil, errInvalidMFAWire
		}
		bindingID, err := parseEntityIDWire(value.BindingID, true)
		if err != nil {
			return nil, errInvalidMFAWire
		}
		result[index] = identity.AssuranceEvidence{
			Level: level, Kind: kind,
			Source:          identity.AssuranceSource{Local: value.Local, ProviderID: providerID, BindingID: bindingID},
			AuthenticatedAt: value.AuthenticatedAt, ExpiresAt: copyTimePointer(value.ExpiresAt),
			FactorRevision: copyInt64Pointer(value.FactorRevision), TrustRuleRevision: copyInt64Pointer(value.TrustRuleRevision),
		}
	}
	return result, nil
}

func stepUpBindingToWire(value mfa.StepUpBinding) (stepUpBindingWire, error) {
	if !validMFAJSONVersion(value.IdentityEpoch) || !validMFAJSONSuccessorVersion(value.AnchorVersion) {
		return stepUpBindingWire{}, errInvalidMFAWire
	}
	flow := ""
	switch value.Flow {
	case mfa.FlowPostPrimaryContinuation:
		flow = "continuation"
	case mfa.FlowExistingSession:
		flow = "session"
	default:
		return stepUpBindingWire{}, errInvalidMFAWire
	}
	requirement, err := requirementToWire(value.Requirement)
	if err != nil {
		return stepUpBindingWire{}, err
	}
	evidence, err := evidenceToWire(value.BaselineEvidence)
	if err != nil {
		return stepUpBindingWire{}, err
	}
	return stepUpBindingWire{
		Flow: flow, TenantID: entityIDWire(value.TenantID), UserID: entityIDWire(value.UserID),
		IdentityEpoch: int64(value.IdentityEpoch), SessionID: entityIDWire(value.SessionID),
		SessionFamilyID: entityIDWire(value.SessionFamilyID), ContinuationID: entityIDWire(value.ContinuationID),
		AnchorVersion: int64(value.AnchorVersion), AnchorExpiresAt: value.AnchorExpiresAt,
		AnchorRecoveryRestricted: value.AnchorRecoveryRestricted, Action: value.Action, Audience: value.Audience,
		Requirement: requirement, BaselineEvidence: evidence,
	}, nil
}

func stepUpBindingFromWire(value stepUpBindingWire) (mfa.StepUpBinding, error) {
	flow := mfa.StepUpFlow(0)
	switch value.Flow {
	case "continuation":
		flow = mfa.FlowPostPrimaryContinuation
	case "session":
		flow = mfa.FlowExistingSession
	default:
		return mfa.StepUpBinding{}, errInvalidMFAWire
	}
	ids, err := parseBindingIDs(value.TenantID, value.UserID, value.SessionID, value.SessionFamilyID, value.ContinuationID)
	if err != nil || !validMFAJSONRevision(value.IdentityEpoch) ||
		!validMFAJSONSuccessorRevision(value.AnchorVersion) {
		return mfa.StepUpBinding{}, errInvalidMFAWire
	}
	requirement, err := requirementFromWire(value.Requirement)
	if err != nil {
		return mfa.StepUpBinding{}, err
	}
	evidence, err := evidenceFromWire(value.BaselineEvidence)
	if err != nil {
		return mfa.StepUpBinding{}, err
	}
	return mfa.StepUpBinding{
		Flow: flow, TenantID: ids[0], UserID: ids[1], IdentityEpoch: uint64(value.IdentityEpoch),
		SessionID: ids[2], SessionFamilyID: ids[3], ContinuationID: ids[4],
		AnchorVersion: uint64(value.AnchorVersion), AnchorExpiresAt: value.AnchorExpiresAt,
		AnchorRecoveryRestricted: value.AnchorRecoveryRestricted, Action: value.Action, Audience: value.Audience,
		Requirement: requirement, BaselineEvidence: evidence,
	}, nil
}

func webauthnBindingToWire(value webauthn.CeremonyBinding) (webauthnBindingWire, error) {
	if value.IdentityEpoch > uint64(maximumMFAJSONSafeInteger) ||
		value.AnchorVersion > 0 && !validMFAJSONSuccessorVersion(value.AnchorVersion) {
		return webauthnBindingWire{}, errInvalidMFAWire
	}
	purpose, err := ceremonyPurposeToWire(value.Purpose)
	if err != nil {
		return webauthnBindingWire{}, err
	}
	requirement, err := requirementToWire(value.Requirement)
	if err != nil {
		return webauthnBindingWire{}, err
	}
	evidence, err := evidenceToWire(value.BaselineEvidence)
	if err != nil {
		return webauthnBindingWire{}, err
	}
	var anchorExpiresAt *time.Time
	if !value.AnchorExpiresAt.IsZero() {
		anchorExpiresAt = copyTimePointer(&value.AnchorExpiresAt)
	}
	return webauthnBindingWire{
		Purpose: purpose, TenantID: entityIDWire(value.TenantID), UserID: entityIDWire(value.UserID),
		IdentityEpoch: int64(value.IdentityEpoch), SessionID: entityIDWire(value.SessionID),
		SessionFamilyID: entityIDWire(value.SessionFamilyID), ContinuationID: entityIDWire(value.ContinuationID),
		AnchorVersion: int64(value.AnchorVersion), AnchorExpiresAt: anchorExpiresAt,
		AnchorRecoveryRestricted: value.AnchorRecoveryRestricted, Action: value.Action, Audience: value.Audience,
		Requirement: requirement, BaselineEvidence: evidence,
	}, nil
}

func webauthnBindingFromWire(value webauthnBindingWire) (webauthn.CeremonyBinding, error) {
	purpose, err := ceremonyPurposeFromWire(value.Purpose)
	if err != nil {
		return webauthn.CeremonyBinding{}, err
	}
	ids, err := parseBindingIDs(value.TenantID, value.UserID, value.SessionID, value.SessionFamilyID, value.ContinuationID)
	if err != nil || value.IdentityEpoch < 0 || value.IdentityEpoch > maximumMFAJSONSafeInteger ||
		value.AnchorVersion < 0 || value.AnchorVersion > 0 && !validMFAJSONSuccessorRevision(value.AnchorVersion) {
		return webauthn.CeremonyBinding{}, errInvalidMFAWire
	}
	requirement, err := requirementFromWire(value.Requirement)
	if err != nil {
		return webauthn.CeremonyBinding{}, err
	}
	evidence, err := evidenceFromWire(value.BaselineEvidence)
	if err != nil {
		return webauthn.CeremonyBinding{}, err
	}
	anchorExpiresAt := time.Time{}
	if value.AnchorExpiresAt != nil {
		anchorExpiresAt = *value.AnchorExpiresAt
	}
	return webauthn.CeremonyBinding{
		Purpose: purpose, TenantID: ids[0], UserID: ids[1], IdentityEpoch: uint64(value.IdentityEpoch),
		SessionID: ids[2], SessionFamilyID: ids[3], ContinuationID: ids[4],
		AnchorVersion: uint64(value.AnchorVersion), AnchorExpiresAt: anchorExpiresAt,
		AnchorRecoveryRestricted: value.AnchorRecoveryRestricted, Action: value.Action, Audience: value.Audience,
		Requirement: requirement, BaselineEvidence: evidence,
	}, nil
}

func parseBindingIDs(values ...string) ([5]identity.EntityID, error) {
	var result [5]identity.EntityID
	for index, value := range values {
		identifier, err := parseEntityIDWire(value, index >= 2 || index == 1)
		if err != nil {
			return [5]identity.EntityID{}, err
		}
		result[index] = identifier
	}
	return result, nil
}

func rpToWire(value webauthn.RelyingParty) (relyingPartyWire, error) {
	if !validMFAJSONVersion(value.Revision()) {
		return relyingPartyWire{}, errInvalidMFAWire
	}
	return relyingPartyWire{ID: value.ID(), Origins: value.Origins(), Revision: int64(value.Revision())}, nil
}

func rpFromWire(value relyingPartyWire) (webauthn.RelyingParty, error) {
	if !validMFAJSONRevision(value.Revision) {
		return webauthn.RelyingParty{}, errInvalidMFAWire
	}
	result, err := webauthn.CompileRelyingParty(value.ID, value.Origins, uint64(value.Revision))
	if err != nil {
		return webauthn.RelyingParty{}, errInvalidMFAWire
	}
	return result, nil
}

func ceremonyPolicyToWire(value webauthn.CeremonyPolicy) (ceremonyPolicyWire, error) {
	verification, err := userVerificationToWire(value.UserVerification)
	if err != nil {
		return ceremonyPolicyWire{}, err
	}
	resident, err := residentKeyToWire(value.ResidentKey)
	if err != nil {
		return ceremonyPolicyWire{}, err
	}
	attestation, err := attestationPolicyToWire(value.Attestation)
	if err != nil || value.MetadataRevision > uint64(maximumMFAJSONSafeInteger) {
		return ceremonyPolicyWire{}, errInvalidMFAWire
	}
	return ceremonyPolicyWire{
		RequireUserPresence: value.RequireUserPresence, UserVerification: verification,
		ResidentKey: resident, Attestation: attestation, MetadataRevision: int64(value.MetadataRevision),
	}, nil
}

func ceremonyPolicyFromWire(value ceremonyPolicyWire) (webauthn.CeremonyPolicy, error) {
	verification, err := userVerificationFromWire(value.UserVerification)
	if err != nil {
		return webauthn.CeremonyPolicy{}, err
	}
	resident, err := residentKeyFromWire(value.ResidentKey)
	if err != nil {
		return webauthn.CeremonyPolicy{}, err
	}
	attestation, err := attestationPolicyFromWire(value.Attestation)
	if err != nil || value.MetadataRevision < 0 || value.MetadataRevision > maximumMFAJSONSafeInteger {
		return webauthn.CeremonyPolicy{}, errInvalidMFAWire
	}
	return webauthn.CeremonyPolicy{
		RequireUserPresence: value.RequireUserPresence, UserVerification: verification,
		ResidentKey: resident, Attestation: attestation, MetadataRevision: uint64(value.MetadataRevision),
	}, nil
}

func assuranceLevelToWire(value identity.AssuranceLevel) (string, error) {
	switch value {
	case identity.AssurancePrimary:
		return "primary", nil
	case identity.AssuranceMFA:
		return "mfa", nil
	case identity.AssurancePhishingResistant:
		return "phishing_resistant", nil
	default:
		return "", errInvalidMFAWire
	}
}

func assuranceLevelFromWire(value string) (identity.AssuranceLevel, error) {
	switch value {
	case "primary":
		return identity.AssurancePrimary, nil
	case "mfa":
		return identity.AssuranceMFA, nil
	case "phishing_resistant":
		return identity.AssurancePhishingResistant, nil
	default:
		return 0, errInvalidMFAWire
	}
}

func ceremonyPurposeToWire(value webauthn.CeremonyPurpose) (string, error) {
	switch value {
	case webauthn.PurposeRegistration:
		return "registration", nil
	case webauthn.PurposePrimaryAuthentication:
		return "primary_authentication", nil
	case webauthn.PurposeContinuationAuthentication:
		return "continuation_authentication", nil
	case webauthn.PurposeStepUpAuthentication:
		return "step_up_authentication", nil
	default:
		return "", errInvalidMFAWire
	}
}

func ceremonyPurposeFromWire(value string) (webauthn.CeremonyPurpose, error) {
	switch value {
	case "registration":
		return webauthn.PurposeRegistration, nil
	case "primary_authentication":
		return webauthn.PurposePrimaryAuthentication, nil
	case "continuation_authentication":
		return webauthn.PurposeContinuationAuthentication, nil
	case "step_up_authentication":
		return webauthn.PurposeStepUpAuthentication, nil
	default:
		return 0, errInvalidMFAWire
	}
}

func userVerificationToWire(value webauthn.UserVerificationRequirement) (string, error) {
	if value == webauthn.UserVerificationPreferred {
		return "preferred", nil
	}
	if value == webauthn.UserVerificationRequired {
		return "required", nil
	}
	return "", errInvalidMFAWire
}

func userVerificationFromWire(value string) (webauthn.UserVerificationRequirement, error) {
	if value == "preferred" {
		return webauthn.UserVerificationPreferred, nil
	}
	if value == "required" {
		return webauthn.UserVerificationRequired, nil
	}
	return 0, errInvalidMFAWire
}

func residentKeyToWire(value webauthn.ResidentKeyRequirement) (string, error) {
	if value == webauthn.ResidentKeyPreferred {
		return "preferred", nil
	}
	if value == webauthn.ResidentKeyRequired {
		return "required", nil
	}
	return "", errInvalidMFAWire
}

func residentKeyFromWire(value string) (webauthn.ResidentKeyRequirement, error) {
	if value == "preferred" {
		return webauthn.ResidentKeyPreferred, nil
	}
	if value == "required" {
		return webauthn.ResidentKeyRequired, nil
	}
	return 0, errInvalidMFAWire
}

func attestationPolicyToWire(value webauthn.AttestationPolicy) (string, error) {
	switch value {
	case webauthn.AttestationNone:
		return "none", nil
	case webauthn.AttestationDirect:
		return "direct", nil
	case webauthn.AttestationEnterprise:
		return "enterprise", nil
	default:
		return "", errInvalidMFAWire
	}
}

func attestationPolicyFromWire(value string) (webauthn.AttestationPolicy, error) {
	switch value {
	case "none":
		return webauthn.AttestationNone, nil
	case "direct":
		return webauthn.AttestationDirect, nil
	case "enterprise":
		return webauthn.AttestationEnterprise, nil
	default:
		return 0, errInvalidMFAWire
	}
}

func copyTimePointer(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	copyValue := *value
	return &copyValue
}

func copyInt64Pointer(value *int64) *int64 {
	if value == nil {
		return nil
	}
	copyValue := *value
	return &copyValue
}

func validMFAJSONVersion(value uint64) bool {
	return value > 0 && value <= uint64(maximumMFAJSONSafeInteger)
}

func validMFAJSONSuccessorVersion(value uint64) bool {
	return value > 0 && value < uint64(maximumMFAJSONSafeInteger)
}

func validMFAJSONRevision(value int64) bool {
	return value > 0 && value <= maximumMFAJSONSafeInteger
}

func validMFAJSONSuccessorRevision(value int64) bool {
	return value > 0 && value < maximumMFAJSONSafeInteger
}

func validMFAJSONOptionalRevision(value *int64) bool {
	return value == nil || validMFAJSONRevision(*value)
}
