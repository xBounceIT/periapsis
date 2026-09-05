package mfaauth

import (
	"bytes"
	"cmp"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/mfa"
)

const (
	stableUserHandleBytes  = 32
	maximumTOTPFactors     = 16
	maximumPasskeyFactors  = 128
	maximumCredentialBytes = 4 * 1024
	maximumStoredVersion   = uint64(9_007_199_254_740_991)
)

type AuthorityLookup struct {
	Flow                      mfa.StepUpFlow
	AnchorID                  identity.EntityID
	Action                    string
	Audience                  string
	Admission                 AdmissionContext
	ContinuationReceiptDigest [sha256.Size]byte `json:"-"`
	evaluatedAt               time.Time
}

func (lookup AuthorityLookup) String() string {
	return fmt.Sprintf("mfaauth.AuthorityLookup{flow:%d,action:%t,audience:%t,anchor:[REDACTED]}",
		lookup.Flow, lookup.Action != "", lookup.Audience != "")
}
func (lookup AuthorityLookup) GoString() string       { return lookup.String() }
func (lookup AuthorityLookup) EvaluatedAt() time.Time { return lookup.evaluatedAt }

type AuthoritySnapshotInput struct {
	LoadedAt                  time.Time
	Flow                      mfa.StepUpFlow
	TenantID                  identity.EntityID
	UserID                    identity.EntityID
	IdentityEpoch             uint64
	SessionID                 identity.EntityID
	SessionFamilyID           identity.EntityID
	ContinuationID            identity.EntityID
	AnchorVersion             uint64
	AnchorExpiresAt           time.Time
	AnchorRecoveryRestricted  bool
	Action                    string
	Audience                  string
	PolicyContext             mfa.PolicyContext
	Policies                  []mfa.ScopedPolicy
	BaselineEvidence          []identity.AssuranceEvidence
	TOTPFactorIDs             []identity.EntityID
	RecoveryAvailable         bool
	RecoverySetID             identity.EntityID
	RecoverySetVersion        uint64
	PasskeyUserHandle         []byte
	PasskeyCredentialIDs      [][]byte
	ContinuationReceiptDigest [sha256.Size]byte `json:"-"`
}

func (input AuthoritySnapshotInput) String() string {
	return fmt.Sprintf(
		"mfaauth.AuthoritySnapshotInput{flow:%d,policies:%d,evidence:%d,totp:%d,passkeys:%d,provenance:[REDACTED]}",
		input.Flow, len(input.Policies), len(input.BaselineEvidence), len(input.TOTPFactorIDs),
		len(input.PasskeyCredentialIDs),
	)
}
func (input AuthoritySnapshotInput) GoString() string { return input.String() }

// AuthoritySnapshot is constructor-only. It combines the exact live anchor,
// deterministic effective policy, evidence provenance, and factor inventory
// loaded by one deny-by-default repository projection.
type AuthoritySnapshot struct {
	loadedAt                  time.Time
	flow                      mfa.StepUpFlow
	tenantID                  identity.EntityID
	userID                    identity.EntityID
	identityEpoch             uint64
	sessionID                 identity.EntityID
	sessionFamilyID           identity.EntityID
	continuationID            identity.EntityID
	anchorVersion             uint64
	anchorExpiresAt           time.Time
	anchorRecoveryRestricted  bool
	action                    string
	audience                  string
	resolved                  mfa.ResolvedPolicy
	evidence                  []identity.AssuranceEvidence
	totpFactorIDs             []identity.EntityID
	recoveryAvailable         bool
	recoverySetID             identity.EntityID
	recoverySetVersion        uint64
	passkeyUserHandle         []byte
	passkeyIDs                [][]byte
	continuationReceiptDigest [sha256.Size]byte
}

func NewAuthoritySnapshot(input AuthoritySnapshotInput) (AuthoritySnapshot, error) {
	if !validInstant(input.LoadedAt) || input.TenantID == (identity.EntityID{}) ||
		input.UserID == (identity.EntityID{}) || !validStoredVersion(input.IdentityEpoch) ||
		!validPublicText(input.Action, 256) || !validPublicText(input.Audience, 256) ||
		!validStoredSuccessorVersion(input.AnchorVersion) ||
		!validDeadline(input.AnchorExpiresAt) || !input.AnchorExpiresAt.After(input.LoadedAt) ||
		input.PolicyContext.TenantID != input.TenantID || input.PolicyContext.Action != input.Action ||
		!validAuthorityAnchor(input) ||
		!validContinuationReceiptForFlow(input.Flow, input.ContinuationReceiptDigest) {
		return AuthoritySnapshot{}, ErrInvalidInput
	}
	resolved, err := mfa.ResolvePolicy(input.PolicyContext, input.Policies)
	if err != nil {
		return AuthoritySnapshot{}, ErrDenied
	}
	evidence, evidenceOK := normalizeEvidence(input.BaselineEvidence)
	if !evidenceOK || len(evidence) == 0 || evidenceFromFuture(input.LoadedAt, evidence) ||
		identity.EvaluateAssurance(input.LoadedAt, resolved.Requirement, evidence, true) == identity.AssuranceDenied {
		return AuthoritySnapshot{}, ErrDenied
	}
	if input.AnchorRecoveryRestricted && !hasLiveRecoveryEvidence(input.LoadedAt, evidence) {
		return AuthoritySnapshot{}, ErrDenied
	}
	totp, ok := normalizeIDs(input.TOTPFactorIDs, maximumTOTPFactors)
	if !ok {
		return AuthoritySnapshot{}, ErrInvalidInput
	}
	passkeys, ok := normalizeCredentialIDs(input.PasskeyCredentialIDs)
	if !ok || input.RecoveryAvailable != (input.RecoverySetID != (identity.EntityID{})) ||
		input.RecoveryAvailable && !validStoredSuccessorVersion(input.RecoverySetVersion) ||
		!input.RecoveryAvailable && input.RecoverySetVersion != 0 ||
		len(input.PasskeyUserHandle) != 0 &&
			(len(input.PasskeyUserHandle) != stableUserHandleBytes || allZeroMaterial(input.PasskeyUserHandle)) ||
		len(passkeys) > 0 && len(input.PasskeyUserHandle) != stableUserHandleBytes {
		return AuthoritySnapshot{}, ErrInvalidInput
	}
	return AuthoritySnapshot{
		loadedAt: input.LoadedAt, flow: input.Flow, tenantID: input.TenantID, userID: input.UserID,
		identityEpoch: input.IdentityEpoch,
		sessionID:     input.SessionID, sessionFamilyID: input.SessionFamilyID,
		continuationID: input.ContinuationID, anchorVersion: input.AnchorVersion,
		anchorExpiresAt:          input.AnchorExpiresAt,
		anchorRecoveryRestricted: input.AnchorRecoveryRestricted,
		action:                   input.Action, audience: input.Audience, resolved: cloneResolved(resolved), evidence: evidence,
		totpFactorIDs: totp, recoveryAvailable: input.RecoveryAvailable,
		recoverySetID: input.RecoverySetID, recoverySetVersion: input.RecoverySetVersion,
		passkeyUserHandle: append([]byte(nil), input.PasskeyUserHandle...), passkeyIDs: passkeys,
		continuationReceiptDigest: input.ContinuationReceiptDigest,
	}, nil
}

func validStoredVersion(value uint64) bool { return value > 0 && value <= maximumStoredVersion }

func validStoredSuccessorVersion(value uint64) bool {
	return value > 0 && value < maximumStoredVersion
}

func validStoredRevision(value int64) bool {
	return value > 0 && uint64(value) <= maximumStoredVersion
}

func normalizeEvidence(values []identity.AssuranceEvidence) ([]identity.AssuranceEvidence, bool) {
	if len(values) > 1_024 {
		return nil, false
	}
	result := cloneEvidence(values)
	if !validEvidenceRevisions(result) {
		return nil, false
	}
	slices.SortFunc(result, compareEvidence)
	for index := 1; index < len(result); index++ {
		if compareEvidence(result[index-1], result[index]) == 0 {
			return nil, false
		}
	}
	return result, true
}

func validEvidenceRevisions(values []identity.AssuranceEvidence) bool {
	for _, proof := range values {
		if proof.FactorRevision != nil && !validStoredRevision(*proof.FactorRevision) ||
			proof.TrustRuleRevision != nil && !validStoredRevision(*proof.TrustRuleRevision) {
			return false
		}
	}
	return true
}

func validPolicyRevisions(values []identity.AssurancePolicyRevision) bool {
	for _, revision := range values {
		if !validStoredRevision(revision.Revision) {
			return false
		}
	}
	return true
}

func compareEvidence(left, right identity.AssuranceEvidence) int {
	if order := cmp.Compare(left.Level, right.Level); order != 0 {
		return order
	}
	if order := cmp.Compare(left.Kind, right.Kind); order != 0 {
		return order
	}
	if left.Source.Local != right.Source.Local {
		if !left.Source.Local {
			return -1
		}
		return 1
	}
	if order := bytes.Compare(left.Source.ProviderID[:], right.Source.ProviderID[:]); order != 0 {
		return order
	}
	if order := bytes.Compare(left.Source.BindingID[:], right.Source.BindingID[:]); order != 0 {
		return order
	}
	if order := left.AuthenticatedAt.Compare(right.AuthenticatedAt); order != 0 {
		return order
	}
	if order := compareOptionalTime(left.ExpiresAt, right.ExpiresAt); order != 0 {
		return order
	}
	if order := compareOptionalInt64(left.FactorRevision, right.FactorRevision); order != 0 {
		return order
	}
	return compareOptionalInt64(left.TrustRuleRevision, right.TrustRuleRevision)
}

func compareOptionalTime(left, right *time.Time) int {
	if left == nil || right == nil {
		if left == nil && right != nil {
			return -1
		}
		if left != nil && right == nil {
			return 1
		}
		return 0
	}
	return left.Compare(*right)
}

func compareOptionalInt64(left, right *int64) int {
	if left == nil || right == nil {
		if left == nil && right != nil {
			return -1
		}
		if left != nil && right == nil {
			return 1
		}
		return 0
	}
	return cmp.Compare(*left, *right)
}

func evidenceFromFuture(now time.Time, values []identity.AssuranceEvidence) bool {
	for _, value := range values {
		if value.AuthenticatedAt.After(now) {
			return true
		}
	}
	return false
}

func (snapshot AuthoritySnapshot) String() string {
	return fmt.Sprintf(
		"mfaauth.AuthoritySnapshot{flow:%d,policies:%d,totp:%d,passkeys:%d,recovery:%t,provenance:[REDACTED]}",
		snapshot.flow, len(snapshot.resolved.Applications), len(snapshot.totpFactorIDs), len(snapshot.passkeyIDs),
		snapshot.recoveryAvailable,
	)
}
func (snapshot AuthoritySnapshot) GoString() string { return snapshot.String() }

func (snapshot AuthoritySnapshot) binding() mfa.StepUpBinding {
	return mfa.StepUpBinding{
		Flow: snapshot.flow, TenantID: snapshot.tenantID, UserID: snapshot.userID,
		IdentityEpoch: snapshot.identityEpoch,
		SessionID:     snapshot.sessionID, SessionFamilyID: snapshot.sessionFamilyID,
		ContinuationID: snapshot.continuationID, AnchorVersion: snapshot.anchorVersion,
		AnchorExpiresAt:          snapshot.anchorExpiresAt,
		AnchorRecoveryRestricted: snapshot.anchorRecoveryRestricted,
		Action:                   snapshot.action, Audience: snapshot.audience,
		Requirement:      cloneRequirement(snapshot.resolved.Requirement),
		BaselineEvidence: cloneEvidence(snapshot.evidence),
	}
}

func (snapshot AuthoritySnapshot) decision() identity.AssuranceDecision {
	requirement := cloneRequirement(snapshot.resolved.Requirement)
	if snapshot.flow != mfa.FlowPostPrimaryContinuation {
		requirement.EnrollmentDeadline = nil
	}
	return identity.EvaluateAssurance(snapshot.loadedAt, requirement, snapshot.evidence,
		len(snapshot.totpFactorIDs) > 0 || snapshot.recoveryAvailable || len(snapshot.passkeyIDs) > 0)
}

func (snapshot AuthoritySnapshot) enrollmentAllowed() bool {
	if snapshot.flow == mfa.FlowExistingSession && snapshot.anchorRecoveryRestricted {
		return hasLiveRecoveryEvidence(snapshot.loadedAt, snapshot.evidence)
	}
	decision := snapshot.decision()
	return decision == identity.AssuranceSatisfied && snapshot.resolved.Requirement.Level >= identity.AssuranceMFA ||
		snapshot.flow == mfa.FlowPostPrimaryContinuation && decision == identity.AssuranceEnrollmentOnly
}

func (snapshot AuthoritySnapshot) freshLocalMFA() bool {
	requirement := cloneRequirement(snapshot.resolved.Requirement)
	requirement.Level = identity.AssuranceMFA
	requirement.LocalRequired = true
	requirement.EnrollmentDeadline = nil
	return identity.EvaluateAssurance(snapshot.loadedAt, requirement, snapshot.evidence, false) == identity.AssuranceSatisfied
}

func (snapshot AuthoritySnapshot) matches(lookup AuthorityLookup) bool {
	if lookup.Flow != snapshot.flow || lookup.Action != snapshot.action || lookup.Audience != snapshot.audience {
		return false
	}
	switch lookup.Flow {
	case mfa.FlowExistingSession:
		return lookup.AnchorID == snapshot.sessionID &&
			lookup.ContinuationReceiptDigest == ([sha256.Size]byte{}) &&
			snapshot.continuationReceiptDigest == ([sha256.Size]byte{})
	case mfa.FlowPostPrimaryContinuation:
		return lookup.AnchorID == snapshot.continuationID &&
			subtle.ConstantTimeCompare(
				lookup.ContinuationReceiptDigest[:], snapshot.continuationReceiptDigest[:],
			) == 1
	default:
		return false
	}
}

func validAuthorityLookup(value AuthorityLookup) bool {
	if value.AnchorID == (identity.EntityID{}) || !validPublicText(value.Action, 256) ||
		!validPublicText(value.Audience, 256) {
		return false
	}
	return validContinuationReceiptForFlow(value.Flow, value.ContinuationReceiptDigest)
}

func validContinuationReceiptForFlow(flow mfa.StepUpFlow, digest [sha256.Size]byte) bool {
	switch flow {
	case mfa.FlowExistingSession:
		return digest == ([sha256.Size]byte{})
	case mfa.FlowPostPrimaryContinuation:
		return digest != ([sha256.Size]byte{})
	default:
		return false
	}
}

func validAuthorityAnchor(input AuthoritySnapshotInput) bool {
	zero := identity.EntityID{}
	switch input.Flow {
	case mfa.FlowExistingSession:
		return input.SessionID != zero && input.SessionFamilyID != zero && input.ContinuationID == zero
	case mfa.FlowPostPrimaryContinuation:
		return input.SessionID == zero && input.SessionFamilyID == zero && input.ContinuationID != zero &&
			!input.AnchorRecoveryRestricted
	default:
		return false
	}
}

func hasLiveRecoveryEvidence(now time.Time, values []identity.AssuranceEvidence) bool {
	for _, value := range values {
		if value.Kind == identity.AssuranceEvidenceRecovery && value.Source.Local &&
			!value.AuthenticatedAt.After(now) && (value.ExpiresAt == nil || value.ExpiresAt.After(now)) {
			return true
		}
	}
	return false
}

func normalizeIDs(values []identity.EntityID, maximum int) ([]identity.EntityID, bool) {
	if len(values) > maximum {
		return nil, false
	}
	result := append([]identity.EntityID(nil), values...)
	slices.SortFunc(result, func(left, right identity.EntityID) int { return bytes.Compare(left[:], right[:]) })
	for index, value := range result {
		if value == (identity.EntityID{}) || index > 0 && value == result[index-1] {
			return nil, false
		}
	}
	return result, true
}

func normalizeCredentialIDs(values [][]byte) ([][]byte, bool) {
	if len(values) > maximumPasskeyFactors {
		return nil, false
	}
	result := make([][]byte, len(values))
	for index, value := range values {
		if len(value) == 0 || len(value) > maximumCredentialBytes {
			return nil, false
		}
		result[index] = append([]byte(nil), value...)
	}
	slices.SortFunc(result, bytes.Compare)
	for index := 1; index < len(result); index++ {
		if bytes.Equal(result[index-1], result[index]) {
			return nil, false
		}
	}
	return result, true
}

func cloneResolved(value mfa.ResolvedPolicy) mfa.ResolvedPolicy {
	value.Requirement = cloneRequirement(value.Requirement)
	value.Applications = append([]mfa.PolicyApplication(nil), value.Applications...)
	return value
}

func cloneRequirement(value identity.EffectiveAssuranceRequirement) identity.EffectiveAssuranceRequirement {
	value.PolicyRevisions = append([]identity.AssurancePolicyRevision(nil), value.PolicyRevisions...)
	if value.EnrollmentDeadline != nil {
		copyValue := *value.EnrollmentDeadline
		value.EnrollmentDeadline = &copyValue
	}
	return value
}

func cloneEvidence(values []identity.AssuranceEvidence) []identity.AssuranceEvidence {
	result := append([]identity.AssuranceEvidence(nil), values...)
	for index := range result {
		if result[index].ExpiresAt != nil {
			copyValue := *result[index].ExpiresAt
			result[index].ExpiresAt = &copyValue
		}
		if result[index].FactorRevision != nil {
			copyValue := *result[index].FactorRevision
			result[index].FactorRevision = &copyValue
		}
		if result[index].TrustRuleRevision != nil {
			copyValue := *result[index].TrustRuleRevision
			result[index].TrustRuleRevision = &copyValue
		}
	}
	return result
}

func validPublicText(value string, maximum int) bool {
	if value == "" || len(value) > maximum || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) || unicode.In(character, unicode.Cf) {
			return false
		}
	}
	return true
}
