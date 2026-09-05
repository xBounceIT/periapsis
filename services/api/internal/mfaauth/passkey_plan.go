package mfaauth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"slices"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/mfa"
	"github.com/periapsis-im/periapsis/modules/identity/webauthn"
)

type PasskeyLookup struct {
	ReferenceID               identity.EntityID
	Purpose                   webauthn.CeremonyPurpose
	Action                    string
	Audience                  string
	Admission                 AdmissionContext
	ContinuationReceiptDigest [sha256.Size]byte `json:"-"`
	evaluatedAt               time.Time
}

func (lookup PasskeyLookup) String() string {
	return fmt.Sprintf("mfaauth.PasskeyLookup{purpose:%d,action:%t,reference:[REDACTED]}",
		lookup.Purpose, lookup.Action != "" && lookup.Audience != "")
}
func (lookup PasskeyLookup) GoString() string       { return lookup.String() }
func (lookup PasskeyLookup) EvaluatedAt() time.Time { return lookup.evaluatedAt }

func validPasskeyLookup(lookup PasskeyLookup, registration bool) bool {
	if lookup.ReferenceID == (identity.EntityID{}) || !validPublicText(lookup.Action, 256) ||
		!validPublicText(lookup.Audience, 256) {
		return false
	}
	if registration {
		return lookup.Purpose == webauthn.PurposeRegistration
	}
	switch lookup.Purpose {
	case webauthn.PurposeContinuationAuthentication:
		return lookup.ContinuationReceiptDigest != ([sha256.Size]byte{})
	case webauthn.PurposePrimaryAuthentication, webauthn.PurposeStepUpAuthentication:
		return lookup.ContinuationReceiptDigest == ([sha256.Size]byte{})
	default:
		return false
	}
}

type PasskeyRegistrationPlan struct {
	referenceID               identity.EntityID
	evaluatedAt               time.Time
	continuationReceiptDigest [sha256.Size]byte
	request                   webauthn.RegistrationStartRequest
}

func (plan PasskeyRegistrationPlan) String() string {
	return fmt.Sprintf("mfaauth.PasskeyRegistrationPlan{configured:%t,material:[REDACTED]}",
		plan.referenceID != (identity.EntityID{}))
}
func (plan PasskeyRegistrationPlan) GoString() string { return plan.String() }

func NewPasskeyRegistrationPlan(
	referenceID identity.EntityID,
	authority AuthoritySnapshot,
	rp webauthn.RelyingParty,
	policy webauthn.CeremonyPolicy,
) (PasskeyRegistrationPlan, error) {
	if referenceID == (identity.EntityID{}) || !authority.enrollmentAllowed() ||
		len(authority.passkeyUserHandle) != stableUserHandleBytes || !validPlanRP(rp) ||
		!validPasskeyPolicy(policy, webauthn.PurposeRegistration, authority.resolved.Requirement,
			webauthn.AuthenticationKnownUser) {
		return PasskeyRegistrationPlan{}, ErrDenied
	}
	binding := passkeyBinding(authority, webauthn.PurposeRegistration)
	return PasskeyRegistrationPlan{
		referenceID: referenceID, evaluatedAt: authority.loadedAt,
		continuationReceiptDigest: authority.continuationReceiptDigest,
		request: webauthn.RegistrationStartRequest{
			RP: rp, Binding: binding, Policy: policy,
			UserHandle:           append([]byte(nil), authority.passkeyUserHandle...),
			ExcludeCredentialIDs: cloneBytes2D(authority.passkeyIDs),
		},
	}, nil
}

type PrimaryPasskeyPlanInput struct {
	ReferenceID   identity.EntityID
	LoadedAt      time.Time
	TenantID      identity.EntityID
	UserID        identity.EntityID
	IdentityEpoch uint64
	Action        string
	Audience      string
	PolicyContext mfa.PolicyContext
	Policies      []mfa.ScopedPolicy
	RP            webauthn.RelyingParty
	Policy        webauthn.CeremonyPolicy
	Mode          webauthn.AuthenticationMode
	UserHandle    []byte
	CredentialIDs [][]byte
}

func (input PrimaryPasskeyPlanInput) String() string {
	return fmt.Sprintf("mfaauth.PrimaryPasskeyPlanInput{mode:%d,policies:%d,credentials:%d,material:[REDACTED]}",
		input.Mode, len(input.Policies), len(input.CredentialIDs))
}
func (input PrimaryPasskeyPlanInput) GoString() string { return input.String() }

type PasskeyAuthenticationPlan struct {
	referenceID               identity.EntityID
	evaluatedAt               time.Time
	continuationReceiptDigest [sha256.Size]byte
	request                   webauthn.AuthenticationStartRequest
}

func (plan PasskeyAuthenticationPlan) String() string {
	return fmt.Sprintf("mfaauth.PasskeyAuthenticationPlan{configured:%t,material:[REDACTED]}",
		plan.referenceID != (identity.EntityID{}))
}
func (plan PasskeyAuthenticationPlan) GoString() string { return plan.String() }

func NewPrimaryPasskeyPlan(input PrimaryPasskeyPlanInput) (PasskeyAuthenticationPlan, error) {
	if input.ReferenceID == (identity.EntityID{}) || !validInstant(input.LoadedAt) ||
		input.TenantID == (identity.EntityID{}) || !validPublicText(input.Action, 256) ||
		!validPublicText(input.Audience, 256) ||
		input.PolicyContext.TenantID != input.TenantID || input.PolicyContext.Action != input.Action {
		return PasskeyAuthenticationPlan{}, ErrInvalidInput
	}
	resolved, err := mfa.ResolvePolicy(input.PolicyContext, input.Policies)
	if err != nil {
		return PasskeyAuthenticationPlan{}, ErrDenied
	}
	ids, ok := normalizeCredentialIDs(input.CredentialIDs)
	if !ok {
		return PasskeyAuthenticationPlan{}, ErrInvalidInput
	}
	switch input.Mode {
	case webauthn.AuthenticationKnownUser:
		if input.UserID == (identity.EntityID{}) || !validStoredVersion(input.IdentityEpoch) ||
			len(input.UserHandle) != stableUserHandleBytes || allZeroMaterial(input.UserHandle) || len(ids) == 0 {
			return PasskeyAuthenticationPlan{}, ErrDenied
		}
	case webauthn.AuthenticationDiscoverable:
		if input.UserID != (identity.EntityID{}) || input.IdentityEpoch != 0 || len(input.UserHandle) != 0 || len(ids) != 0 {
			return PasskeyAuthenticationPlan{}, ErrInvalidInput
		}
	default:
		return PasskeyAuthenticationPlan{}, ErrInvalidInput
	}
	if !validPlanRP(input.RP) || !validPasskeyPolicy(input.Policy, webauthn.PurposePrimaryAuthentication,
		resolved.Requirement, input.Mode) {
		return PasskeyAuthenticationPlan{}, ErrInvalidInput
	}
	binding := webauthn.CeremonyBinding{
		Purpose: webauthn.PurposePrimaryAuthentication, TenantID: input.TenantID, UserID: input.UserID,
		IdentityEpoch: input.IdentityEpoch,
		Action:        input.Action, Audience: input.Audience, Requirement: cloneRequirement(resolved.Requirement),
	}
	return PasskeyAuthenticationPlan{
		referenceID: input.ReferenceID, evaluatedAt: input.LoadedAt,
		request: webauthn.AuthenticationStartRequest{
			RP: input.RP, Binding: binding, Policy: input.Policy, Mode: input.Mode,
			UserHandle: append([]byte(nil), input.UserHandle...), AllowedCredentialIDs: ids,
		},
	}, nil
}

func NewStepUpPasskeyPlan(
	referenceID identity.EntityID,
	authority AuthoritySnapshot,
	rp webauthn.RelyingParty,
	policy webauthn.CeremonyPolicy,
) (PasskeyAuthenticationPlan, error) {
	if referenceID == (identity.EntityID{}) || len(authority.passkeyUserHandle) != stableUserHandleBytes ||
		len(authority.passkeyIDs) == 0 || !validPlanRP(rp) {
		return PasskeyAuthenticationPlan{}, ErrDenied
	}
	decision := authority.decision()
	if decision != identity.AssuranceStepUpRequired && decision != identity.AssuranceEnrollmentOnly {
		return PasskeyAuthenticationPlan{}, ErrDenied
	}
	purpose := webauthn.PurposeStepUpAuthentication
	if authority.flow == mfa.FlowPostPrimaryContinuation {
		purpose = webauthn.PurposeContinuationAuthentication
	}
	if !validPasskeyPolicy(policy, purpose, authority.resolved.Requirement, webauthn.AuthenticationKnownUser) {
		return PasskeyAuthenticationPlan{}, ErrInvalidInput
	}
	return PasskeyAuthenticationPlan{
		referenceID: referenceID, evaluatedAt: authority.loadedAt,
		continuationReceiptDigest: authority.continuationReceiptDigest,
		request: webauthn.AuthenticationStartRequest{
			RP: rp, Binding: passkeyBinding(authority, purpose), Policy: policy,
			Mode:                 webauthn.AuthenticationKnownUser,
			UserHandle:           append([]byte(nil), authority.passkeyUserHandle...),
			AllowedCredentialIDs: cloneBytes2D(authority.passkeyIDs),
		},
	}, nil
}

type PasskeyPlanSource interface {
	ResolvePasskeyRegistration(context.Context, PasskeyLookup) (PasskeyRegistrationPlan, error)
	ResolvePasskeyAuthentication(context.Context, PasskeyLookup) (PasskeyAuthenticationPlan, error)
}

func (plan PasskeyRegistrationPlan) matches(lookup PasskeyLookup) bool {
	return lookup.Purpose == webauthn.PurposeRegistration && lookup.ReferenceID == plan.referenceID &&
		lookup.Action == plan.request.Binding.Action && lookup.Audience == plan.request.Binding.Audience &&
		lookup.evaluatedAt.Equal(plan.evaluatedAt) &&
		subtle.ConstantTimeCompare(
			lookup.ContinuationReceiptDigest[:], plan.continuationReceiptDigest[:],
		) == 1
}

func (plan PasskeyAuthenticationPlan) matches(lookup PasskeyLookup) bool {
	return lookup.Purpose == plan.request.Binding.Purpose && lookup.ReferenceID == plan.referenceID &&
		lookup.Action == plan.request.Binding.Action && lookup.Audience == plan.request.Binding.Audience &&
		lookup.evaluatedAt.Equal(plan.evaluatedAt) &&
		subtle.ConstantTimeCompare(
			lookup.ContinuationReceiptDigest[:], plan.continuationReceiptDigest[:],
		) == 1
}

func passkeyBinding(authority AuthoritySnapshot, purpose webauthn.CeremonyPurpose) webauthn.CeremonyBinding {
	return webauthn.CeremonyBinding{
		Purpose: purpose, TenantID: authority.tenantID, UserID: authority.userID,
		IdentityEpoch: authority.identityEpoch,
		SessionID:     authority.sessionID, SessionFamilyID: authority.sessionFamilyID,
		ContinuationID: authority.continuationID, AnchorVersion: authority.anchorVersion,
		AnchorExpiresAt:          authority.anchorExpiresAt,
		AnchorRecoveryRestricted: authority.anchorRecoveryRestricted,
		Action:                   authority.action, Audience: authority.audience,
		Requirement:      cloneRequirement(authority.resolved.Requirement),
		BaselineEvidence: cloneEvidence(authority.evidence),
	}
}

func cloneBytes2D(values [][]byte) [][]byte {
	result := make([][]byte, len(values))
	for index := range values {
		result[index] = append([]byte(nil), values[index]...)
	}
	return result
}

func validPlanRP(value webauthn.RelyingParty) bool {
	compiled, err := webauthn.CompileRelyingParty(value.ID(), value.Origins(), value.Revision())
	return err == nil && compiled.ID() == value.ID() && compiled.Revision() == value.Revision() &&
		slices.Equal(compiled.Origins(), value.Origins())
}

func validPasskeyPolicy(
	policy webauthn.CeremonyPolicy,
	purpose webauthn.CeremonyPurpose,
	requirement identity.EffectiveAssuranceRequirement,
	mode webauthn.AuthenticationMode,
) bool {
	if !policy.RequireUserPresence ||
		(policy.UserVerification != webauthn.UserVerificationPreferred &&
			policy.UserVerification != webauthn.UserVerificationRequired) ||
		(policy.ResidentKey != webauthn.ResidentKeyPreferred && policy.ResidentKey != webauthn.ResidentKeyRequired) {
		return false
	}
	if purpose == webauthn.PurposeRegistration {
		if policy.UserVerification != webauthn.UserVerificationRequired {
			return false
		}
		switch policy.Attestation {
		case webauthn.AttestationNone:
			return policy.MetadataRevision == 0
		case webauthn.AttestationDirect, webauthn.AttestationEnterprise:
			return policy.MetadataRevision > 0
		default:
			return false
		}
	}
	if policy.Attestation != webauthn.AttestationNone || policy.MetadataRevision != 0 {
		return false
	}
	if (requirement.Level >= identity.AssurancePhishingResistant ||
		purpose == webauthn.PurposePrimaryAuthentication && requirement.Level > identity.AssurancePrimary) &&
		policy.UserVerification != webauthn.UserVerificationRequired {
		return false
	}
	return mode != webauthn.AuthenticationDiscoverable ||
		policy.UserVerification == webauthn.UserVerificationRequired && policy.ResidentKey == webauthn.ResidentKeyRequired
}
