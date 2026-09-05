package federatedauth

import (
	"context"
	"fmt"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/federatedoidc"
)

// OIDCApplicationRequest carries the verified proof together with the exact
// configuration that produced it and the optional one-use token material.
// The application validates the configuration pins again before sealing.
type OIDCApplicationRequest struct {
	TenantID      identity.EntityID
	Configuration federatedoidc.AuthorizationConfiguration
	Proof         *federatedoidc.VerifiedAuthentication
	Session       OIDCSessionMaterial `json:"-"`
}

func (request OIDCApplicationRequest) String() string {
	return fmt.Sprintf(
		"federatedauth.OIDCApplicationRequest{tenant:%t,proof:%t,session:%t,material:[REDACTED]}",
		request.TenantID != (identity.EntityID{}), request.Proof != nil, request.Session != nil,
	)
}

func (request OIDCApplicationRequest) GoString() string { return request.String() }

// OIDCSessionMaterialSealContext authenticates token material to the exact
// tenant admission and immutable material row. Mutable session ownership is
// deliberately absent from cryptographic AAD.
type OIDCSessionMaterialSealContext struct {
	Provider         identity.ProviderContext
	Admission        identity.TenantAdmissionContext
	MaterialID       identity.EntityID
	KeepIDToken      bool
	KeepRefreshToken bool
}

// OIDCSessionMaterial is the one-use ownership-safe kernel projection. The
// production implementation is *federatedoidc.SessionMaterial; this narrow
// interface prevents the application from reaching the original TokenBundle.
type OIDCSessionMaterial interface {
	MaterialID() identity.EntityID
	HasIDToken() bool
	HasRefreshToken() bool
	TakeTokens() (*federatedoidc.OwnedSessionTokens, bool)
	Destroy()
}

type ProtectedOIDCSessionMaterial struct {
	MaterialID         identity.EntityID
	IDToken            *ProtectedToken
	IDTokenDigest      [32]byte
	RefreshToken       *ProtectedToken
	RefreshTokenDigest [32]byte
	RefreshGeneration  uint64
	AccessExpiresAt    time.Time
}

func (material ProtectedOIDCSessionMaterial) ValidFor(
	materialID identity.EntityID,
	wantIDToken, wantRefreshToken bool,
) bool {
	return validProtectedOIDCSessionMaterial(material, materialID, wantIDToken, wantRefreshToken)
}

func (material *ProtectedOIDCSessionMaterial) Clone() *ProtectedOIDCSessionMaterial {
	return cloneProtectedOIDCSessionMaterial(material)
}

func (material *ProtectedOIDCSessionMaterial) Destroy() {
	clearProtectedOIDCSessionMaterial(material)
}

func (material ProtectedOIDCSessionMaterial) String() string {
	return fmt.Sprintf(
		"federatedauth.ProtectedOIDCSessionMaterial{id_token:%t,refresh_token:%t,generation:%d,material:[REDACTED]}",
		material.IDToken != nil, material.RefreshToken != nil, material.RefreshGeneration,
	)
}

func (material ProtectedOIDCSessionMaterial) GoString() string { return material.String() }

type OIDCSessionMaterialSealer interface {
	SealOIDCSessionMaterial(
		context.Context,
		OIDCSessionMaterialSealContext,
		OIDCSessionMaterial,
	) (ProtectedOIDCSessionMaterial, error)
}

// OIDCApplyRequest keeps the protocol-neutral apply and encrypted token
// material in the same atomic persistence call. MaterialExpiresAt is bounded
// by both the ID-token proof and the owner session/continuation lifetime.
type OIDCApplyRequest struct {
	Apply             ApplyRequest
	MaterialID        identity.EntityID
	Configuration     federatedoidc.AuthorizationConfiguration
	SessionMaterial   *ProtectedOIDCSessionMaterial `json:"-"`
	MaterialExpiresAt time.Time
}

func (request OIDCApplyRequest) String() string {
	return fmt.Sprintf(
		"federatedauth.OIDCApplyRequest{apply:%q,material:%t,session:%t,expiry:%t}",
		request.Apply.String(), validApplyUUIDv7(request.MaterialID), request.SessionMaterial != nil,
		!request.MaterialExpiresAt.IsZero(),
	)
}

func (request OIDCApplyRequest) GoString() string { return request.String() }

type OIDCTransactionalApplier interface {
	ApplyOIDCAuthentication(context.Context, OIDCApplyRequest) (ApplyResult, error)
}

func (service *Service) planAndApplyOIDC(
	ctx context.Context,
	projection AuthenticationProjection,
	configuration federatedoidc.AuthorizationConfiguration,
	sessionMaterial OIDCSessionMaterial,
) (ApplyResult, error) {
	operation, cancel, err := service.operation(ctx)
	if err != nil {
		return ApplyResult{}, err
	}
	defer cancel()
	if !validProjection(projection) || projection.OIDCCompletion == nil ||
		!validApplyUUIDv7(projection.OIDCCompletion.MaterialID) ||
		configuration.Pins() != projection.OIDCCompletion.Pins || service.oidcApplier == nil ||
		service.oidcSessionSealer == nil {
		return ApplyResult{}, ErrInvalidInput
	}
	admission, validAdmission := configuration.TenantAdmission()
	if !validAdmission || admission.TenantID != projection.TenantID ||
		admission != projection.Admission {
		return ApplyResult{}, ErrInvalidInput
	}
	endpoints := configuration.Discovery.Endpoints()
	wantIDToken := endpoints.EndSession != ""
	wantRefreshToken := configuration.AllowRefreshToken
	wantMaterial := wantIDToken || wantRefreshToken
	if wantMaterial != (sessionMaterial != nil) || sessionMaterial != nil &&
		sessionMaterial.MaterialID() != projection.OIDCCompletion.MaterialID {
		return ApplyResult{}, ErrInvalidInput
	}

	var protected *ProtectedOIDCSessionMaterial
	if sessionMaterial != nil {
		sealed, sealErr := service.oidcSessionSealer.SealOIDCSessionMaterial(
			operation,
			OIDCSessionMaterialSealContext{
				Provider: configuration.Provider, Admission: admission,
				MaterialID:  projection.OIDCCompletion.MaterialID,
				KeepIDToken: wantIDToken, KeepRefreshToken: wantRefreshToken,
			},
			sessionMaterial,
		)
		if sealErr != nil || !validProtectedOIDCSessionMaterial(
			sealed, projection.OIDCCompletion.MaterialID, wantIDToken, wantRefreshToken,
		) {
			clearProtectedOIDCSessionMaterial(&sealed)
			return ApplyResult{}, ErrAuthentication
		}
		protected = &sealed
		defer clearProtectedOIDCSessionMaterial(protected)
	}

	var collidedPlan AuthenticationPlan
	for planningAttempt := range 2 {
		plan, planErr := service.planner.PlanFederatedAuthentication(operation, PlanningRequest{
			Authentication: cloneProjection(projection), Action: "session.create",
		})
		if planErr != nil || !validPlan(plan, projection) ||
			planningAttempt == 1 && !validConvergedFirstJITPlan(collidedPlan, plan) {
			return ApplyResult{}, ErrAuthentication
		}
		now := service.currentTime()
		if !validInstant(now) || !projection.ValidUntil.After(now) {
			return ApplyResult{}, ErrAuthentication
		}
		assurance := identity.EvaluateAssurance(now, plan.Requirement, projection.Evidence, plan.HasEnrollableFactor)
		disposition := ApplyContinuation
		switch assurance {
		case identity.AssuranceSatisfied:
			disposition = ApplySession
		case identity.AssuranceStepUpRequired, identity.AssuranceEnrollmentOnly:
			disposition = ApplyContinuation
		default:
			return ApplyResult{}, ErrAuthentication
		}
		apply := ApplyRequest{
			Authentication: applyAuthenticationProjection(projection), Plan: clonePlan(plan),
			Disposition: disposition, Assurance: assurance, AppliedAt: now,
		}
		credentialRequest := ApplyCredentialRequest{
			Disposition: disposition, Method: apply.Authentication.Method, IssuedAt: now,
		}
		credential, credentialErr := service.credentials.ReserveApplyCredential(credentialRequest)
		if credentialErr != nil || credential == nil || !credential.validFor(credentialRequest) {
			if credential != nil {
				credential.Destroy()
			}
			return ApplyResult{}, ErrAuthentication
		}
		apply.Session, apply.Continuation = credential.Session(), credential.Continuation()
		ownerExpiresAt := apply.Session.AbsoluteExpiresAt()
		if disposition == ApplyContinuation {
			ownerExpiresAt = apply.Continuation.ExpiresAt()
		}
		materialExpiresAt := ownerExpiresAt
		if projection.ValidUntil.Before(materialExpiresAt) {
			materialExpiresAt = projection.ValidUntil
		}
		protectedForApply := cloneProtectedOIDCSessionMaterial(protected)
		if protectedForApply != nil && protectedForApply.RefreshToken != nil &&
			protectedForApply.AccessExpiresAt.After(materialExpiresAt) {
			protectedForApply.AccessExpiresAt = materialExpiresAt
		}
		request := OIDCApplyRequest{
			Apply: apply, MaterialID: projection.OIDCCompletion.MaterialID,
			Configuration: configuration, SessionMaterial: protectedForApply,
			MaterialExpiresAt: materialExpiresAt,
		}
		var result ApplyResult
		for range 2 {
			result, err = service.oidcApplier.ApplyOIDCAuthentication(operation, request)
			if err == nil || operation.Err() != nil {
				break
			}
		}
		clearProtectedOIDCSessionMaterial(request.SessionMaterial)
		if err != nil {
			credential.Destroy()
			return ApplyResult{}, ErrAuthentication
		}
		if result.Credential != nil {
			result.Credential.Destroy()
			credential.Destroy()
			return ApplyResult{}, ErrAuthentication
		}
		switch result.Category {
		case ApplySuccess:
			if result.UserID == (identity.EntityID{}) || plan.UserID != (identity.EntityID{}) && result.UserID != plan.UserID ||
				result.ReturnPath != projectionReturnPath(projection) ||
				disposition == ApplySession && (result.SessionID != apply.Session.SessionID() || result.ContinuationID != (identity.EntityID{})) ||
				disposition == ApplyContinuation && (result.ContinuationID != apply.Continuation.ContinuationID() || result.SessionID != (identity.EntityID{})) {
				credential.Destroy()
				return ApplyResult{}, ErrAuthentication
			}
			var released bool
			result.Credential, released = credential.ReleaseBrowserCredential(result.SessionID, result.ContinuationID)
			if !released {
				credential.Destroy()
				return ApplyResult{}, ErrAuthentication
			}
			return result, nil
		case ApplyCollision:
			credential.Destroy()
			if planningAttempt == 0 && eligibleFirstJITCollisionPlan(projection, plan) {
				collidedPlan = clonePlan(plan)
				continue
			}
			return ApplyResult{}, ErrIdentityCollision
		case ApplyStale:
			credential.Destroy()
			return ApplyResult{}, ErrStaleConfiguration
		case ApplyReplay, ApplyDenied:
			credential.Destroy()
			return ApplyResult{}, ErrAuthentication
		default:
			credential.Destroy()
			return ApplyResult{}, ErrAuthentication
		}
	}
	return ApplyResult{}, ErrAuthentication
}

func validProtectedOIDCSessionMaterial(
	value ProtectedOIDCSessionMaterial,
	materialID identity.EntityID,
	wantIDToken, wantRefreshToken bool,
) bool {
	if value.MaterialID != materialID || (value.IDToken != nil) != wantIDToken ||
		(value.RefreshToken != nil) != wantRefreshToken {
		return false
	}
	if value.IDToken != nil && !validProtectedOIDCToken(*value.IDToken) {
		return false
	}
	if (value.IDToken != nil) != (value.IDTokenDigest != ([32]byte{})) {
		return false
	}
	if value.RefreshToken == nil {
		return value.RefreshTokenDigest == ([32]byte{}) && value.RefreshGeneration == 0 &&
			value.AccessExpiresAt.IsZero()
	}
	return validProtectedOIDCToken(*value.RefreshToken) && value.RefreshTokenDigest != ([32]byte{}) &&
		value.RefreshGeneration == 1 && validInstant(value.AccessExpiresAt)
}

func validProtectedOIDCToken(value ProtectedToken) bool {
	return value.KeyVersion > 0 && len(value.Ciphertext) >= minimumProtectedTokenBytes &&
		len(value.Ciphertext) <= maximumProtectedTokenBytes
}

func cloneProtectedOIDCSessionMaterial(
	value *ProtectedOIDCSessionMaterial,
) *ProtectedOIDCSessionMaterial {
	if value == nil {
		return nil
	}
	result := *value
	if value.IDToken != nil {
		copyValue := *value.IDToken
		copyValue.Ciphertext = append([]byte(nil), value.IDToken.Ciphertext...)
		result.IDToken = &copyValue
	}
	if value.RefreshToken != nil {
		copyValue := *value.RefreshToken
		copyValue.Ciphertext = append([]byte(nil), value.RefreshToken.Ciphertext...)
		result.RefreshToken = &copyValue
	}
	return &result
}

func clearProtectedOIDCSessionMaterial(value *ProtectedOIDCSessionMaterial) {
	if value == nil {
		return
	}
	if value.IDToken != nil {
		clear(value.IDToken.Ciphertext)
	}
	if value.RefreshToken != nil {
		clear(value.RefreshToken.Ciphertext)
	}
	*value = ProtectedOIDCSessionMaterial{}
}
