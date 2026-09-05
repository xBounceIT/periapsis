package oidcmaintenance

import (
	"net/url"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/federatedoidc"
)

func validKind(kind Kind) bool {
	return kind == KindLogoutRetry || kind == KindRefresh || kind == KindScrub
}

func validQueueSnapshot(snapshot QueueSnapshot) bool {
	if !validInstant(snapshot.ObservedAt) {
		return false
	}
	return validQueueCategory(snapshot.LogoutRetry, snapshot.ObservedAt, true, true) &&
		validQueueCategory(snapshot.Refresh, snapshot.ObservedAt, true, false) &&
		validQueueCategory(snapshot.Scrub, snapshot.ObservedAt, false, false)
}

func validQueueCategory(
	category QueueCategorySnapshot,
	observedAt time.Time,
	allowReclaimable bool,
	allowDeadLetter bool,
) bool {
	if category.DueCount > MaximumPersistentCount || category.ReclaimableCount > MaximumPersistentCount ||
		category.DeadLetterCount > MaximumPersistentCount || category.ReclaimableCount > category.DueCount ||
		(!allowReclaimable && category.ReclaimableCount != 0) ||
		(!allowDeadLetter && category.DeadLetterCount != 0) {
		return false
	}
	if category.DueCount == 0 {
		return category.OldestDueAt.IsZero()
	}
	return validInstant(category.OldestDueAt) && !category.OldestDueAt.After(observedAt)
}

func validWorkShape(work Work) bool {
	if !validKind(work.Kind) || !validInstant(work.ObservedAt) {
		return false
	}
	switch work.Kind {
	case KindRefresh:
		return work.Refresh != nil && work.LogoutRetry == nil && work.Scrub == nil
	case KindLogoutRetry:
		return work.Refresh == nil && work.LogoutRetry != nil && work.Scrub == nil
	case KindScrub:
		return work.Refresh == nil && work.LogoutRetry == nil && work.Scrub != nil &&
			validEntityID(work.Scrub.MaterialID) && validEntityID(work.Scrub.OperationRunID) &&
			validInstant(work.Scrub.CompletedAt) && work.Scrub.CompletedAt.Equal(work.ObservedAt)
	default:
		return false
	}
}

func validRefreshClaim(claim RefreshClaim, claimedAt time.Time) bool {
	return validEntityID(claim.MaterialID) && validEntityID(claim.SessionFamilyID) &&
		claim.Generation > 0 && claim.Generation < MaximumPersistentCount &&
		claim.Version > 0 && claim.Version < MaximumPersistentCount &&
		validRefreshProviderOwnership(
			claim.Provider, claim.TenantID, claim.EffectiveTenantID, claim.Admission, claim.BindingID,
		) &&
		claim.ClientSecretRevision > 0 && claim.ClientSecretRevision < MaximumPersistentCount &&
		validEndpoint(claim.Endpoint) && validClientAuthentication(claim.ClientAuthentication) &&
		validClientID(claim.ClientID) && validProtectedToken(claim.Token) &&
		claim.TokenDigest != ([32]byte{}) && validInstant(claimedAt) &&
		validInstant(claim.LeaseExpiresAt) && claim.LeaseExpiresAt.After(claimedAt) &&
		validInstant(claim.MaterialExpiresAt) && claim.MaterialExpiresAt.After(claimedAt) &&
		!claim.LeaseExpiresAt.After(claim.MaterialExpiresAt) &&
		validInstant(claim.AbsoluteSessionExpiry) && claim.AbsoluteSessionExpiry.After(claimedAt) &&
		!claim.MaterialExpiresAt.After(claim.AbsoluteSessionExpiry)
}

func validRefreshProviderOwnership(
	provider identity.ProviderContext,
	materialTenantID identity.EntityID,
	effectiveTenantID identity.EntityID,
	admission identity.TenantAdmissionContext,
	bindingID identity.EntityID,
) bool {
	zero := identity.EntityID{}
	if !validEntityID(provider.ProviderID) {
		return false
	}
	switch provider.Scope {
	case identity.TenantProviderScope:
		return validEntityID(materialTenantID) && effectiveTenantID == materialTenantID &&
			validEntityID(bindingID) && provider.TenantID == materialTenantID &&
			admission == (identity.TenantAdmissionContext{})
	case identity.PlatformProviderScope:
		if provider.TenantID != zero {
			return false
		}
		if materialTenantID == zero {
			return (effectiveTenantID == zero || validEntityID(effectiveTenantID)) &&
				bindingID == zero && admission == (identity.TenantAdmissionContext{})
		}
		return effectiveTenantID == materialTenantID && validEntityID(bindingID) &&
			admission == (identity.TenantAdmissionContext{
				TenantID: materialTenantID, BindingID: bindingID,
			})
	default:
		return false
	}
}

func validLogoutClaim(claim LogoutRetryClaim, claimedAt time.Time) bool {
	return validEntityID(claim.JobID) && validEntityID(claim.MaterialID) &&
		validEntityID(claim.SessionFamilyID) && claim.Attempt > 0 &&
		claim.MaximumAttempts > 0 && claim.MaximumAttempts <= 16 && claim.Attempt <= claim.MaximumAttempts &&
		claim.ClaimVersion > 0 && claim.ClaimVersion < MaximumPersistentCount &&
		validProviderOwnership(claim.Provider, claim.TenantID, claim.Admission, claim.BindingID) &&
		claim.ClientSecretRevision > 0 && claim.ClientSecretRevision < MaximumPersistentCount &&
		validClientAuthentication(claim.ClientAuthentication) && validClientID(claim.ClientID) &&
		validEndpoint(claim.Endpoint) && claim.RefreshGeneration > 0 &&
		claim.RefreshGeneration < MaximumPersistentCount && claim.TokenDigest != ([32]byte{}) &&
		validProtectedToken(claim.OpaqueReference) && validInstant(claimedAt) &&
		validInstant(claim.NotBefore) && !claim.NotBefore.After(claimedAt) &&
		validInstant(claim.LeaseExpiresAt) && claim.LeaseExpiresAt.After(claimedAt) &&
		validInstant(claim.MaterialExpiresAt) && claim.MaterialExpiresAt.After(claimedAt) &&
		!claim.LeaseExpiresAt.After(claim.MaterialExpiresAt)
}

func validProviderOwnership(
	provider identity.ProviderContext,
	tenantID identity.EntityID,
	admission identity.TenantAdmissionContext,
	bindingID identity.EntityID,
) bool {
	zero := identity.EntityID{}
	if !validEntityID(provider.ProviderID) {
		return false
	}
	switch provider.Scope {
	case identity.TenantProviderScope:
		return validEntityID(tenantID) && validEntityID(bindingID) && provider.TenantID == tenantID &&
			admission == (identity.TenantAdmissionContext{})
	case identity.PlatformProviderScope:
		if provider.TenantID != zero {
			return false
		}
		if tenantID == zero {
			return bindingID == zero && admission == (identity.TenantAdmissionContext{})
		}
		return validEntityID(tenantID) && validEntityID(bindingID) &&
			admission == (identity.TenantAdmissionContext{TenantID: tenantID, BindingID: bindingID})
	default:
		return false
	}
}

func validClientSecretLookup(lookup ClientSecretLookup) bool {
	if !validEntityID(lookup.Provider.ProviderID) || lookup.Revision == 0 ||
		lookup.Revision >= MaximumPersistentCount || !validEntityID(lookup.MaterialID) ||
		!validEntityID(lookup.SessionFamilyID) || lookup.ClaimVersion == 0 ||
		lookup.ClaimVersion >= MaximumPersistentCount || lookup.RefreshGeneration == 0 ||
		lookup.RefreshGeneration >= MaximumPersistentCount {
		return false
	}
	switch lookup.Kind {
	case KindRefresh:
		if lookup.JobID != (identity.EntityID{}) || lookup.Attempt != 0 {
			return false
		}
	case KindLogoutRetry:
		if !validEntityID(lookup.JobID) || lookup.Attempt < 1 || lookup.Attempt > 16 {
			return false
		}
	default:
		return false
	}
	zero := identity.EntityID{}
	switch lookup.Provider.Scope {
	case identity.TenantProviderScope:
		return validEntityID(lookup.Provider.TenantID) && validEntityID(lookup.BindingID) &&
			lookup.Admission == (identity.TenantAdmissionContext{})
	case identity.PlatformProviderScope:
		return lookup.Provider.TenantID == zero && lookup.BindingID == zero &&
			(lookup.Admission == (identity.TenantAdmissionContext{}) ||
				validEntityID(lookup.Admission.TenantID) && validEntityID(lookup.Admission.BindingID))
	default:
		return false
	}
}

func validRefreshCompletion(completion RefreshCompletion, claim RefreshClaim) bool {
	if completion.TenantID != claim.TenantID || completion.EffectiveTenantID != claim.EffectiveTenantID ||
		completion.MaterialID != claim.MaterialID ||
		completion.SessionFamilyID != claim.SessionFamilyID || completion.ExpectedVersion != claim.Version ||
		completion.ExpectedGeneration != claim.Generation || !validInstant(completion.CompletedAt) {
		return false
	}
	if completion.Outcome != RefreshRotated {
		return (completion.Outcome == RefreshSafeToRetry || completion.Outcome == RefreshAmbiguous ||
			completion.Outcome == RefreshRejected || completion.Outcome == RefreshLocalUnavailable) &&
			completion.SuccessorGeneration == 0 &&
			completion.SuccessorDigest == ([32]byte{}) && completion.SuccessorToken.KeyVersion == 0 &&
			len(completion.SuccessorToken.Ciphertext) == 0 && completion.AccessExpiresAt.IsZero()
	}
	return completion.CompletedAt.Before(claim.LeaseExpiresAt) &&
		completion.SuccessorGeneration == claim.Generation+1 &&
		completion.SuccessorGeneration < MaximumPersistentCount &&
		completion.SuccessorDigest != ([32]byte{}) && validProtectedToken(completion.SuccessorToken) &&
		validInstant(completion.AccessExpiresAt) && completion.AccessExpiresAt.After(completion.CompletedAt) &&
		!completion.AccessExpiresAt.After(claim.MaterialExpiresAt) &&
		!completion.AccessExpiresAt.After(claim.AbsoluteSessionExpiry)
}

func validLogoutCompletion(completion LogoutCompletion, claim LogoutRetryClaim) bool {
	if completion.JobID != claim.JobID || completion.Attempt != claim.Attempt ||
		completion.ExpectedVersion != claim.ClaimVersion || !validInstant(completion.CompletedAt) {
		return false
	}
	switch completion.Outcome {
	case LogoutLocalUnavailable:
		return completion.NextTryAt.IsZero()
	case LogoutSafeToRetry:
		return claim.Attempt < claim.MaximumAttempts && completion.CompletedAt.Before(claim.LeaseExpiresAt) &&
			validInstant(completion.NextTryAt) && completion.NextTryAt.After(completion.CompletedAt) &&
			!completion.NextTryAt.After(completion.CompletedAt.Add(15*time.Minute))
	case LogoutSucceeded:
		return completion.CompletedAt.Before(claim.LeaseExpiresAt) && completion.NextTryAt.IsZero()
	case LogoutAmbiguous, LogoutRejected:
		return completion.NextTryAt.IsZero()
	default:
		return false
	}
}

func validProtectedToken(value ProtectedToken) bool {
	return value.KeyVersion > 0 && value.KeyVersion <= 32767 &&
		len(value.Ciphertext) >= minimumProtectedTokenBytes &&
		len(value.Ciphertext) <= maximumProtectedTokenBytes
}

func validClientAuthentication(value federatedoidc.ClientAuthenticationMode) bool {
	return value == federatedoidc.ClientSecretBasic || value == federatedoidc.ClientSecretPost
}

func validClientID(value string) bool {
	if len(value) == 0 || len(value) > 512 || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) || unicode.IsSpace(character) {
			return false
		}
	}
	return true
}

func validEndpoint(value string) bool {
	if value == "" || len(value) > 4096 || !utf8.ValidString(value) {
		return false
	}
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.User == nil &&
		parsed.Fragment == "" && parsed.String() == value
}

func validRefreshToken(value []byte) bool {
	if len(value) == 0 || len(value) > maximumRefreshTokenBytes {
		return false
	}
	for _, character := range value {
		if character < 0x21 || character > 0x7e {
			return false
		}
	}
	return true
}

func validEntityID(value identity.EntityID) bool {
	parsed := uuid.UUID(value)
	return parsed != uuid.Nil && parsed.Version() == 7
}

func validInstant(value time.Time) bool {
	if value.IsZero() || value.Year() < 2000 || value.Year() > 9999 || value.Nanosecond()%1000 != 0 {
		return false
	}
	_, offset := value.Zone()
	return offset == 0
}

func clearWork(work *Work) {
	if work == nil {
		return
	}
	if work.Refresh != nil {
		clear(work.Refresh.Token.Ciphertext)
	}
	if work.LogoutRetry != nil {
		clear(work.LogoutRetry.OpaqueReference.Ciphertext)
	}
	*work = Work{}
}
