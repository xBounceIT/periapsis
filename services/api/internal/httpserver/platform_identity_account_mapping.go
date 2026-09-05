package httpserver

import (
	"bytes"
	"errors"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	openapi_types "github.com/oapi-codegen/runtime/types"

	"github.com/periapsis-im/periapsis/services/api/internal/contract"
	"github.com/periapsis-im/periapsis/services/api/internal/platformidentityaccount"
)

const maximumPlatformIdentityAccountRevision int64 = 9_007_199_254_740_991

func mapPlatformIdentityAccountPage(
	providerID uuid.UUID,
	value platformidentityaccount.AccountPage,
) (contract.PlatformAuthProviderAccountList, error) {
	if !validPlatformIdentityAccountUUID(providerID) || len(value.Items) > 100 ||
		value.NextCursor != nil && (!validPlatformIdentityAccountUUID(*value.NextCursor) ||
			len(value.Items) == 0 || *value.NextCursor != value.Items[len(value.Items)-1].ID) {
		return contract.PlatformAuthProviderAccountList{}, errors.New("invalid platform identity account page")
	}
	items := make([]contract.PlatformAuthProviderAccount, len(value.Items))
	for index := range value.Items {
		if value.Items[index].ProviderID != providerID || index > 0 &&
			bytes.Compare(value.Items[index-1].ID[:], value.Items[index].ID[:]) >= 0 {
			return contract.PlatformAuthProviderAccountList{}, errors.New("invalid platform identity account page order")
		}
		mapped, err := mapPlatformIdentityAccount(value.Items[index])
		if err != nil {
			return contract.PlatformAuthProviderAccountList{}, err
		}
		items[index] = mapped
	}
	result := contract.PlatformAuthProviderAccountList{Items: items}
	if value.NextCursor != nil {
		cursor := *value.NextCursor
		result.NextCursor = &cursor
	}
	return result, nil
}

func mapPlatformIdentityAccount(
	value platformidentityaccount.Account,
) (contract.PlatformAuthProviderAccount, error) {
	state := contract.PlatformAuthProviderAccountState(value.State)
	observationState := contract.PlatformAuthProviderAccountLastObservationState(
		value.LastObservationState,
	)
	if !state.Valid() || !observationState.Valid() || !validPlatformIdentityAccountUUID(value.ID) ||
		!validPlatformIdentityAccountUUID(value.ProviderID) ||
		!validPlatformIdentityAccountUUID(value.User.ID) ||
		!validPlatformIdentityAccountText(value.User.DisplayName, 1, 160) ||
		!validPlatformIdentityAccountEmail(value.User.Email) ||
		value.User.Version < 1 || value.User.Version > maximumResourceVersion ||
		value.AdmittedConfigurationRevision < 1 ||
		value.AdmittedConfigurationRevision > maximumPlatformIdentityAccountRevision ||
		value.AdmittedSecurityRevision < 1 ||
		value.AdmittedSecurityRevision > maximumPlatformIdentityAccountRevision ||
		value.Version < 1 || value.Version > maximumResourceVersion ||
		!validPlatformIdentityAccountInstant(value.CreatedAt) ||
		!validPlatformIdentityAccountInstant(value.UpdatedAt) ||
		value.UpdatedAt.Before(value.CreatedAt) ||
		(value.State == platformidentityaccount.AccountStateActive) != (value.RetiredAt == nil) {
		return contract.PlatformAuthProviderAccount{}, errors.New("invalid platform identity account")
	}
	switch value.LastObservationState {
	case platformidentityaccount.LastObservationStateKnown:
		if value.LastObservedAt == nil || !validPlatformIdentityAccountInstant(*value.LastObservedAt) ||
			value.LastObservedAt.Before(value.CreatedAt) || value.LastObservedAt.After(value.UpdatedAt) {
			return contract.PlatformAuthProviderAccount{}, errors.New("invalid platform identity account observation")
		}
	case platformidentityaccount.LastObservationStateLegacyUnknown:
		if value.State != platformidentityaccount.AccountStateRetired || value.RetiredAt == nil ||
			value.LastObservedAt != nil || value.Version != 1 {
			return contract.PlatformAuthProviderAccount{}, errors.New("invalid legacy platform identity account observation")
		}
	}
	if value.RetiredAt != nil &&
		(!validPlatformIdentityAccountInstant(*value.RetiredAt) ||
			value.RetiredAt.Before(value.CreatedAt) ||
			(value.LastObservedAt != nil && value.RetiredAt.Before(*value.LastObservedAt)) ||
			value.RetiredAt.After(value.UpdatedAt)) {
		return contract.PlatformAuthProviderAccount{}, errors.New("invalid retired platform identity account")
	}

	var email *openapi_types.Email
	if value.User.Email != nil {
		mappedEmail := openapi_types.Email(*value.User.Email)
		email = &mappedEmail
	}
	return contract.PlatformAuthProviderAccount{
		AdmittedConfigurationRevision: contract.PlatformAuthProviderRevision(value.AdmittedConfigurationRevision),
		AdmittedSecurityRevision:      contract.PlatformAuthProviderRevision(value.AdmittedSecurityRevision),
		CreatedAt:                     value.CreatedAt,
		Id:                            value.ID,
		LastObservationState:          observationState,
		LastObservedAt:                utcTimePointer(value.LastObservedAt),
		ProviderId:                    value.ProviderID,
		RetiredAt:                     utcTimePointer(value.RetiredAt),
		State:                         state,
		UpdatedAt:                     value.UpdatedAt,
		User: contract.PlatformAuthProviderAccountUser{
			Active: value.User.Active, DisplayName: value.User.DisplayName,
			Email: email, Id: value.User.ID, Version: contract.ResourceVersion(value.User.Version),
		},
		Version: contract.ResourceVersion(value.Version),
	}, nil
}

func validPlatformIdentityAccountUUID(value uuid.UUID) bool {
	return value != uuid.Nil && value.Version() == 7 && value.Variant() == uuid.RFC4122
}

func validPlatformIdentityAccountInstant(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && value.Year() >= 1970 &&
		value.Year() <= 9999 && value.Nanosecond()%1_000 == 0
}

func validPlatformIdentityAccountText(value string, minimum, maximum int) bool {
	if !utf8.ValidString(value) || utf8.RuneCountInString(value) < minimum ||
		utf8.RuneCountInString(value) > maximum || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) || unicode.In(character, unicode.Cf) {
			return false
		}
	}
	return true
}

func validPlatformIdentityAccountEmail(value *string) bool {
	if value == nil {
		return true
	}
	email := *value
	return len(email) >= 3 && len(email) <= 320 && strings.ToLower(email) == email &&
		strings.IndexByte(email, '@') > 0 && validPlatformIdentityAccountText(email, 3, 320)
}
