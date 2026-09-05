package httpserver

import (
	"bytes"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	openapi_types "github.com/oapi-codegen/runtime/types"

	"github.com/periapsis-im/periapsis/services/api/internal/contract"
	"github.com/periapsis-im/periapsis/services/api/internal/platformlocalaccount"
)

const maximumPlatformLocalAccountRevision uint64 = 9_007_199_254_740_991

func mapPlatformLocalAccountPage(
	value platformlocalaccount.Page,
) (contract.PlatformLocalAccountList, error) {
	if len(value.Items) > 100 || value.NextCursor != nil &&
		(!validPlatformLocalAccountUUID(*value.NextCursor) || len(value.Items) == 0 ||
			*value.NextCursor != value.Items[len(value.Items)-1].ID) {
		return contract.PlatformLocalAccountList{}, errors.New("invalid platform local-account page")
	}
	items := make([]contract.PlatformLocalAccount, len(value.Items))
	for index := range value.Items {
		if index > 0 && bytes.Compare(value.Items[index-1].ID[:], value.Items[index].ID[:]) >= 0 {
			return contract.PlatformLocalAccountList{}, errors.New("invalid platform local-account order")
		}
		mapped, err := mapPlatformLocalAccount(value.Items[index])
		if err != nil {
			return contract.PlatformLocalAccountList{}, err
		}
		items[index] = mapped
	}
	result := contract.PlatformLocalAccountList{Items: items}
	if value.NextCursor != nil {
		cursor := openapi_types.UUID(*value.NextCursor)
		result.NextCursor = &cursor
	}
	return result, nil
}

func mapPlatformLocalAccount(
	value platformlocalaccount.Account,
) (contract.PlatformLocalAccount, error) {
	status := contract.PlatformLocalAccountStatus(value.Status)
	identifierStatus := contract.PlatformLocalLoginIdentifierStatus(value.LoginIdentifierStatus)
	credentialStatus := contract.PlatformLocalCredentialStatus(value.CredentialStatus)
	if !platformlocalaccount.ValidAccountProjection(value) ||
		!status.Valid() || !identifierStatus.Valid() || !credentialStatus.Valid() ||
		!validPlatformLocalAccountUUID(value.ID) || !validPlatformLocalAccountUUID(value.UserID) ||
		value.CredentialVersion > maximumPlatformLocalAccountRevision || value.Revision == 0 ||
		value.Revision > maximumPlatformLocalAccountRevision || value.IdentityEpoch == 0 ||
		value.IdentityEpoch > maximumPlatformLocalAccountRevision {
		return contract.PlatformLocalAccount{}, errors.New("invalid platform local-account projection")
	}
	return contract.PlatformLocalAccount{
		ActivatedAt:                platformLocalAccountTimePointer(value.ActivatedAt),
		ConfirmedAcceptableFactors: int(value.ConfirmedAcceptableFactors),
		CredentialStatus:           credentialStatus,
		CredentialVersion:          int64(value.CredentialVersion),
		DisabledAt:                 platformLocalAccountTimePointer(value.DisabledAt),
		DisplayName:                value.DisplayName,
		Id:                         openapi_types.UUID(value.ID),
		IdentityEpoch:              int64(value.IdentityEpoch),
		InvitedAt:                  value.InvitedAt,
		LoginIdentifier:            openapi_types.Email(value.LoginIdentifier),
		LoginIdentifierStatus:      identifierStatus,
		ProtectedRecoveryPrincipal: value.ProtectedRecoveryPrincipal,
		RecoveryStartedAt:          platformLocalAccountTimePointer(value.RecoveryStartedAt),
		Revision:                   int64(value.Revision),
		Status:                     status,
		UpdatedAt:                  value.UpdatedAt,
		UserId:                     openapi_types.UUID(value.UserID),
	}, nil
}

func setPlatformLocalAccountETag(w http.ResponseWriter, revision uint64) bool {
	value, err := platformlocalaccount.EntityTag(revision)
	if err != nil {
		return false
	}
	w.Header().Set("ETag", value)
	return true
}
func platformLocalAccountTimePointer(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func validPlatformLocalAccountUUID(value uuid.UUID) bool {
	return value != uuid.Nil && value.Version() == 7 && value.Variant() == uuid.RFC4122
}
