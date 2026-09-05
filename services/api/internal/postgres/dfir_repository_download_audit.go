package postgres

import (
	"context"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	kernel "github.com/periapsis-im/periapsis/modules/dfir"
	application "github.com/periapsis-im/periapsis/services/api/internal/dfir"
)

const appendDFIRDownloadGrantAuditQuery = `
	SELECT app.append_dfir_download_grant_audit_v1(
		$1,$2,$3,$4,$5::public.ticket_aggregate_kind,$6,$7,
		$8::public.dfir_entity_kind,$9,$10,$11,$12,$13,
		$14::public.dfir_scan_state,$15::public.dfir_scan_state,
		$16,$17::public.authorization_scope,$18::uuid,$19::timestamptz,$20,$21,$22::inet,$23,$24
	)`

const maximumDFIRDownloadRevision = uint64(9_007_199_254_740_991)

// AuditDownloadGrant is the final capability boundary. It performs no object
// storage work and its ABI cannot represent a URL, signature, bucket, key,
// filename, content digest, or other customer payload.
func (repository *DFIRRepository) AuditDownloadGrant(
	ctx context.Context,
	write application.DownloadGrantAuditWrite,
) error {
	if repository == nil || repository.begin == nil || repository.newID == nil ||
		!validDFIRDownloadGrantAuditWrite(write) {
		return application.ErrRepositoryForbidden
	}
	identifiers, err := phase4NewIDs(repository.newID, 1)
	if err != nil {
		return err
	}
	var portalContactID any
	if write.PortalAuthorization != nil {
		portalContactID = write.PortalAuthorization.ContactID
	}
	_, err = withinTransactionWithOptions(
		ctx,
		repository.begin,
		pgx.TxOptions{IsoLevel: pgx.ReadCommitted, AccessMode: pgx.ReadWrite},
		func(tx databaseTransaction) (uuid.UUID, error) {
			authority, authorityErr := phase4Authority(
				ctx, tx, dfirAuthorizationActor(write.Actor), write.Actor.TenantID,
			)
			if authorityErr != nil {
				return uuid.Nil, authorityErr
			}
			if authorityErr = validateDFIRAuthority(authority, write.Actor); authorityErr != nil {
				return uuid.Nil, authorityErr
			}
			var eventID uuid.UUID
			queryErr := tx.QueryRow(
				ctx, appendDFIRDownloadGrantAuditQuery,
				identifiers[0], string(write.Actor.Kind), write.Actor.SessionID, write.Actor.MembershipID,
				string(write.Root.Kind), uuid.UUID(write.Root.ID.Bytes()), int64(write.RootVersion),
				string(write.Subject.Kind()), uuid.UUID(write.Subject.ID().Bytes()),
				uuid.UUID(write.AttachmentID.Bytes()), int64(write.AttachmentVersion),
				uuid.UUID(write.StorageObjectID.Bytes()), int64(write.StorageVersion),
				string(write.AttachmentState), string(write.StorageState), string(write.Access.Audience),
				string(write.Access.Scope), portalContactID, write.ExpiresAt,
				write.Audit.RequestID, write.Audit.CorrelationID, write.Audit.IPAddress,
				write.Audit.UserAgent, write.Audit.AuthenticationMethod,
			).Scan(&eventID)
			if queryErr != nil {
				return uuid.Nil, queryErr
			}
			if eventID != identifiers[0] {
				return uuid.Nil, errors.New("database returned an unexpected DFIR download audit identifier")
			}
			return eventID, nil
		},
	)
	return mapDFIRDatabaseError(err)
}

func validDFIRDownloadGrantAuditWrite(write application.DownloadGrantAuditWrite) bool {
	rootID := uuid.UUID(write.Root.ID.Bytes())
	subjectTenantID := uuid.UUID(write.Subject.TenantID().Bytes())
	subjectID := uuid.UUID(write.Subject.ID().Bytes())
	attachmentID := uuid.UUID(write.AttachmentID.Bytes())
	storageID := uuid.UUID(write.StorageObjectID.Bytes())
	if !authorizationUUIDv7(write.Actor.TenantID) || write.Actor.ActiveTenantID != write.Actor.TenantID ||
		!authorizationUUIDv7(write.Actor.UserID) || !authorizationUUIDv7(write.Actor.SessionID) ||
		!authorizationUUIDv7(write.Actor.MembershipID) ||
		(write.Root.Kind != application.PortalTicketCase && write.Root.Kind != application.PortalTicketAlert) ||
		!authorizationUUIDv7(rootID) || subjectTenantID != write.Actor.TenantID ||
		write.Subject.Kind() == kernel.EntityExternal || !authorizationUUIDv7(subjectID) ||
		!authorizationUUIDv7(attachmentID) || !authorizationUUIDv7(storageID) ||
		write.RootVersion == 0 || write.RootVersion > maximumDFIRDownloadRevision ||
		write.AttachmentVersion == 0 || write.AttachmentVersion > maximumDFIRDownloadRevision ||
		write.StorageVersion == 0 || write.StorageVersion > maximumDFIRDownloadRevision ||
		write.AttachmentState != kernel.ScanAvailable || write.StorageState != kernel.ScanAvailable ||
		write.ExpiresAt.IsZero() || write.ExpiresAt.Location() != time.UTC ||
		write.ExpiresAt.Nanosecond()%1_000 != 0 || !validDFIRDownloadAuditContext(write) {
		return false
	}
	if write.Actor.Kind == application.PrincipalHuman {
		return write.PortalAuthorization == nil && write.Access.Audience == kernel.AudienceOperator &&
			(write.Access.Scope == application.ScopeAssigned || write.Access.Scope == application.ScopeOperatorTeam ||
				write.Access.Scope == application.ScopeTenant)
	}
	return write.Actor.Kind == application.PrincipalCustomer && write.Access.Audience == kernel.AudienceCustomer &&
		write.Access.Scope == application.ScopeOwn && write.PortalAuthorization != nil &&
		write.PortalAuthorization.TenantID == write.Actor.TenantID && write.PortalAuthorization.Root == write.Root &&
		authorizationUUIDv7(write.PortalAuthorization.ContactID) &&
		write.PortalAuthorization.TicketVersion == write.RootVersion
}

func validDFIRDownloadAuditContext(write application.DownloadGrantAuditWrite) bool {
	audit := write.Audit
	return authorizationUUIDv7(audit.RequestID) && authorizationUUIDv7(audit.CorrelationID) &&
		audit.IPAddress.IsValid() && audit.IPAddress.Zone() == "" && audit.AuthenticationMethod == write.Actor.AuthenticationMethod &&
		validDFIRDownloadAuditText(audit.UserAgent, maximumAuditUserAgentBytes) && validDFIRDownloadAuditText(audit.AuthenticationMethod, 64)
}

func validDFIRDownloadAuditText(value string, maximumBytes int) bool {
	if value == "" || len(value) > maximumBytes || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	return !strings.ContainsFunc(value, func(character rune) bool {
		return character < 0x20 || character == 0x7f || character >= 0x202a && character <= 0x202e ||
			character >= 0x2066 && character <= 0x2069
	})
}

var _ application.Repository = (*DFIRRepository)(nil)
