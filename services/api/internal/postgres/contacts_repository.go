package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	kernel "github.com/periapsis-im/periapsis/modules/contacts"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
	application "github.com/periapsis-im/periapsis/services/api/internal/contacts"
)

// ContactsRepository keeps all contact data behind tenant RLS and delegates
// mutations to the bounded app.commit_* ABI. The ABI re-resolves authority,
// optimistic versions, idempotency, activity, redacted audit and outbox intent
// in the same serializable transaction.
type ContactsRepository struct {
	begin transactionBeginner
	newID func() (uuid.UUID, error)
}

func NewContactsRepository(pool *pgxpool.Pool) *ContactsRepository {
	if pool == nil {
		return nil
	}
	return &ContactsRepository{begin: poolTransactionBeginner(pool), newID: uuid.NewV7}
}

var _ application.Repository = (*ContactsRepository)(nil)

func (repository *ContactsRepository) ResolveAccess(
	ctx context.Context,
	actor application.Actor,
	tenantID uuid.UUID,
	capability application.Capability,
) (application.Access, error) {
	if repository == nil || repository.begin == nil {
		return application.Access{}, application.ErrRepositoryForbidden
	}
	access, err := withinTransactionWithOptions(ctx, repository.begin, phase4ReadOptions(),
		func(tx databaseTransaction) (application.Access, error) {
			return resolveContactAccess(ctx, tx, actor, tenantID, capability)
		},
	)
	return access, mapContactDatabaseError(err)
}

func (repository *ContactsRepository) ResolveSelfContact(
	ctx context.Context,
	actor application.Actor,
	tenantID uuid.UUID,
	capability application.Capability,
) (kernel.Contact, application.Access, error) {
	if repository == nil || repository.begin == nil || capability != application.CapabilityPortalPreferenceManage {
		return kernel.Contact{}, application.Access{}, application.ErrRepositoryForbidden
	}
	result, err := withinTransactionWithOptions(ctx, repository.begin, phase4ReadOptions(),
		func(tx databaseTransaction) (contactWithAccess, error) {
			authority, authorityErr := phase4Authority(ctx, tx, contactAuthorizationActor(actor), tenantID)
			if authorityErr != nil {
				return contactWithAccess{}, authorityErr
			}
			if !contactCustomerAuthority(authority, actor) ||
				!phase4HasPermission(authority, string(capability), authorization.ScopeOwn) {
				return contactWithAccess{}, application.ErrRepositoryForbidden
			}
			contact, loadErr := loadSelfContact(ctx, tx, tenantID, authority.MembershipID, actor.UserID)
			if loadErr != nil {
				return contactWithAccess{}, loadErr
			}
			access := application.Access{
				Capability: capability, Scope: application.ScopeContactSelf,
				Projection: application.ProjectionCustomer, ContactID: uuid.UUID(contact.ID().Bytes()),
			}
			return contactWithAccess{contact: contact, access: access}, nil
		},
	)
	if err != nil {
		return kernel.Contact{}, application.Access{}, mapContactDatabaseError(err)
	}
	return result.contact, result.access, nil
}

type contactWithAccess struct {
	contact kernel.Contact
	access  application.Access
}

func (repository *ContactsRepository) ListContacts(
	ctx context.Context,
	actor application.Actor,
	tenantID uuid.UUID,
	input application.ContactListInput,
	claimed application.Access,
) (application.ContactPage, error) {
	after, err := decodeContactCursor(input.After)
	if err != nil {
		return application.ContactPage{}, application.ErrRepositoryConflict
	}
	page, err := withinTransactionWithOptions(ctx, repository.begin, phase4ReadOptions(),
		func(tx databaseTransaction) (application.ContactPage, error) {
			access, accessErr := resolveContactAccess(ctx, tx, actor, tenantID, application.CapabilityContactRead)
			if accessErr != nil || access != claimed {
				if accessErr != nil {
					return application.ContactPage{}, accessErr
				}
				return application.ContactPage{}, application.ErrRepositoryForbidden
			}
			arguments := []any{tenantID, input.IncludeArchived, input.Limit + 1}
			query := `SELECT ` + contactColumns + `
				FROM public.customer_contacts AS contact
				WHERE contact.tenant_id = $1
				  AND ($2 OR contact.archived_at IS NULL)`
			if input.Active != nil {
				arguments = append(arguments, *input.Active)
				query += fmt.Sprintf(" AND contact.active = $%d", len(arguments))
			}
			if input.Class != "" {
				arguments = append(arguments, input.Class)
				query += fmt.Sprintf(" AND contact.contact_class = $%d", len(arguments))
			}
			if input.Tag != "" {
				arguments = append(arguments, input.Tag)
				query += fmt.Sprintf(" AND $%d = ANY(contact.tags)", len(arguments))
			}
			if input.Search != "" {
				arguments = append(arguments, input.Search)
				query += fmt.Sprintf(` AND to_tsvector('simple'::regconfig,
					coalesce(contact.first_name, '') || ' ' || coalesce(contact.last_name, '') || ' ' ||
					coalesce(contact.email, '') || ' ' || coalesce(contact.function, ''))
					@@ websearch_to_tsquery('simple'::regconfig, $%d)`, len(arguments))
			}
			if after != uuid.Nil {
				arguments = append(arguments, after)
				query += fmt.Sprintf(" AND contact.id > $%d", len(arguments))
			}
			query += " ORDER BY contact.id LIMIT $3"
			rows, queryErr := tx.Query(ctx, query, arguments...)
			if queryErr != nil {
				return application.ContactPage{}, queryErr
			}
			defer rows.Close()
			bases := make([]contactRow, 0, input.Limit+1)
			for rows.Next() {
				contact, scanErr := scanContactRow(rows)
				if scanErr != nil {
					return application.ContactPage{}, scanErr
				}
				bases = append(bases, contact)
			}
			if rows.Err() != nil {
				return application.ContactPage{}, rows.Err()
			}
			rows.Close()
			result := application.ContactPage{}
			if len(bases) > input.Limit {
				bases = bases[:input.Limit]
				result.NextCursor = encodeContactCursor(bases[len(bases)-1].id)
			}
			result.Items = make([]kernel.Contact, len(bases))
			for index, base := range bases {
				contact, hydrateErr := hydrateContact(ctx, tx, base)
				if hydrateErr != nil {
					return application.ContactPage{}, hydrateErr
				}
				result.Items[index] = contact
			}
			return result, nil
		},
	)
	return page, mapContactDatabaseError(err)
}

func (repository *ContactsRepository) GetContact(
	ctx context.Context,
	actor application.Actor,
	tenantID, contactID uuid.UUID,
	claimed application.Access,
) (kernel.Contact, error) {
	value, err := withinTransactionWithOptions(ctx, repository.begin, phase4ReadOptions(),
		func(tx databaseTransaction) (kernel.Contact, error) {
			capability := claimed.Capability
			if capability != application.CapabilityContactRead && capability != application.CapabilityContactManage {
				return kernel.Contact{}, application.ErrRepositoryForbidden
			}
			access, accessErr := resolveContactAccess(ctx, tx, actor, tenantID, capability)
			if accessErr != nil || access != claimed {
				if accessErr != nil {
					return kernel.Contact{}, accessErr
				}
				return kernel.Contact{}, application.ErrRepositoryForbidden
			}
			return loadContact(ctx, tx, tenantID, contactID)
		},
	)
	return value, mapContactDatabaseError(err)
}

func (repository *ContactsRepository) ReserveID(_ context.Context, _ uuid.UUID) (kernel.EntityID, error) {
	if repository == nil || repository.newID == nil {
		return kernel.EntityID{}, application.ErrRepositoryConflict
	}
	identifier, err := repository.newID()
	if err != nil {
		return kernel.EntityID{}, err
	}
	return kernel.NewEntityID([16]byte(identifier))
}

func (repository *ContactsRepository) ReplayContact(
	ctx context.Context,
	actor application.Actor,
	tenantID, contactID uuid.UUID,
	command application.CommandBinding,
) (application.ContactResult, bool, error) {
	if repository == nil || repository.begin == nil || !validContactCommand(command) ||
		!validContactReplayRoute(command.Operation, contactID) {
		return application.ContactResult{}, false, application.ErrRepositoryConflict
	}
	result, err := withinTransactionWithOptions(ctx, repository.begin, phase4WriteOptions(),
		func(tx databaseTransaction) (application.ContactResult, error) {
			if _, authorityErr := phase4Authority(ctx, tx, contactAuthorizationActor(actor), tenantID); authorityErr != nil {
				return application.ContactResult{}, authorityErr
			}
			replay, found, replayErr := replayCustomerContactCommand(
				ctx, tx, command, contactID, 0, uuid.Nil,
			)
			if replayErr != nil {
				return application.ContactResult{}, replayErr
			}
			if !found {
				return application.ContactResult{}, pgx.ErrNoRows
			}
			return decodeContactReplay(tenantID, command.Operation, replay)
		},
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return application.ContactResult{}, false, nil
	}
	if err != nil {
		return application.ContactResult{}, false, mapContactDatabaseError(err)
	}
	return result, true, nil
}

func (repository *ContactsRepository) CommitContact(ctx context.Context, write application.ContactWrite) (application.ContactResult, error) {
	if repository == nil || repository.begin == nil || !validContactCommand(write.Command) {
		return application.ContactResult{}, application.ErrRepositoryConflict
	}
	tenantID := uuid.UUID(write.Next.TenantID().Bytes())
	contactID := uuid.UUID(write.Next.ID().Bytes())
	payload, err := marshalContact(write.Next)
	if err != nil {
		return application.ContactResult{}, err
	}
	result, err := withinTransactionWithOptions(ctx, repository.begin, phase4WriteOptions(),
		func(tx databaseTransaction) (application.ContactResult, error) {
			if _, accessErr := resolveContactWriteAccess(ctx, tx, write, tenantID); accessErr != nil {
				return application.ContactResult{}, accessErr
			}
			var resultID uuid.UUID
			var version int64
			var replayed bool
			queryErr := tx.QueryRow(ctx, `
				SELECT contact_id, version, replayed
				FROM app.commit_customer_contact_v1(
					$1, $2, $3, $4::jsonb, $5, $6, $7,
					$8, $9, $10, $11::inet, $12, $13
				)`, write.Command.Operation, contactID, int64(write.ExpectedVersion), payload,
				write.Command.KeyDigest[:], write.Command.RequestDigest[:], write.Reason,
				write.Audit.RequestID, write.Audit.CorrelationID, write.Actor.MembershipID,
				write.Audit.RemoteAddress.Unmap(), write.Audit.UserAgent, write.Actor.AuthenticationMethod,
			).Scan(&resultID, &version, &replayed)
			if queryErr != nil {
				return application.ContactResult{}, queryErr
			}
			if resultID != contactID || version < 1 {
				return application.ContactResult{}, errors.New("contact commit returned an unexpected result")
			}
			replay, found, replayErr := replayCustomerContactCommand(
				ctx, tx, write.Command, resultID, 0, uuid.Nil,
			)
			if replayErr != nil {
				return application.ContactResult{}, replayErr
			}
			if !found || replay.version != version {
				return application.ContactResult{}, errors.New("contact commit omitted its exact replay snapshot")
			}
			decoded, decodeErr := decodeContactReplay(tenantID, write.Command.Operation, replay)
			decoded.Replayed = replayed
			return decoded, decodeErr
		},
	)
	return result, mapContactDatabaseError(err)
}

func (repository *ContactsRepository) ListGroups(
	ctx context.Context,
	actor application.Actor,
	tenantID uuid.UUID,
	input application.GroupListInput,
	claimed application.Access,
) (application.GroupPage, error) {
	after, err := decodeContactCursor(input.After)
	if err != nil {
		return application.GroupPage{}, application.ErrRepositoryConflict
	}
	page, err := withinTransactionWithOptions(ctx, repository.begin, phase4ReadOptions(),
		func(tx databaseTransaction) (application.GroupPage, error) {
			access, accessErr := resolveContactAccess(ctx, tx, actor, tenantID, application.CapabilityContactGroupRead)
			if accessErr != nil || access != claimed {
				if accessErr != nil {
					return application.GroupPage{}, accessErr
				}
				return application.GroupPage{}, application.ErrRepositoryForbidden
			}
			arguments := []any{tenantID, input.IncludeArchived, input.Limit + 1}
			query := `SELECT group_record.id
				FROM public.customer_contact_groups AS group_record
				JOIN public.customer_contact_group_versions AS version
				  ON version.tenant_id = group_record.tenant_id
				 AND version.group_id = group_record.id
				 AND version.version = group_record.current_version
				WHERE group_record.tenant_id = $1
				  AND ($2 OR group_record.archived_at IS NULL)`
			if input.Search != "" {
				arguments = append(arguments, input.Search)
				query += fmt.Sprintf(` AND to_tsvector('simple'::regconfig,
					coalesce(group_record.key, '') || ' ' || coalesce(version.name, '') || ' ' || coalesce(version.description, ''))
					@@ websearch_to_tsquery('simple'::regconfig, $%d)`, len(arguments))
			}
			if after != uuid.Nil {
				arguments = append(arguments, after)
				query += fmt.Sprintf(" AND group_record.id > $%d", len(arguments))
			}
			query += " ORDER BY group_record.id LIMIT $3"
			rows, queryErr := tx.Query(ctx, query, arguments...)
			if queryErr != nil {
				return application.GroupPage{}, queryErr
			}
			defer rows.Close()
			identifiers := make([]uuid.UUID, 0, input.Limit+1)
			for rows.Next() {
				var identifier uuid.UUID
				if scanErr := rows.Scan(&identifier); scanErr != nil {
					return application.GroupPage{}, scanErr
				}
				identifiers = append(identifiers, identifier)
			}
			if rows.Err() != nil {
				return application.GroupPage{}, rows.Err()
			}
			result := application.GroupPage{}
			if len(identifiers) > input.Limit {
				identifiers = identifiers[:input.Limit]
				result.NextCursor = encodeContactCursor(identifiers[len(identifiers)-1])
			}
			result.Items = make([]kernel.RecipientGroup, len(identifiers))
			for index, identifier := range identifiers {
				group, loadErr := loadContactGroup(ctx, tx, tenantID, identifier)
				if loadErr != nil {
					return application.GroupPage{}, loadErr
				}
				result.Items[index] = group
			}
			return result, nil
		},
	)
	return page, mapContactDatabaseError(err)
}

func (repository *ContactsRepository) GetGroup(
	ctx context.Context,
	actor application.Actor,
	tenantID, groupID uuid.UUID,
	claimed application.Access,
) (kernel.RecipientGroup, error) {
	group, err := withinTransactionWithOptions(ctx, repository.begin, phase4ReadOptions(),
		func(tx databaseTransaction) (kernel.RecipientGroup, error) {
			capability := claimed.Capability
			if capability != application.CapabilityContactGroupRead && capability != application.CapabilityContactGroupManage {
				return kernel.RecipientGroup{}, application.ErrRepositoryForbidden
			}
			access, accessErr := resolveContactAccess(ctx, tx, actor, tenantID, capability)
			if accessErr != nil || access != claimed {
				if accessErr != nil {
					return kernel.RecipientGroup{}, accessErr
				}
				return kernel.RecipientGroup{}, application.ErrRepositoryForbidden
			}
			return loadContactGroup(ctx, tx, tenantID, groupID)
		},
	)
	return group, mapContactDatabaseError(err)
}

func (repository *ContactsRepository) CommitGroup(ctx context.Context, write application.GroupWrite) (application.GroupResult, error) {
	if repository == nil || repository.begin == nil || !validContactCommand(write.Command) {
		return application.GroupResult{}, application.ErrRepositoryConflict
	}
	tenantID := uuid.UUID(write.Next.TenantID().Bytes())
	groupID := uuid.UUID(write.Next.ID().Bytes())
	payload, err := marshalContactGroup(write.Next)
	if err != nil {
		return application.GroupResult{}, err
	}
	result, err := withinTransactionWithOptions(ctx, repository.begin, phase4WriteOptions(),
		func(tx databaseTransaction) (application.GroupResult, error) {
			access, accessErr := resolveContactAccess(ctx, tx, write.Actor, tenantID, application.CapabilityContactGroupManage)
			if accessErr != nil || access != write.Access {
				if accessErr != nil {
					return application.GroupResult{}, accessErr
				}
				return application.GroupResult{}, application.ErrRepositoryForbidden
			}
			var resultID uuid.UUID
			var version int64
			var replayed bool
			queryErr := tx.QueryRow(ctx, `
				SELECT group_id, version, replayed
				FROM app.commit_customer_contact_group_v1(
					$1, $2, $3, $4::jsonb, $5, $6,
					$7, $8, $9, $10::inet, $11, $12
				)`, write.Command.Operation, groupID, int64(write.ExpectedVersion), payload,
				write.Command.KeyDigest[:], write.Command.RequestDigest[:],
				write.Audit.RequestID, write.Audit.CorrelationID, write.Actor.MembershipID,
				write.Audit.RemoteAddress.Unmap(), write.Audit.UserAgent, write.Actor.AuthenticationMethod,
			).Scan(&resultID, &version, &replayed)
			if queryErr != nil {
				return application.GroupResult{}, queryErr
			}
			if resultID != groupID || version < 1 {
				return application.GroupResult{}, errors.New("contact-group commit returned an unexpected result")
			}
			replay, found, replayErr := replayCustomerContactCommand(
				ctx, tx, write.Command, resultID, 0, uuid.Nil,
			)
			if replayErr != nil {
				return application.GroupResult{}, replayErr
			}
			if !found || replay.version != version || replay.projection != "operator" {
				return application.GroupResult{}, errors.New("contact-group commit omitted its exact replay snapshot")
			}
			group, decodeErr := decodeContactGroupCommandSnapshot(replay.resource, tenantID, replay.resourceID)
			return application.GroupResult{Group: group, Replayed: replayed}, decodeErr
		},
	)
	return result, mapContactDatabaseError(err)
}

func (repository *ContactsRepository) ReplayGroup(
	ctx context.Context,
	actor application.Actor,
	tenantID, groupID uuid.UUID,
	command application.CommandBinding,
) (application.GroupResult, bool, error) {
	if repository == nil || repository.begin == nil || !validContactCommand(command) ||
		!validGroupReplayRoute(command.Operation, groupID) {
		return application.GroupResult{}, false, application.ErrRepositoryConflict
	}
	result, err := withinTransactionWithOptions(ctx, repository.begin, phase4WriteOptions(),
		func(tx databaseTransaction) (application.GroupResult, error) {
			if _, authorityErr := phase4Authority(ctx, tx, contactAuthorizationActor(actor), tenantID); authorityErr != nil {
				return application.GroupResult{}, authorityErr
			}
			replay, found, replayErr := replayCustomerContactCommand(ctx, tx, command, groupID, 0, uuid.Nil)
			if replayErr != nil {
				return application.GroupResult{}, replayErr
			}
			if !found {
				return application.GroupResult{}, pgx.ErrNoRows
			}
			if replay.projection != "operator" {
				return application.GroupResult{}, errors.New("contact-group replay returned a non-operator projection")
			}
			group, decodeErr := decodeContactGroupCommandSnapshot(replay.resource, tenantID, replay.resourceID)
			return application.GroupResult{Group: group, Replayed: true}, decodeErr
		},
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return application.GroupResult{}, false, nil
	}
	if err != nil {
		return application.GroupResult{}, false, mapContactDatabaseError(err)
	}
	return result, true, nil
}

func (repository *ContactsRepository) ResolveExactLinkAccess(
	ctx context.Context,
	actor application.Actor,
	tenantID uuid.UUID,
	kind kernel.TicketKind,
	ticketID, contactID uuid.UUID,
	expectedVersion uint64,
) (application.ExactLinkAccess, error) {
	result, err := withinTransactionWithOptions(ctx, repository.begin, phase4ReadOptions(),
		func(tx databaseTransaction) (application.ExactLinkAccess, error) {
			return resolveExactContactLinkAccess(ctx, tx, actor, tenantID, kind, ticketID, contactID, expectedVersion)
		},
	)
	return result, mapContactDatabaseError(err)
}

func (repository *ContactsRepository) ListLinks(
	ctx context.Context,
	actor application.Actor,
	tenantID uuid.UUID,
	input application.LinkListInput,
) (application.LinkPage, error) {
	after, err := decodeContactCursor(input.After)
	if err != nil {
		return application.LinkPage{}, application.ErrRepositoryConflict
	}
	page, err := withinTransactionWithOptions(ctx, repository.begin, phase4ReadOptions(),
		func(tx databaseTransaction) (application.LinkPage, error) {
			authority, authorityErr := phase4Authority(ctx, tx, contactAuthorizationActor(actor), tenantID)
			if authorityErr != nil || !contactOperatorAuthority(authority, actor) ||
				!phase4HasPermission(authority, string(application.CapabilityContactRead), authorization.ScopeTenant) {
				if authorityErr != nil {
					return application.LinkPage{}, authorityErr
				}
				return application.LinkPage{}, application.ErrRepositoryForbidden
			}
			readCapability := application.Capability("alert.read")
			if input.TicketKind == kernel.TicketCase {
				readCapability = application.Capability("case.read")
			}
			if allowed, permissionErr := contactResourcePermission(ctx, tx, authority, tenantID, input.TicketKind, input.TicketID, readCapability); permissionErr != nil || !allowed {
				if permissionErr != nil {
					return application.LinkPage{}, permissionErr
				}
				return application.LinkPage{}, application.ErrRepositoryNotFound
			}
			_, resourceColumn, tableErr := contactTicketTable(input.TicketKind)
			if tableErr != nil {
				return application.LinkPage{}, tableErr
			}
			arguments := []any{tenantID, input.TicketID, input.Limit + 1}
			query := `SELECT link.id
				FROM public.ticket_customer_contacts AS link
				WHERE link.tenant_id = $1 AND link.` + resourceColumn + ` = $2
				  AND link.archived_at IS NULL`
			if after != uuid.Nil {
				arguments = append(arguments, after)
				query += " AND link.id > $4"
			}
			query += " ORDER BY link.id LIMIT $3"
			rows, queryErr := tx.Query(ctx, query, arguments...)
			if queryErr != nil {
				return application.LinkPage{}, queryErr
			}
			identifiers := make([]uuid.UUID, 0, input.Limit+1)
			for rows.Next() {
				var identifier uuid.UUID
				if scanErr := rows.Scan(&identifier); scanErr != nil {
					rows.Close()
					return application.LinkPage{}, scanErr
				}
				identifiers = append(identifiers, identifier)
			}
			if rows.Err() != nil {
				rows.Close()
				return application.LinkPage{}, rows.Err()
			}
			rows.Close()
			result := application.LinkPage{}
			if len(identifiers) > input.Limit {
				identifiers = identifiers[:input.Limit]
				result.NextCursor = encodeContactCursor(identifiers[len(identifiers)-1])
			}
			result.Items = make([]kernel.TicketContactLink, len(identifiers))
			for index, identifier := range identifiers {
				link, loadErr := loadContactLink(ctx, tx, tenantID, identifier)
				if loadErr != nil {
					return application.LinkPage{}, loadErr
				}
				result.Items[index] = link
			}
			return result, nil
		},
	)
	return page, mapContactDatabaseError(err)
}

func (repository *ContactsRepository) GetLinkForArchive(
	ctx context.Context,
	actor application.Actor,
	tenantID, linkID uuid.UUID,
	kind kernel.TicketKind,
	ticketID uuid.UUID,
) (kernel.TicketContactLink, error) {
	link, err := withinTransactionWithOptions(ctx, repository.begin, phase4ReadOptions(),
		func(tx databaseTransaction) (kernel.TicketContactLink, error) {
			authority, authorityErr := phase4Authority(ctx, tx, contactAuthorizationActor(actor), tenantID)
			if authorityErr != nil {
				return kernel.TicketContactLink{}, authorityErr
			}
			return loadContactLinkForArchive(ctx, tx, authority, actor, tenantID, linkID, kind, ticketID)
		},
	)
	return link, mapContactDatabaseError(err)
}

func loadContactLinkForArchive(
	ctx context.Context,
	tx databaseTransaction,
	authority authorization.TenantAuthority,
	actor application.Actor,
	tenantID, linkID uuid.UUID,
	kind kernel.TicketKind,
	ticketID uuid.UUID,
) (kernel.TicketContactLink, error) {
	if !contactOperatorAuthority(authority, actor) ||
		!phase4HasPermission(authority, string(application.CapabilityContactRead), authorization.ScopeTenant) {
		return kernel.TicketContactLink{}, application.ErrRepositoryForbidden
	}
	resourceCapability := application.CapabilityAlertUpdate
	if kind == kernel.TicketCase {
		resourceCapability = application.CapabilityCaseUpdate
	} else if kind != kernel.TicketAlert {
		return kernel.TicketContactLink{}, application.ErrRepositoryForbidden
	}
	allowed, permissionErr := contactResourcePermission(
		ctx, tx, authority, tenantID, kind, ticketID, resourceCapability,
	)
	if permissionErr != nil {
		if errors.Is(permissionErr, pgx.ErrNoRows) {
			return kernel.TicketContactLink{}, application.ErrRepositoryNotFound
		}
		return kernel.TicketContactLink{}, permissionErr
	}
	if !allowed {
		return kernel.TicketContactLink{}, application.ErrRepositoryNotFound
	}
	link, loadErr := loadContactLink(ctx, tx, tenantID, linkID)
	if loadErr != nil {
		return kernel.TicketContactLink{}, loadErr
	}
	if link.TicketKind() != kind || uuid.UUID(link.TicketID().Bytes()) != ticketID {
		return kernel.TicketContactLink{}, application.ErrRepositoryNotFound
	}
	return link, nil
}

func (repository *ContactsRepository) CommitLink(ctx context.Context, write application.LinkWrite) (application.LinkResult, error) {
	if repository == nil || repository.begin == nil || !validContactCommand(write.Command) {
		return application.LinkResult{}, application.ErrRepositoryConflict
	}
	tenantID := uuid.UUID(write.Next.TenantID().Bytes())
	linkID := uuid.UUID(write.Next.ID().Bytes())
	payload, err := marshalContactLink(write.Next)
	if err != nil {
		return application.LinkResult{}, err
	}
	result, err := withinTransactionWithOptions(ctx, repository.begin, phase4WriteOptions(),
		func(tx databaseTransaction) (application.LinkResult, error) {
			access, accessErr := resolveExactContactLinkAccess(ctx, tx, write.Actor, tenantID,
				write.Next.TicketKind(), uuid.UUID(write.Next.TicketID().Bytes()), uuid.UUID(write.Next.ContactID().Bytes()),
				write.ExpectedTicketVersion)
			if accessErr != nil || access != write.Access {
				if accessErr != nil {
					return application.LinkResult{}, accessErr
				}
				return application.LinkResult{}, application.ErrRepositoryForbidden
			}
			var resultID uuid.UUID
			var version int64
			var replayed bool
			queryErr := tx.QueryRow(ctx, `
				SELECT link_id, version, replayed
				FROM app.commit_ticket_customer_contact_v1(
					$1, $2, $3, $4, $5::jsonb, $6, $7, $8,
					$9, $10, $11, $12::inet, $13, $14
				)`, write.Command.Operation, linkID, int64(write.ExpectedLinkVersion), int64(write.ExpectedTicketVersion), payload,
				write.Command.KeyDigest[:], write.Command.RequestDigest[:], write.Reason,
				write.Audit.RequestID, write.Audit.CorrelationID, write.Actor.MembershipID,
				write.Audit.RemoteAddress.Unmap(), write.Audit.UserAgent, write.Actor.AuthenticationMethod,
			).Scan(&resultID, &version, &replayed)
			if queryErr != nil {
				return application.LinkResult{}, queryErr
			}
			if resultID != linkID || version < 1 {
				return application.LinkResult{}, errors.New("ticket-contact commit returned an unexpected result")
			}
			replay, found, replayErr := replayCustomerContactCommand(
				ctx, tx, write.Command, resultID, write.Next.TicketKind(),
				uuid.UUID(write.Next.TicketID().Bytes()),
			)
			if replayErr != nil {
				return application.LinkResult{}, replayErr
			}
			if !found || replay.version != version || replay.projection != "operator" {
				return application.LinkResult{}, errors.New("ticket-contact commit omitted its exact replay snapshot")
			}
			link, decodeErr := decodeContactLinkCommandSnapshot(replay.resource, tenantID, replay.resourceID)
			if decodeErr != nil {
				return application.LinkResult{}, decodeErr
			}
			if link.TicketKind() != write.Next.TicketKind() || link.TicketID() != write.Next.TicketID() {
				return application.LinkResult{}, errors.New("ticket-contact commit returned a mismatched replay route")
			}
			return application.LinkResult{Link: link, Replayed: replayed}, nil
		},
	)
	return result, mapContactDatabaseError(err)
}

func (repository *ContactsRepository) ReplayLink(
	ctx context.Context,
	actor application.Actor,
	tenantID, linkID uuid.UUID,
	kind kernel.TicketKind,
	ticketID uuid.UUID,
	command application.CommandBinding,
) (application.LinkResult, bool, error) {
	if repository == nil || repository.begin == nil || !validContactCommand(command) ||
		!validLinkReplayRoute(command.Operation, linkID) ||
		(kind != kernel.TicketAlert && kind != kernel.TicketCase) || !authorizationUUIDv7(ticketID) {
		return application.LinkResult{}, false, application.ErrRepositoryConflict
	}
	result, err := withinTransactionWithOptions(ctx, repository.begin, phase4WriteOptions(),
		func(tx databaseTransaction) (application.LinkResult, error) {
			if _, authorityErr := phase4Authority(ctx, tx, contactAuthorizationActor(actor), tenantID); authorityErr != nil {
				return application.LinkResult{}, authorityErr
			}
			replay, found, replayErr := replayCustomerContactCommand(ctx, tx, command, linkID, kind, ticketID)
			if replayErr != nil {
				return application.LinkResult{}, replayErr
			}
			if !found {
				return application.LinkResult{}, pgx.ErrNoRows
			}
			if replay.projection != "operator" {
				return application.LinkResult{}, errors.New("ticket-contact replay returned a non-operator projection")
			}
			link, decodeErr := decodeContactLinkCommandSnapshot(replay.resource, tenantID, replay.resourceID)
			if decodeErr != nil {
				return application.LinkResult{}, decodeErr
			}
			if link.TicketKind() != kind || uuid.UUID(link.TicketID().Bytes()) != ticketID {
				return application.LinkResult{}, errors.New("ticket-contact replay returned a mismatched route")
			}
			return application.LinkResult{Link: link, Replayed: true}, nil
		},
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return application.LinkResult{}, false, nil
	}
	if err != nil {
		return application.LinkResult{}, false, mapContactDatabaseError(err)
	}
	return result, true, nil
}

func (repository *ContactsRepository) ResolvePortalResource(
	ctx context.Context,
	actor application.Actor,
	tenantID uuid.UUID,
	input application.PortalResourceInput,
) (application.PortalResourceEvidence, error) {
	result, err := withinTransactionWithOptions(ctx, repository.begin, phase4ReadOptions(),
		func(tx databaseTransaction) (application.PortalResourceEvidence, error) {
			authority, authorityErr := phase4Authority(ctx, tx, contactAuthorizationActor(actor), tenantID)
			if authorityErr != nil || !contactCustomerAuthority(authority, actor) ||
				!phase4HasPermission(authority, string(input.Capability), authorization.ScopeOwn) ||
				(input.RequiredCapability != "" &&
					!phase4HasPermission(authority, string(input.RequiredCapability), authorization.ScopeOwn)) {
				if authorityErr != nil {
					return application.PortalResourceEvidence{}, authorityErr
				}
				return application.PortalResourceEvidence{}, application.ErrRepositoryForbidden
			}
			resourceTable, resourceColumn, err := contactTicketTable(input.TicketKind)
			if err != nil {
				return application.PortalResourceEvidence{}, err
			}
			query := fmt.Sprintf(`
				SELECT contact.id, contact.version, ticket.version,
				       ticket.customer_visible AND EXISTS (
				         SELECT 1
				         FROM jsonb_array_elements(workflow.states) AS state(value)
				         WHERE state.value ->> 'key' = ticket.state_key
				           AND state.value ->> 'visibility' = 'customer'
				       ),
				       contact.active AND contact.archived_at IS NULL,
				       link.archived_at IS NULL
				FROM public.customer_contacts AS contact
				JOIN public.ticket_customer_contacts AS link
				  ON link.tenant_id = contact.tenant_id
				 AND link.contact_id = contact.id
				 AND link.%s = $4
				JOIN public.%s AS ticket
				  ON ticket.tenant_id = link.tenant_id
				 AND ticket.id = link.%s
				JOIN public.ticket_workflow_versions AS workflow
				  ON workflow.tenant_id = ticket.tenant_id
				 AND workflow.workflow_id = ticket.workflow_id
				 AND workflow.version = ticket.workflow_version
				 AND workflow.aggregate_kind = $5::public.ticket_aggregate_kind
				WHERE contact.tenant_id = $1
				  AND contact.linked_membership_id = $2
				  AND contact.linked_user_id = $3`, resourceColumn, resourceTable, resourceColumn)
			var evidence application.PortalResourceEvidence
			var active, linked bool
			if queryErr := tx.QueryRow(ctx, query, tenantID, authority.MembershipID, actor.UserID, input.TicketID, input.TicketKind.String()).Scan(
				&evidence.ContactID, &evidence.ContactVersion, &evidence.TicketVersion,
				&evidence.CustomerVisible, &active, &linked,
			); queryErr != nil {
				return application.PortalResourceEvidence{}, queryErr
			}
			evidence.TenantID = tenantID
			evidence.TicketKind = input.TicketKind
			evidence.TicketID = input.TicketID
			evidence.ContactActive = active
			evidence.Linked = linked
			evidence.Capability = input.Capability
			evidence.RequiredCapability = input.RequiredCapability
			return evidence, nil
		},
	)
	return result, mapContactDatabaseError(err)
}

func resolveContactWriteAccess(
	ctx context.Context,
	tx databaseTransaction,
	write application.ContactWrite,
	tenantID uuid.UUID,
) (application.Access, error) {
	if write.Command.Operation == "portal.preference.replace" {
		contact, access, err := resolveSelfContactInTransaction(ctx, tx, write.Actor, tenantID)
		if err != nil {
			return application.Access{}, err
		}
		if access != write.Access || contact.ID() != write.Next.ID() {
			return application.Access{}, application.ErrRepositoryForbidden
		}
		return access, nil
	}
	access, err := resolveContactAccess(ctx, tx, write.Actor, tenantID, application.CapabilityContactManage)
	if err != nil || access != write.Access {
		if err != nil {
			return application.Access{}, err
		}
		return application.Access{}, application.ErrRepositoryForbidden
	}
	return access, nil
}

func resolveSelfContactInTransaction(
	ctx context.Context,
	tx databaseTransaction,
	actor application.Actor,
	tenantID uuid.UUID,
) (kernel.Contact, application.Access, error) {
	authority, err := phase4Authority(ctx, tx, contactAuthorizationActor(actor), tenantID)
	if err != nil || !contactCustomerAuthority(authority, actor) ||
		!phase4HasPermission(authority, string(application.CapabilityPortalPreferenceManage), authorization.ScopeOwn) {
		if err != nil {
			return kernel.Contact{}, application.Access{}, err
		}
		return kernel.Contact{}, application.Access{}, application.ErrRepositoryForbidden
	}
	contact, err := loadSelfContact(ctx, tx, tenantID, authority.MembershipID, actor.UserID)
	if err != nil {
		return kernel.Contact{}, application.Access{}, err
	}
	return contact, application.Access{
		Capability: application.CapabilityPortalPreferenceManage,
		Scope:      application.ScopeContactSelf, Projection: application.ProjectionCustomer,
		ContactID: uuid.UUID(contact.ID().Bytes()),
	}, nil
}

func resolveContactAccess(
	ctx context.Context,
	tx databaseTransaction,
	actor application.Actor,
	tenantID uuid.UUID,
	capability application.Capability,
) (application.Access, error) {
	if !operatorContactCapability(capability) {
		return application.Access{}, application.ErrRepositoryForbidden
	}
	authority, err := phase4Authority(ctx, tx, contactAuthorizationActor(actor), tenantID)
	if err != nil {
		return application.Access{}, err
	}
	if !contactOperatorAuthority(authority, actor) ||
		!phase4HasPermission(authority, string(capability), authorization.ScopeTenant) {
		return application.Access{}, application.ErrRepositoryForbidden
	}
	return application.Access{
		Capability: capability, Scope: application.ScopeTenant, Projection: application.ProjectionOperator,
	}, nil
}

func resolveExactContactLinkAccess(
	ctx context.Context,
	tx databaseTransaction,
	actor application.Actor,
	tenantID uuid.UUID,
	kind kernel.TicketKind,
	ticketID, contactID uuid.UUID,
	expectedVersion uint64,
) (application.ExactLinkAccess, error) {
	resourceCapability := application.CapabilityAlertUpdate
	if kind == kernel.TicketCase {
		resourceCapability = application.CapabilityCaseUpdate
	} else if kind != kernel.TicketAlert {
		return application.ExactLinkAccess{}, application.ErrRepositoryForbidden
	}
	authority, err := phase4Authority(ctx, tx, contactAuthorizationActor(actor), tenantID)
	if err != nil {
		return application.ExactLinkAccess{}, err
	}
	if !contactOperatorAuthority(authority, actor) ||
		!phase4HasPermission(authority, string(application.CapabilityContactRead), authorization.ScopeTenant) {
		return application.ExactLinkAccess{}, application.ErrRepositoryForbidden
	}
	allowed, permissionErr := contactResourcePermission(ctx, tx, authority, tenantID, kind, ticketID, resourceCapability)
	if permissionErr != nil {
		return application.ExactLinkAccess{}, permissionErr
	}
	if !allowed {
		return application.ExactLinkAccess{}, application.ErrRepositoryNotFound
	}
	resourceTable, _, err := contactTicketTable(kind)
	if err != nil {
		return application.ExactLinkAccess{}, err
	}
	query := fmt.Sprintf(`
		SELECT ticket.version, contact.version
		FROM public.%s AS ticket
		JOIN public.customer_contacts AS contact ON contact.tenant_id = ticket.tenant_id
		WHERE ticket.tenant_id = $1 AND ticket.id = $2 AND ticket.version = $3
		  AND contact.id = $4 AND contact.active AND contact.archived_at IS NULL`, resourceTable)
	var ticketVersion, contactVersion uint64
	if err := tx.QueryRow(ctx, query, tenantID, ticketID, expectedVersion, contactID).Scan(&ticketVersion, &contactVersion); err != nil {
		return application.ExactLinkAccess{}, err
	}
	return application.ExactLinkAccess{
		TenantID: tenantID, TicketKind: kind, TicketID: ticketID, ContactID: contactID,
		TicketVersion: ticketVersion, ContactVersion: contactVersion,
		ResourceCapability: resourceCapability, ContactReadable: true, ResourceWritable: true,
	}, nil
}

func contactResourcePermission(
	ctx context.Context,
	tx databaseTransaction,
	authority authorization.TenantAuthority,
	tenantID uuid.UUID,
	kind kernel.TicketKind,
	ticketID uuid.UUID,
	capability application.Capability,
) (bool, error) {
	table, _, err := contactTicketTable(kind)
	if err != nil {
		return false, err
	}
	creatorColumn := "ticket.created_by"
	if kind == kernel.TicketCase {
		creatorColumn = "ticket.created_by_user_id"
	}
	query := fmt.Sprintf(`
		SELECT %s, ticket.assignee_user_id, ticket.claimed_by_user_id,
		       ticket.assigned_team_id, ticket.assigned_team_epoch_id
		FROM public.%s AS ticket
		WHERE ticket.tenant_id = $1 AND ticket.id = $2`, creatorColumn, table)
	var ownerID, assigneeID, claimantID, teamID, epochID *uuid.UUID
	if err := tx.QueryRow(ctx, query, tenantID, ticketID).Scan(&ownerID, &assigneeID, &claimantID, &teamID, &epochID); err != nil {
		return false, err
	}
	for _, grant := range authority.Permissions {
		if string(grant.Permission) != string(capability) {
			continue
		}
		switch grant.Scope {
		case authorization.ScopeTenant:
			return true, nil
		case authorization.ScopeOwn:
			if ownerID != nil && *ownerID == authority.Principal.ID {
				return true, nil
			}
		case authorization.ScopeAssigned:
			if assigneeID != nil && *assigneeID == authority.Principal.ID ||
				claimantID != nil && *claimantID == authority.Principal.ID {
				return true, nil
			}
		case authorization.ScopeOperatorTeam:
			if teamID == nil || epochID == nil {
				continue
			}
			for _, relationship := range authority.OperatorTeamRelationships {
				if relationship.OperatorTeamID == *teamID && relationship.AssignmentEpochID == *epochID {
					return true, nil
				}
			}
		}
	}
	return false, nil
}

func contactAuthorizationActor(actor application.Actor) authorization.Actor {
	return authorization.Actor{
		UserID: actor.UserID, SessionID: actor.SessionID,
		ActiveTenantID: actor.ActiveTenantID, AuthenticationMethod: actor.AuthenticationMethod,
	}
}

func contactOperatorAuthority(authority authorization.TenantAuthority, actor application.Actor) bool {
	return actor.Kind == application.PrincipalOperator && validPhase4Authority(authority, actor.MembershipID) &&
		authority.Principal.ID == actor.UserID
}

func contactCustomerAuthority(authority authorization.TenantAuthority, actor application.Actor) bool {
	return actor.Kind == application.PrincipalCustomer && validPhase4Authority(authority, actor.MembershipID) &&
		authority.Principal.ID == actor.UserID
}

func operatorContactCapability(value application.Capability) bool {
	switch value {
	case application.CapabilityContactRead, application.CapabilityContactManage,
		application.CapabilityContactGroupRead, application.CapabilityContactGroupManage:
		return true
	default:
		return false
	}
}

func contactTicketTable(kind kernel.TicketKind) (table string, column string, err error) {
	switch kind {
	case kernel.TicketAlert:
		return "alerts", "alert_id", nil
	case kernel.TicketCase:
		return "cases", "case_id", nil
	default:
		return "", "", application.ErrRepositoryForbidden
	}
}

func validContactCommand(binding application.CommandBinding) bool {
	if binding.KeyDigest == [sha256.Size]byte{} || binding.RequestDigest == [sha256.Size]byte{} {
		return false
	}
	switch binding.Operation {
	case "contact.create", "contact.replace", "contact.archive", "portal.preference.replace",
		"contact_group.create", "contact_group.version", "contact_group.archive",
		"ticket_contact.link", "ticket_contact.archive":
		return true
	default:
		return false
	}
}

func validContactReplayRoute(operation string, contactID uuid.UUID) bool {
	switch operation {
	case "contact.create":
		return contactID == uuid.Nil
	case "contact.replace", "contact.archive", "portal.preference.replace":
		return authorizationUUIDv7(contactID)
	default:
		return false
	}
}

func validGroupReplayRoute(operation string, groupID uuid.UUID) bool {
	switch operation {
	case "contact_group.create":
		return groupID == uuid.Nil
	case "contact_group.version", "contact_group.archive":
		return authorizationUUIDv7(groupID)
	default:
		return false
	}
}

func validLinkReplayRoute(operation string, linkID uuid.UUID) bool {
	switch operation {
	case "ticket_contact.link":
		return linkID == uuid.Nil
	case "ticket_contact.archive":
		return authorizationUUIDv7(linkID)
	default:
		return false
	}
}

type contactCommandReplay struct {
	resourceID uuid.UUID
	version    int64
	projection string
	resource   []byte
}

func replayCustomerContactCommand(
	ctx context.Context,
	tx databaseTransaction,
	command application.CommandBinding,
	resourceID uuid.UUID,
	ticketKind kernel.TicketKind,
	ticketID uuid.UUID,
) (contactCommandReplay, bool, error) {
	var resourceArgument any
	if resourceID != uuid.Nil {
		resourceArgument = resourceID
	}
	var kindArgument any
	var ticketArgument any
	if ticketKind != 0 {
		kindArgument = ticketKind.String()
		ticketArgument = ticketID
	}
	var replay contactCommandReplay
	err := tx.QueryRow(ctx, `
		SELECT resource_id, version, projection, resource
		FROM app.replay_customer_contact_command_v1(
			$1, $2, $3, $4, $5::public.ticket_aggregate_kind, $6
		)`, command.Operation, command.KeyDigest[:], command.RequestDigest[:],
		resourceArgument, kindArgument, ticketArgument,
	).Scan(&replay.resourceID, &replay.version, &replay.projection, &replay.resource)
	if errors.Is(err, pgx.ErrNoRows) {
		return contactCommandReplay{}, false, nil
	}
	if err != nil {
		return contactCommandReplay{}, false, err
	}
	if !authorizationUUIDv7(replay.resourceID) || replay.version < 1 ||
		(replay.projection != "operator" && replay.projection != "customer") ||
		len(replay.resource) == 0 || len(replay.resource) > 512*1024 {
		return contactCommandReplay{}, false, errors.New("customer contact replay returned an invalid envelope")
	}
	return replay, true, nil
}

func decodeContactReplay(
	tenantID uuid.UUID,
	operation string,
	replay contactCommandReplay,
) (application.ContactResult, error) {
	if operation == "portal.preference.replace" {
		if replay.projection != "customer" {
			return application.ContactResult{}, errors.New("portal contact replay returned an operator projection")
		}
		projection, err := decodeCustomerContactCommandSnapshot(replay.resource, replay.resourceID)
		if err != nil || int64(projection.Version) != replay.version {
			return application.ContactResult{}, errors.New("portal contact replay returned an invalid snapshot")
		}
		return application.ContactResult{CustomerProjection: &projection, Replayed: true}, nil
	}
	if replay.projection != "operator" {
		return application.ContactResult{}, errors.New("operator contact replay returned a customer projection")
	}
	contact, err := decodeContactCommandSnapshot(replay.resource, tenantID, replay.resourceID)
	if err != nil || int64(contact.Version()) != replay.version {
		return application.ContactResult{}, errors.New("operator contact replay returned an invalid snapshot")
	}
	return application.ContactResult{Contact: contact, Replayed: true}, nil
}

func encodeContactCursor(identifier uuid.UUID) string {
	payload := append([]byte{1}, identifier[:]...)
	return base64.RawURLEncoding.EncodeToString(payload)
}

func decodeContactCursor(value string) (uuid.UUID, error) {
	if value == "" {
		return uuid.Nil, nil
	}
	payload, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(payload) != 17 || payload[0] != 1 || base64.RawURLEncoding.EncodeToString(payload) != value {
		return uuid.Nil, application.ErrInvalidInput
	}
	identifier, err := uuid.FromBytes(payload[1:])
	if err != nil || !authorizationUUIDv7(identifier) {
		return uuid.Nil, application.ErrInvalidInput
	}
	return identifier, nil
}

func mapContactDatabaseError(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, application.ErrRepositoryForbidden), errors.Is(err, authorization.ErrForbidden):
		return application.ErrRepositoryForbidden
	case errors.Is(err, application.ErrRepositoryNotFound), errors.Is(err, authorization.ErrNotFound), errors.Is(err, pgx.ErrNoRows):
		return application.ErrRepositoryNotFound
	case errors.Is(err, application.ErrRepositoryPrecondition):
		return application.ErrRepositoryPrecondition
	case errors.Is(err, application.ErrRepositoryConflict), errors.Is(err, authorization.ErrConflict):
		return application.ErrRepositoryConflict
	}
	switch postgresCode(err) {
	case "42501":
		return application.ErrRepositoryForbidden
	case "P0002":
		return application.ErrRepositoryNotFound
	case "40001":
		return application.ErrRepositoryPrecondition
	case "23505", "23503", "23514", "40P01", "22023", "22P02", "55000":
		return application.ErrRepositoryConflict
	default:
		return err
	}
}

func sortedUUIDs(values []uuid.UUID) []uuid.UUID {
	result := slices.Clone(values)
	slices.SortFunc(result, func(left, right uuid.UUID) int { return strings.Compare(left.String(), right.String()) })
	return result
}

func marshalJSON(value any) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) > 256*1024 {
		if err != nil {
			return nil, err
		}
		return nil, application.ErrRepositoryConflict
	}
	return encoded, nil
}
