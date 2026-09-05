package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/services/api/internal/identityprovider"
	"github.com/periapsis-im/periapsis/services/api/internal/ldapauth"
)

const (
	beginLDAPAuthenticationSQL = `SELECT * FROM app.begin_tenant_ldap_jit_authentication_v1(
		$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`
	ldapAuthenticationBlockedSQL = `SELECT EXISTS (
		SELECT 1
		FROM (VALUES
			('ldap_network'::public.auth_rate_limit_scope,$1::bytea),
			('ldap_account'::public.auth_rate_limit_scope,$2::bytea),
			('ldap_provider'::public.auth_rate_limit_scope,$3::bytea)
		) AS rate_key(scope,key_digest)
		CROSS JOIN LATERAL app.get_auth_rate_limit(
			rate_key.scope,rate_key.key_digest
		) AS rate
		WHERE rate.blocked_until > statement_timestamp()
	)`
	claimLDAPAuthenticationSQL = `SELECT * FROM app.claim_tenant_ldap_jit_planning_v1(
		$1,$2,$3,$4,$5,$6,$7,$8,$9)`
	ldapAssuranceSnapshotSQL = `SELECT requirement,has_enrollable_factor
		FROM app.tenant_ldap_jit_assurance_snapshot_v1($1,$2,$3,$4)`
	applyLDAPIdentityPlanSQL = `SELECT * FROM app.apply_tenant_ldap_jit_identity_plan_v1(
		$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,
		$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30)`
	issueLDAPAuthoritySQL = `SELECT app.issue_tenant_ldap_jit_authority_v1(
		$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`
	completeLDAPAuthenticationSQL = `SELECT app.complete_tenant_ldap_jit_authentication_v1(
		$1,$2,$3,$4,$5,$6,$7,$8)`
)

type LDAPAuthenticationRepository struct {
	queryer federatedAuthQueryer
	begin   transactionBeginner
}

func NewLDAPAuthenticationRepository(pool *pgxpool.Pool) *LDAPAuthenticationRepository {
	return &LDAPAuthenticationRepository{queryer: pool, begin: poolTransactionBeginner(pool)}
}

func (repository *LDAPAuthenticationRepository) String() string {
	return fmt.Sprintf("postgres.LDAPAuthenticationRepository{configured:%t}",
		repository != nil && repository.queryer != nil && repository.begin != nil)
}

func (repository *LDAPAuthenticationRepository) GoString() string { return repository.String() }

var _ ldapauth.Repository = (*LDAPAuthenticationRepository)(nil)

func (repository *LDAPAuthenticationRepository) Begin(
	ctx context.Context,
	request ldapauth.BeginRequest,
) (ldapauth.NetworkSnapshot, error) {
	if repository == nil || repository.queryer == nil || ctx == nil || ctx.Err() != nil {
		return ldapauth.NetworkSnapshot{}, ldapauth.ErrUnavailable
	}
	var row ldapNetworkSnapshotRow
	err := repository.queryer.QueryRow(ctx, beginLDAPAuthenticationSQL,
		request.OperationRunID, request.ReceiptDigest[:], request.TenantSlug, request.LoginKey,
		request.NetworkRateKey[:], request.AccountRateKey[:], request.ProviderRateKey[:],
		request.AuditEventID, request.Audit.RequestID, request.Audit.CorrelationID,
		request.Audit.ClientIP.String(), request.Audit.UserAgent,
	).Scan(
		&row.OperationRunID, &row.TenantID, &row.ProviderID, &row.ProviderVersion,
		&row.ConfigurationVersion, &row.EndpointDigest, &row.Configuration, &row.Endpoints,
		&row.SecretID, &row.SecretCiphertext, &row.SecretNonce, &row.SecretVersion,
		&row.SecretKeyVersion, &row.SecretAlgorithm, &row.BindingID, &row.BindingVersion,
		&row.BindingAuthRevision, &row.BindingAccessEpochID, &row.RuleSetRevision,
		&row.AuthorizationRevision, &row.StartedAt, &row.ExpiresAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			blocked, blockErr := repository.authenticationBlocked(ctx, request)
			if blockErr != nil {
				return ldapauth.NetworkSnapshot{}, blockErr
			}
			if blocked {
				return ldapauth.NetworkSnapshot{}, ldapauth.ErrRateLimited
			}
		}
		return ldapauth.NetworkSnapshot{}, mapLDAPAuthenticationDatabaseError(err)
	}
	return mapLDAPNetworkSnapshot(row, request.OperationRunID)
}

func (repository *LDAPAuthenticationRepository) authenticationBlocked(
	ctx context.Context,
	request ldapauth.BeginRequest,
) (bool, error) {
	var blocked bool
	if err := repository.queryer.QueryRow(
		ctx,
		ldapAuthenticationBlockedSQL,
		request.NetworkRateKey[:],
		request.AccountRateKey[:],
		request.ProviderRateKey[:],
	).Scan(&blocked); err != nil {
		return false, ldapauth.ErrUnavailable
	}
	return blocked, nil
}

type ldapNetworkSnapshotRow struct {
	OperationRunID, TenantID, ProviderID, SecretID, BindingID, BindingAccessEpochID uuid.UUID
	ProviderVersion, ConfigurationVersion, SecretVersion, SecretKeyVersion          int32
	BindingVersion, BindingAuthRevision                                             int32
	RuleSetRevision, AuthorizationRevision                                          int64
	EndpointDigest, Configuration, Endpoints, SecretCiphertext, SecretNonce         []byte
	SecretAlgorithm                                                                 string
	StartedAt, ExpiresAt                                                            time.Time
}

func mapLDAPNetworkSnapshot(row ldapNetworkSnapshotRow, expectedRunID uuid.UUID) (ldapauth.NetworkSnapshot, error) {
	defer clear(row.EndpointDigest)
	if !identityProviderUUIDv7(row.OperationRunID) || row.OperationRunID != expectedRunID ||
		!identityProviderUUIDv7(row.TenantID) || !identityProviderUUIDv7(row.ProviderID) ||
		!identityProviderUUIDv7(row.SecretID) || !identityProviderUUIDv7(row.BindingID) ||
		!identityProviderUUIDv7(row.BindingAccessEpochID) || row.ProviderVersion < 1 ||
		row.ConfigurationVersion < 1 || row.SecretVersion < 1 || row.SecretKeyVersion < 1 ||
		row.SecretKeyVersion > math.MaxInt16 || row.BindingVersion < 1 || row.BindingAuthRevision < 1 ||
		row.RuleSetRevision < 1 || row.AuthorizationRevision < 1 || len(row.EndpointDigest) != sha256.Size ||
		len(row.SecretNonce) != 12 || len(row.SecretCiphertext) < 17 || len(row.SecretCiphertext) > 8192 ||
		row.SecretAlgorithm != "aes-256-gcm" {
		clear(row.SecretCiphertext)
		clear(row.SecretNonce)
		return ldapauth.NetworkSnapshot{}, ldapauth.ErrUnavailable
	}
	configuration, err := decodeIdentityProviderJSON[identityprovider.Configuration](row.Configuration)
	if err != nil {
		clear(row.SecretCiphertext)
		clear(row.SecretNonce)
		return ldapauth.NetworkSnapshot{}, ldapauth.ErrUnavailable
	}
	// The frozen 0072 network snapshot predates sync/deprovision transport
	// fields. They do not affect an interactive bind, but the shared canonical
	// network mapper deliberately validates the complete document.
	if configuration.DeprovisionMode == "" {
		configuration.DeprovisionMode = identityprovider.DeprovisionModeRetain
		configuration.DeprovisionGraceSeconds = 0
	}
	endpoints, err := decodeIdentityProviderJSON[[]identityprovider.Endpoint](row.Endpoints)
	if err != nil || len(endpoints) < 1 || len(endpoints) > 8 {
		clear(row.SecretCiphertext)
		clear(row.SecretNonce)
		return ldapauth.NetworkSnapshot{}, ldapauth.ErrUnavailable
	}
	var nonce [12]byte
	copy(nonce[:], row.SecretNonce)
	clear(row.SecretNonce)
	return ldapauth.NetworkSnapshot{
		OperationRunID: row.OperationRunID, TenantID: row.TenantID, ProviderID: row.ProviderID,
		ProviderVersion: int64(row.ProviderVersion), ConfigurationVersion: int64(row.ConfigurationVersion),
		Configuration: configuration, Endpoints: endpoints, SecretID: row.SecretID,
		Secret: identity.BindSecretEnvelope{KeyVersion: int16(row.SecretKeyVersion), Nonce: nonce,
			Ciphertext: row.SecretCiphertext},
		BindingID: row.BindingID, BindingVersion: int64(row.BindingVersion),
		BindingAuthRevision: int64(row.BindingAuthRevision), RuleSetRevision: row.RuleSetRevision,
		AuthorizationRevision: row.AuthorizationRevision, StartedAt: row.StartedAt.UTC(),
		ExpiresAt: row.ExpiresAt.UTC(),
	}, nil
}

func (repository *LDAPAuthenticationRepository) Claim(
	ctx context.Context,
	request ldapauth.ClaimRequest,
) (ldapauth.Claim, error) {
	if repository == nil || repository.begin == nil || ctx == nil || ctx.Err() != nil ||
		len(request.SubjectAliases) < 1 || len(request.SubjectAliases) > 16 {
		return ldapauth.Claim{}, ldapauth.ErrUnavailable
	}
	versions := make([]int32, len(request.SubjectAliases))
	digests := make([][]byte, len(request.SubjectAliases))
	for index, alias := range request.SubjectAliases {
		versions[index] = int32(alias.KeyVersion)
		digests[index] = append([]byte(nil), alias.Digest[:]...)
	}
	defer func() {
		for index := range digests {
			clear(digests[index])
		}
	}()
	return withinTransaction(ctx, repository.begin, func(tx databaseTransaction) (ldapauth.Claim, error) {
		var row ldapPlanningRow
		err := tx.QueryRow(ctx, claimLDAPAuthenticationSQL,
			request.OperationRunID, request.ReceiptDigest[:], versions, digests,
			request.AuditEventID, request.Audit.RequestID, request.Audit.CorrelationID,
			request.Audit.ClientIP.String(), request.Audit.UserAgent,
		).Scan(
			&row.OperationRunID, &row.TenantID, &row.ProviderID, &row.ProviderVersion,
			&row.BindingID, &row.BindingVersion, &row.BindingAuthRevision,
			&row.BindingAccessEpochID, &row.ConfigurationRevision, &row.RuleSetRevision,
			&row.AuthorizationRevision, &row.JITMode, &row.NoMatchPolicy,
			&row.ProviderAccessSourceID, &row.ExternalIdentityID, &row.UserID,
			&row.MembershipID, &row.ExternalIdentityExists, &row.UserActive,
			&row.MembershipExists, &row.MembershipActive, &row.AccessGrantLive,
			&row.Rules, &row.RolePolicies, &row.ExistingRoleIDs, &row.LiveOwnedEdges,
		)
		if err != nil {
			return ldapauth.Claim{}, mapLDAPAuthenticationDatabaseError(err)
		}
		claim, err := mapLDAPPlanningClaim(row, request.OperationRunID)
		if err != nil {
			return ldapauth.Claim{}, err
		}
		var requirementDocument []byte
		var userArgument any
		if claim.UserID != uuid.Nil {
			userArgument = claim.UserID
		}
		if err = tx.QueryRow(ctx, ldapAssuranceSnapshotSQL, request.OperationRunID,
			request.ReceiptDigest[:], userArgument, request.EvaluatedAt,
		).Scan(&requirementDocument, &claim.HasEnrollableFactor); err != nil {
			return ldapauth.Claim{}, mapLDAPAuthenticationDatabaseError(err)
		}
		wire, err := decodeIdentityProviderJSON[assuranceRequirementWire](requirementDocument)
		if err != nil {
			return ldapauth.Claim{}, ldapauth.ErrUnavailable
		}
		claim.Requirement, err = requirementFromWire(wire)
		if err != nil || !validFederatedPlanningRequirement(claim.Requirement) {
			return ldapauth.Claim{}, ldapauth.ErrUnavailable
		}
		return claim, nil
	})
}

type ldapPlanningRow struct {
	OperationRunID, TenantID, ProviderID, BindingID, BindingAccessEpochID,
	ProviderAccessSourceID uuid.UUID
	ProviderVersion, BindingVersion, BindingAuthRevision, ConfigurationRevision int32
	RuleSetRevision, AuthorizationRevision                                      int64
	JITMode, NoMatchPolicy                                                      string
	ExternalIdentityID, UserID, MembershipID                                    pgtype.UUID
	ExternalIdentityExists, UserActive, MembershipExists, MembershipActive,
	AccessGrantLive bool
	Rules, RolePolicies, LiveOwnedEdges []byte
	ExistingRoleIDs                     []uuid.UUID
}

func mapLDAPPlanningClaim(row ldapPlanningRow, expectedRunID uuid.UUID) (ldapauth.Claim, error) {
	if row.OperationRunID != expectedRunID || !identityProviderUUIDv7(row.OperationRunID) ||
		!identityProviderUUIDv7(row.TenantID) || !identityProviderUUIDv7(row.ProviderID) ||
		!identityProviderUUIDv7(row.BindingID) || !identityProviderUUIDv7(row.BindingAccessEpochID) ||
		!identityProviderUUIDv7(row.ProviderAccessSourceID) || row.ProviderVersion < 1 ||
		row.BindingVersion < 1 || row.BindingAuthRevision < 1 || row.ConfigurationRevision < 1 ||
		row.RuleSetRevision < 1 || row.AuthorizationRevision < 1 ||
		row.ExternalIdentityID.Valid != row.ExternalIdentityExists ||
		row.UserID.Valid != row.ExternalIdentityExists || row.UserActive && !row.ExternalIdentityExists ||
		row.MembershipID.Valid != row.MembershipExists || row.MembershipExists && !row.ExternalIdentityExists ||
		row.MembershipActive && !row.MembershipExists || row.AccessGrantLive && !row.MembershipActive {
		return ldapauth.Claim{}, ldapauth.ErrUnavailable
	}
	rules, groups, assignments, err := mapLDAPJITPlanningRules(row.Rules)
	if err != nil {
		return ldapauth.Claim{}, ldapauth.ErrUnavailable
	}
	rolePolicies, err := mapLDAPPlanningRolePolicies(row.RolePolicies)
	if err != nil {
		return ldapauth.Claim{}, ldapauth.ErrUnavailable
	}
	existingRoles, err := mapLDAPPlanningUUIDs(row.ExistingRoleIDs, maximumLDAPDryRunMappings*10)
	if err != nil {
		return ldapauth.Claim{}, ldapauth.ErrUnavailable
	}
	edges, err := mapLDAPPlanningEdges(row.LiveOwnedEdges)
	if err != nil {
		return ldapauth.Claim{}, ldapauth.ErrUnavailable
	}
	jitMode, err := mapLDAPPlanningJITMode(row.JITMode)
	if err != nil {
		return ldapauth.Claim{}, ldapauth.ErrUnavailable
	}
	noMatch, err := mapLDAPPlanningNoMatchPolicy(row.NoMatchPolicy)
	if err != nil {
		return ldapauth.Claim{}, ldapauth.ErrUnavailable
	}
	provider := identity.ProviderContext{Scope: identity.TenantProviderScope,
		TenantID: identity.EntityID(row.TenantID), ProviderID: identity.EntityID(row.ProviderID)}
	planning := identity.LDAPPlanningSnapshot{
		TenantID: identity.EntityID(row.TenantID), Provider: provider,
		BindingID: identity.EntityID(row.BindingID), ConfigurationRevision: int64(row.ConfigurationRevision),
		RuleSetRevision: row.RuleSetRevision, AuthorizationRevision: row.AuthorizationRevision,
		JITMode: jitMode, NoMatchPolicy: noMatch,
		ProviderAccess: identity.LDAPProviderAccessState{
			SourceID:               identity.EntityID(row.ProviderAccessSourceID),
			AccessEpochID:          identity.EntityID(row.BindingAccessEpochID),
			ExternalIdentityExists: row.ExternalIdentityExists, UserActive: row.UserActive,
			TenantMembershipExists: row.MembershipExists, TenantMembershipActive: row.MembershipActive,
			AccessGrantLive: row.AccessGrantLive,
		},
		Rules: rules, SecurityGroups: groups, LiveAssignments: assignments,
		RolePolicies: rolePolicies, ExistingEffectiveRoleIDs: existingRoles,
		Delegation: ldapJITMappingDelegation(rolePolicies), LiveOwnedEdges: edges,
	}
	return ldapauth.Claim{
		OperationRunID: row.OperationRunID, TenantID: row.TenantID, ProviderID: row.ProviderID,
		BindingID: row.BindingID, BindingAuthRevision: int64(row.BindingAuthRevision),
		ExternalIdentityID: nullableLDAPUUID(row.ExternalIdentityID), UserID: nullableLDAPUUID(row.UserID),
		MembershipID: nullableLDAPUUID(row.MembershipID), Planning: planning,
	}, nil
}

// A JIT login has no human administration actor. Its closed delegation is
// therefore the permission tuple union of the exact role policies already
// selected by the pinned mapping epochs. The database apply ABI rechecks the
// same epochs and rejects platform-scoped targets before any mutation.
func ldapJITMappingDelegation(policies []identity.LDAPRolePolicy) []identity.LDAPDelegationGrant {
	seen := make(map[identity.LDAPPermissionTuple]struct{})
	result := make([]identity.LDAPDelegationGrant, 0)
	for _, policy := range policies {
		for _, tuple := range policy.Policy {
			if _, exists := seen[tuple]; exists {
				continue
			}
			seen[tuple] = struct{}{}
			result = append(result, identity.LDAPDelegationGrant{Tuple: tuple})
		}
	}
	return result
}

func mapLDAPJITPlanningRules(document []byte) (
	[]identity.LDAPMappingRule,
	[]identity.LDAPSecurityGroupPolicy,
	[]identity.LDAPOperatorTeamAssignment,
	error,
) {
	rows, err := decodeIdentityProviderJSON[[]ldapPlanningRuleDocument](document)
	if err != nil || len(rows) > maximumLDAPDryRunMappings {
		return nil, nil, nil, errInvalidMFAWire
	}
	groups := make(map[uuid.UUID][]uuid.UUID)
	assignments := make(map[uuid.UUID]identity.LDAPOperatorTeamAssignment)
	for index := range rows {
		rows[index].Enabled = true
		rows[index].AdministrativeNote = ""
		if (rows[index].OperatorTeamID == nil) != (rows[index].OperatorTeamAssignmentEpochID == nil) {
			return nil, nil, nil, errInvalidMFAWire
		}
		roles := append([]uuid.UUID(nil), rows[index].ActiveGroupRoleIDs...)
		if previous, exists := groups[rows[index].SecurityGroupID]; exists && !equalLDAPUUIDs(previous, roles) {
			return nil, nil, nil, errInvalidMFAWire
		}
		groups[rows[index].SecurityGroupID] = roles
		if rows[index].OperatorTeamID != nil {
			teamID := *rows[index].OperatorTeamID
			assignment := identity.LDAPOperatorTeamAssignment{
				TeamID: identity.EntityID(teamID), AssignmentEpochID: identity.EntityID(*rows[index].OperatorTeamAssignmentEpochID),
				Live: rows[index].OperatorTeamAssignmentLive,
			}
			if previous, exists := assignments[teamID]; exists && previous != assignment {
				return nil, nil, nil, errInvalidMFAWire
			}
			assignments[teamID] = assignment
		}
	}
	normalized, err := json.Marshal(rows)
	if err != nil {
		return nil, nil, nil, errInvalidMFAWire
	}
	defer clear(normalized)
	rules, err := mapLDAPPlanningRules(normalized)
	if err != nil {
		return nil, nil, nil, err
	}
	groupPolicies := make([]identity.LDAPSecurityGroupPolicy, 0, len(groups))
	seenGroups := make(map[uuid.UUID]struct{}, len(groups))
	for _, row := range rows {
		if _, seen := seenGroups[row.SecurityGroupID]; seen {
			continue
		}
		seenGroups[row.SecurityGroupID] = struct{}{}
		roleIDs, mapErr := mapLDAPPlanningUUIDs(groups[row.SecurityGroupID], maximumLDAPDryRunMappings*10)
		if mapErr != nil {
			return nil, nil, nil, mapErr
		}
		groupPolicies = append(groupPolicies, identity.LDAPSecurityGroupPolicy{
			SecurityGroupID: identity.EntityID(row.SecurityGroupID), ActiveRoleIDs: roleIDs,
		})
	}
	teamAssignments := make([]identity.LDAPOperatorTeamAssignment, 0, len(assignments))
	seenTeams := make(map[uuid.UUID]struct{}, len(assignments))
	for _, row := range rows {
		if row.OperatorTeamID == nil {
			continue
		}
		if _, seen := seenTeams[*row.OperatorTeamID]; seen {
			continue
		}
		seenTeams[*row.OperatorTeamID] = struct{}{}
		teamAssignments = append(teamAssignments, assignments[*row.OperatorTeamID])
	}
	return rules, groupPolicies, teamAssignments, nil
}

func equalLDAPUUIDs(left, right []uuid.UUID) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func nullableLDAPUUID(value pgtype.UUID) uuid.UUID {
	if !value.Valid {
		return uuid.Nil
	}
	return uuid.UUID(value.Bytes)
}

func (repository *LDAPAuthenticationRepository) Apply(
	ctx context.Context,
	request ldapauth.ApplyRequest,
) (ldapauth.ApplyResult, error) {
	if repository == nil || repository.begin == nil || ctx == nil || ctx.Err() != nil {
		return ldapauth.ApplyResult{}, ldapauth.ErrUnavailable
	}
	command, err := buildLDAPApplyCommand(request)
	if err != nil {
		return ldapauth.ApplyResult{}, ldapauth.ErrUnavailable
	}
	defer command.destroy()
	return withinTransaction(ctx, repository.begin, func(tx databaseTransaction) (ldapauth.ApplyResult, error) {
		var applied ldapIdentityApplyRow
		err := tx.QueryRow(ctx, applyLDAPIdentityPlanSQL, command.arguments()...).Scan(
			&applied.ApplicationID, &applied.Decision, &applied.ExternalIdentityID,
			&applied.UserID, &applied.MembershipID, &applied.AccessGrantID,
			&applied.EnsuredEdges, &applied.RevokedEdges, &applied.Replayed,
		)
		if err != nil || applied.ApplicationID != request.ApplicationID || applied.Decision != "admitted" ||
			applied.ExternalIdentityID != request.ExternalIdentityID || applied.UserID != request.UserID ||
			applied.MembershipID != request.MembershipID {
			if err == nil {
				err = errInvalidMFAWire
			}
			return ldapauth.ApplyResult{}, mapLDAPAuthenticationDatabaseError(err)
		}
		reservation, disposition, err := ldapAuthorityReservation(request)
		if err != nil {
			return ldapauth.ApplyResult{}, ldapauth.ErrUnavailable
		}
		defer clear(reservation)
		var sessionJSON, continuationJSON any
		if disposition == "session" {
			sessionJSON = json.RawMessage(reservation)
		} else {
			continuationJSON = json.RawMessage(reservation)
		}
		var resultDocument []byte
		if err = tx.QueryRow(ctx, issueLDAPAuthoritySQL,
			request.OperationRunID, request.ReceiptDigest[:], request.ApplicationID,
			disposition, string(request.Assurance), request.Evidence.AuthenticatedAt,
			request.ObservedAt, request.ReturnPath, sessionJSON, continuationJSON,
			request.AuthorityAuditID, request.Audit.ClientIP.String(), request.Audit.UserAgent,
		).Scan(&resultDocument); err != nil {
			return ldapauth.ApplyResult{}, mapLDAPAuthenticationDatabaseError(err)
		}
		return decodeLDAPAuthorityResult(resultDocument, request, disposition)
	})
}

type ldapApplyCommand struct {
	request                   ldapauth.ApplyRequest
	planDigest                [sha256.Size]byte
	subjectFormat             string
	aliasKeyVersions          []int32
	aliasDigests              [][]byte
	matchedMappingEpochIDs    []uuid.UUID
	displayName, firstName    any
	lastName, username, email any
}

func buildLDAPApplyCommand(request ldapauth.ApplyRequest) (ldapApplyCommand, error) {
	command := ldapApplyCommand{request: request}
	if request.OperationRunID == uuid.Nil || request.ApplicationID == uuid.Nil ||
		request.AuditEventID == uuid.Nil || request.AuthorityAuditID == uuid.Nil ||
		request.ExternalIdentityID == uuid.Nil || request.UserID == uuid.Nil || request.MembershipID == uuid.Nil ||
		request.AccessGrantID == uuid.Nil || request.ProfileContributionID == uuid.Nil ||
		len(request.AliasIDs) != len(request.SubjectAliases) || len(request.AliasIDs) < 1 ||
		request.Plan.Disposition() != identity.LDAPPlanAdmitted || request.SubjectEnvelope.KeyVersion < 1 ||
		request.SubjectEnvelope.Format != request.SubjectFormat || len(request.SubjectEnvelope.Ciphertext) < 17 {
		return command, errInvalidMFAWire
	}
	var err error
	command.subjectFormat, err = federatedSubjectFormatToWire(request.SubjectFormat)
	if err != nil {
		return command, err
	}
	command.aliasKeyVersions = make([]int32, len(request.SubjectAliases))
	command.aliasDigests = make([][]byte, len(request.SubjectAliases))
	for index, alias := range request.SubjectAliases {
		if alias.KeyVersion < 1 || request.AliasIDs[index] == uuid.Nil {
			command.destroy()
			return ldapApplyCommand{}, errInvalidMFAWire
		}
		command.aliasKeyVersions[index] = int32(alias.KeyVersion)
		command.aliasDigests[index] = append([]byte(nil), alias.Digest[:]...)
	}
	matched := request.Plan.MatchedRuleIDs()
	ruleEpochs := make(map[identity.EntityID]identity.EntityID, len(request.Planning.Rules))
	for _, rule := range request.Planning.Rules {
		ruleEpochs[rule.RuleID] = rule.RuleEpochID
	}
	command.matchedMappingEpochIDs = make([]uuid.UUID, len(matched))
	for index, ruleID := range matched {
		epochID, ok := ruleEpochs[ruleID]
		if !ok {
			command.destroy()
			return ldapApplyCommand{}, errInvalidMFAWire
		}
		command.matchedMappingEpochIDs[index] = uuid.UUID(epochID)
	}
	if command.displayName, err = ldapProfileArgument(request.Plan, identity.LDAPProfileDisplayName); err != nil {
		command.destroy()
		return ldapApplyCommand{}, err
	}
	if command.firstName, err = ldapProfileArgument(request.Plan, identity.LDAPProfileFirstName); err != nil {
		command.destroy()
		return ldapApplyCommand{}, err
	}
	if command.lastName, err = ldapProfileArgument(request.Plan, identity.LDAPProfileLastName); err != nil {
		command.destroy()
		return ldapApplyCommand{}, err
	}
	if command.username, err = ldapProfileArgument(request.Plan, identity.LDAPProfileUsername); err != nil {
		command.destroy()
		return ldapApplyCommand{}, err
	}
	if command.email, err = ldapProfileArgument(request.Plan, identity.LDAPProfileEmail); err != nil {
		command.destroy()
		return ldapApplyCommand{}, err
	}
	digestDocument, err := json.Marshal(struct {
		RunID, ApplicationID, ExternalIdentityID, UserID, MembershipID, AccessGrantID,
		ProfileContributionID uuid.UUID
		SubjectFormat                   string
		SubjectCiphertext, SubjectNonce []byte
		SubjectKeyVersion               int16
		AliasIDs                        []uuid.UUID
		AliasKeyVersions                []int32
		AliasDigests                    [][]byte
		MatchedEpochIDs                 []uuid.UUID
		Profile                         [5]any
		ObservedAt                      time.Time
	}{
		request.OperationRunID, request.ApplicationID, request.ExternalIdentityID, request.UserID,
		request.MembershipID, request.AccessGrantID, request.ProfileContributionID,
		command.subjectFormat, request.SubjectEnvelope.Ciphertext, request.SubjectEnvelope.Nonce[:],
		request.SubjectEnvelope.KeyVersion, request.AliasIDs, command.aliasKeyVersions,
		command.aliasDigests, command.matchedMappingEpochIDs,
		[5]any{command.displayName, command.firstName, command.lastName, command.username, command.email},
		request.ObservedAt,
	})
	if err != nil {
		command.destroy()
		return ldapApplyCommand{}, err
	}
	command.planDigest = sha256.Sum256(digestDocument)
	clear(digestDocument)
	return command, nil
}

func ldapProfileArgument(plan identity.LDAPMappingPlan, field identity.LDAPProfileField) (any, error) {
	value, present, err := plan.RevealProfileField(field)
	if err != nil {
		return nil, err
	}
	if !present {
		return nil, nil
	}
	return value, nil
}

func (command *ldapApplyCommand) arguments() []any {
	request := command.request
	return []any{
		request.OperationRunID, request.ReceiptDigest[:], request.ApplicationID, command.planDigest[:],
		"admitted", nil, request.ExternalIdentityID, request.UserID, request.MembershipID,
		request.AccessGrantID, request.ProfileContributionID, command.subjectFormat,
		request.SubjectEnvelope.Ciphertext, request.SubjectEnvelope.Nonce[:], int32(request.SubjectEnvelope.KeyVersion),
		request.AliasIDs, command.aliasKeyVersions, command.aliasDigests, command.displayName,
		command.firstName, command.lastName, command.username, command.email,
		command.matchedMappingEpochIDs, request.ObservedAt, request.AuditEventID,
		request.Audit.RequestID, request.Audit.CorrelationID, request.Audit.ClientIP.String(), request.Audit.UserAgent,
	}
}

func (command *ldapApplyCommand) destroy() {
	if command == nil {
		return
	}
	clear(command.planDigest[:])
	for index := range command.aliasDigests {
		clear(command.aliasDigests[index])
	}
	command.aliasDigests = nil
}

type ldapIdentityApplyRow struct {
	ApplicationID, ExternalIdentityID, UserID, MembershipID, AccessGrantID uuid.UUID
	Decision                                                               string
	EnsuredEdges, RevokedEdges                                             int32
	Replayed                                                               bool
}

func ldapAuthorityReservation(request ldapauth.ApplyRequest) ([]byte, string, error) {
	if request.Session != nil && request.Continuation == nil {
		reservation := request.Session.Session()
		if reservation.IsZero() {
			return nil, "", errInvalidMFAWire
		}
		tokenDigest := reservation.TokenDigest()
		csrfDigest := reservation.CSRFDigest()
		defer clear(tokenDigest[:])
		defer clear(csrfDigest[:])
		document, err := json.Marshal(struct {
			SessionID            string    `json:"sessionId"`
			FamilyID             string    `json:"familyId"`
			TokenDigest          string    `json:"tokenDigest"`
			CSRFDigest           string    `json:"csrfDigest"`
			AuthenticationMethod string    `json:"authenticationMethod"`
			IdleExpiresAt        time.Time `json:"idleExpiresAt"`
			AbsoluteExpiresAt    time.Time `json:"absoluteExpiresAt"`
		}{
			entityIDWire(reservation.SessionID()), entityIDWire(reservation.FamilyID()),
			base64.StdEncoding.EncodeToString(tokenDigest[:]),
			base64.StdEncoding.EncodeToString(csrfDigest[:]),
			string(reservation.AuthenticationMethod()), reservation.IdleExpiresAt(), reservation.AbsoluteExpiresAt(),
		})
		return document, "session", err
	}
	if request.Continuation != nil && request.Session == nil {
		reservation := request.Continuation.Continuation()
		if reservation.IsZero() {
			return nil, "", errInvalidMFAWire
		}
		receiptDigest := reservation.ReceiptDigest()
		defer clear(receiptDigest[:])
		document, err := json.Marshal(struct {
			ContinuationID string    `json:"continuationId"`
			ReceiptDigest  string    `json:"receiptDigest"`
			ExpiresAt      time.Time `json:"expiresAt"`
		}{
			entityIDWire(reservation.ContinuationID()),
			base64.StdEncoding.EncodeToString(receiptDigest[:]), reservation.ExpiresAt(),
		})
		return document, "continuation", err
	}
	return nil, "", errInvalidMFAWire
}

type ldapAuthorityResultWire struct {
	Category       string `json:"category"`
	Disposition    string `json:"disposition"`
	UserID         string `json:"userId"`
	SessionID      string `json:"sessionId"`
	ContinuationID string `json:"continuationId"`
	ReturnPath     string `json:"returnPath"`
	Replayed       bool   `json:"replayed"`
}

func decodeLDAPAuthorityResult(document []byte, request ldapauth.ApplyRequest, disposition string) (ldapauth.ApplyResult, error) {
	wire, err := decodeIdentityProviderJSON[ldapAuthorityResultWire](document)
	if err != nil || wire.Category != "success" || wire.Disposition != disposition ||
		wire.ReturnPath != request.ReturnPath {
		return ldapauth.ApplyResult{}, ldapauth.ErrUnavailable
	}
	userID, err := uuid.Parse(wire.UserID)
	if err != nil || userID != request.UserID {
		return ldapauth.ApplyResult{}, ldapauth.ErrUnavailable
	}
	result := ldapauth.ApplyResult{UserID: userID, ReturnPath: wire.ReturnPath, Replayed: wire.Replayed}
	if disposition == "session" {
		sessionID, parseErr := uuid.Parse(wire.SessionID)
		if parseErr != nil || wire.ContinuationID != "" ||
			identity.EntityID(sessionID) != request.Session.Session().SessionID() {
			return ldapauth.ApplyResult{}, ldapauth.ErrUnavailable
		}
		result.SessionID = identity.EntityID(sessionID)
	} else {
		continuationID, parseErr := uuid.Parse(wire.ContinuationID)
		if parseErr != nil || wire.SessionID != "" ||
			identity.EntityID(continuationID) != request.Continuation.Continuation().ContinuationID() {
			return ldapauth.ApplyResult{}, ldapauth.ErrUnavailable
		}
		result.ContinuationID = identity.EntityID(continuationID)
	}
	return result, nil
}

func (repository *LDAPAuthenticationRepository) CompleteFailure(
	ctx context.Context,
	request ldapauth.FailureRequest,
) error {
	if repository == nil || repository.queryer == nil || ctx == nil || ctx.Err() != nil {
		return ldapauth.ErrUnavailable
	}
	category := mapLDAPFailureCategory(request.Category)
	if category == "" {
		return ldapauth.ErrUnavailable
	}
	var completed bool
	if err := repository.queryer.QueryRow(ctx, completeLDAPAuthenticationSQL,
		request.OperationRunID, request.ReceiptDigest[:], category, request.AuditEventID,
		request.Audit.RequestID, request.Audit.CorrelationID, request.Audit.ClientIP.String(),
		request.Audit.UserAgent,
	).Scan(&completed); err != nil {
		return mapLDAPAuthenticationDatabaseError(err)
	}
	if !completed {
		return ldapauth.ErrAuthentication
	}
	return nil
}

func mapLDAPFailureCategory(category ldapauth.FailureCategory) string {
	switch category {
	case ldapauth.FailureCredentials:
		return "invalid_credentials"
	case ldapauth.FailureDirectory:
		return "directory_error"
	case ldapauth.FailurePolicy:
		return "account_disabled"
	case ldapauth.FailureStale:
		return "cancelled"
	default:
		return ""
	}
}

func mapLDAPAuthenticationDatabaseError(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return ldapauth.ErrAuthentication
	}
	return ldapauth.ErrUnavailable
}
