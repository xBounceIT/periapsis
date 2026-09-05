package authorization

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestServiceRejectsUnrepresentableWritableExpiryBeforeDependencies(t *testing.T) {
	t.Parallel()

	roleID := serviceTestID(200)
	userID := serviceTestID(201)
	groupID := serviceTestID(202)
	invalidExpiries := []struct {
		name  string
		value time.Time
	}{
		{name: "zero", value: time.Time{}},
		{
			name: "UTC year overflow",
			value: time.Date(
				9999, time.December, 31, 23, 59, 59, 999999000,
				time.FixedZone("-23:59", -(23*60*60+59*60)),
			),
		},
		{
			name: "UTC year underflow",
			value: time.Date(
				0, time.January, 1, 0, 0, 0, 0,
				time.FixedZone("+23:59", 23*60*60+59*60),
			),
		},
		{
			name:  "sub-microsecond",
			value: serviceTestNow.Add(time.Hour + time.Nanosecond),
		},
	}
	operations := []struct {
		name   string
		invoke func(*Service, *time.Time) error
	}{
		{
			name: "direct role grant",
			invoke: func(service *Service, expiresAt *time.Time) error {
				input := validGrantRoleInput(roleID)
				input.ExpiresAt = expiresAt
				_, err := service.GrantUserRole(
					context.Background(), serviceTestActor(), testTenantID, userID, input,
				)
				return err
			},
		},
		{
			name: "security group membership",
			invoke: func(service *Service, expiresAt *time.Time) error {
				_, err := service.AddTenantSecurityGroupMembership(
					context.Background(), serviceTestActor(), testTenantID, groupID,
					AddTenantSecurityGroupMembershipInput{
						UserID: userID, Reason: "Temporary group membership", ExpiresAt: expiresAt,
						IdempotencyKey: "invalid-expiry-membership", Audit: serviceTestAudit(),
					},
				)
				return err
			},
		},
		{
			name: "security group role grant",
			invoke: func(service *Service, expiresAt *time.Time) error {
				_, err := service.GrantTenantSecurityGroupRole(
					context.Background(), serviceTestActor(), testTenantID, groupID,
					GrantTenantSecurityGroupRoleInput{
						RoleID: roleID, Reason: "Temporary group role", ExpiresAt: expiresAt,
						IdempotencyKey: "invalid-expiry-group-role", Audit: serviceTestAudit(),
					},
				)
				return err
			},
		},
	}

	for _, operation := range operations {
		for _, expiry := range invalidExpiries {
			t.Run(operation.name+"/"+expiry.name, func(t *testing.T) {
				service := &Service{}
				if err := operation.invoke(service, &expiry.value); !errors.Is(err, ErrInvalidInput) {
					t.Fatalf("operation error = %v, want invalid input", err)
				}
			})
		}
	}
}

func TestNormalizedWritableExpiryPreservesRepresentableInstant(t *testing.T) {
	t.Parallel()

	location := time.FixedZone("test", 2*60*60)
	value := time.Date(2026, time.August, 24, 16, 30, 0, 123456000, location)
	normalized, err := NormalizeWritableExpiry(&value)
	if err != nil || normalized == nil || !normalized.Equal(value) || normalized.Location() != time.UTC {
		t.Fatalf("normalized expiry = %v, error = %v", normalized, err)
	}
	if normalized == &value {
		t.Fatal("normalized expiry aliases caller-owned storage")
	}
}

func TestServiceResolvedAuthorityEffectiveRolePathLimit(t *testing.T) {
	tests := []struct {
		name      string
		pathCount int
		wantError error
	}{
		{name: "page boundary", pathCount: 100},
		{name: "above page boundary", pathCount: 101},
		{name: "effective path boundary", pathCount: 200},
		{name: "truncation sentinel", pathCount: 201, wantError: ErrUnavailable},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			authority := serviceTestAuthority()
			authority.RoleGrants = serviceTestGroupAuthorityPaths(test.pathCount)
			repository := &serviceRepositoryStub{
				resolveAuthorityFunc: func(ResolveAuthorityParams) (TenantAuthority, error) {
					return authority, nil
				},
			}
			service := newTestService(t, repository)

			resolved, err := service.GetTenantAuthority(
				context.Background(), serviceTestActor(), testTenantID,
			)
			if !errors.Is(err, test.wantError) {
				t.Fatalf("GetTenantAuthority() error = %v, want %v", err, test.wantError)
			}
			if test.wantError == nil && len(resolved.RoleGrants) != test.pathCount {
				t.Fatalf("GetTenantAuthority() role paths = %d, want %d", len(resolved.RoleGrants), test.pathCount)
			}
			if repository.resolveAuthorityCalls != 1 {
				t.Fatalf("authority resolutions = %d, want 1", repository.resolveAuthorityCalls)
			}
		})
	}
}

func TestServiceResolvedAuthorityRequiresLiveEffectiveRoleGrantExpiries(t *testing.T) {
	t.Parallel()

	past := serviceTestNow.Add(-time.Minute)
	equal := serviceTestNow
	future := serviceTestNow.Add(time.Minute)
	tests := []struct {
		name      string
		path      RoleGrantPathType
		expiresAt *time.Time
		wantError error
	}{
		{name: "direct non-expiring", path: RoleGrantPathDirect},
		{name: "direct unexpired", path: RoleGrantPathDirect, expiresAt: &future},
		{name: "direct expires at evaluation", path: RoleGrantPathDirect, expiresAt: &equal, wantError: ErrUnavailable},
		{name: "direct expired before evaluation", path: RoleGrantPathDirect, expiresAt: &past, wantError: ErrUnavailable},
		{name: "group non-expiring", path: RoleGrantPathGroup},
		{name: "group unexpired", path: RoleGrantPathGroup, expiresAt: &future},
		{name: "group expires at evaluation", path: RoleGrantPathGroup, expiresAt: &equal, wantError: ErrUnavailable},
		{name: "group expired before evaluation", path: RoleGrantPathGroup, expiresAt: &past, wantError: ErrUnavailable},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			authority := serviceTestAuthority()
			switch test.path {
			case RoleGrantPathDirect:
				authority.RoleGrants = []EffectiveTenantRoleGrant{
					serviceTestEffectiveDirectAuthorityPath(test.expiresAt),
				}
			case RoleGrantPathGroup:
				authority.RoleGrants = []EffectiveTenantRoleGrant{
					serviceTestEffectiveGroupAuthorityPath(test.expiresAt),
				}
			default:
				t.Fatalf("unsupported path %q", test.path)
			}
			repository := &serviceRepositoryStub{
				resolveAuthorityFunc: func(ResolveAuthorityParams) (TenantAuthority, error) {
					return authority, nil
				},
			}
			service := newTestService(t, repository)

			_, err := service.GetTenantAuthority(
				context.Background(), serviceTestActor(), testTenantID,
			)
			if !errors.Is(err, test.wantError) {
				t.Fatalf("GetTenantAuthority() error = %v, want %v", err, test.wantError)
			}
		})
	}
}

func serviceTestEffectiveDirectAuthorityPath(expiresAt *time.Time) EffectiveTenantRoleGrant {
	grantID := serviceTestID(191)
	provenance := RoleGrantProvenance{
		SourceType: RoleGrantSourceDirect, SourceKind: AuthorizationSourceManual,
		SourceID: uuidPointer(serviceTestID(192)), GrantedByUserID: uuidPointer(testPrincipalID),
		GrantedAt: serviceTestNow.Add(-time.Hour), Reason: "Direct role grant",
		ExpiresAt: cloneTimePointer(expiresAt),
	}
	return EffectiveTenantRoleGrant{
		GrantID: grantID, RoleID: serviceTestID(193),
		RoleKey: "direct_role", RoleName: "Direct role", Provenance: provenance,
		Path: EffectiveTenantRoleAuthorityPath{
			PathType: RoleGrantPathDirect,
			Direct:   &DirectTenantRoleAuthorityPath{GrantID: grantID, Provenance: provenance},
		},
		EffectiveExpiresAt: cloneTimePointer(expiresAt),
	}
}

func serviceTestEffectiveGroupAuthorityPath(expiresAt *time.Time) EffectiveTenantRoleGrant {
	grantID := serviceTestID(194)
	membershipProvenance := AuthorizationEdgeProvenance{
		SourceKind: AuthorizationSourceManual,
		SourceID:   uuidPointer(serviceTestID(195)), GrantedByUserID: uuidPointer(testPrincipalID),
		GrantedAt: serviceTestNow.Add(-time.Hour), Reason: "Group membership",
	}
	roleGrantProvenance := AuthorizationEdgeProvenance{
		SourceKind: AuthorizationSourceManual,
		SourceID:   uuidPointer(serviceTestID(195)), GrantedByUserID: uuidPointer(testPrincipalID),
		GrantedAt: serviceTestNow.Add(-time.Hour), Reason: "Group role grant",
		ExpiresAt: cloneTimePointer(expiresAt),
	}
	return EffectiveTenantRoleGrant{
		GrantID: grantID, RoleID: serviceTestID(196),
		RoleKey: "group_role", RoleName: "Group role",
		Provenance: RoleGrantProvenance{
			SourceType: RoleGrantSourceGroup, SourceKind: roleGrantProvenance.SourceKind,
			SourceID: roleGrantProvenance.SourceID, Authoritative: roleGrantProvenance.Authoritative,
			RetiredAt: roleGrantProvenance.RetiredAt, GrantedByUserID: roleGrantProvenance.GrantedByUserID,
			GrantedAt: roleGrantProvenance.GrantedAt, Reason: roleGrantProvenance.Reason,
			ExpiresAt: roleGrantProvenance.ExpiresAt,
		},
		Path: EffectiveTenantRoleAuthorityPath{
			PathType: RoleGrantPathGroup,
			Group: &GroupTenantRoleAuthorityPath{
				Group: TenantSecurityGroupAuthoritySummary{
					ID: serviceTestID(197), Key: "test_group", Name: "Test group",
				},
				MembershipEdge: TenantSecurityGroupAuthorityEdge{
					ID: serviceTestID(198), Provenance: membershipProvenance,
				},
				RoleGrantEdge: TenantSecurityGroupAuthorityEdge{
					ID: grantID, Provenance: roleGrantProvenance,
				},
			},
		},
		EffectiveExpiresAt: cloneTimePointer(expiresAt),
	}
}

func TestAuditContextAcceptsCallerSuppliedRFC4122Identifiers(t *testing.T) {
	audit := serviceTestAudit()
	audit.RequestID = uuid.New()
	audit.CorrelationID = uuid.New()

	if !validAuditContext(audit) {
		t.Fatal("valid UUIDv4 request and correlation identifiers were rejected")
	}
}

func TestBoundedPageRejectsNonAdvancingRepositoryCursors(t *testing.T) {
	t.Parallel()

	after := serviceTestSequenceID(10)
	first := serviceTestSequenceID(11)
	second := serviceTestSequenceID(12)
	invalid := uuid.MustParse("00000000-0000-4000-8000-000000000013")
	tests := []struct {
		name string
		rows []uuid.UUID
	}{
		{name: "immediate repeat", rows: []uuid.UUID{after, first}},
		{name: "duplicate lookahead", rows: []uuid.UUID{first, first}},
		{name: "descending lookahead", rows: []uuid.UUID{second, first}},
		{name: "invalid lookahead", rows: []uuid.UUID{first, invalid}},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			items, next, err := boundedPage(
				test.rows, &after, 1, func(value uuid.UUID) uuid.UUID { return value },
			)
			if !errors.Is(err, ErrUnavailable) || items != nil || next != nil {
				t.Fatalf("boundedPage() = %#v, %v, %v; want unavailable", items, next, err)
			}
		})
	}
}

func TestBoundedPageReturnsLastVisibleCursorForStrictSequence(t *testing.T) {
	t.Parallel()

	after := serviceTestSequenceID(20)
	first := serviceTestSequenceID(21)
	second := serviceTestSequenceID(22)
	items, next, err := boundedPage(
		[]uuid.UUID{first, second}, &after, 1,
		func(value uuid.UUID) uuid.UUID { return value },
	)
	if err != nil || len(items) != 1 || items[0] != first || next == nil || *next != first {
		t.Fatalf("boundedPage() = %#v, %v, %v", items, next, err)
	}
}

func serviceTestGroupAuthorityPaths(count int) []EffectiveTenantRoleGrant {
	paths := make([]EffectiveTenantRoleGrant, 0, count)
	for index := 0; index < count; index++ {
		groupID := serviceTestSequenceID(index*3 + 1)
		membershipEdgeID := serviceTestSequenceID(index*3 + 2)
		roleGrantEdgeID := serviceTestSequenceID(index*3 + 3)
		membershipProvenance := AuthorizationEdgeProvenance{
			SourceKind: AuthorizationSourceManual,
			SourceID:   uuidPointer(serviceTestID(91)), GrantedByUserID: uuidPointer(testPrincipalID),
			GrantedAt: serviceTestNow, Reason: "Group membership",
		}
		roleGrantProvenance := AuthorizationEdgeProvenance{
			SourceKind: AuthorizationSourceManual,
			SourceID:   uuidPointer(serviceTestID(91)), GrantedByUserID: uuidPointer(testPrincipalID),
			GrantedAt: serviceTestNow, Reason: "Group role grant",
		}
		paths = append(paths, EffectiveTenantRoleGrant{
			GrantID: roleGrantEdgeID, RoleID: serviceTestID(90),
			RoleKey: "custom_role", RoleName: "Custom role",
			Provenance: RoleGrantProvenance{
				SourceType: RoleGrantSourceGroup, SourceKind: roleGrantProvenance.SourceKind,
				SourceID: roleGrantProvenance.SourceID, Authoritative: roleGrantProvenance.Authoritative,
				RetiredAt: roleGrantProvenance.RetiredAt, GrantedByUserID: roleGrantProvenance.GrantedByUserID,
				GrantedAt: roleGrantProvenance.GrantedAt, Reason: roleGrantProvenance.Reason,
				ExpiresAt: roleGrantProvenance.ExpiresAt,
			},
			Path: EffectiveTenantRoleAuthorityPath{
				PathType: RoleGrantPathGroup,
				Group: &GroupTenantRoleAuthorityPath{
					Group: TenantSecurityGroupAuthoritySummary{
						ID: groupID, Key: "test_group", Name: "Test group",
					},
					MembershipEdge: TenantSecurityGroupAuthorityEdge{
						ID: membershipEdgeID, Provenance: membershipProvenance,
					},
					RoleGrantEdge: TenantSecurityGroupAuthorityEdge{
						ID: roleGrantEdgeID, Provenance: roleGrantProvenance,
					},
				},
			},
		})
	}
	return paths
}

func serviceTestSequenceID(value int) uuid.UUID {
	id := uuid.MustParse("00000000-0000-7000-8000-000000000000")
	id[14] = byte(value >> 8)
	id[15] = byte(value)
	return id
}

func TestStoredAuthorizationResourcesRejectVersionsOutsideContractRange(t *testing.T) {
	role := serviceTestRole(serviceTestID(122), false, validRolePolicy())
	role.Version = maximumResourceVersion + 1
	if validStoredRoleSummary(role.TenantRoleSummary, testTenantID) {
		t.Fatal("tenant role summary accepted a version above the contract maximum")
	}

	userID := serviceTestID(123)
	role.Version = 1
	grant := serviceTestDirectGrant(serviceTestID(124), userID, role, "Administrative grant", nil)
	grant.Version = maximumResourceVersion + 1
	if validDirectRoleGrant(grant, testTenantID, userID) {
		t.Fatal("direct role grant accepted a version above the contract maximum")
	}
}

func TestDirectRoleGrantLifecycleRequiresCanonicalRevokeReason(t *testing.T) {
	role := serviceTestRole(serviceTestID(125), false, validRolePolicy())
	userID := serviceTestID(126)
	base := serviceTestDirectGrant(
		serviceTestID(127), userID, role, "Administrative grant", nil,
	)
	revokedAt := serviceTestNow.Add(time.Minute)
	revokerID := serviceTestID(128)
	reason := "Removed after access review"
	expiresAt := serviceTestNow.Add(time.Hour)

	tests := []struct {
		name   string
		mutate func(*DirectUserRoleGrant)
		valid  bool
	}{
		{name: "active", valid: true},
		{
			name: "active with revoke reason",
			mutate: func(grant *DirectUserRoleGrant) {
				grant.RevokeReason = &reason
			},
		},
		{
			name: "expired",
			mutate: func(grant *DirectUserRoleGrant) {
				grant.State = DirectRoleGrantStateExpired
				grant.Provenance.ExpiresAt = &expiresAt
			},
			valid: true,
		},
		{
			name: "expired without expiry",
			mutate: func(grant *DirectUserRoleGrant) {
				grant.State = DirectRoleGrantStateExpired
			},
		},
		{
			name: "revoked",
			mutate: func(grant *DirectUserRoleGrant) {
				grant.State = DirectRoleGrantStateRevoked
				grant.RevokedAt = &revokedAt
				grant.RevokedByUserID = &revokerID
				grant.RevokeReason = &reason
			},
			valid: true,
		},
		{
			name: "revoked without reason",
			mutate: func(grant *DirectUserRoleGrant) {
				grant.State = DirectRoleGrantStateRevoked
				grant.RevokedAt = &revokedAt
				grant.RevokedByUserID = &revokerID
			},
		},
		{
			name: "revoked with noncanonical reason",
			mutate: func(grant *DirectUserRoleGrant) {
				paddedReason := "  " + reason + "  "
				grant.State = DirectRoleGrantStateRevoked
				grant.RevokedAt = &revokedAt
				grant.RevokedByUserID = &revokerID
				grant.RevokeReason = &paddedReason
			},
		},
		{
			name: "revoked with blank reason",
			mutate: func(grant *DirectUserRoleGrant) {
				blankReason := ""
				grant.State = DirectRoleGrantStateRevoked
				grant.RevokedAt = &revokedAt
				grant.RevokedByUserID = &revokerID
				grant.RevokeReason = &blankReason
			},
		},
		{
			name: "revoked without revoker",
			mutate: func(grant *DirectUserRoleGrant) {
				grant.State = DirectRoleGrantStateRevoked
				grant.RevokedAt = &revokedAt
				grant.RevokeReason = &reason
			},
		},
		{
			name: "unknown state",
			mutate: func(grant *DirectUserRoleGrant) {
				grant.State = "future"
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			grant := base
			if test.mutate != nil {
				test.mutate(&grant)
			}
			if got := validDirectRoleGrant(grant, testTenantID, userID); got != test.valid {
				t.Fatalf("validDirectRoleGrant() = %t, want %t", got, test.valid)
			}
		})
	}
}

func TestDirectRoleGrantOwnershipRequiresCoherentSourceType(t *testing.T) {
	role := serviceTestRole(serviceTestID(129), false, validRolePolicy())
	userID := serviceTestID(130)
	base := serviceTestDirectGrant(
		serviceTestID(131), userID, role, "Administrative grant", nil,
	)

	tests := []struct {
		name       string
		kind       AuthorizationSourceKind
		sourceType RoleGrantSourceType
		grantor    bool
		managed    bool
		valid      bool
	}{
		{name: "managed manual direct", kind: AuthorizationSourceManual, sourceType: RoleGrantSourceDirect, grantor: true, managed: true, valid: true},
		{name: "unmanaged manual direct", kind: AuthorizationSourceManual, sourceType: RoleGrantSourceDirect, grantor: true, valid: true},
		{name: "manual without grantor", kind: AuthorizationSourceManual, sourceType: RoleGrantSourceDirect},
		{name: "manual system mismatch", kind: AuthorizationSourceManual, sourceType: RoleGrantSourceSystem, grantor: true},
		{name: "identity mapping", kind: AuthorizationSourceIdentityMapping, sourceType: RoleGrantSourceIdentityProvider, valid: true},
		{name: "identity mapping falsely marked managed", kind: AuthorizationSourceIdentityMapping, sourceType: RoleGrantSourceIdentityProvider, managed: true},
		{name: "identity mapping direct mismatch", kind: AuthorizationSourceIdentityMapping, sourceType: RoleGrantSourceDirect},
		{name: "system", kind: AuthorizationSourceSystem, sourceType: RoleGrantSourceSystem, valid: true},
		{name: "tenant creation", kind: AuthorizationSourceTenantCreation, sourceType: RoleGrantSourceSystem, grantor: true, valid: true},
		{name: "platform recovery", kind: AuthorizationSourcePlatformRecovery, sourceType: RoleGrantSourceSystem, valid: true},
		{name: "system direct mismatch", kind: AuthorizationSourceSystem, sourceType: RoleGrantSourceDirect},
		{name: "unknown owner", kind: "future", sourceType: RoleGrantSourceSystem},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			grant := base
			grant.Provenance.SourceKind = test.kind
			grant.Provenance.SourceType = test.sourceType
			grant.ManagedByAuthorizationAPI = test.managed
			if !test.grantor {
				grant.Provenance.GrantedByUserID = nil
			}
			if got := validDirectRoleGrant(grant, testTenantID, userID); got != test.valid {
				t.Fatalf("validDirectRoleGrant() = %t, want %t", got, test.valid)
			}
		})
	}
}

func TestSecurityGroupAPIOwnershipRequiresLiveManualSource(t *testing.T) {
	groupID := serviceTestID(179)
	userID := serviceTestID(180)
	membershipID := serviceTestID(181)
	roleGrantID := serviceTestID(182)
	roleID := serviceTestID(183)
	sourceID := serviceTestID(184)
	group := serviceTestGroup(groupID, "incident_responders")
	membership := serviceTestGroupMembership(membershipID, userID, group)
	roleGrant := TenantSecurityGroupRoleGrant{
		ID: roleGrantID, TenantID: testTenantID, Group: group,
		Role: serviceTestRole(roleID, false, validRolePolicy()).TenantRoleSummary,
		Provenance: AuthorizationEdgeProvenance{
			SourceKind: AuthorizationSourceManual, SourceID: &sourceID,
			GrantedByUserID: uuidPointer(testPrincipalID), GrantedAt: serviceTestNow.Add(-time.Hour),
			Reason: "Group role grant",
		},
		State: AuthorizationEdgeStateActive, Version: 1, UpdatedAt: serviceTestNow,
		ManagedByAuthorizationAPI: true,
	}

	if !validSecurityGroupMembership(membership, testTenantID, groupID) ||
		!validSecurityGroupRoleGrant(roleGrant, testTenantID, groupID) {
		t.Fatal("live manual API-managed edges were rejected")
	}
	membership.ManagedByAuthorizationAPI = false
	roleGrant.ManagedByAuthorizationAPI = false
	if !validSecurityGroupMembership(membership, testTenantID, groupID) ||
		!validSecurityGroupRoleGrant(roleGrant, testTenantID, groupID) {
		t.Fatal("unmanaged manual edges were rejected")
	}

	membership.ManagedByAuthorizationAPI = true
	roleGrant.ManagedByAuthorizationAPI = true
	membership.Provenance.SourceKind = AuthorizationSourceIdentityMapping
	membership.Provenance.GrantedByUserID = nil
	roleGrant.Provenance.SourceKind = AuthorizationSourceIdentityMapping
	roleGrant.Provenance.GrantedByUserID = nil
	if validSecurityGroupMembership(membership, testTenantID, groupID) ||
		validSecurityGroupRoleGrant(roleGrant, testTenantID, groupID) {
		t.Fatal("non-manual edges marked as API-managed were accepted")
	}

	membership.Provenance.SourceKind = AuthorizationSourceManual
	membership.Provenance.GrantedByUserID = uuidPointer(testPrincipalID)
	roleGrant.Provenance.SourceKind = AuthorizationSourceManual
	roleGrant.Provenance.GrantedByUserID = uuidPointer(testPrincipalID)
	retiredAt := serviceTestNow
	membership.Provenance.RetiredAt = &retiredAt
	roleGrant.Provenance.RetiredAt = &retiredAt
	if validSecurityGroupMembership(membership, testTenantID, groupID) ||
		validSecurityGroupRoleGrant(roleGrant, testTenantID, groupID) {
		t.Fatal("retired edges marked as API-managed were accepted")
	}
}

func TestEffectiveDirectRoleGrantRequiresCoherentSourceOwnership(t *testing.T) {
	t.Parallel()

	grantID := serviceTestID(132)
	sourceID := serviceTestID(133)
	baseProvenance := RoleGrantProvenance{
		SourceType: RoleGrantSourceDirect, SourceKind: AuthorizationSourceManual,
		SourceID: &sourceID, GrantedByUserID: uuidPointer(testPrincipalID),
		GrantedAt: serviceTestNow.Add(-time.Hour), Reason: "Administrative grant",
	}
	base := EffectiveTenantRoleGrant{
		GrantID: grantID, RoleID: serviceTestID(134), RoleKey: "effective_direct",
		RoleName: "Effective direct", Provenance: baseProvenance,
		Path: EffectiveTenantRoleAuthorityPath{
			PathType: RoleGrantPathDirect,
			Direct:   &DirectTenantRoleAuthorityPath{GrantID: grantID, Provenance: baseProvenance},
		},
	}
	if !validEffectiveRoleGrant(base) {
		t.Fatal("valid effective direct role grant was rejected")
	}

	for _, test := range []struct {
		name       string
		kind       AuthorizationSourceKind
		sourceType RoleGrantSourceType
		grantor    bool
	}{
		{name: "manual without grantor", kind: AuthorizationSourceManual, sourceType: RoleGrantSourceDirect},
		{name: "manual system mismatch", kind: AuthorizationSourceManual, sourceType: RoleGrantSourceSystem, grantor: true},
		{name: "identity direct mismatch", kind: AuthorizationSourceIdentityMapping, sourceType: RoleGrantSourceDirect},
		{name: "tenant creation direct mismatch", kind: AuthorizationSourceTenantCreation, sourceType: RoleGrantSourceDirect},
		{name: "system group mismatch", kind: AuthorizationSourceSystem, sourceType: RoleGrantSourceGroup},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			grant := base
			provenance := baseProvenance
			provenance.SourceKind = test.kind
			provenance.SourceType = test.sourceType
			if !test.grantor {
				provenance.GrantedByUserID = nil
			}
			grant.Provenance = provenance
			grant.Path.Direct = &DirectTenantRoleAuthorityPath{
				GrantID: grantID, Provenance: provenance,
			}
			if validEffectiveRoleGrant(grant) {
				t.Fatal("incoherent effective direct source was accepted")
			}
		})
	}
}
