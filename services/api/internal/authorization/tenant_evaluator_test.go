package authorization

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/services/api/internal/contract"
)

const tenantPermissionTestResourceRead TenantPermission = "test_resource.read"

var (
	testTenantID               = uuid.MustParse("00000000-0000-7000-8000-000000000001")
	testOtherTenantID          = uuid.MustParse("00000000-0000-7000-8000-000000000002")
	testPrincipalID            = uuid.MustParse("00000000-0000-7000-8000-000000000003")
	testOtherUserID            = uuid.MustParse("00000000-0000-7000-8000-000000000004")
	testOperatorTeamID         = uuid.MustParse("00000000-0000-7000-8000-000000000005")
	testOtherTeamID            = uuid.MustParse("00000000-0000-7000-8000-000000000006")
	testMembershipID           = uuid.MustParse("00000000-0000-7000-8000-000000000007")
	testAssignmentEpochID      = uuid.MustParse("00000000-0000-7000-8000-000000000008")
	testOtherAssignmentEpochID = uuid.MustParse("00000000-0000-7000-8000-000000000009")
	testEvaluatedAt            = time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
)

func TestEvaluatorInitialTenantPermissionCatalog(t *testing.T) {
	t.Parallel()

	permissions := []TenantPermission{
		TenantPermissionPermissionRead,
		TenantPermissionRoleRead,
		TenantPermissionRoleManage,
		TenantPermissionRoleGrant,
		TenantPermissionUserRead,
		TenantPermissionMembershipManage,
		TenantPermissionGroupRead,
		TenantPermissionGroupManage,
		TenantPermissionGroupMembershipManage,
		TenantPermissionOperatorTeamRead,
		TenantPermissionOperatorTeamManage,
		TenantPermissionOperatorTeamRosterManage,
		TenantPermissionServiceAccountRead,
		TenantPermissionServiceAccountManage,
		TenantPermissionServiceAccountCredentialManage,
		TenantPermissionAlertCreate,
		TenantPermissionAlertRead,
		TenantPermissionAlertActivityRead,
		TenantPermissionAlertCommentRead,
		TenantPermissionAlertLinkRead,
		TenantPermissionAlertUpdate,
		TenantPermissionAlertDelete,
		TenantPermissionAlertAssign,
		TenantPermissionAlertClaim,
		TenantPermissionAlertEscalate,
		TenantPermissionAlertCommentPublic,
		TenantPermissionAlertCommentPrivate,
		TenantPermissionCaseRead,
		TenantPermissionCaseActivityRead,
		TenantPermissionCaseCommentRead,
		TenantPermissionCaseLinkRead,
		TenantPermissionCaseCreate,
		TenantPermissionCaseUpdate,
		TenantPermissionCaseClaim,
		TenantPermissionCaseTransfer,
		TenantPermissionCaseTransition,
		TenantPermissionCaseCommentPublic,
		TenantPermissionCaseCommentPrivate,
		TenantPermissionContactRead,
		TenantPermissionContactManage,
		TenantPermissionContactPreferenceManage,
		TenantPermissionContactGroupRead,
		TenantPermissionContactGroupManage,
		TenantPermissionPortalAlertRead,
		TenantPermissionPortalCaseRead,
		TenantPermissionPortalCommentPublic,
		TenantPermissionPortalAttachmentRead,
		TenantPermissionPortalContactPreferenceManage,
		TenantPermissionIdentityProviderRead,
		TenantPermissionIdentityProviderManage,
		TenantPermissionIdentityProviderTest,
		TenantPermissionIdentityMappingRead,
		TenantPermissionIdentityMappingManage,
		TenantPermissionIdentitySyncRun,
		TenantPermissionIdentityPolicyRead,
		TenantPermissionIdentityPolicyManage,
		TenantPermissionSettingsRead,
		TenantPermissionSettingsManage,
		TenantPermissionNotificationManage,
		TenantPermissionAuditRead,
		TenantPermissionAuditExport,
		TenantPermissionAuditRetentionManage,
		TenantPermissionSLARead,
		TenantPermissionSLAManage,
		TenantPermissionSLASimulate,
		TenantPermissionWorkflowRead,
		TenantPermissionWorkflowManage,
		TenantPermissionAlertSLAOverride,
		TenantPermissionCaseSLAOverride,
		TenantPermissionCustomFieldRead,
		TenantPermissionCustomFieldManage,
		TenantPermissionDFIRIOCRead,
		TenantPermissionDFIRIOCManage,
		TenantPermissionDFIRAssetRead,
		TenantPermissionDFIRAssetManage,
		TenantPermissionDFIREvidenceRead,
		TenantPermissionDFIREvidenceManage,
		TenantPermissionDFIRTimelineRead,
		TenantPermissionDFIRTimelineManage,
		TenantPermissionDFIRTaskRead,
		TenantPermissionDFIRTaskManage,
		TenantPermissionDFIRAttachmentRead,
		TenantPermissionDFIRAttachmentManage,
		TenantPermissionDFIRRelationshipRead,
		TenantPermissionDFIRRelationshipManage,
	}
	if len(initialTenantPermissions) != len(permissions) {
		t.Fatalf("initial tenant permission count = %d, want %d", len(initialTenantPermissions), len(permissions))
	}

	evaluator := Evaluator{}
	portalPermissions := map[TenantPermission]struct{}{
		TenantPermissionPortalAlertRead:               {},
		TenantPermissionPortalCaseRead:                {},
		TenantPermissionPortalCommentPublic:           {},
		TenantPermissionPortalAttachmentRead:          {},
		TenantPermissionPortalContactPreferenceManage: {},
	}
	overridePermissions := map[TenantPermission]struct{}{
		TenantPermissionAlertUpdate:      {},
		TenantPermissionAlertSLAOverride: {},
		TenantPermissionCaseSLAOverride:  {},
	}
	for _, permission := range permissions {
		permission := permission
		t.Run(string(permission), func(t *testing.T) {
			t.Parallel()

			scope := ScopeTenant
			resource := ResourceContext{TenantID: testTenantID}
			if _, portal := portalPermissions[permission]; portal {
				scope = ScopeOwn
				resource.OwnerID = &testPrincipalID
			}
			authority := testTenantAuthority(permission, scope)
			if err := evaluator.RequireTenant(authority, permission, resource); err != nil {
				t.Fatalf("RequireTenant() error = %v", err)
			}

			if _, override := overridePermissions[permission]; override {
				authority.Permissions[0].Scope = ScopePlatform
			} else if scope == ScopeOwn {
				authority.Permissions[0].Scope = ScopeTenant
			} else {
				authority.Permissions[0].Scope = ScopeOwn
			}
			assertAuthorizationDenied(t, evaluator.RequireTenant(authority, permission, resource))

			authority = testTenantAuthority(permission, scope)
			authority.Principal.Kind = PrincipalKindServiceAccount
			authority.MembershipID = uuid.Nil
			authority.MembershipStatus = ""
			authority.LegacyRole = ""
			err := evaluator.RequireTenant(authority, permission, resource)
			if permission == TenantPermissionAlertCreate {
				if err != nil {
					t.Fatalf("service-account RequireTenant() error = %v", err)
				}
			} else {
				assertAuthorizationDenied(t, err)
			}
		})
	}
}

func TestEvaluatorAlertUpdateOwnScopeRequiresExactOwner(t *testing.T) {
	authority := testTenantAuthority(TenantPermissionAlertUpdate, ScopeOwn)
	evaluator := Evaluator{}
	for _, owner := range []*uuid.UUID{&testPrincipalID, &testOtherUserID, nil} {
		err := evaluator.RequireTenant(authority, TenantPermissionAlertUpdate, ResourceContext{TenantID: testTenantID, OwnerID: owner})
		if owner == &testPrincipalID && err != nil {
			t.Fatalf("own Alert update denied: %v", err)
		}
		if owner != &testPrincipalID && !errors.Is(err, ErrDenied) {
			t.Fatalf("non-owned Alert update: %v", err)
		}
	}
}

func TestTenantPermissionCatalogMatchesCanonicalContract(t *testing.T) {
	t.Parallel()

	document, err := contract.GetSpec()
	if err != nil {
		t.Fatalf("contract.GetSpec() error = %v", err)
	}
	schema, ok := document.Components.Schemas["TenantPermissionKey"]
	if !ok || schema == nil || schema.Value == nil {
		t.Fatal("TenantPermissionKey schema is absent from the canonical contract")
	}

	contractPermissions := make(map[TenantPermission]struct{}, len(schema.Value.Enum))
	for _, rawPermission := range schema.Value.Enum {
		permission, ok := rawPermission.(string)
		if !ok || permission == "" {
			t.Fatalf("TenantPermissionKey enum contains invalid value %#v", rawPermission)
		}
		contractPermissions[TenantPermission(permission)] = struct{}{}
	}
	if len(contractPermissions) != len(schema.Value.Enum) {
		t.Fatal("TenantPermissionKey enum contains duplicate values")
	}
	if len(contractPermissions) != len(initialTenantPermissions) {
		t.Fatalf(
			"canonical tenant permission count = %d, evaluator count = %d",
			len(contractPermissions),
			len(initialTenantPermissions),
		)
	}
	for permission := range initialTenantPermissions {
		if _, found := contractPermissions[permission]; !found {
			t.Errorf("evaluator permission %q is absent from the canonical contract", permission)
		}
	}
	for permission := range contractPermissions {
		if _, found := initialTenantPermissions[permission]; !found {
			t.Errorf("canonical permission %q is absent from the evaluator", permission)
		}
	}
}

func TestEvaluatorSLAOverrideScopeMatrix(t *testing.T) {
	t.Parallel()

	evaluator := Evaluator{}
	for _, permission := range []TenantPermission{
		TenantPermissionAlertSLAOverride,
		TenantPermissionCaseSLAOverride,
	} {
		permission := permission
		for _, scope := range []Scope{ScopeOwn, ScopeAssigned, ScopeOperatorTeam, ScopeTenant} {
			scope := scope
			t.Run(string(permission)+"_"+string(scope), func(t *testing.T) {
				t.Parallel()
				resource := ResourceContext{
					TenantID:   testTenantID,
					OwnerID:    uuidPointer(testPrincipalID),
					AssigneeID: uuidPointer(testPrincipalID),
					OperatorTeamRelationship: operatorTeamRelationshipPointer(
						testOperatorTeamID, testAssignmentEpochID,
					),
				}
				authority := testTenantAuthority(permission, scope)
				authority.OperatorTeamRelationships = []OperatorTeamRelationship{
					testOperatorTeamRelationship(testOperatorTeamID, testAssignmentEpochID),
				}
				if err := evaluator.RequireTenant(authority, permission, resource); err != nil {
					t.Fatalf("RequireTenant() error = %v", err)
				}
			})
		}
	}
}

func TestEvaluatorAlertCreateIsExactTenantScopeForBothPrincipalKinds(t *testing.T) {
	t.Parallel()

	evaluator := Evaluator{}
	for _, kind := range []PrincipalKind{PrincipalKindHuman, PrincipalKindServiceAccount} {
		authority := testTenantAuthority(TenantPermissionAlertCreate, ScopeTenant)
		if kind == PrincipalKindServiceAccount {
			authority.Principal.Kind = kind
			authority.MembershipID = uuid.Nil
			authority.MembershipStatus = ""
			authority.LegacyRole = ""
		}
		if err := evaluator.RequireTenant(authority, TenantPermissionAlertCreate, ResourceContext{TenantID: testTenantID}); err != nil {
			t.Fatalf("RequireTenant(%s) error = %v", kind, err)
		}
		authority.Permissions[0].Scope = ScopeOwn
		assertAuthorizationDenied(t, evaluator.RequireTenant(authority, TenantPermissionAlertCreate, ResourceContext{TenantID: testTenantID}))
	}
}

func TestEvaluatorOperatorTeamPermissionMatrix(t *testing.T) {
	t.Parallel()

	evaluator := Evaluator{}
	teamResource := ResourceContext{
		TenantID: testTenantID,
		OperatorTeamRelationship: operatorTeamRelationshipPointer(
			testOperatorTeamID, testAssignmentEpochID,
		),
	}
	tests := []struct {
		name       string
		permission TenantPermission
		scope      Scope
		resource   ResourceContext
		wantAllow  bool
	}{
		{name: "read tenant", permission: TenantPermissionOperatorTeamRead, scope: ScopeTenant, resource: ResourceContext{TenantID: testTenantID}, wantAllow: true},
		{name: "read exact team", permission: TenantPermissionOperatorTeamRead, scope: ScopeOperatorTeam, resource: teamResource, wantAllow: true},
		{name: "manage tenant", permission: TenantPermissionOperatorTeamManage, scope: ScopeTenant, resource: ResourceContext{TenantID: testTenantID}, wantAllow: true},
		{name: "manage rejects team scope", permission: TenantPermissionOperatorTeamManage, scope: ScopeOperatorTeam, resource: teamResource},
		{name: "roster tenant", permission: TenantPermissionOperatorTeamRosterManage, scope: ScopeTenant, resource: teamResource, wantAllow: true},
		{name: "roster exact team", permission: TenantPermissionOperatorTeamRosterManage, scope: ScopeOperatorTeam, resource: teamResource, wantAllow: true},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			authority := testTenantAuthority(test.permission, test.scope)
			authority.OperatorTeamRelationships = []OperatorTeamRelationship{
				testOperatorTeamRelationship(testOperatorTeamID, testAssignmentEpochID),
			}
			err := evaluator.RequireTenant(authority, test.permission, test.resource)
			if test.wantAllow {
				if err != nil {
					t.Fatalf("RequireTenant() error = %v", err)
				}
				return
			}
			assertAuthorizationDenied(t, err)
		})
	}
}

func TestEvaluatorRejectsMalformedOperatorTeamRelationshipProjection(t *testing.T) {
	t.Parallel()

	evaluator := Evaluator{}
	resource := ResourceContext{
		TenantID: testTenantID,
		OperatorTeamRelationship: operatorTeamRelationshipPointer(
			testOperatorTeamID, testAssignmentEpochID,
		),
	}
	for _, relationships := range [][]OperatorTeamRelationship{
		{testOperatorTeamRelationship(uuid.New(), testAssignmentEpochID)},
		{testOperatorTeamRelationship(testOperatorTeamID, uuid.New())},
		{
			testOperatorTeamRelationship(testOperatorTeamID, testAssignmentEpochID),
			testOperatorTeamRelationship(testOperatorTeamID, testOtherAssignmentEpochID),
		},
		{
			testOperatorTeamRelationship(testOperatorTeamID, testAssignmentEpochID),
			testOperatorTeamRelationship(testOtherTeamID, testAssignmentEpochID),
		},
	} {
		authority := testTenantAuthority(TenantPermissionOperatorTeamRead, ScopeOperatorTeam)
		authority.OperatorTeamRelationships = relationships
		assertAuthorizationDenied(t, evaluator.RequireTenant(authority, TenantPermissionOperatorTeamRead, resource))
	}
}

func TestEvaluatorOperatorTeamPermissionsRejectValidServicePrincipalShape(t *testing.T) {
	t.Parallel()

	evaluator := Evaluator{}
	for _, permission := range []TenantPermission{
		TenantPermissionOperatorTeamRead,
		TenantPermissionOperatorTeamManage,
		TenantPermissionOperatorTeamRosterManage,
	} {
		authority := testTenantAuthority(permission, ScopeTenant)
		authority.Principal.Kind = PrincipalKindServiceAccount
		authority.MembershipID = uuid.Nil
		authority.MembershipStatus = ""
		authority.LegacyRole = ""
		assertAuthorizationDenied(t, evaluator.RequireTenant(
			authority,
			permission,
			ResourceContext{TenantID: testTenantID},
		))
	}
}

func TestEvaluatorTenantScopeMatrix(t *testing.T) {
	t.Parallel()

	evaluator := testRelationshipEvaluator()
	tests := []struct {
		name                      string
		scope                     Scope
		resource                  ResourceContext
		operatorTeamRelationships []OperatorTeamRelationship
		wantAllowed               bool
	}{
		{
			name:        "own matching owner",
			scope:       ScopeOwn,
			resource:    ResourceContext{TenantID: testTenantID, OwnerID: uuidPointer(testPrincipalID)},
			wantAllowed: true,
		},
		{
			name:     "own missing owner",
			scope:    ScopeOwn,
			resource: ResourceContext{TenantID: testTenantID},
		},
		{
			name:     "own different owner",
			scope:    ScopeOwn,
			resource: ResourceContext{TenantID: testTenantID, OwnerID: uuidPointer(testOtherUserID)},
		},
		{
			name:        "assigned matching assignee",
			scope:       ScopeAssigned,
			resource:    ResourceContext{TenantID: testTenantID, AssigneeID: uuidPointer(testPrincipalID)},
			wantAllowed: true,
		},
		{
			name:     "assigned missing assignee",
			scope:    ScopeAssigned,
			resource: ResourceContext{TenantID: testTenantID},
		},
		{
			name:     "assigned different assignee",
			scope:    ScopeAssigned,
			resource: ResourceContext{TenantID: testTenantID, AssigneeID: uuidPointer(testOtherUserID)},
		},
		{
			name:  "operator team matching live assignment epoch",
			scope: ScopeOperatorTeam,
			resource: ResourceContext{
				TenantID: testTenantID,
				OperatorTeamRelationship: operatorTeamRelationshipPointer(
					testOperatorTeamID, testAssignmentEpochID,
				),
			},
			operatorTeamRelationships: []OperatorTeamRelationship{
				testOperatorTeamRelationship(testOperatorTeamID, testAssignmentEpochID),
			},
			wantAllowed: true,
		},
		{
			name:     "operator team missing resource team",
			scope:    ScopeOperatorTeam,
			resource: ResourceContext{TenantID: testTenantID},
		},
		{
			name:  "operator team missing live membership",
			scope: ScopeOperatorTeam,
			resource: ResourceContext{
				TenantID: testTenantID,
				OperatorTeamRelationship: operatorTeamRelationshipPointer(
					testOperatorTeamID, testAssignmentEpochID,
				),
			},
		},
		{
			name:  "operator team different membership",
			scope: ScopeOperatorTeam,
			resource: ResourceContext{
				TenantID: testTenantID,
				OperatorTeamRelationship: operatorTeamRelationshipPointer(
					testOperatorTeamID, testAssignmentEpochID,
				),
			},
			operatorTeamRelationships: []OperatorTeamRelationship{
				testOperatorTeamRelationship(testOtherTeamID, testOtherAssignmentEpochID),
			},
		},
		{
			name:  "operator team same identity different epoch",
			scope: ScopeOperatorTeam,
			resource: ResourceContext{
				TenantID: testTenantID,
				OperatorTeamRelationship: operatorTeamRelationshipPointer(
					testOperatorTeamID, testAssignmentEpochID,
				),
			},
			operatorTeamRelationships: []OperatorTeamRelationship{
				testOperatorTeamRelationship(testOperatorTeamID, testOtherAssignmentEpochID),
			},
		},
		{
			name:        "tenant without relationships",
			scope:       ScopeTenant,
			resource:    ResourceContext{TenantID: testTenantID},
			wantAllowed: true,
		},
		{
			name:        "wrong tenant",
			scope:       ScopeTenant,
			resource:    ResourceContext{TenantID: testOtherTenantID},
			wantAllowed: false,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			authority := testTenantAuthority(tenantPermissionTestResourceRead, test.scope)
			authority.OperatorTeamRelationships = test.operatorTeamRelationships
			err := evaluator.RequireTenant(authority, tenantPermissionTestResourceRead, test.resource)
			if test.wantAllowed {
				if err != nil {
					t.Fatalf("RequireTenant() error = %v", err)
				}
				return
			}
			assertAuthorizationDenied(t, err)
		})
	}
}

func TestEvaluatorRelationshipScopesAreIncomparable(t *testing.T) {
	t.Parallel()

	evaluator := testRelationshipEvaluator()
	leaves := []Scope{ScopeOwn, ScopeAssigned, ScopeOperatorTeam}
	resources := map[Scope]ResourceContext{
		ScopeOwn: {
			TenantID: testTenantID,
			OwnerID:  uuidPointer(testPrincipalID),
		},
		ScopeAssigned: {
			TenantID:   testTenantID,
			AssigneeID: uuidPointer(testPrincipalID),
		},
		ScopeOperatorTeam: {
			TenantID: testTenantID,
			OperatorTeamRelationship: operatorTeamRelationshipPointer(
				testOperatorTeamID, testAssignmentEpochID,
			),
		},
	}

	for _, grantedScope := range leaves {
		for _, resourceRelationship := range leaves {
			grantedScope := grantedScope
			resourceRelationship := resourceRelationship
			t.Run(string(grantedScope)+"_grant_on_"+string(resourceRelationship)+"_resource", func(t *testing.T) {
				t.Parallel()

				authority := testTenantAuthority(tenantPermissionTestResourceRead, grantedScope)
				authority.OperatorTeamRelationships = []OperatorTeamRelationship{
					testOperatorTeamRelationship(testOperatorTeamID, testAssignmentEpochID),
				}
				err := evaluator.RequireTenant(
					authority,
					tenantPermissionTestResourceRead,
					resources[resourceRelationship],
				)
				if grantedScope == resourceRelationship {
					if err != nil {
						t.Fatalf("RequireTenant() error = %v", err)
					}
					return
				}
				assertAuthorizationDenied(t, err)
			})
		}
	}
}

func TestEvaluatorTenantUnknownAndMalformedValuesDeny(t *testing.T) {
	t.Parallel()

	evaluator := Evaluator{}
	validAuthority := func() TenantAuthority {
		return testTenantAuthority(TenantPermissionRoleRead, ScopeTenant)
	}
	validResource := func() ResourceContext {
		return ResourceContext{TenantID: testTenantID}
	}

	tests := []struct {
		name      string
		authority TenantAuthority
		requested TenantPermission
		resource  ResourceContext
	}{
		{
			name:      "unknown requested permission",
			authority: validAuthority(),
			requested: "future.read",
			resource:  validResource(),
		},
		{
			name: "unknown permission poisons authority",
			authority: func() TenantAuthority {
				authority := validAuthority()
				authority.Permissions = append(authority.Permissions, ScopedPermission{
					Permission: "future.read",
					Scope:      ScopeTenant,
				})
				return authority
			}(),
			requested: TenantPermissionRoleRead,
			resource:  validResource(),
		},
		{
			name: "unknown scope",
			authority: func() TenantAuthority {
				authority := validAuthority()
				authority.Permissions[0].Scope = "future_scope"
				return authority
			}(),
			requested: TenantPermissionRoleRead,
			resource:  validResource(),
		},
		{
			name: "platform scope is never tenant authority",
			authority: func() TenantAuthority {
				authority := validAuthority()
				authority.Permissions[0].Scope = ScopePlatform
				return authority
			}(),
			requested: TenantPermissionRoleRead,
			resource:  validResource(),
		},
		{
			name: "unknown principal kind",
			authority: func() TenantAuthority {
				authority := validAuthority()
				authority.Principal.Kind = "future_principal"
				return authority
			}(),
			requested: TenantPermissionRoleRead,
			resource:  validResource(),
		},
		{
			name: "recognized but disallowed service account",
			authority: func() TenantAuthority {
				authority := validAuthority()
				authority.Principal.Kind = PrincipalKindServiceAccount
				return authority
			}(),
			requested: TenantPermissionRoleRead,
			resource:  validResource(),
		},
		{
			name: "missing authority tenant",
			authority: func() TenantAuthority {
				authority := validAuthority()
				authority.TenantID = uuid.Nil
				return authority
			}(),
			requested: TenantPermissionRoleRead,
			resource:  validResource(),
		},
		{
			name: "missing principal id",
			authority: func() TenantAuthority {
				authority := validAuthority()
				authority.Principal.ID = uuid.Nil
				return authority
			}(),
			requested: TenantPermissionRoleRead,
			resource:  validResource(),
		},
		{
			name: "missing human membership id",
			authority: func() TenantAuthority {
				authority := validAuthority()
				authority.MembershipID = uuid.Nil
				return authority
			}(),
			requested: TenantPermissionRoleRead,
			resource:  validResource(),
		},
		{
			name: "non-active human membership",
			authority: func() TenantAuthority {
				authority := validAuthority()
				authority.MembershipStatus = MembershipStatusSuspended
				return authority
			}(),
			requested: TenantPermissionRoleRead,
			resource:  validResource(),
		},
		{
			name: "missing evaluation timestamp",
			authority: func() TenantAuthority {
				authority := validAuthority()
				authority.EvaluatedAt = time.Time{}
				return authority
			}(),
			requested: TenantPermissionRoleRead,
			resource:  validResource(),
		},
		{
			name:      "missing resource tenant",
			authority: validAuthority(),
			requested: TenantPermissionRoleRead,
			resource:  ResourceContext{},
		},
		{
			name:      "zero resource relationship",
			authority: validAuthority(),
			requested: TenantPermissionRoleRead,
			resource:  ResourceContext{TenantID: testTenantID, OwnerID: uuidPointer(uuid.Nil)},
		},
		{
			name: "zero live operator-team relationship",
			authority: func() TenantAuthority {
				authority := validAuthority()
				authority.OperatorTeamRelationships = []OperatorTeamRelationship{{
					OperatorTeamID: uuid.Nil, AssignmentEpochID: testAssignmentEpochID,
				}}
				return authority
			}(),
			requested: TenantPermissionRoleRead,
			resource:  validResource(),
		},
		{
			name: "malformed ceiling poisons authority",
			authority: func() TenantAuthority {
				authority := validAuthority()
				authority.DelegationCeiling = []DelegationGrant{{
					ScopedPermission: ScopedPermission{Permission: "future.read", Scope: ScopeTenant},
				}}
				return authority
			}(),
			requested: TenantPermissionRoleRead,
			resource:  validResource(),
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			assertAuthorizationDenied(t, evaluator.RequireTenant(test.authority, test.requested, test.resource))
		})
	}
}

func testRelationshipEvaluator() Evaluator {
	return Evaluator{tenantPermissions: map[TenantPermission]tenantPermissionMetadata{
		tenantPermissionTestResourceRead: {
			principalKinds: setOf(PrincipalKindHuman),
			scopes: setOf(
				ScopeOwn,
				ScopeAssigned,
				ScopeOperatorTeam,
				ScopeTenant,
			),
		},
	}}
}

func testTenantAuthority(permission TenantPermission, scope Scope) TenantAuthority {
	return TenantAuthority{
		TenantID:     testTenantID,
		MembershipID: testMembershipID,
		LegacyRole:   LegacyMembershipRoleAnalyst,
		EvaluatedAt:  testEvaluatedAt,
		Principal: TenantPrincipal{
			ID:   testPrincipalID,
			Kind: PrincipalKindHuman,
		},
		MembershipStatus: MembershipStatusActive,
		Permissions:      []ScopedPermission{{Permission: permission, Scope: scope}},
	}
}

func assertAuthorizationDenied(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("error = %v, want ErrDenied", err)
	}
}

func uuidPointer(value uuid.UUID) *uuid.UUID {
	return &value
}

func testOperatorTeamRelationship(teamID, assignmentEpochID uuid.UUID) OperatorTeamRelationship {
	return OperatorTeamRelationship{
		OperatorTeamID: teamID, AssignmentEpochID: assignmentEpochID,
	}
}

func operatorTeamRelationshipPointer(teamID, assignmentEpochID uuid.UUID) *OperatorTeamRelationship {
	relationship := testOperatorTeamRelationship(teamID, assignmentEpochID)
	return &relationship
}
