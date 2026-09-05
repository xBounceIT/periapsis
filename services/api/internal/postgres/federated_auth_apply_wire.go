package postgres

import (
	"crypto/sha256"
	"encoding/json"
	"net/url"
	"path"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/federatedoidc"
	"github.com/periapsis-im/periapsis/modules/identity/federatedsaml"
	"github.com/periapsis-im/periapsis/modules/identity/mfa"
	"github.com/periapsis-im/periapsis/modules/identity/webauthn"
	"github.com/periapsis-im/periapsis/services/api/internal/federatedauth"
)

type federatedApplyCommandWire struct {
	OperationDigest []byte                    `json:"operationDigest"`
	Apply           federatedApplyRequestWire `json:"apply"`
}

type federatedApplyRequestWire struct {
	Authentication federatedApplyAuthenticationWire  `json:"authentication"`
	Plan           federatedApplyPlanWire            `json:"plan"`
	Disposition    string                            `json:"disposition"`
	Assurance      string                            `json:"assurance"`
	AppliedAt      time.Time                         `json:"appliedAt"`
	Session        *federatedSessionReservationWire  `json:"session,omitempty"`
	Continuation   *federatedContinuationWire        `json:"continuation,omitempty"`
	SAMLSession    *federatedProtectedMaterialWire   `json:"samlSession,omitempty"`
	OIDCSession    *federatedOIDCSessionMaterialWire `json:"oidcSession,omitempty"`
}

type federatedApplyAuthenticationWire struct {
	Protocol        string                        `json:"protocol"`
	Method          string                        `json:"method"`
	TenantID        string                        `json:"tenantId"`
	Admission       *federatedTenantAdmissionWire `json:"admission,omitempty"`
	AuthenticatedAt time.Time                     `json:"authenticatedAt"`
	ValidUntil      time.Time                     `json:"validUntil"`
	Evidence        []assuranceEvidenceWire       `json:"evidence"`
	OIDC            *federatedOIDCCompletionWire  `json:"oidc,omitempty"`
	SAML            *federatedSAMLConsumptionWire `json:"saml,omitempty"`
	Passkey         *federatedPasskeyArtifactWire `json:"passkey,omitempty"`
}

type federatedOIDCCompletionWire struct {
	TransactionID   []byte                  `json:"transactionId"`
	MaterialID      string                  `json:"materialId"`
	ExpectedVersion uint64                  `json:"expectedVersion"`
	Pins            oidcTransactionPinsWire `json:"pins"`
	CompletedAt     time.Time               `json:"completedAt"`
	ReturnPath      string                  `json:"returnPath"`
}

type federatedSAMLConsumptionWire struct {
	TransactionID      []byte                  `json:"transactionId"`
	MaterialID         string                  `json:"materialId"`
	ExpectedVersion    uint64                  `json:"expectedVersion"`
	Pins               samlTransactionPinsWire `json:"pins"`
	ResponseID         string                  `json:"responseId"`
	AssertionID        string                  `json:"assertionId"`
	SessionIndexDigest []byte                  `json:"sessionIndexDigest,omitempty"`
	HasSessionIndex    bool                    `json:"hasSessionIndex"`
	ConsumedAt         time.Time               `json:"consumedAt"`
	ReturnPath         string                  `json:"returnPath"`
}

type federatedPasskeyArtifactWire struct {
	TenantID           string                `json:"tenantId"`
	UserID             string                `json:"userId"`
	IdentityEpoch      uint64                `json:"identityEpoch"`
	CredentialVersion  uint64                `json:"credentialVersion"`
	CredentialDigest   []byte                `json:"credentialDigest"`
	Evidence           assuranceEvidenceWire `json:"evidence"`
	CounterUnsupported bool                  `json:"counterUnsupported"`
	BackupStateChanged bool                  `json:"backupStateChanged"`
}

type federatedApplyPlanWire struct {
	PlanRevision          uint64                         `json:"planRevision"`
	TenantID              string                         `json:"tenantId"`
	UserID                string                         `json:"userId,omitempty"`
	IdentityEpoch         uint64                         `json:"identityEpoch"`
	ProviderRevision      uint64                         `json:"providerRevision"`
	BindingRevision       uint64                         `json:"bindingRevision"`
	ConfigurationRevision uint64                         `json:"configurationRevision"`
	SecurityRevision      uint64                         `json:"securityRevision"`
	MappingRevision       uint64                         `json:"mappingRevision"`
	AuthorizationRevision uint64                         `json:"authorizationRevision"`
	PolicyRevision        uint64                         `json:"policyRevision"`
	RoleIDs               []string                       `json:"roleIds"`
	SecurityGroupIDs      []string                       `json:"securityGroupIds"`
	Subject               *federatedProtectedSubjectWire `json:"subject,omitempty"`
	Mapping               *federatedApplyMappingWire     `json:"mapping,omitempty"`
	Requirement           assuranceRequirementWire       `json:"requirement"`
	HasEnrollableFactor   bool                           `json:"hasEnrollableFactor"`
}

type federatedProtectedSubjectWire struct {
	ExternalIdentityID string                           `json:"externalIdentityId"`
	Aliases            []federatedApplySubjectAliasWire `json:"aliases"`
	Envelope           federatedSubjectEnvelopeWire     `json:"envelope"`
}

type federatedApplySubjectAliasWire struct {
	KeyVersion int16  `json:"keyVersion"`
	Digest     []byte `json:"digest"`
}

type federatedSubjectEnvelopeWire struct {
	KeyVersion int16  `json:"keyVersion"`
	Format     string `json:"format"`
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}

type federatedApplyMappingWire struct {
	Disposition    string                      `json:"disposition"`
	Reason         string                      `json:"reason"`
	IdentityAction string                      `json:"identityAction"`
	AccessAction   string                      `json:"accessAction"`
	MatchedRuleIDs []string                    `json:"matchedRuleIds"`
	SecurityGroups []string                    `json:"securityGroupIds"`
	RoleIDs        []string                    `json:"roleIds"`
	Teams          []federatedApplyTeamWire    `json:"operatorTeams"`
	Changes        []federatedApplyChangeWire  `json:"changes"`
	Profile        []federatedApplyProfileWire `json:"profile"`
}

type federatedApplyTeamWire struct {
	TeamID            string `json:"teamId"`
	AssignmentEpochID string `json:"assignmentEpochId"`
}

type federatedApplyChangeWire struct {
	Operation   string `json:"operation"`
	SourceID    string `json:"sourceId"`
	RuleEpochID string `json:"ruleEpochId"`
	Kind        string `json:"kind"`
	PrimaryID   string `json:"primaryId"`
	SecondaryID string `json:"secondaryId,omitempty"`
}

type federatedApplyProfileWire struct {
	Field   string `json:"field"`
	Present bool   `json:"present"`
	Value   string `json:"value,omitempty"`
}

type federatedSessionReservationWire struct {
	SessionID            string    `json:"sessionId"`
	FamilyID             string    `json:"familyId"`
	TokenDigest          []byte    `json:"tokenDigest"`
	CSRFDigest           []byte    `json:"csrfDigest"`
	AuthenticationMethod string    `json:"authenticationMethod"`
	IdleExpiresAt        time.Time `json:"idleExpiresAt"`
	AbsoluteExpiresAt    time.Time `json:"absoluteExpiresAt"`
}

type federatedContinuationWire struct {
	ContinuationID string    `json:"continuationId"`
	ReceiptDigest  []byte    `json:"receiptDigest"`
	ExpiresAt      time.Time `json:"expiresAt"`
}

type federatedProtectedMaterialWire struct {
	MaterialID string `json:"materialId"`
	KeyVersion uint32 `json:"keyVersion,omitempty"`
	Ciphertext []byte `json:"ciphertext,omitempty"`
}

type federatedProtectedOIDCTokenWire struct {
	KeyVersion uint32 `json:"keyVersion"`
	Ciphertext []byte `json:"ciphertext"`
	Digest     []byte `json:"digest"`
}

type federatedProtectedOIDCRefreshWire struct {
	KeyVersion      uint32    `json:"keyVersion"`
	Ciphertext      []byte    `json:"ciphertext"`
	Digest          []byte    `json:"digest"`
	Generation      uint64    `json:"generation"`
	AccessExpiresAt time.Time `json:"accessExpiresAt"`
}

type federatedOIDCSessionMaterialWire struct {
	MaterialID            string                             `json:"materialId"`
	ExpiresAt             time.Time                          `json:"expiresAt"`
	IDToken               *federatedProtectedOIDCTokenWire   `json:"idToken,omitempty"`
	RefreshToken          *federatedProtectedOIDCRefreshWire `json:"refreshToken,omitempty"`
	ClientSecretRevision  uint64                             `json:"clientSecretRevision,omitempty"`
	ClientAuthentication  string                             `json:"clientAuthentication,omitempty"`
	ClientID              string                             `json:"clientId,omitempty"`
	TokenEndpoint         string                             `json:"tokenEndpoint,omitempty"`
	RevocationEndpoint    string                             `json:"revocationEndpoint,omitempty"`
	EndSessionEndpoint    string                             `json:"endSessionEndpoint,omitempty"`
	PostLogoutRedirectURI string                             `json:"postLogoutRedirectUri,omitempty"`
}

type federatedApplyResultWire struct {
	OperationDigest []byte `json:"operationDigest"`
	Protocol        string `json:"protocol"`
	TenantID        string `json:"tenantId"`
	Disposition     string `json:"disposition"`
	Category        string `json:"category"`
	UserID          string `json:"userId,omitempty"`
	SessionID       string `json:"sessionId,omitempty"`
	ContinuationID  string `json:"continuationId,omitempty"`
	ReturnPath      string `json:"returnPath,omitempty"`
	Replayed        bool   `json:"replayed"`
}

func federatedApplyToWire(
	request federatedauth.ApplyRequest,
	protected *federatedsaml.ProtectedSessionMaterial,
	materialID identity.EntityID,
) (federatedApplyCommandWire, error) {
	authentication, err := federatedApplyAuthenticationToWire(request.Authentication)
	if err != nil {
		return federatedApplyCommandWire{}, errFederatedAuthPersistence
	}
	plan, err := federatedApplyPlanToWire(request.Plan, request.Authentication.Protocol)
	if err != nil || plan.TenantID != authentication.TenantID || !validFederatedDatabaseTime(request.AppliedAt) ||
		!validFederatedApplyDecision(request.Disposition, request.Assurance) ||
		!validFederatedApplyPlanPins(plan, authentication) {
		clearFederatedApplyAuthenticationWire(&authentication)
		clearFederatedApplyPlanWire(&plan)
		return federatedApplyCommandWire{}, errFederatedAuthPersistence
	}
	apply := federatedApplyRequestWire{
		Authentication: authentication, Plan: plan, Disposition: string(request.Disposition),
		Assurance: string(request.Assurance), AppliedAt: request.AppliedAt,
	}
	switch request.Disposition {
	case federatedauth.ApplySession:
		if !request.Continuation.IsZero() || !request.Session.ValidAt(request.AppliedAt.Truncate(time.Millisecond)) ||
			string(request.Session.AuthenticationMethod()) != string(request.Authentication.Method) {
			clearFederatedApplyRequestWire(&apply)
			return federatedApplyCommandWire{}, errFederatedAuthPersistence
		}
		apply.Session = federatedApplySessionReservationToWire(request.Session)
	case federatedauth.ApplyContinuation:
		if !request.Session.IsZero() || !request.Continuation.ValidAt(request.AppliedAt) {
			clearFederatedApplyRequestWire(&apply)
			return federatedApplyCommandWire{}, errFederatedAuthPersistence
		}
		apply.Continuation = continuationReservationToWire(request.Continuation)
	default:
		clearFederatedApplyRequestWire(&apply)
		return federatedApplyCommandWire{}, errFederatedAuthPersistence
	}
	if request.Authentication.Protocol == federatedauth.ProtocolSAML {
		if authentication.SAML == nil || entityIDWire(materialID) == "" ||
			authentication.SAML.MaterialID != entityIDWire(materialID) {
			clearFederatedApplyRequestWire(&apply)
			return federatedApplyCommandWire{}, errFederatedAuthPersistence
		}
	} else if materialID != (identity.EntityID{}) {
		clearFederatedApplyRequestWire(&apply)
		return federatedApplyCommandWire{}, errFederatedAuthPersistence
	}
	if protected != nil {
		if request.Authentication.Protocol != federatedauth.ProtocolSAML || protected.KeyVersion == 0 ||
			len(protected.Ciphertext) < 16 || len(protected.Ciphertext) > 16*1024 {
			clearFederatedApplyRequestWire(&apply)
			return federatedApplyCommandWire{}, errFederatedAuthPersistence
		}
		apply.SAMLSession = &federatedProtectedMaterialWire{
			MaterialID: entityIDWire(materialID), KeyVersion: protected.KeyVersion,
			Ciphertext: append([]byte(nil), protected.Ciphertext...),
		}
	}
	semantic := apply
	if apply.SAMLSession != nil {
		semantic.SAMLSession = &federatedProtectedMaterialWire{MaterialID: apply.SAMLSession.MaterialID}
	}
	document, err := json.Marshal(semantic)
	if err != nil || len(document) == 0 || len(document) > maximumFederatedAuthenticationWireBytes {
		clear(document)
		clearFederatedApplyRequestWire(&apply)
		return federatedApplyCommandWire{}, errFederatedAuthPersistence
	}
	digest := sha256.Sum256(document)
	clear(document)
	return federatedApplyCommandWire{OperationDigest: append([]byte(nil), digest[:]...), Apply: apply}, nil
}

func federatedApplyAuthenticationToWire(
	value federatedauth.ApplyAuthenticationProjection,
) (federatedApplyAuthenticationWire, error) {
	if entityIDWire(value.TenantID) == "" || !validFederatedDatabaseTime(value.AuthenticatedAt) ||
		!validFederatedDatabaseTime(value.ValidUntil) || !value.ValidUntil.After(value.AuthenticatedAt) ||
		!validFederatedApplyProtocolMethod(value.Protocol, value.Method) || len(value.Evidence) == 0 || len(value.Evidence) > 64 {
		return federatedApplyAuthenticationWire{}, errFederatedAuthPersistence
	}
	evidence, err := evidenceToWire(value.Evidence)
	if err != nil {
		return federatedApplyAuthenticationWire{}, errFederatedAuthPersistence
	}
	wire := federatedApplyAuthenticationWire{
		Protocol: string(value.Protocol), Method: string(value.Method), TenantID: entityIDWire(value.TenantID),
		AuthenticatedAt: value.AuthenticatedAt, ValidUntil: value.ValidUntil, Evidence: evidence,
	}
	present := 0
	if value.OIDCCompletion != nil {
		present++
		wire.OIDC, err = federatedOIDCCompletionToWire(*value.OIDCCompletion)
	}
	if value.SAMLConsumption != nil {
		present++
		wire.SAML, err = federatedSAMLConsumptionToWire(*value.SAMLConsumption)
	}
	if value.Passkey != nil {
		present++
		wire.Passkey, err = federatedPasskeyArtifactToWire(*value.Passkey)
	}
	if err != nil || present != 1 ||
		value.Protocol == federatedauth.ProtocolOIDC && wire.OIDC == nil ||
		value.Protocol == federatedauth.ProtocolSAML && wire.SAML == nil ||
		value.Protocol == federatedauth.ProtocolPasskey && wire.Passkey == nil ||
		!validFederatedApplyEvidence(value) {
		clearFederatedApplyAuthenticationWire(&wire)
		return federatedApplyAuthenticationWire{}, errFederatedAuthPersistence
	}
	if value.Protocol == federatedauth.ProtocolOIDC {
		pins := value.OIDCCompletion.Pins
		admission, validAdmission := pins.TenantAdmission()
		if !validAdmission || admission.TenantID != value.TenantID ||
			(value.Admission != (identity.TenantAdmissionContext{}) && value.Admission != admission) ||
			pins.Provider.Scope == identity.PlatformProviderScope && value.Admission != admission {
			clearFederatedApplyAuthenticationWire(&wire)
			return federatedApplyAuthenticationWire{}, errFederatedAuthPersistence
		}
		if pins.Provider.Scope == identity.PlatformProviderScope {
			admissionWire, admissionErr := tenantAdmissionToWire(admission)
			if admissionErr != nil {
				clearFederatedApplyAuthenticationWire(&wire)
				return federatedApplyAuthenticationWire{}, errFederatedAuthPersistence
			}
			wire.Admission = &admissionWire
		}
	} else if value.Admission != (identity.TenantAdmissionContext{}) {
		clearFederatedApplyAuthenticationWire(&wire)
		return federatedApplyAuthenticationWire{}, errFederatedAuthPersistence
	}
	return wire, nil
}

func federatedOIDCCompletionToWire(
	value federatedoidc.TransactionCompletion,
) (*federatedOIDCCompletionWire, error) {
	pins, err := oidcPinsToWire(value.Pins)
	if err != nil || !validOpaque32(value.ID[:]) || entityIDWire(value.MaterialID) == "" ||
		!validFederatedSuccessorRevision(value.ExpectedVersion) ||
		!validFederatedDatabaseTime(value.CompletedAt) || !validFederatedReturnPath(value.ReturnPath) {
		return nil, errFederatedAuthPersistence
	}
	return &federatedOIDCCompletionWire{
		TransactionID: append([]byte(nil), value.ID[:]...), MaterialID: entityIDWire(value.MaterialID),
		ExpectedVersion: value.ExpectedVersion,
		Pins:            pins, CompletedAt: value.CompletedAt, ReturnPath: value.ReturnPath,
	}, nil
}

func federatedOIDCApplyToWire(
	request federatedauth.OIDCApplyRequest,
) (federatedApplyCommandWire, error) {
	if request.Apply.Authentication.Protocol != federatedauth.ProtocolOIDC ||
		request.Apply.Authentication.OIDCCompletion == nil ||
		request.Apply.Authentication.OIDCCompletion.MaterialID != request.MaterialID ||
		request.Configuration.Pins() != request.Apply.Authentication.OIDCCompletion.Pins ||
		entityIDWire(request.MaterialID) == "" || !validFederatedDatabaseTime(request.MaterialExpiresAt) ||
		request.MaterialExpiresAt.After(request.Apply.Authentication.ValidUntil) {
		return federatedApplyCommandWire{}, errFederatedAuthPersistence
	}
	ownerExpiry := request.Apply.Session.AbsoluteExpiresAt()
	if request.Apply.Disposition == federatedauth.ApplyContinuation {
		ownerExpiry = request.Apply.Continuation.ExpiresAt()
	}
	if ownerExpiry.IsZero() || request.MaterialExpiresAt.After(ownerExpiry) {
		return federatedApplyCommandWire{}, errFederatedAuthPersistence
	}
	command, err := federatedApplyToWire(request.Apply, nil, identity.EntityID{})
	if err != nil {
		return federatedApplyCommandWire{}, err
	}
	clear(command.OperationDigest)
	command.OperationDigest = nil

	endpoints := request.Configuration.Discovery.Endpoints()
	wantIDToken := endpoints.EndSession != ""
	wantRefreshToken := request.Configuration.AllowRefreshToken
	if (request.SessionMaterial != nil) != (wantIDToken || wantRefreshToken) {
		clearFederatedApplyCommandWire(&command)
		return federatedApplyCommandWire{}, errFederatedAuthPersistence
	}
	if request.SessionMaterial != nil {
		material, materialErr := federatedOIDCSessionMaterialToWire(request)
		if materialErr != nil {
			clearFederatedApplyCommandWire(&command)
			return federatedApplyCommandWire{}, errFederatedAuthPersistence
		}
		command.Apply.OIDCSession = material
	}
	semantic := command.Apply
	if command.Apply.OIDCSession != nil {
		semanticMaterial := *command.Apply.OIDCSession
		if semanticMaterial.IDToken != nil {
			semanticMaterial.IDToken = &federatedProtectedOIDCTokenWire{
				Digest: append([]byte(nil), semanticMaterial.IDToken.Digest...),
			}
		}
		if semanticMaterial.RefreshToken != nil {
			semanticMaterial.RefreshToken = &federatedProtectedOIDCRefreshWire{
				Digest:          append([]byte(nil), semanticMaterial.RefreshToken.Digest...),
				Generation:      semanticMaterial.RefreshToken.Generation,
				AccessExpiresAt: semanticMaterial.RefreshToken.AccessExpiresAt,
			}
		}
		semantic.OIDCSession = &semanticMaterial
	}
	document, err := json.Marshal(semantic)
	if semantic.OIDCSession != nil && semantic.OIDCSession.RefreshToken != nil {
		clear(semantic.OIDCSession.RefreshToken.Digest)
	}
	if semantic.OIDCSession != nil && semantic.OIDCSession.IDToken != nil {
		clear(semantic.OIDCSession.IDToken.Digest)
	}
	if err != nil || len(document) == 0 || len(document) > maximumFederatedAuthenticationWireBytes {
		clear(document)
		clearFederatedApplyCommandWire(&command)
		return federatedApplyCommandWire{}, errFederatedAuthPersistence
	}
	digest := sha256.Sum256(document)
	clear(document)
	command.OperationDigest = append([]byte(nil), digest[:]...)
	return command, nil
}

func federatedOIDCSessionMaterialToWire(
	request federatedauth.OIDCApplyRequest,
) (*federatedOIDCSessionMaterialWire, error) {
	return federatedOIDCSessionMaterialValuesToWire(
		request.Configuration, request.MaterialID, request.SessionMaterial, request.MaterialExpiresAt,
	)
}

func federatedOIDCSessionMaterialValuesToWire(
	configuration federatedoidc.AuthorizationConfiguration,
	materialID identity.EntityID,
	material *federatedauth.ProtectedOIDCSessionMaterial,
	expiresAt time.Time,
) (*federatedOIDCSessionMaterialWire, error) {
	if material == nil || material.MaterialID != materialID ||
		(material.IDToken != nil) != (configuration.Discovery.Endpoints().EndSession != "") ||
		(material.RefreshToken != nil) != configuration.AllowRefreshToken {
		return nil, errFederatedAuthPersistence
	}
	wire := &federatedOIDCSessionMaterialWire{
		MaterialID: entityIDWire(materialID), ExpiresAt: expiresAt,
	}
	if material.IDToken != nil {
		if !validFederatedProtectedOIDCToken(*material.IDToken) {
			return nil, errFederatedAuthPersistence
		}
		endpoint, err := configuration.Discovery.PinnedEndpoint(federatedoidc.EndpointEndSession)
		if err != nil || endpoint.URL() == "" || configuration.PostLogoutRedirectURI == "" {
			return nil, errFederatedAuthPersistence
		}
		wire.IDToken = &federatedProtectedOIDCTokenWire{
			KeyVersion: material.IDToken.KeyVersion,
			Ciphertext: append([]byte(nil), material.IDToken.Ciphertext...),
			Digest:     append([]byte(nil), material.IDTokenDigest[:]...),
		}
		wire.EndSessionEndpoint = endpoint.URL()
		wire.PostLogoutRedirectURI = configuration.PostLogoutRedirectURI
	}
	if material.RefreshToken != nil {
		if !validFederatedProtectedOIDCToken(*material.RefreshToken) ||
			material.RefreshTokenDigest == ([sha256.Size]byte{}) || material.RefreshGeneration != 1 ||
			!validFederatedDatabaseTime(material.AccessExpiresAt) ||
			material.AccessExpiresAt.After(expiresAt) {
			clearFederatedOIDCSessionMaterialWire(wire)
			return nil, errFederatedAuthPersistence
		}
		tokenEndpoint, err := configuration.Discovery.PinnedEndpoint(federatedoidc.EndpointToken)
		if err != nil || tokenEndpoint.URL() == "" || configuration.ClientSecretRevision == 0 ||
			configuration.ClientID == "" {
			clearFederatedOIDCSessionMaterialWire(wire)
			return nil, errFederatedAuthPersistence
		}
		wire.RefreshToken = &federatedProtectedOIDCRefreshWire{
			KeyVersion:      material.RefreshToken.KeyVersion,
			Ciphertext:      append([]byte(nil), material.RefreshToken.Ciphertext...),
			Digest:          append([]byte(nil), material.RefreshTokenDigest[:]...),
			Generation:      material.RefreshGeneration,
			AccessExpiresAt: material.AccessExpiresAt,
		}
		wire.ClientSecretRevision = configuration.ClientSecretRevision
		wire.ClientAuthentication = string(configuration.Discovery.ClientAuthentication())
		wire.ClientID = configuration.ClientID
		wire.TokenEndpoint = tokenEndpoint.URL()
		if configuration.Discovery.Endpoints().Revocation != "" {
			revocation, pinErr := configuration.Discovery.PinnedEndpoint(federatedoidc.EndpointRevocation)
			if pinErr != nil || revocation.URL() == "" {
				clearFederatedOIDCSessionMaterialWire(wire)
				return nil, errFederatedAuthPersistence
			}
			wire.RevocationEndpoint = revocation.URL()
		}
	}
	return wire, nil
}

func validFederatedProtectedOIDCToken(value federatedauth.ProtectedToken) bool {
	return value.KeyVersion > 0 && value.KeyVersion <= 32767 && len(value.Ciphertext) >= 29 &&
		len(value.Ciphertext) <= 262172
}

func federatedSAMLConsumptionToWire(
	value federatedsaml.ConsumptionRequest,
) (*federatedSAMLConsumptionWire, error) {
	pins, err := samlPinsToWire(value.Pins)
	sessionDigest, digestErr := optionalDigestToWire(value.SessionIndexDigest[:], value.HasSessionIndex)
	if err != nil || digestErr != nil || !validOpaque32(value.TransactionID[:]) || entityIDWire(value.MaterialID) == "" ||
		!validFederatedSuccessorRevision(value.ExpectedVersion) || !validFederatedPublicText(value.ResponseID, 1024) ||
		!validFederatedPublicText(value.AssertionID, 1024) || value.ResponseID == value.AssertionID ||
		!validFederatedDatabaseTime(value.ConsumedAt) || !validFederatedReturnPath(value.ReturnPath) {
		clear(sessionDigest)
		return nil, errFederatedAuthPersistence
	}
	return &federatedSAMLConsumptionWire{
		TransactionID: append([]byte(nil), value.TransactionID[:]...), MaterialID: entityIDWire(value.MaterialID),
		ExpectedVersion: value.ExpectedVersion,
		Pins:            pins, ResponseID: value.ResponseID, AssertionID: value.AssertionID,
		SessionIndexDigest: sessionDigest, HasSessionIndex: value.HasSessionIndex,
		ConsumedAt: value.ConsumedAt, ReturnPath: value.ReturnPath,
	}, nil
}

func federatedPasskeyArtifactToWire(
	value webauthn.AuthenticationArtifact,
) (*federatedPasskeyArtifactWire, error) {
	evidence, err := evidenceToWire([]identity.AssuranceEvidence{value.Evidence})
	if err != nil || entityIDWire(value.TenantID) == "" || entityIDWire(value.UserID) == "" ||
		!validFederatedRevision(value.IdentityEpoch) || !validFederatedRevision(value.CredentialVersion) ||
		!validDigestWire(value.CredentialDigest[:]) || len(evidence) != 1 {
		return nil, errFederatedAuthPersistence
	}
	return &federatedPasskeyArtifactWire{
		TenantID: entityIDWire(value.TenantID), UserID: entityIDWire(value.UserID), IdentityEpoch: value.IdentityEpoch,
		CredentialVersion: value.CredentialVersion, CredentialDigest: append([]byte(nil), value.CredentialDigest[:]...),
		Evidence: evidence[0], CounterUnsupported: value.CounterUnsupported, BackupStateChanged: value.BackupStateChanged,
	}, nil
}

func federatedApplyPlanToWire(
	value federatedauth.AuthenticationPlan,
	protocol federatedauth.Protocol,
) (federatedApplyPlanWire, error) {
	requirement, err := requirementToWire(value.Requirement)
	roleIDs, roleErr := federatedEntityIDsToWire(value.RoleIDs, 1024)
	groupIDs, groupErr := federatedEntityIDsToWire(value.SecurityGroupIDs, 1024)
	if err != nil || roleErr != nil || groupErr != nil || !validFederatedRevision(value.PlanRevision) ||
		entityIDWire(value.TenantID) == "" || !validFederatedRevision(value.PolicyRevision) ||
		(value.UserID == (identity.EntityID{})) != (value.IdentityEpoch == 0) ||
		value.UserID != (identity.EntityID{}) && (!validFederatedRevision(value.IdentityEpoch) || entityIDWire(value.UserID) == "") {
		return federatedApplyPlanWire{}, errFederatedAuthPersistence
	}
	wire := federatedApplyPlanWire{
		PlanRevision: value.PlanRevision, TenantID: entityIDWire(value.TenantID), UserID: entityIDWire(value.UserID),
		IdentityEpoch: value.IdentityEpoch, ProviderRevision: value.ProviderRevision,
		BindingRevision: value.BindingRevision, ConfigurationRevision: value.ConfigurationRevision,
		SecurityRevision: value.SecurityRevision, MappingRevision: value.MappingRevision,
		AuthorizationRevision: value.AuthorizationRevision, PolicyRevision: value.PolicyRevision,
		RoleIDs: roleIDs, SecurityGroupIDs: groupIDs, Requirement: requirement,
		HasEnrollableFactor: value.HasEnrollableFactor,
	}
	if protocol == federatedauth.ProtocolPasskey {
		if value.Subject != nil || value.Mapping != nil || value.ProviderRevision != 0 || value.BindingRevision != 0 ||
			value.ConfigurationRevision != 0 || value.SecurityRevision != 0 || value.MappingRevision != 0 ||
			value.AuthorizationRevision != 0 || value.UserID == (identity.EntityID{}) {
			clearFederatedApplyPlanWire(&wire)
			return federatedApplyPlanWire{}, errFederatedAuthPersistence
		}
		return wire, nil
	}
	if value.Subject == nil || value.Mapping == nil || !validFederatedRevision(value.ProviderRevision) ||
		!validFederatedRevision(value.BindingRevision) || !validFederatedRevision(value.ConfigurationRevision) ||
		!validFederatedRevision(value.SecurityRevision) || !validFederatedRevision(value.MappingRevision) ||
		!validFederatedRevision(value.AuthorizationRevision) {
		clearFederatedApplyPlanWire(&wire)
		return federatedApplyPlanWire{}, errFederatedAuthPersistence
	}
	wire.Subject, err = federatedProtectedSubjectToWire(*value.Subject)
	if err == nil {
		wire.Mapping, err = federatedApplyMappingToWire(*value.Mapping)
	}
	if err != nil || !sameFederatedIDStrings(wire.RoleIDs, wire.Mapping.RoleIDs) ||
		!sameFederatedIDStrings(wire.SecurityGroupIDs, wire.Mapping.SecurityGroups) ||
		value.UserID == (identity.EntityID{}) && value.Mapping.IdentityAction() != identity.LDAPIdentityCreateUserAndExternalIdentity ||
		value.UserID != (identity.EntityID{}) && value.Mapping.IdentityAction() != identity.LDAPIdentityNoChange {
		clearFederatedApplyPlanWire(&wire)
		return federatedApplyPlanWire{}, errFederatedAuthPersistence
	}
	return wire, nil
}

func federatedProtectedSubjectToWire(
	value federatedauth.ProtectedFederatedSubject,
) (*federatedProtectedSubjectWire, error) {
	if entityIDWire(value.ExternalIdentityID) == "" || len(value.Aliases) == 0 || len(value.Aliases) > 16 ||
		value.Envelope.KeyVersion < 1 || len(value.Envelope.Nonce) != 12 ||
		len(value.Envelope.Ciphertext) < 17 || len(value.Envelope.Ciphertext) > 16*1024 {
		return nil, errFederatedAuthPersistence
	}
	format, err := federatedSubjectFormatToWire(value.Envelope.Format)
	if err != nil {
		return nil, err
	}
	aliases := make([]federatedApplySubjectAliasWire, len(value.Aliases))
	for index, alias := range value.Aliases {
		if alias.KeyVersion < 1 || !validDigestWire(alias.Digest[:]) ||
			index > 0 && value.Aliases[index-1].KeyVersion >= alias.KeyVersion {
			clearFederatedSubjectAliasesWire(aliases)
			return nil, errFederatedAuthPersistence
		}
		aliases[index] = federatedApplySubjectAliasWire{KeyVersion: alias.KeyVersion, Digest: append([]byte(nil), alias.Digest[:]...)}
	}
	return &federatedProtectedSubjectWire{
		ExternalIdentityID: entityIDWire(value.ExternalIdentityID), Aliases: aliases,
		Envelope: federatedSubjectEnvelopeWire{
			KeyVersion: value.Envelope.KeyVersion, Format: format,
			Nonce:      append([]byte(nil), value.Envelope.Nonce[:]...),
			Ciphertext: append([]byte(nil), value.Envelope.Ciphertext...),
		},
	}, nil
}

func federatedApplyMappingToWire(value identity.FederatedMappingPlan) (*federatedApplyMappingWire, error) {
	if value.Disposition() != identity.LDAPPlanAdmitted {
		return nil, errFederatedAuthPersistence
	}
	reason, err := federatedMappingReasonToWire(value.Reason())
	identityAction, identityErr := federatedIdentityActionToWire(value.IdentityAction())
	accessAction, accessErr := federatedAccessActionToWire(value.ProviderAccessAction())
	matched, matchedErr := federatedEntityIDsToWire(value.MatchedRuleIDs(), 2000)
	groups, groupErr := federatedEntityIDsToWire(value.ProspectiveSecurityGroupIDs(), 1024)
	roles, roleErr := federatedEntityIDsToWire(value.ProspectiveRoleIDs(), 1024)
	if err != nil || identityErr != nil || accessErr != nil || matchedErr != nil || groupErr != nil || roleErr != nil {
		return nil, errFederatedAuthPersistence
	}
	teams := value.ProspectiveOperatorTeamAssignments()
	if len(teams) > 1024 {
		return nil, errFederatedAuthPersistence
	}
	teamWire := make([]federatedApplyTeamWire, len(teams))
	for index, team := range teams {
		if entityIDWire(team.TeamID) == "" || entityIDWire(team.AssignmentEpochID) == "" {
			return nil, errFederatedAuthPersistence
		}
		teamWire[index] = federatedApplyTeamWire{TeamID: entityIDWire(team.TeamID), AssignmentEpochID: entityIDWire(team.AssignmentEpochID)}
	}
	changes := value.Changes()
	if len(changes) > 10_000 {
		return nil, errFederatedAuthPersistence
	}
	changeWire := make([]federatedApplyChangeWire, len(changes))
	for index, change := range changes {
		operation, operationErr := federatedChangeOperationToWire(change.Operation)
		kind, kindErr := federatedEdgeKindToWire(change.Key.Kind)
		if operationErr != nil || kindErr != nil || entityIDWire(change.SourceID) == "" ||
			entityIDWire(change.RuleEpochID) == "" || entityIDWire(change.Key.PrimaryID) == "" ||
			(change.Key.Kind == identity.LDAPSecurityGroupMembershipEdge) != (change.Key.SecondaryID == (identity.EntityID{})) ||
			change.Key.SecondaryID != (identity.EntityID{}) && entityIDWire(change.Key.SecondaryID) == "" {
			return nil, errFederatedAuthPersistence
		}
		changeWire[index] = federatedApplyChangeWire{
			Operation: operation, SourceID: entityIDWire(change.SourceID), RuleEpochID: entityIDWire(change.RuleEpochID),
			Kind: kind, PrimaryID: entityIDWire(change.Key.PrimaryID), SecondaryID: entityIDWire(change.Key.SecondaryID),
		}
	}
	profile, err := federatedProfileToWire(value)
	if err != nil {
		clearFederatedApplyProfileWire(profile)
		return nil, err
	}
	return &federatedApplyMappingWire{
		Disposition: "admitted", Reason: reason, IdentityAction: identityAction, AccessAction: accessAction,
		MatchedRuleIDs: matched, SecurityGroups: groups, RoleIDs: roles,
		Teams: teamWire, Changes: changeWire, Profile: profile,
	}, nil
}

func federatedProfileToWire(value identity.FederatedMappingPlan) ([]federatedApplyProfileWire, error) {
	fields := []struct {
		field identity.LDAPProfileField
		name  string
	}{
		{identity.LDAPProfileFirstName, "first_name"},
		{identity.LDAPProfileLastName, "last_name"},
		{identity.LDAPProfileDisplayName, "display_name"},
		{identity.LDAPProfileUsername, "username"},
		{identity.LDAPProfileAlternateUsername, "alternate_username"},
		{identity.LDAPProfileEmail, "email"},
	}
	result := make([]federatedApplyProfileWire, len(fields))
	for index, field := range fields {
		profileValue, present, err := value.RevealProfileField(field.field)
		if err != nil || present && !validFederatedProfileValue(profileValue, field.field) {
			clearFederatedApplyProfileWire(result)
			return nil, errFederatedAuthPersistence
		}
		result[index] = federatedApplyProfileWire{Field: field.name, Present: present, Value: profileValue}
	}
	return result, nil
}

func federatedApplySessionReservationToWire(value mfa.SessionReservation) *federatedSessionReservationWire {
	tokenDigest := value.TokenDigest()
	csrfDigest := value.CSRFDigest()
	return &federatedSessionReservationWire{
		SessionID: entityIDWire(value.SessionID()), FamilyID: entityIDWire(value.FamilyID()),
		TokenDigest:          append([]byte(nil), tokenDigest[:]...),
		CSRFDigest:           append([]byte(nil), csrfDigest[:]...),
		AuthenticationMethod: string(value.AuthenticationMethod()),
		IdleExpiresAt:        value.IdleExpiresAt(), AbsoluteExpiresAt: value.AbsoluteExpiresAt(),
	}
}

func continuationReservationToWire(
	value federatedauth.PostPrimaryContinuationReservation,
) *federatedContinuationWire {
	digest := value.ReceiptDigest()
	return &federatedContinuationWire{
		ContinuationID: entityIDWire(value.ContinuationID()), ReceiptDigest: append([]byte(nil), digest[:]...),
		ExpiresAt: value.ExpiresAt(),
	}
}

func federatedApplyResultFromWire(
	wire federatedApplyResultWire,
	command federatedApplyCommandWire,
) (federatedauth.ApplyResult, error) {
	request := command.Apply
	if !bytesEqualFederated(wire.OperationDigest, command.OperationDigest) ||
		wire.Protocol != request.Authentication.Protocol || wire.TenantID != request.Authentication.TenantID ||
		wire.Disposition != request.Disposition {
		return federatedauth.ApplyResult{}, errFederatedAuthPersistence
	}
	category := federatedauth.ApplyCategory(wire.Category)
	if category != federatedauth.ApplySuccess {
		if category != federatedauth.ApplyStale && category != federatedauth.ApplyCollision &&
			category != federatedauth.ApplyReplay && category != federatedauth.ApplyDenied ||
			wire.Replayed || wire.UserID != "" || wire.SessionID != "" || wire.ContinuationID != "" || wire.ReturnPath != "" {
			return federatedauth.ApplyResult{}, errFederatedAuthPersistence
		}
		return federatedauth.ApplyResult{Category: category}, nil
	}
	userID, err := parseEntityIDWire(wire.UserID, false)
	if err != nil || request.Plan.UserID != "" && wire.UserID != request.Plan.UserID ||
		wire.ReturnPath != federatedApplyReturnPath(request.Authentication) {
		return federatedauth.ApplyResult{}, errFederatedAuthPersistence
	}
	result := federatedauth.ApplyResult{
		Category: category, UserID: userID, ReturnPath: wire.ReturnPath, Replayed: wire.Replayed,
	}
	switch federatedauth.ApplyDisposition(request.Disposition) {
	case federatedauth.ApplySession:
		if request.Session == nil || wire.SessionID != request.Session.SessionID || wire.ContinuationID != "" {
			return federatedauth.ApplyResult{}, errFederatedAuthPersistence
		}
		result.SessionID, err = parseEntityIDWire(wire.SessionID, false)
	case federatedauth.ApplyContinuation:
		if request.Continuation == nil || wire.ContinuationID != request.Continuation.ContinuationID || wire.SessionID != "" {
			return federatedauth.ApplyResult{}, errFederatedAuthPersistence
		}
		result.ContinuationID, err = parseEntityIDWire(wire.ContinuationID, false)
	default:
		err = errFederatedAuthPersistence
	}
	if err != nil {
		return federatedauth.ApplyResult{}, errFederatedAuthPersistence
	}
	return result, nil
}

func validFederatedApplyDecision(disposition federatedauth.ApplyDisposition, decision identity.AssuranceDecision) bool {
	return disposition == federatedauth.ApplySession && decision == identity.AssuranceSatisfied ||
		disposition == federatedauth.ApplyContinuation &&
			(decision == identity.AssuranceStepUpRequired || decision == identity.AssuranceEnrollmentOnly)
}

func validFederatedApplyProtocolMethod(protocol federatedauth.Protocol, method federatedauth.AuthenticationMethod) bool {
	return protocol == federatedauth.ProtocolOIDC && method == federatedauth.AuthenticationMethodOIDC ||
		protocol == federatedauth.ProtocolSAML && method == federatedauth.AuthenticationMethodSAML ||
		protocol == federatedauth.ProtocolPasskey && method == federatedauth.AuthenticationMethodPasskey
}

func validFederatedApplyPlanPins(plan federatedApplyPlanWire, authentication federatedApplyAuthenticationWire) bool {
	if plan.TenantID != authentication.TenantID {
		return false
	}
	switch federatedauth.Protocol(authentication.Protocol) {
	case federatedauth.ProtocolOIDC:
		if authentication.OIDC == nil {
			return false
		}
		pins := authentication.OIDC.Pins
		if pins.Provider.Scope == federatedPlatformProviderScopeWire {
			if authentication.Admission == nil || pins.Admission == nil ||
				*authentication.Admission != *pins.Admission || !validPlatformApplyPlanWire(plan) {
				return false
			}
		} else if pins.Provider.Scope != federatedTenantProviderScopeWire || authentication.Admission != nil || pins.Admission != nil {
			return false
		}
		return plan.ProviderRevision == pins.ProviderRevision && plan.BindingRevision == pins.BindingRevision &&
			plan.ConfigurationRevision == pins.ConfigurationRevision && plan.SecurityRevision == pins.SecurityRevision &&
			plan.MappingRevision == pins.MappingRevision && plan.AuthorizationRevision == pins.AuthorizationRevision &&
			plan.PolicyRevision == pins.AssurancePolicyRevision
	case federatedauth.ProtocolSAML:
		if authentication.SAML == nil {
			return false
		}
		pins := authentication.SAML.Pins
		return plan.ProviderRevision == pins.ProviderRevision && plan.BindingRevision == pins.BindingRevision &&
			plan.ConfigurationRevision == pins.ConfigurationRevision && plan.SecurityRevision == pins.SecurityRevision &&
			plan.MappingRevision == pins.MappingRevision && plan.AuthorizationRevision == pins.AuthorizationRevision &&
			plan.PolicyRevision == pins.AssurancePolicyRevision
	case federatedauth.ProtocolPasskey:
		return authentication.Passkey != nil && plan.UserID == authentication.Passkey.UserID &&
			plan.IdentityEpoch == authentication.Passkey.IdentityEpoch
	default:
		return false
	}
}

func validFederatedApplyEvidence(value federatedauth.ApplyAuthenticationProjection) bool {
	for _, evidence := range value.Evidence {
		switch value.Protocol {
		case federatedauth.ProtocolOIDC:
			if value.OIDCCompletion == nil {
				return false
			}
			pins := value.OIDCCompletion.Pins
			admission, validAdmission := pins.TenantAdmission()
			if evidence.Source.Local || evidence.Source.ProviderID != pins.Provider.ProviderID ||
				!validAdmission || evidence.Source.BindingID != admission.BindingID || evidence.FactorRevision != nil ||
				evidence.TrustRuleRevision == nil {
				return false
			}
		case federatedauth.ProtocolSAML:
			if value.SAMLConsumption == nil {
				return false
			}
			pins := value.SAMLConsumption.Pins
			if evidence.Source.Local || evidence.Source.ProviderID != pins.Provider.ProviderID ||
				evidence.Source.BindingID != pins.BindingID || evidence.FactorRevision != nil ||
				evidence.TrustRuleRevision == nil {
				return false
			}
		case federatedauth.ProtocolPasskey:
			if !evidence.Source.Local || evidence.Source.ProviderID != (identity.EntityID{}) ||
				evidence.Source.BindingID != (identity.EntityID{}) || evidence.FactorRevision == nil ||
				evidence.TrustRuleRevision != nil || value.Passkey == nil ||
				!sameFederatedAssuranceEvidence(evidence, value.Passkey.Evidence) {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func validPlatformApplyPlanWire(plan federatedApplyPlanWire) bool {
	if len(plan.RoleIDs) != 0 || len(plan.SecurityGroupIDs) != 0 || plan.Mapping == nil {
		return false
	}
	mapping := plan.Mapping
	return mapping.Reason == "provider_access_only" && mapping.Disposition == "admitted" &&
		(mapping.AccessAction == "ensure" || mapping.AccessAction == "no_change") &&
		(mapping.IdentityAction == "no_change" || mapping.IdentityAction == "create_user_and_external_identity") &&
		len(mapping.MatchedRuleIDs) == 0 && len(mapping.SecurityGroups) == 0 &&
		len(mapping.RoleIDs) == 0 && len(mapping.Teams) == 0 && len(mapping.Changes) == 0 &&
		len(mapping.Profile) <= 6
}

func sameFederatedAssuranceEvidence(left, right identity.AssuranceEvidence) bool {
	return left.Level == right.Level && left.Kind == right.Kind && left.Source == right.Source &&
		left.AuthenticatedAt.Equal(right.AuthenticatedAt) && sameFederatedOptionalTime(left.ExpiresAt, right.ExpiresAt) &&
		sameFederatedOptionalInt64(left.FactorRevision, right.FactorRevision) &&
		sameFederatedOptionalInt64(left.TrustRuleRevision, right.TrustRuleRevision)
}

func sameFederatedOptionalTime(left, right *time.Time) bool {
	return left == nil && right == nil || left != nil && right != nil && left.Equal(*right)
}

func sameFederatedOptionalInt64(left, right *int64) bool {
	return left == nil && right == nil || left != nil && right != nil && *left == *right
}

func federatedEntityIDsToWire(values []identity.EntityID, maximum int) ([]string, error) {
	if len(values) > maximum {
		return nil, errFederatedAuthPersistence
	}
	result := make([]string, len(values))
	seen := make(map[identity.EntityID]struct{}, len(values))
	for index, value := range values {
		if entityIDWire(value) == "" {
			return nil, errFederatedAuthPersistence
		}
		if _, duplicate := seen[value]; duplicate {
			return nil, errFederatedAuthPersistence
		}
		seen[value] = struct{}{}
		result[index] = entityIDWire(value)
	}
	return result, nil
}

func sameFederatedIDStrings(left, right []string) bool {
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

func federatedSubjectFormatToWire(value identity.SubjectFormat) (string, error) {
	switch value {
	case identity.ADObjectGUIDSubject:
		return "ad_object_guid", nil
	case identity.EntryUUIDSubject:
		return "entry_uuid", nil
	case identity.UTF8ExactSubject:
		return "utf8_exact", nil
	case identity.UTF8CaseFoldSubject:
		return "utf8_case_fold", nil
	default:
		return "", errFederatedAuthPersistence
	}
}

func federatedMappingReasonToWire(value identity.LDAPPlanReason) (string, error) {
	switch value {
	case identity.LDAPPlanReasonMapped, identity.LDAPPlanReasonProviderAccessOnly:
		return string(value), nil
	default:
		return "", errFederatedAuthPersistence
	}
}

func federatedIdentityActionToWire(value identity.LDAPIdentityPlanAction) (string, error) {
	switch value {
	case identity.LDAPIdentityNoChange:
		return "no_change", nil
	case identity.LDAPIdentityCreateUserAndExternalIdentity:
		return "create_user_and_external_identity", nil
	default:
		return "", errFederatedAuthPersistence
	}
}

func federatedAccessActionToWire(value identity.LDAPProviderAccessPlanAction) (string, error) {
	switch value {
	case identity.LDAPProviderAccessNoChange:
		return "no_change", nil
	case identity.LDAPProviderAccessEnsure:
		return "ensure", nil
	case identity.LDAPProviderAccessSuspend:
		return "suspend", nil
	default:
		return "", errFederatedAuthPersistence
	}
}

func federatedChangeOperationToWire(value identity.LDAPMappingChangeOperation) (string, error) {
	switch value {
	case identity.LDAPMappingEnsure:
		return "ensure", nil
	case identity.LDAPMappingRefresh:
		return "refresh", nil
	case identity.LDAPMappingRevoke:
		return "revoke", nil
	default:
		return "", errFederatedAuthPersistence
	}
}

func federatedEdgeKindToWire(value identity.LDAPMappingEdgeKind) (string, error) {
	switch value {
	case identity.LDAPSecurityGroupMembershipEdge:
		return "security_group_membership", nil
	case identity.LDAPSecurityGroupRoleGrantEdge:
		return "security_group_role_grant", nil
	case identity.LDAPOperatorTeamRosterEdge:
		return "operator_team_roster", nil
	default:
		return "", errFederatedAuthPersistence
	}
}

func validFederatedReturnPath(value string) bool {
	if value == "" || len(value) > 2048 || !utf8.ValidString(value) || !strings.HasPrefix(value, "/") ||
		strings.HasPrefix(value, "//") || strings.ContainsRune(value, '\\') {
		return false
	}
	parsed, err := url.ParseRequestURI(value)
	if err != nil || parsed.IsAbs() || parsed.Host != "" || parsed.Fragment != "" || parsed.RawPath != "" ||
		parsed.Path == "" || strings.Contains(parsed.Path, "//") || path.Clean(parsed.Path) != parsed.Path ||
		parsed.String() != value {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func validFederatedPublicText(value string, maximum int) bool {
	if value == "" || len(value) > maximum || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func validFederatedProfileValue(value string, field identity.LDAPProfileField) bool {
	maximum := 4096
	if field == identity.LDAPProfileEmail {
		maximum = 1280
	}
	if len(value) > maximum || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func federatedApplyReturnPath(value federatedApplyAuthenticationWire) string {
	if value.OIDC != nil {
		return value.OIDC.ReturnPath
	}
	if value.SAML != nil {
		return value.SAML.ReturnPath
	}
	return ""
}

func clearFederatedApplyCommandWire(value *federatedApplyCommandWire) {
	if value == nil {
		return
	}
	clear(value.OperationDigest)
	clearFederatedApplyRequestWire(&value.Apply)
	*value = federatedApplyCommandWire{}
}

func clearFederatedApplyRequestWire(value *federatedApplyRequestWire) {
	if value == nil {
		return
	}
	clearFederatedApplyAuthenticationWire(&value.Authentication)
	clearFederatedApplyPlanWire(&value.Plan)
	if value.Session != nil {
		clear(value.Session.TokenDigest)
		clear(value.Session.CSRFDigest)
	}
	if value.Continuation != nil {
		clear(value.Continuation.ReceiptDigest)
	}
	if value.SAMLSession != nil {
		clear(value.SAMLSession.Ciphertext)
	}
	clearFederatedOIDCSessionMaterialWire(value.OIDCSession)
	*value = federatedApplyRequestWire{}
}

func clearFederatedOIDCSessionMaterialWire(value *federatedOIDCSessionMaterialWire) {
	if value == nil {
		return
	}
	if value.IDToken != nil {
		clear(value.IDToken.Ciphertext)
		clear(value.IDToken.Digest)
	}
	if value.RefreshToken != nil {
		clear(value.RefreshToken.Ciphertext)
		clear(value.RefreshToken.Digest)
	}
	*value = federatedOIDCSessionMaterialWire{}
}

func clearFederatedApplyAuthenticationWire(value *federatedApplyAuthenticationWire) {
	if value == nil {
		return
	}
	if value.OIDC != nil {
		clear(value.OIDC.TransactionID)
		clear(value.OIDC.Pins.DiscoveryDigest)
		clear(value.OIDC.Pins.JWKSDigest)
	}
	if value.SAML != nil {
		clear(value.SAML.TransactionID)
		clear(value.SAML.SessionIndexDigest)
		clear(value.SAML.Pins.MetadataDigest)
		clear(value.SAML.Pins.ConfigurationDigest)
	}
	if value.Passkey != nil {
		clear(value.Passkey.CredentialDigest)
	}
	*value = federatedApplyAuthenticationWire{}
}

func clearFederatedApplyPlanWire(value *federatedApplyPlanWire) {
	if value == nil {
		return
	}
	if value.Subject != nil {
		clearFederatedSubjectAliasesWire(value.Subject.Aliases)
		clear(value.Subject.Envelope.Nonce)
		clear(value.Subject.Envelope.Ciphertext)
	}
	if value.Mapping != nil {
		clearFederatedApplyProfileWire(value.Mapping.Profile)
	}
	*value = federatedApplyPlanWire{}
}

func clearFederatedSubjectAliasesWire(values []federatedApplySubjectAliasWire) {
	for index := range values {
		clear(values[index].Digest)
	}
}

func clearFederatedApplyProfileWire(values []federatedApplyProfileWire) {
	for index := range values {
		values[index].Value = ""
	}
}
