package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/ldapclient"
	"github.com/periapsis-im/periapsis/services/api/internal/identityprovider"
	"github.com/periapsis-im/periapsis/services/api/internal/platformldapauth"
	"github.com/periapsis-im/periapsis/services/api/internal/platformoidcauth"
)

const (
	beginPlatformLDAPAuthenticationSQL = `select app.begin_platform_ldap_authentication_v1($1::jsonb)`
	loadPlatformLDAPMFASQL             = `select app.load_platform_ldap_mfa_v1($1::jsonb)`
	failPlatformLDAPAuthenticationSQL  = `select app.fail_platform_ldap_authentication_v1($1::jsonb)`
	applyPlatformLDAPAuthenticationSQL = `select app.apply_platform_ldap_authentication_v1($1::jsonb)`
	revalidatePlatformLDAPSessionSQL   = `select app.revalidate_platform_ldap_session_v1($1,$2,$3)`

	maximumPlatformLDAPAuthenticationWireBytes = 256 * 1024
)

type platformLDAPAuditWire struct {
	EventID              uuid.UUID `json:"eventId"`
	RequestID            uuid.UUID `json:"requestId"`
	CorrelationID        uuid.UUID `json:"correlationId"`
	IPAddress            string    `json:"ipAddress"`
	UserAgent            string    `json:"userAgent"`
	AuthenticationMethod string    `json:"authenticationMethod"`
}

type platformLDAPBeginRequestWire struct {
	RunID              uuid.UUID             `json:"runId"`
	ProviderKey        string                `json:"providerKey"`
	ReceiptDigest      string                `json:"receiptDigest"`
	NetworkRateDigest  string                `json:"networkRateDigest"`
	AccountRateDigest  string                `json:"accountRateDigest"`
	ProviderRateDigest string                `json:"providerRateDigest"`
	Audit              platformLDAPAuditWire `json:"audit"`
}

type platformLDAPBindSecretWire struct {
	ID         uuid.UUID `json:"id"`
	Revision   int64     `json:"revision"`
	KeyVersion int16     `json:"keyVersion"`
	Nonce      string    `json:"nonce"`
	Ciphertext string    `json:"ciphertext"`
}

type platformLDAPNetworkSnapshotWire struct {
	RunID                 uuid.UUID                        `json:"runId"`
	State                 platformldapauth.RunState        `json:"state"`
	Allowed               bool                             `json:"allowed"`
	FailureCategory       platformldapauth.FailureCategory `json:"failureCategory"`
	ProviderID            uuid.UUID                        `json:"providerId"`
	ProviderVersion       int64                            `json:"providerVersion"`
	ConfigurationRevision int64                            `json:"configurationRevision"`
	SecurityRevision      int64                            `json:"securityRevision"`
	MappingRevision       int64                            `json:"mappingRevision"`
	Configuration         identityprovider.Configuration   `json:"configuration"`
	Endpoints             []platformLDAPEndpointWire       `json:"endpoints"`
	BindSecret            platformLDAPBindSecretWire       `json:"bindSecret"`
	SessionID             *uuid.UUID                       `json:"sessionId"`
	UserID                *uuid.UUID                       `json:"userId"`
	CompletedAt           *time.Time                       `json:"completedAt"`
}

type platformLDAPMFARequestWire struct {
	RunID                 uuid.UUID `json:"runId"`
	ProviderID            uuid.UUID `json:"providerId"`
	ProviderVersion       int64     `json:"providerVersion"`
	ConfigurationRevision int64     `json:"configurationRevision"`
	SecurityRevision      int64     `json:"securityRevision"`
	MappingRevision       int64     `json:"mappingRevision"`
	ExternalIdentityID    uuid.UUID `json:"externalIdentityId"`
	SubjectDigest         string    `json:"subjectDigest"`
	SubjectKeyVersion     int16     `json:"subjectKeyVersion"`
	Email                 *string   `json:"email"`
}

type platformLDAPTOTPCredentialWire struct {
	ID                  uuid.UUID `json:"id"`
	SecurityRevision    uint64    `json:"securityRevision"`
	KeyVersion          int16     `json:"keyVersion"`
	EncryptionAlgorithm string    `json:"encryptionAlgorithm"`
	OTPAlgorithm        string    `json:"otpAlgorithm"`
	Digits              uint8     `json:"digits"`
	PeriodSeconds       uint16    `json:"periodSeconds"`
	SecretCiphertext    string    `json:"secretCiphertext"`
	SecretNonce         string    `json:"secretNonce"`
	SecretAAD           string    `json:"secretAad"`
	LastAcceptedCounter *int64    `json:"lastAcceptedCounter"`
}

type platformLDAPMappingWireV1 struct {
	ID                 uuid.UUID                           `json:"id"`
	MatcherType        platformldapauth.MappingMatcherType `json:"matcherType"`
	MatcherValue       string                              `json:"matcherValue"`
	CaseSensitive      bool                                `json:"caseSensitive"`
	Priority           int                                 `json:"priority"`
	PlatformRoleID     uuid.UUID                           `json:"platformRoleId"`
	PlatformRoleKey    string                              `json:"platformRoleKey"`
	ReconciliationMode platformldapauth.ReconciliationMode `json:"reconciliationMode"`
}

type platformLDAPMFASnapshotWire struct {
	RunID                      uuid.UUID                      `json:"runId"`
	UserID                     uuid.UUID                      `json:"userId"`
	UserAuthenticationRevision uint64                         `json:"userAuthenticationRevision"`
	ExternalIdentityID         uuid.UUID                      `json:"externalIdentityId"`
	IdentityVersion            int64                          `json:"identityVersion"`
	TOTPCredential             platformLDAPTOTPCredentialWire `json:"totpCredential"`
	Mappings                   []platformLDAPMappingWireV1    `json:"mappings"`
}

type platformLDAPApplyRequestWire struct {
	RunID                      uuid.UUID             `json:"runId"`
	ProviderID                 uuid.UUID             `json:"providerId"`
	ProviderVersion            int64                 `json:"providerVersion"`
	ConfigurationRevision      int64                 `json:"configurationRevision"`
	SecurityRevision           int64                 `json:"securityRevision"`
	MappingRevision            int64                 `json:"mappingRevision"`
	UserID                     uuid.UUID             `json:"userId"`
	UserAuthenticationRevision uint64                `json:"userAuthenticationRevision"`
	ExternalIdentityID         uuid.UUID             `json:"externalIdentityId"`
	IdentityVersion            int64                 `json:"identityVersion"`
	SubjectKeyVersion          int16                 `json:"subjectKeyVersion"`
	SubjectDigest              string                `json:"subjectDigest"`
	SubjectCiphertext          string                `json:"subjectCiphertext"`
	SubjectNonce               string                `json:"subjectNonce"`
	Username                   string                `json:"username"`
	Email                      *string               `json:"email"`
	DisplayName                string                `json:"displayName"`
	FirstName                  *string               `json:"firstName"`
	LastName                   *string               `json:"lastName"`
	GroupsDigest               string                `json:"groupsDigest"`
	SelectedMappingIDs         []uuid.UUID           `json:"selectedMappingIds"`
	TOTPCredentialID           uuid.UUID             `json:"totpCredentialId"`
	TOTPSecurityRevision       uint64                `json:"totpSecurityRevision"`
	TOTPCounter                int64                 `json:"totpCounter"`
	SessionID                  uuid.UUID             `json:"sessionId"`
	RotationFamilyID           uuid.UUID             `json:"rotationFamilyId"`
	TokenDigest                string                `json:"tokenDigest"`
	CSRFDigest                 string                `json:"csrfDigest"`
	IdleExpiresAt              time.Time             `json:"idleExpiresAt"`
	AbsoluteExpiresAt          time.Time             `json:"absoluteExpiresAt"`
	CompletedAt                time.Time             `json:"completedAt"`
	ResultDigest               string                `json:"resultDigest"`
	Audit                      platformLDAPAuditWire `json:"audit"`
}

type platformLDAPApplyResultWire struct {
	RunID     uuid.UUID                 `json:"runId"`
	State     platformldapauth.RunState `json:"state"`
	SessionID uuid.UUID                 `json:"sessionId"`
	UserID    uuid.UUID                 `json:"userId"`
	Replayed  bool                      `json:"replayed"`
}

type platformLDAPFailureRequestWire struct {
	RunID    uuid.UUID                        `json:"runId"`
	Category platformldapauth.FailureCategory `json:"category"`
	Audit    platformLDAPAuditWire            `json:"audit"`
}

type platformLDAPFailureResultWire struct {
	RunID    uuid.UUID                        `json:"runId"`
	State    platformldapauth.RunState        `json:"state"`
	Category platformldapauth.FailureCategory `json:"category"`
}

type PlatformLDAPSessionAuthorityResult struct {
	SessionID        uuid.UUID `json:"sessionId"`
	UserID           uuid.UUID `json:"userId"`
	Allowed          bool      `json:"allowed"`
	IdleTouchAllowed bool      `json:"idleTouchAllowed"`
}

var _ platformldapauth.Repository = (*FederatedAuthRepository)(nil)

func (repository *FederatedAuthRepository) Begin(
	ctx context.Context,
	request platformldapauth.BeginRequest,
) (platformldapauth.NetworkSnapshot, error) {
	wire := platformLDAPBeginRequestWire{
		RunID: request.RunID, ProviderKey: request.ProviderKey,
		ReceiptDigest:      hex.EncodeToString(request.ReceiptDigest[:]),
		NetworkRateDigest:  hex.EncodeToString(request.NetworkRateDigest[:]),
		AccountRateDigest:  hex.EncodeToString(request.AccountRateDigest[:]),
		ProviderRateDigest: hex.EncodeToString(request.ProviderRateDigest[:]),
		Audit:              platformLDAPAuditToWire(request.Audit),
	}
	var response platformLDAPNetworkSnapshotWire
	if err := repository.queryPlatformLDAPJSON(ctx, beginPlatformLDAPAuthenticationSQL, wire, &response); err != nil {
		return platformldapauth.NetworkSnapshot{}, err
	}
	return platformLDAPNetworkSnapshotFromWire(response)
}

func (repository *FederatedAuthRepository) LoadMFA(
	ctx context.Context,
	request platformldapauth.LoadMFARequest,
) (platformldapauth.MFASnapshot, error) {
	wire := platformLDAPMFARequestWire{
		RunID: request.RunID, ProviderID: request.ProviderID, ProviderVersion: request.ProviderVersion,
		ConfigurationRevision: request.ConfigurationRevision,
		SecurityRevision:      request.SecurityRevision, MappingRevision: request.MappingRevision,
		ExternalIdentityID: request.ExternalIdentityID,
		SubjectDigest:      hex.EncodeToString(request.SubjectDigest[:]),
		SubjectKeyVersion:  request.SubjectKeyVersion, Email: request.Email,
	}
	var response platformLDAPMFASnapshotWire
	if err := repository.queryPlatformLDAPJSON(ctx, loadPlatformLDAPMFASQL, wire, &response); err != nil {
		return platformldapauth.MFASnapshot{}, err
	}
	return platformLDAPMFASnapshotFromWire(response)
}

func (repository *FederatedAuthRepository) Apply(
	ctx context.Context,
	request platformldapauth.ApplyRequest,
) (platformldapauth.ApplyResult, error) {
	if request.Session == nil {
		return platformldapauth.ApplyResult{}, platformldapauth.ErrInvalidInput
	}
	session := request.Session.Session()
	tokenDigest := session.TokenDigest()
	csrfDigest := session.CSRFDigest()
	wire := platformLDAPApplyRequestWire{
		RunID: request.RunID, ProviderID: request.ProviderID, ProviderVersion: request.ProviderVersion,
		ConfigurationRevision: request.ConfigurationRevision,
		SecurityRevision:      request.SecurityRevision, MappingRevision: request.MappingRevision,
		UserID: request.UserID, UserAuthenticationRevision: request.UserAuthenticationRevision,
		ExternalIdentityID: request.ExternalIdentityID, IdentityVersion: request.IdentityVersion,
		SubjectKeyVersion: request.SubjectAlias.KeyVersion,
		SubjectDigest:     hex.EncodeToString(request.SubjectAlias.Digest[:]),
		SubjectCiphertext: hex.EncodeToString(request.SubjectEnvelope.Ciphertext),
		SubjectNonce:      hex.EncodeToString(request.SubjectEnvelope.Nonce[:]),
		Username:          request.Profile.Username, Email: request.Profile.Email,
		DisplayName: request.Profile.DisplayName, FirstName: request.Profile.FirstName,
		LastName:           request.Profile.LastName,
		GroupsDigest:       hex.EncodeToString(request.GroupsDigest[:]),
		SelectedMappingIDs: append([]uuid.UUID(nil), request.SelectedMappingIDs...),
		TOTPCredentialID:   request.TOTPFactorID, TOTPSecurityRevision: request.TOTPSecurityRevision,
		TOTPCounter: request.TOTPCounter, SessionID: uuid.UUID(session.SessionID()),
		RotationFamilyID: uuid.UUID(session.FamilyID()),
		TokenDigest:      hex.EncodeToString(tokenDigest[:]), CSRFDigest: hex.EncodeToString(csrfDigest[:]),
		IdleExpiresAt: session.IdleExpiresAt(), AbsoluteExpiresAt: session.AbsoluteExpiresAt(),
		CompletedAt: request.CompletedAt, ResultDigest: hex.EncodeToString(request.ResultDigest[:]),
		Audit: platformLDAPAuditToWire(request.Audit),
	}
	var response platformLDAPApplyResultWire
	if err := repository.queryPlatformLDAPJSON(ctx, applyPlatformLDAPAuthenticationSQL, wire, &response); err != nil {
		return platformldapauth.ApplyResult{}, err
	}
	return platformldapauth.ApplyResult{
		RunID: response.RunID, State: response.State,
		SessionID: identity.EntityID(response.SessionID), UserID: response.UserID,
		Replayed: response.Replayed,
	}, nil
}

func (repository *FederatedAuthRepository) Fail(
	ctx context.Context,
	request platformldapauth.FailureRequest,
) error {
	wire := platformLDAPFailureRequestWire{
		RunID: request.RunID, Category: request.Category,
		Audit: platformLDAPAuditToWire(request.Audit),
	}
	var response platformLDAPFailureResultWire
	if err := repository.queryPlatformLDAPJSON(ctx, failPlatformLDAPAuthenticationSQL, wire, &response); err != nil {
		return err
	}
	if response.RunID != request.RunID || response.State == platformldapauth.RunPending {
		return platformldapauth.ErrUnavailable
	}
	return nil
}

// RevalidatePlatformLDAPSession is the tenantless session authority consumed
// by the authentication dispatcher. Denied rows are already family-revoked by
// the database function before this method returns.
func (repository *FederatedAuthRepository) RevalidatePlatformLDAPSession(
	ctx context.Context,
	sessionID uuid.UUID,
	userID uuid.UUID,
	audience string,
) (PlatformLDAPSessionAuthorityResult, error) {
	if repository == nil || repository.queryer == nil || ctx == nil || ctx.Err() != nil {
		return PlatformLDAPSessionAuthorityResult{}, platformldapauth.ErrUnavailable
	}
	var raw []byte
	if err := repository.queryer.QueryRow(
		ctx, revalidatePlatformLDAPSessionSQL, sessionID, userID, audience,
	).Scan(&raw); err != nil {
		clear(raw)
		return PlatformLDAPSessionAuthorityResult{}, mapPlatformLDAPDatabaseError(err)
	}
	defer clear(raw)
	var result PlatformLDAPSessionAuthorityResult
	if err := decodePlatformLDAPJSON(raw, &result); err != nil ||
		result.SessionID != sessionID || result.UserID != userID {
		return PlatformLDAPSessionAuthorityResult{}, platformldapauth.ErrUnavailable
	}
	return result, nil
}

func (repository *FederatedAuthRepository) queryPlatformLDAPJSON(
	ctx context.Context,
	query string,
	request any,
	response any,
) error {
	if repository == nil || repository.queryer == nil || ctx == nil || ctx.Err() != nil || response == nil {
		return platformldapauth.ErrUnavailable
	}
	payload, err := json.Marshal(request)
	if err != nil || len(payload) == 0 || len(payload) > maximumPlatformLDAPAuthenticationWireBytes {
		clear(payload)
		return platformldapauth.ErrInvalidInput
	}
	defer clear(payload)
	var raw []byte
	if err = repository.queryer.QueryRow(ctx, query, payload).Scan(&raw); err != nil {
		clear(raw)
		return mapPlatformLDAPDatabaseError(err)
	}
	defer clear(raw)
	if ctx.Err() != nil || len(raw) == 0 || len(raw) > maximumPlatformLDAPAuthenticationWireBytes {
		return platformldapauth.ErrUnavailable
	}
	return decodePlatformLDAPJSON(raw, response)
}

func decodePlatformLDAPJSON(raw []byte, response any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(response); err != nil {
		return platformldapauth.ErrUnavailable
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return platformldapauth.ErrUnavailable
	}
	return nil
}

func platformLDAPNetworkSnapshotFromWire(
	wire platformLDAPNetworkSnapshotWire,
) (platformldapauth.NetworkSnapshot, error) {
	result := platformldapauth.NetworkSnapshot{
		RunID: wire.RunID, State: wire.State, Allowed: wire.Allowed,
		FailureCategory: wire.FailureCategory, ProviderID: wire.ProviderID,
		ProviderVersion: wire.ProviderVersion, ConfigurationRevision: wire.ConfigurationRevision,
		SecurityRevision: wire.SecurityRevision, MappingRevision: wire.MappingRevision,
		Configuration: wire.Configuration,
	}
	if wire.SessionID != nil {
		result.SessionID = identity.EntityID(*wire.SessionID)
	}
	if wire.UserID != nil {
		result.UserID = *wire.UserID
	}
	if wire.CompletedAt != nil {
		result.CompletedAt = wire.CompletedAt.UTC()
	}
	if !wire.Allowed {
		return result, nil
	}
	result.Endpoints = make([]identityprovider.Endpoint, len(wire.Endpoints))
	for index, endpoint := range wire.Endpoints {
		result.Endpoints[index] = identityprovider.Endpoint{
			Priority: endpoint.Priority, Host: endpoint.Host, Port: endpoint.Port,
			Transport: ldapclient.Transport(endpoint.Transport), TLSServerName: endpoint.TLSServerName,
			ReferralAllowed: endpoint.ReferralAllowed, Enabled: endpoint.Enabled,
		}
	}
	nonce, err := hex.DecodeString(wire.BindSecret.Nonce)
	if err != nil || len(nonce) != len(result.BindSecret.Nonce) {
		clear(nonce)
		return platformldapauth.NetworkSnapshot{}, platformldapauth.ErrUnavailable
	}
	copy(result.BindSecret.Nonce[:], nonce)
	clear(nonce)
	ciphertext, err := hex.DecodeString(wire.BindSecret.Ciphertext)
	if err != nil {
		clear(ciphertext)
		return platformldapauth.NetworkSnapshot{}, platformldapauth.ErrUnavailable
	}
	result.BindSecretID = wire.BindSecret.ID
	result.BindSecretRevision = wire.BindSecret.Revision
	result.BindSecret.KeyVersion = wire.BindSecret.KeyVersion
	result.BindSecret.Ciphertext = ciphertext
	return result, nil
}

func platformLDAPMFASnapshotFromWire(
	wire platformLDAPMFASnapshotWire,
) (platformldapauth.MFASnapshot, error) {
	ciphertext, err := hex.DecodeString(wire.TOTPCredential.SecretCiphertext)
	if err != nil {
		return platformldapauth.MFASnapshot{}, platformldapauth.ErrUnavailable
	}
	nonce, err := hex.DecodeString(wire.TOTPCredential.SecretNonce)
	if err != nil {
		clear(ciphertext)
		return platformldapauth.MFASnapshot{}, platformldapauth.ErrUnavailable
	}
	aad, err := hex.DecodeString(wire.TOTPCredential.SecretAAD)
	if err != nil {
		clear(ciphertext)
		clear(nonce)
		return platformldapauth.MFASnapshot{}, platformldapauth.ErrUnavailable
	}
	result := platformldapauth.MFASnapshot{
		RunID: wire.RunID, UserID: wire.UserID,
		UserAuthenticationRevision: wire.UserAuthenticationRevision,
		ExternalIdentityID:         wire.ExternalIdentityID, IdentityVersion: wire.IdentityVersion,
		TOTP: platformldapauth.TOTPFactor{
			ID: wire.TOTPCredential.ID, SecurityRevision: wire.TOTPCredential.SecurityRevision,
			Secret: platformoidcauth.DirectProtectedTOTPSecret{
				Ciphertext: ciphertext, Nonce: nonce, AAD: aad,
				KeyVersion:          wire.TOTPCredential.KeyVersion,
				EncryptionAlgorithm: wire.TOTPCredential.EncryptionAlgorithm,
				OTPAlgorithm:        wire.TOTPCredential.OTPAlgorithm,
				Digits:              wire.TOTPCredential.Digits, PeriodSeconds: wire.TOTPCredential.PeriodSeconds,
			},
			LastAcceptedCounter: clonePlatformLDAPCounter(wire.TOTPCredential.LastAcceptedCounter),
		},
		Mappings: make([]platformldapauth.Mapping, len(wire.Mappings)),
	}
	for index, mapping := range wire.Mappings {
		result.Mappings[index] = platformldapauth.Mapping{
			ID: mapping.ID, MatcherType: mapping.MatcherType, MatcherValue: mapping.MatcherValue,
			CaseSensitive: mapping.CaseSensitive, Priority: mapping.Priority,
			PlatformRoleID: mapping.PlatformRoleID, PlatformRoleKey: mapping.PlatformRoleKey,
			ReconciliationMode: mapping.ReconciliationMode,
		}
	}
	return result, nil
}

func platformLDAPAuditToWire(value platformldapauth.AuditMetadata) platformLDAPAuditWire {
	return platformLDAPAuditWire{
		EventID: value.EventID, RequestID: value.RequestID, CorrelationID: value.CorrelationID,
		IPAddress: value.ClientIP.String(), UserAgent: value.UserAgent,
		AuthenticationMethod: value.AuthenticationMethod,
	}
}

func clonePlatformLDAPCounter(value *int64) *int64 {
	if value == nil {
		return nil
	}
	result := *value
	return &result
}

func mapPlatformLDAPDatabaseError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return platformldapauth.ErrUnavailable
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return platformldapauth.ErrAuthentication
	}
	var databaseError *pgconn.PgError
	if !errors.As(err, &databaseError) {
		return platformldapauth.ErrUnavailable
	}
	switch databaseError.Code {
	case "23505":
		return platformldapauth.ErrReplayConflict
	case "40001":
		return platformldapauth.ErrStaleConfiguration
	case "42501", "P0002":
		return platformldapauth.ErrAuthentication
	case "22023", "23514":
		return platformldapauth.ErrInvalidInput
	default:
		return platformldapauth.ErrUnavailable
	}
}

func validPlatformLDAPDigest(value [sha256.Size]byte) bool {
	var combined byte
	for _, item := range value {
		combined |= item
	}
	return combined != 0
}
