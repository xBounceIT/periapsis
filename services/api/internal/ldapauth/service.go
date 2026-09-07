package ldapauth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/ldapclient"
	"github.com/periapsis-im/periapsis/services/api/internal/federatedauth"
	"github.com/periapsis-im/periapsis/services/api/internal/identityprovider"
)

const (
	minimumOperationTimeout = time.Second
	maximumOperationTimeout = 2 * time.Minute
)

type Options struct {
	Repository       Repository
	Directory        DirectoryClient
	Keyring          identity.Keyring
	Credentials      federatedauth.ApplyCredentialIssuer
	RateDigestKey    []byte
	OperationTimeout time.Duration
	Now              func() time.Time
	NewID            func() (uuid.UUID, error)
	Random           io.Reader
}

type Service struct {
	repository       Repository
	directory        DirectoryClient
	keyring          identity.Keyring
	credentials      federatedauth.ApplyCredentialIssuer
	rateDigestKey    [sha256.Size]byte
	operationTimeout time.Duration
	now              func() time.Time
	newID            func() (uuid.UUID, error)
	random           io.Reader
}

func New(options Options) (*Service, error) {
	if options.Repository == nil || options.Directory == nil || options.Credentials == nil ||
		len(options.Keyring.Versions()) == 0 || len(options.RateDigestKey) != sha256.Size ||
		options.OperationTimeout < minimumOperationTimeout || options.OperationTimeout > maximumOperationTimeout ||
		options.OperationTimeout%time.Microsecond != 0 {
		return nil, ErrInvalidInput
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.NewID == nil {
		options.NewID = uuid.NewV7
	}
	if options.Random == nil {
		options.Random = rand.Reader
	}
	service := &Service{
		repository: options.Repository, directory: options.Directory, keyring: options.Keyring,
		credentials: options.Credentials, operationTimeout: options.OperationTimeout,
		now: options.Now, newID: options.NewID, random: options.Random,
	}
	copy(service.rateDigestKey[:], options.RateDigestKey)
	return service, nil
}

// Authenticate takes ownership of command.Password and clears its backing
// bytes before returning on every path, including validation failures.
func (service *Service) Authenticate(ctx context.Context, command Command) (Result, error) {
	defer clear(command.Password)
	if service == nil || ctx == nil || ctx.Err() != nil || !validCommand(command) {
		return Result{}, ErrInvalidInput
	}
	operation, cancel := context.WithTimeout(ctx, service.operationTimeout)
	defer cancel()
	now := service.currentTime()
	ids, err := service.ids(12)
	if err != nil {
		return Result{}, ErrUnavailable
	}
	receipt := make([]byte, sha256.Size)
	if _, err = io.ReadFull(service.random, receipt); err != nil {
		clear(receipt)
		return Result{}, ErrUnavailable
	}
	receiptDigest := sha256.Sum256(receipt)
	clear(receipt)
	rateKeys := service.rateKeys(command)
	snapshot, err := service.repository.Begin(operation, BeginRequest{
		OperationRunID: ids[0], ReceiptDigest: receiptDigest,
		TenantSlug: command.TenantSlug, LoginKey: command.LoginKey,
		NetworkRateKey: rateKeys[0], AccountRateKey: rateKeys[1], ProviderRateKey: rateKeys[2],
		AuditEventID: ids[1], Audit: auditMetadata(command),
	})
	if err != nil {
		return Result{}, mapBeginError(err)
	}
	defer snapshot.Destroy()
	if !validSnapshot(snapshot, ids[0], now) {
		return Result{}, ErrAuthentication
	}

	bindSecret, err := service.keyring.DecryptBindSecret(identity.BindSecretContext{
		Provider: identity.ProviderContext{
			Scope: identity.TenantProviderScope, TenantID: identity.EntityID(snapshot.TenantID),
			ProviderID: identity.EntityID(snapshot.ProviderID),
		},
		SecretID: identity.EntityID(snapshot.SecretID),
	}, snapshot.Secret)
	if err != nil {
		service.fail(operation, snapshot, receiptDigest, ids[2], command, FailureDirectory)
		return Result{}, ErrUnavailable
	}
	request, err := identityprovider.BuildDirectoryAuthenticationRequest(
		snapshot.Configuration, snapshot.Endpoints, command.Username,
	)
	if err != nil {
		clear(bindSecret)
		service.fail(operation, snapshot, receiptDigest, ids[2], command, FailureDirectory)
		return Result{}, ErrUnavailable
	}
	defer identityprovider.ClearDirectoryAuthenticationRequest(&request)
	directoryResult, networkErr := service.directory.AuthenticateDirectory(
		operation, request, bindSecret, command.Password,
	)
	// AuthenticateDirectory owns both secret slices. Clear them again to make
	// that ownership invariant robust to a faulty test double.
	clear(bindSecret)
	clear(command.Password)
	if networkErr != nil || directoryResult.Category != ldapclient.DirectoryCategorySuccess {
		category, publicErr := directoryFailure(directoryResult.Category, networkErr)
		service.fail(operation, snapshot, receiptDigest, ids[2], command, category)
		return Result{}, publicErr
	}
	observedAt := service.currentTime()
	normalization, err := identityprovider.BuildDirectoryNormalizationConfiguration(
		snapshot.Configuration, command.Username,
	)
	if err != nil {
		service.fail(operation, snapshot, receiptDigest, ids[2], command, FailureDirectory)
		return Result{}, ErrUnavailable
	}
	observation, err := ldapclient.NormalizeDirectoryObservation(normalization, directoryResult.Observation)
	if err != nil {
		service.fail(operation, snapshot, receiptDigest, ids[2], command, FailureDirectory)
		return Result{}, ErrUnavailable
	}
	provider := identity.ProviderContext{
		Scope: identity.TenantProviderScope, TenantID: identity.EntityID(snapshot.TenantID),
		ProviderID: identity.EntityID(snapshot.ProviderID),
	}
	aliases, err := observation.SubjectAliases(service.keyring, provider)
	if err != nil {
		service.fail(operation, snapshot, receiptDigest, ids[2], command, FailureDirectory)
		return Result{}, ErrUnavailable
	}
	defer clearAliases(aliases)
	claim, err := service.repository.Claim(operation, ClaimRequest{
		OperationRunID: snapshot.OperationRunID, ReceiptDigest: receiptDigest,
		SubjectAliases: aliases, EvaluatedAt: service.currentTime(),
		AuditEventID: ids[2], Audit: auditMetadata(command),
	})
	if err != nil || !validClaim(claim, snapshot) {
		return Result{}, ErrAuthentication
	}
	plan, err := identity.PlanLDAPMapping(observation, claim.Planning)
	if err != nil || plan.Disposition() != identity.LDAPPlanAdmitted {
		service.fail(operation, snapshot, receiptDigest, ids[8], command, FailurePolicy)
		return Result{}, ErrAuthentication
	}

	externalIdentityID := claim.ExternalIdentityID
	userID := claim.UserID
	membershipID := claim.MembershipID
	accessGrantID := claim.AccessGrantID
	if claim.Planning.ProviderAccess.AccessGrantLive != (accessGrantID != uuid.Nil) {
		return Result{}, ErrAuthentication
	}
	if accessGrantID == uuid.Nil {
		accessGrantID = ids[9]
	}
	if plan.IdentityAction() == identity.LDAPIdentityCreateUserAndExternalIdentity {
		externalIdentityID, userID, membershipID = ids[5], ids[6], ids[7]
	}
	if externalIdentityID == uuid.Nil || userID == uuid.Nil || membershipID == uuid.Nil {
		service.fail(operation, snapshot, receiptDigest, ids[8], command, FailurePolicy)
		return Result{}, ErrAuthentication
	}
	envelope, protectedAliases, err := observation.ProtectSubject(service.keyring, identity.ExternalSubjectContext{
		Provider: provider, ExternalIdentityID: identity.EntityID(externalIdentityID),
	})
	if err != nil {
		return Result{}, ErrUnavailable
	}
	defer clear(envelope.Ciphertext)
	defer clearAliases(protectedAliases)
	aliasIDs, err := service.ids(len(protectedAliases))
	if err != nil {
		return Result{}, ErrUnavailable
	}
	trustRevision := snapshot.BindingAuthRevision
	expiresAt := snapshot.ExpiresAt
	evidence := identity.AssuranceEvidence{
		Level: identity.AssurancePrimary, Kind: identity.AssuranceEvidenceFactor,
		Source: identity.AssuranceSource{
			ProviderID: identity.EntityID(snapshot.ProviderID), BindingID: identity.EntityID(snapshot.BindingID),
		},
		AuthenticatedAt: observedAt, ExpiresAt: &expiresAt, TrustRuleRevision: &trustRevision,
	}
	assurance := identity.EvaluateAssurance(observedAt, claim.Requirement, []identity.AssuranceEvidence{evidence}, claim.HasEnrollableFactor)
	disposition := federatedauth.ApplyContinuation
	if assurance == identity.AssuranceSatisfied {
		disposition = federatedauth.ApplySession
	} else if assurance != identity.AssuranceStepUpRequired && assurance != identity.AssuranceEnrollmentOnly {
		return Result{}, ErrAuthentication
	}
	credential, err := service.credentials.ReserveApplyCredential(federatedauth.ApplyCredentialRequest{
		Disposition: disposition, Method: federatedauth.AuthenticationMethodLDAP, IssuedAt: observedAt,
	})
	if err != nil || credential == nil {
		if credential != nil {
			credential.Destroy()
		}
		return Result{}, ErrUnavailable
	}
	defer credential.Destroy()
	apply := ApplyRequest{
		OperationRunID: snapshot.OperationRunID, ReceiptDigest: receiptDigest,
		ApplicationID: ids[3], AuditEventID: ids[4], AuthorityAuditID: ids[11], Audit: auditMetadata(command),
		ObservedAt: observedAt, ReturnPath: command.ReturnPath,
		ExternalIdentityID: externalIdentityID, UserID: userID, MembershipID: membershipID,
		AccessGrantID: accessGrantID, ProfileContributionID: ids[10], AliasIDs: aliasIDs,
		SubjectFormat: observation.SubjectFormat(), SubjectEnvelope: envelope, SubjectAliases: protectedAliases,
		Planning: claim.Planning, Plan: plan, Assurance: assurance, Evidence: evidence,
	}
	if disposition == federatedauth.ApplySession {
		apply.Session = credential
	} else {
		apply.Continuation = credential
	}
	applied, err := service.repository.Apply(operation, apply)
	if err != nil || !validApplyResult(applied, userID, command.ReturnPath, credential) {
		return Result{}, ErrAuthentication
	}
	browserCredential, ok := credential.ReleaseBrowserCredential(applied.SessionID, applied.ContinuationID)
	if !ok {
		return Result{}, ErrAuthentication
	}
	return Result{
		UserID: applied.UserID, SessionID: applied.SessionID, ContinuationID: applied.ContinuationID,
		ReturnPath: applied.ReturnPath, Credential: browserCredential,
	}, nil
}

func (service *Service) fail(ctx context.Context, snapshot NetworkSnapshot, receipt [sha256.Size]byte, auditID uuid.UUID, command Command, category FailureCategory) {
	_ = service.repository.CompleteFailure(ctx, FailureRequest{
		OperationRunID: snapshot.OperationRunID, ReceiptDigest: receipt, Category: category,
		AuditEventID: auditID, Audit: auditMetadata(command),
	})
}

func (service *Service) currentTime() time.Time {
	return service.now().UTC().Truncate(time.Microsecond)
}

func (service *Service) ids(count int) ([]uuid.UUID, error) {
	result := make([]uuid.UUID, count)
	seen := make(map[uuid.UUID]struct{}, count)
	for index := range result {
		value, err := service.newID()
		if err != nil || value == uuid.Nil || value.Version() != 7 {
			return nil, ErrUnavailable
		}
		if _, duplicate := seen[value]; duplicate {
			return nil, ErrUnavailable
		}
		seen[value] = struct{}{}
		result[index] = value
	}
	return result, nil
}

func (service *Service) rateKeys(command Command) [3][sha256.Size]byte {
	return [3][sha256.Size]byte{
		service.rateKey("network", command.TenantSlug, command.LoginKey, command.ClientIP.String()),
		service.rateKey("account", command.TenantSlug, command.LoginKey, strings.ToLower(command.Username)),
		service.rateKey("provider", command.TenantSlug, command.LoginKey),
	}
}

func (service *Service) rateKey(domain string, values ...string) [sha256.Size]byte {
	mac := hmac.New(sha256.New, service.rateDigestKey[:])
	_, _ = mac.Write([]byte("periapsis/ldap-login-rate/v1\x00" + domain))
	for _, value := range values {
		_, _ = mac.Write([]byte{0})
		_, _ = mac.Write([]byte(value))
	}
	var result [sha256.Size]byte
	copy(result[:], mac.Sum(nil))
	return result
}

func validCommand(command Command) bool {
	if len(command.TenantSlug) < 1 || len(command.TenantSlug) > 63 || strings.ToLower(command.TenantSlug) != command.TenantSlug ||
		len(command.LoginKey) < 3 || len(command.LoginKey) > 64 || strings.ToLower(command.LoginKey) != command.LoginKey ||
		len(command.Username) < 1 || len(command.Username) > 1280 || utf8.RuneCountInString(command.Username) > 320 ||
		len(command.Password) < 1 || len(command.Password) > 1024 || !utf8.Valid(command.Password) ||
		len(command.UserAgent) < 1 || len(command.UserAgent) > 1024 || !utf8.ValidString(command.UserAgent) ||
		!command.ClientIP.IsValid() || command.RequestID == uuid.Nil || command.CorrelationID == uuid.Nil {
		return false
	}
	if _, err := identity.NewLDAPUsername(command.Username); err != nil {
		return false
	}
	return validReturnPath(command.ReturnPath)
}

func validReturnPath(value string) bool {
	if len(value) < 1 || len(value) > 2048 || !utf8.ValidString(value) || !strings.HasPrefix(value, "/") || strings.HasPrefix(value, "//") {
		return false
	}
	parsed, err := url.Parse(value)
	return err == nil && parsed.IsAbs() == false && parsed.Host == "" && parsed.User == nil && parsed.Fragment == ""
}

func validSnapshot(snapshot NetworkSnapshot, runID uuid.UUID, now time.Time) bool {
	return snapshot.OperationRunID == runID && snapshot.TenantID != uuid.Nil && snapshot.ProviderID != uuid.Nil &&
		snapshot.BindingID != uuid.Nil && snapshot.SecretID != uuid.Nil && snapshot.ProviderVersion > 0 &&
		snapshot.ConfigurationVersion > 0 && snapshot.BindingVersion > 0 && snapshot.BindingAuthRevision > 0 &&
		snapshot.RuleSetRevision > 0 && snapshot.AuthorizationRevision > 0 && snapshot.StartedAt.Location() == time.UTC &&
		snapshot.ExpiresAt.Location() == time.UTC && snapshot.ExpiresAt.After(now) && len(snapshot.Endpoints) > 0
}

func validClaim(claim Claim, snapshot NetworkSnapshot) bool {
	return claim.OperationRunID == snapshot.OperationRunID && claim.TenantID == snapshot.TenantID &&
		claim.ProviderID == snapshot.ProviderID && claim.BindingID == snapshot.BindingID &&
		claim.BindingAuthRevision == snapshot.BindingAuthRevision && claim.Planning.TenantID == identity.EntityID(snapshot.TenantID) &&
		claim.Planning.Provider.ProviderID == identity.EntityID(snapshot.ProviderID) &&
		claim.Planning.BindingID == identity.EntityID(snapshot.BindingID)
}

func validApplyResult(result ApplyResult, userID uuid.UUID, returnPath string, credential *federatedauth.ApplyCredentialReservation) bool {
	if result.UserID != userID || result.ReturnPath != returnPath || credential == nil {
		return false
	}
	session := credential.Session()
	continuation := credential.Continuation()
	return !session.IsZero() && continuation.IsZero() && result.SessionID == session.SessionID() && result.ContinuationID == (identity.EntityID{}) ||
		session.IsZero() && !continuation.IsZero() && result.SessionID == (identity.EntityID{}) && result.ContinuationID == continuation.ContinuationID()
}

func directoryFailure(category ldapclient.DirectoryCategory, err error) (FailureCategory, error) {
	if errors.Is(err, ldapclient.ErrBusy) {
		return FailureDirectory, ErrRateLimited
	}
	if err != nil {
		return FailureDirectory, ErrUnavailable
	}
	switch category {
	case ldapclient.DirectoryCategoryCredentialsRejected, ldapclient.DirectoryCategoryUserNotFound,
		ldapclient.DirectoryCategoryUserAmbiguous:
		return FailureCredentials, ErrAuthentication
	default:
		return FailureDirectory, ErrUnavailable
	}
}

func mapBeginError(err error) error {
	if errors.Is(err, ErrRateLimited) {
		return ErrRateLimited
	}
	if errors.Is(err, ErrUnavailable) {
		return ErrUnavailable
	}
	return ErrAuthentication
}

func auditMetadata(command Command) AuditMetadata {
	return AuditMetadata{RequestID: command.RequestID, CorrelationID: command.CorrelationID, ClientIP: command.ClientIP, UserAgent: command.UserAgent}
}

func clearAliases(aliases []identity.SubjectAlias) {
	for index := range aliases {
		clear(aliases[index].Digest[:])
		aliases[index].KeyVersion = 0
	}
	clear(aliases)
}
