package platformlocalaccount

import (
	"context"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
)

const (
	initialTOTPEnrollmentVersion = uint64(1)
	initialTOTPFactorRevision    = uint64(1)
	maximumTOTPProvisioningURI   = 2048
	maximumTOTPSecretBytes       = 256
	maximumTOTPEnvelopeBytes     = 8 * 1024
	localTOTPEnrollmentIssuer    = "Periapsis"
)

type TOTPEnrollmentPurpose string

const (
	TOTPEnrollmentInvite  TOTPEnrollmentPurpose = "invite"
	TOTPEnrollmentRecover TOTPEnrollmentPurpose = "recover"
)

type TOTPEnrollmentEngine interface {
	Generate(string) (secret string, provisioningURI string, err error)
	Validate(secret, code string, at time.Time, lastAcceptedCounter int64) (int64, error)
}

type TOTPEnrollmentCipher interface {
	EncryptTOTP(string, string) (authentication.EncryptedSecret, error)
	DecryptTOTP(string, authentication.EncryptedSecret) (string, error)
}

type TOTPEnrollmentSecurity interface {
	New(context.Context, NewTOTPEnrollmentRequest) (TOTPEnrollmentMaterial, error)
	Confirm(context.Context, ConfirmTOTPEnrollmentRequest) (ConfirmedTOTPFactor, error)
}

type NewTOTPEnrollmentRequest struct {
	AccountID           uuid.UUID
	UserID              uuid.UUID
	FactorID            uuid.UUID
	Purpose             TOTPEnrollmentPurpose
	Version             uint64
	CeremonyTokenDigest [sha256.Size]byte
}

func (NewTOTPEnrollmentRequest) String() string {
	return "platformlocalaccount.NewTOTPEnrollmentRequest{material:[REDACTED]}"
}
func (request NewTOTPEnrollmentRequest) GoString() string { return request.String() }

type TOTPEnrollmentMaterial struct {
	ProtectedSecret authentication.EncryptedSecret `json:"-"`
	DisplaySecret   []byte                         `json:"-"`
	ProvisioningURI []byte                         `json:"-"`
}

func (TOTPEnrollmentMaterial) String() string {
	return "platformlocalaccount.TOTPEnrollmentMaterial{material:[REDACTED]}"
}
func (material TOTPEnrollmentMaterial) GoString() string { return material.String() }

func (material *TOTPEnrollmentMaterial) Destroy() {
	if material == nil {
		return
	}
	clearEncryptedTOTPSecret(&material.ProtectedSecret)
	clear(material.DisplaySecret)
	clear(material.ProvisioningURI)
	*material = TOTPEnrollmentMaterial{}
}

type PendingTOTPEnrollment struct {
	AccountID           uuid.UUID
	UserID              uuid.UUID
	FactorID            uuid.UUID
	Purpose             TOTPEnrollmentPurpose
	Version             uint64
	FactorRevision      uint64
	CeremonyTokenDigest [sha256.Size]byte
	ProtectedSecret     authentication.EncryptedSecret `json:"-"`
	ExpiresAt           time.Time
}

func (pending PendingTOTPEnrollment) String() string {
	return "platformlocalaccount.PendingTOTPEnrollment{material:[REDACTED]}"
}
func (pending PendingTOTPEnrollment) GoString() string { return pending.String() }

func (pending *PendingTOTPEnrollment) Destroy() {
	if pending == nil {
		return
	}
	clear(pending.CeremonyTokenDigest[:])
	clearEncryptedTOTPSecret(&pending.ProtectedSecret)
	*pending = PendingTOTPEnrollment{}
}

func clonePendingTOTPEnrollment(source *PendingTOTPEnrollment) *PendingTOTPEnrollment {
	if source == nil {
		return nil
	}
	cloned := *source
	cloned.ProtectedSecret = cloneEncryptedTOTPSecret(source.ProtectedSecret)
	return &cloned
}

type ConfirmTOTPEnrollmentRequest struct {
	Pending             PendingTOTPEnrollment
	Code                []byte `json:"-"`
	At                  time.Time
	LastAcceptedCounter *int64
}

func (ConfirmTOTPEnrollmentRequest) String() string {
	return "platformlocalaccount.ConfirmTOTPEnrollmentRequest{proof:[REDACTED]}"
}
func (request ConfirmTOTPEnrollmentRequest) GoString() string { return request.String() }

type ConfirmedTOTPFactor struct {
	FactorID            uuid.UUID
	Revision            uint64
	ProtectedSecret     authentication.EncryptedSecret `json:"-"`
	AcceptedCounter     int64
	EncryptionAlgorithm string
	OTPAlgorithm        string
	Digits              uint8
	PeriodSeconds       uint16
}

func (ConfirmedTOTPFactor) String() string {
	return "platformlocalaccount.ConfirmedTOTPFactor{material:[REDACTED]}"
}
func (factor ConfirmedTOTPFactor) GoString() string { return factor.String() }

func (factor *ConfirmedTOTPFactor) Destroy() {
	if factor == nil {
		return
	}
	clearEncryptedTOTPSecret(&factor.ProtectedSecret)
	*factor = ConfirmedTOTPFactor{}
}

type EncryptedTOTPEnrollmentSecurity struct {
	engine TOTPEnrollmentEngine
	cipher TOTPEnrollmentCipher
}

func NewEncryptedTOTPEnrollmentSecurity(
	engine TOTPEnrollmentEngine,
	cipher TOTPEnrollmentCipher,
) (*EncryptedTOTPEnrollmentSecurity, error) {
	if interfaceIsNil(engine) || interfaceIsNil(cipher) {
		return nil, errors.New("TOTP enrollment engine and cipher are required")
	}
	return &EncryptedTOTPEnrollmentSecurity{engine: engine, cipher: cipher}, nil
}

func (security *EncryptedTOTPEnrollmentSecurity) New(
	ctx context.Context,
	request NewTOTPEnrollmentRequest,
) (TOTPEnrollmentMaterial, error) {
	if security == nil || interfaceIsNil(security.engine) || interfaceIsNil(security.cipher) ||
		ctx == nil || ctx.Err() != nil || !validNewTOTPEnrollmentRequest(request) {
		return TOTPEnrollmentMaterial{}, authentication.ErrUnavailable
	}
	secret, provisioningURI, err := security.engine.Generate(request.AccountID.String())
	if err != nil || ctx.Err() != nil {
		return TOTPEnrollmentMaterial{}, authentication.ErrUnavailable
	}
	secretBytes := []byte(secret)
	uriBytes := []byte(provisioningURI)
	defer clear(secretBytes)
	defer clear(uriBytes)
	if !validTOTPDisplaySecret(secretBytes) ||
		!validTOTPProvisioningURI(provisioningURI, request.AccountID, secret) {
		return TOTPEnrollmentMaterial{}, authentication.ErrUnavailable
	}
	pendingContext, err := pendingTOTPContext(request)
	if err != nil {
		return TOTPEnrollmentMaterial{}, authentication.ErrUnavailable
	}
	protected, err := security.cipher.EncryptTOTP(pendingContext, secret)
	if err != nil || ctx.Err() != nil || !validEncryptedTOTPSecret(protected, pendingContext) {
		clearEncryptedTOTPSecret(&protected)
		return TOTPEnrollmentMaterial{}, authentication.ErrUnavailable
	}
	return TOTPEnrollmentMaterial{
		ProtectedSecret: protected,
		DisplaySecret:   append([]byte(nil), secretBytes...),
		ProvisioningURI: append([]byte(nil), uriBytes...),
	}, nil
}

func (security *EncryptedTOTPEnrollmentSecurity) Confirm(
	ctx context.Context,
	request ConfirmTOTPEnrollmentRequest,
) (ConfirmedTOTPFactor, error) {
	defer request.Pending.Destroy()
	defer clear(request.Code)
	if security == nil || interfaceIsNil(security.engine) || interfaceIsNil(security.cipher) ||
		ctx == nil || ctx.Err() != nil || !validPendingTOTPEnrollment(request.Pending) ||
		!validFactorProof(request.Code) || !validInstant(request.At) || !request.At.Before(request.Pending.ExpiresAt) ||
		request.Pending.ExpiresAt.After(request.At.Add(ceremonyLifetime)) ||
		request.LastAcceptedCounter != nil && *request.LastAcceptedCounter < 0 {
		return ConfirmedTOTPFactor{}, authentication.ErrUnavailable
	}
	pendingContext, err := pendingTOTPContext(NewTOTPEnrollmentRequest{
		AccountID: request.Pending.AccountID, UserID: request.Pending.UserID,
		FactorID: request.Pending.FactorID, Purpose: request.Pending.Purpose,
		Version: request.Pending.Version, CeremonyTokenDigest: request.Pending.CeremonyTokenDigest,
	})
	if err != nil || !validEncryptedTOTPSecret(request.Pending.ProtectedSecret, pendingContext) {
		return ConfirmedTOTPFactor{}, authentication.ErrUnavailable
	}
	secret, err := security.cipher.DecryptTOTP(pendingContext, request.Pending.ProtectedSecret)
	if err != nil || secret == "" || ctx.Err() != nil {
		return ConfirmedTOTPFactor{}, authentication.ErrUnavailable
	}
	secretBytes := []byte(secret)
	defer clear(secretBytes)
	if !validTOTPDisplaySecret(secretBytes) {
		return ConfirmedTOTPFactor{}, authentication.ErrUnavailable
	}
	lastAcceptedCounter := int64(-1)
	if request.LastAcceptedCounter != nil {
		lastAcceptedCounter = *request.LastAcceptedCounter
	}
	counter, err := security.engine.Validate(secret, string(request.Code), request.At, lastAcceptedCounter)
	if errors.Is(err, authentication.ErrInvalidAuthentication) {
		return ConfirmedTOTPFactor{}, ErrEnrollmentProofRejected
	}
	if err != nil || counter < 0 || counter <= lastAcceptedCounter || ctx.Err() != nil {
		return ConfirmedTOTPFactor{}, authentication.ErrUnavailable
	}
	confirmedContext, err := authentication.CredentialTOTPContextAtRevision(
		request.Pending.FactorID, request.Pending.UserID, request.Pending.FactorRevision,
	)
	if err != nil {
		return ConfirmedTOTPFactor{}, authentication.ErrUnavailable
	}
	protected, err := security.cipher.EncryptTOTP(confirmedContext, secret)
	if err != nil || ctx.Err() != nil || !validEncryptedTOTPSecret(protected, confirmedContext) {
		clearEncryptedTOTPSecret(&protected)
		return ConfirmedTOTPFactor{}, authentication.ErrUnavailable
	}
	return ConfirmedTOTPFactor{
		FactorID: request.Pending.FactorID, Revision: request.Pending.FactorRevision,
		ProtectedSecret: protected, AcceptedCounter: counter,
		EncryptionAlgorithm: "aes-256-gcm", OTPAlgorithm: "SHA1", Digits: 6, PeriodSeconds: 30,
	}, nil
}

func pendingTOTPContext(request NewTOTPEnrollmentRequest) (string, error) {
	if !validNewTOTPEnrollmentRequest(request) {
		return "", errors.New("invalid pending TOTP context")
	}
	digest := base64.RawURLEncoding.EncodeToString(request.CeremonyTokenDigest[:])
	return "platform_local_account_enrollment:v1:purpose:" + string(request.Purpose) +
		":account:" + request.AccountID.String() + ":user:" + request.UserID.String() +
		":factor:" + request.FactorID.String() + ":ceremony:" + digest +
		":version:" + strconv.FormatUint(request.Version, 10), nil
}

func validNewTOTPEnrollmentRequest(request NewTOTPEnrollmentRequest) bool {
	return validUUIDv7(request.AccountID) && validUUIDv7(request.UserID) && validUUIDv7(request.FactorID) &&
		request.AccountID != request.UserID && request.AccountID != request.FactorID && request.UserID != request.FactorID &&
		(request.Purpose == TOTPEnrollmentInvite || request.Purpose == TOTPEnrollmentRecover) &&
		request.Version == initialTOTPEnrollmentVersion && request.CeremonyTokenDigest != ([sha256.Size]byte{})
}

func validPendingTOTPEnrollment(pending PendingTOTPEnrollment) bool {
	request := NewTOTPEnrollmentRequest{
		AccountID: pending.AccountID, UserID: pending.UserID, FactorID: pending.FactorID,
		Purpose: pending.Purpose, Version: pending.Version, CeremonyTokenDigest: pending.CeremonyTokenDigest,
	}
	context, err := pendingTOTPContext(request)
	return err == nil && pending.FactorRevision == initialTOTPFactorRevision &&
		validInstant(pending.ExpiresAt) && validEncryptedTOTPSecret(pending.ProtectedSecret, context)
}

func validConfirmedTOTPFactor(factor ConfirmedTOTPFactor, pending PendingTOTPEnrollment) bool {
	context, err := authentication.CredentialTOTPContextAtRevision(factor.FactorID, pending.UserID, factor.Revision)
	return err == nil && factor.FactorID == pending.FactorID && factor.Revision == pending.FactorRevision &&
		factor.AcceptedCounter >= 0 && factor.EncryptionAlgorithm == "aes-256-gcm" &&
		factor.OTPAlgorithm == "SHA1" && factor.Digits == 6 && factor.PeriodSeconds == 30 &&
		validEncryptedTOTPSecret(factor.ProtectedSecret, context)
}

func validTOTPEnrollmentMaterial(
	value TOTPEnrollmentMaterial,
	request NewTOTPEnrollmentRequest,
) bool {
	context, err := pendingTOTPContext(request)
	return err == nil && validTOTPDisplaySecret(value.DisplaySecret) &&
		validTOTPProvisioningURI(string(value.ProvisioningURI), request.AccountID, string(value.DisplaySecret)) &&
		validEncryptedTOTPSecret(value.ProtectedSecret, context)
}

func validEncryptedTOTPSecret(value authentication.EncryptedSecret, expectedAAD string) bool {
	return value.KeyVersion == 1 && len(value.Ciphertext) > 16 && len(value.Ciphertext) <= maximumTOTPEnvelopeBytes &&
		len(value.Nonce) == 12 && len(value.AAD) > 0 && len(value.AAD) <= 1024 && string(value.AAD) == expectedAAD
}

func cloneEncryptedTOTPSecret(value authentication.EncryptedSecret) authentication.EncryptedSecret {
	return authentication.EncryptedSecret{
		Ciphertext: append([]byte(nil), value.Ciphertext...), Nonce: append([]byte(nil), value.Nonce...),
		AAD: append([]byte(nil), value.AAD...), KeyVersion: value.KeyVersion,
	}
}

func clearEncryptedTOTPSecret(value *authentication.EncryptedSecret) {
	if value == nil {
		return
	}
	clear(value.Ciphertext)
	clear(value.Nonce)
	clear(value.AAD)
	*value = authentication.EncryptedSecret{}
}

func validTOTPDisplaySecret(value []byte) bool {
	if len(value) < 16 || len(value) > maximumTOTPSecretBytes || strings.ContainsRune(string(value), '=') ||
		string(value) != strings.ToUpper(string(value)) {
		return false
	}
	decoded := make([]byte, maximumTOTPSecretBytes)
	written, err := base32.StdEncoding.WithPadding(base32.NoPadding).Decode(decoded, value)
	canonical := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(decoded[:written])
	var combined byte
	for _, item := range decoded[:written] {
		combined |= item
	}
	clear(decoded)
	return err == nil && written >= 10 && combined != 0 && canonical == string(value)
}

func validTOTPProvisioningURI(raw string, accountID uuid.UUID, secret string) bool {
	if len(raw) < 1 || len(raw) > maximumTOTPProvisioningURI || strings.TrimSpace(raw) != raw {
		return false
	}
	parsed, err := url.Parse(raw)
	expectedPath := "/" + localTOTPEnrollmentIssuer + ":" + accountID.String()
	if err != nil || parsed.Scheme != "otpauth" || parsed.Host != "totp" || parsed.User != nil ||
		parsed.Fragment != "" || parsed.Path != expectedPath || parsed.RawPath != "" || parsed.EscapedPath() != expectedPath ||
		parsed.RawQuery == "" || parsed.Query().Encode() != parsed.RawQuery || parsed.String() != raw {
		return false
	}
	query := parsed.Query()
	for key, values := range query {
		if len(values) != 1 || key != "algorithm" && key != "digits" && key != "issuer" && key != "period" && key != "secret" {
			return false
		}
	}
	return query.Get("issuer") == localTOTPEnrollmentIssuer && query.Get("secret") == secret &&
		validOptionalTOTPParameter(query, "algorithm", "SHA1") &&
		validOptionalTOTPParameter(query, "digits", "6") &&
		validOptionalTOTPParameter(query, "period", "30")
}

func validOptionalTOTPParameter(query url.Values, name, canonical string) bool {
	values, present := query[name]
	return !present || len(values) == 1 && values[0] == canonical
}
