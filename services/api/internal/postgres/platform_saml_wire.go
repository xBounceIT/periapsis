package postgres

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"hash"
	"slices"
	"strings"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/federatedsaml"
	"github.com/periapsis-im/periapsis/services/api/internal/platformsamlauth"
)

const maximumPlatformSAMLWireBytes = 4 * 1024 * 1024

var errPlatformSAMLPersistence = errors.New("direct platform SAML persistence operation rejected")

type platformSAMLProviderWire struct {
	Scope      string `json:"scope"`
	ProviderID string `json:"providerId"`
}

type platformSAMLProtocolPinsWire struct {
	Provider                platformSAMLProviderWire `json:"provider"`
	ProviderRevision        uint64                   `json:"providerRevision"`
	PlatformLoginRevision   uint64                   `json:"platformLoginRevision"`
	ConfigurationRevision   uint64                   `json:"configurationRevision"`
	SecurityRevision        uint64                   `json:"securityRevision"`
	PlanRevision            uint64                   `json:"planRevision"`
	AssurancePolicyRevision uint64                   `json:"assurancePolicyRevision"`
	MetadataRevision        uint64                   `json:"metadataRevision"`
	MetadataDigest          []byte                   `json:"metadataDigest"`
	SPKeyRevision           uint64                   `json:"spKeyRevision"`
	ConfigurationDigest     []byte                   `json:"configurationDigest,omitempty"`
}

type platformSAMLDirectPinsWire struct {
	Protocol                    platformSAMLProtocolPinsWire `json:"protocol"`
	PlatformFloorPolicyID       string                       `json:"platformFloorPolicyId"`
	PlatformFloorPolicyRevision uint64                       `json:"platformFloorPolicyRevision"`
}

type platformSAMLTrustRuleWire struct {
	ID                              string `json:"id"`
	RuleID                          string `json:"ruleId,omitempty"`
	ClassRef                        string `json:"classRef"`
	Level                           string `json:"level"`
	Revision                        uint64 `json:"revision"`
	Enabled                         bool   `json:"enabled,omitempty"`
	MaximumAuthenticationAgeSeconds int64  `json:"maximumAuthenticationAgeSeconds"`
}

type platformSAMLSubjectWire struct {
	Source              string `json:"source"`
	AttributeName       string `json:"attributeName"`
	AttributeNameFormat string `json:"attributeNameFormat"`
}

type platformSAMLMappingWire struct {
	Scalars  []federatedsaml.ScalarAttributeRule  `json:"scalars"`
	Profiles []federatedsaml.ProfileAttributeRule `json:"profiles"`
	Groups   *federatedsaml.GroupAttributeRule    `json:"groups,omitempty"`
}

type platformSAMLAuthenticationWire struct {
	Provider                             platformSAMLProviderWire                 `json:"provider"`
	ProviderRevision                     uint64                                   `json:"providerRevision"`
	PlatformLoginRevision                uint64                                   `json:"platformLoginRevision"`
	ConfigurationRevision                uint64                                   `json:"configurationRevision"`
	SecurityRevision                     uint64                                   `json:"securityRevision"`
	PlanRevision                         uint64                                   `json:"planRevision"`
	AssurancePolicyRevision              uint64                                   `json:"assurancePolicyRevision"`
	SPEntityID                           string                                   `json:"spEntityId"`
	ACSURL                               string                                   `json:"acsUrl"`
	SPKeyRevision                        uint64                                   `json:"spKeyRevision"`
	RedirectSignatureAlgorithm           federatedsaml.RedirectSignatureAlgorithm `json:"redirectSignatureAlgorithm"`
	SignaturePolicy                      federatedsaml.SignaturePolicy            `json:"signaturePolicy"`
	EncryptionPolicy                     federatedsaml.EncryptionPolicy           `json:"encryptionPolicy"`
	DirectPlatformDecryptionKeyRevisions []uint64                                 `json:"directPlatformDecryptionKeyRevisions"`
	RequestedAuthnContexts               []string                                 `json:"requestedAuthnContexts"`
	Subject                              platformSAMLSubjectWire                  `json:"subject"`
	Mapping                              platformSAMLMappingWire                  `json:"mapping"`
	TrustRules                           []platformSAMLTrustRuleWire              `json:"trustRules"`
	ClockSkewNanoseconds                 int64                                    `json:"clockSkewNanoseconds"`
	MaxAuthenticationAgeNanoseconds      int64                                    `json:"maxAuthenticationAgeNanoseconds"`
}

type platformSAMLMetadataWire struct {
	ExpectedEntityID  string    `json:"expectedEntityId"`
	Revision          uint64    `json:"revision"`
	Document          []byte    `json:"document"`
	Digest            []byte    `json:"digest"`
	RetrievedAt       time.Time `json:"retrievedAt"`
	MaximumValidUntil time.Time `json:"maximumValidUntil"`
}

type directPlatformSAMLConfigurationWire struct {
	ProviderKey    string                         `json:"providerKey"`
	ObservedAt     time.Time                      `json:"observedAt"`
	Pins           platformSAMLProtocolPinsWire   `json:"pins"`
	DirectPins     *platformSAMLDirectPinsWire    `json:"directPins,omitempty"`
	Authentication platformSAMLAuthenticationWire `json:"authentication"`
	Metadata       platformSAMLMetadataWire       `json:"metadata"`
	PlatformFloor  assurancePolicyWire            `json:"platformFloor"`
}

type platformSAMLAuditWire struct {
	RequestID     string `json:"requestId"`
	CorrelationID string `json:"correlationId"`
	IPAddress     string `json:"ipAddress"`
	UserAgent     string `json:"userAgent"`
}

func platformSAMLAuditToWire(value platformsamlauth.AuditContext) (platformSAMLAuditWire, error) {
	requestID := entityIDWire(value.RequestID)
	correlationID := entityIDWire(value.CorrelationID)
	if requestID == "" || correlationID == "" || !value.RemoteAddress.IsValid() || value.UserAgent == "" {
		return platformSAMLAuditWire{}, errPlatformSAMLPersistence
	}
	return platformSAMLAuditWire{
		RequestID: requestID, CorrelationID: correlationID,
		IPAddress: value.RemoteAddress.String(), UserAgent: value.UserAgent,
	}, nil
}

func platformSAMLProviderToWire(value identity.ProviderContext) (platformSAMLProviderWire, error) {
	if value.Scope != identity.PlatformProviderScope || value.TenantID != (identity.EntityID{}) {
		return platformSAMLProviderWire{}, errPlatformSAMLPersistence
	}
	providerID := entityIDWire(value.ProviderID)
	if providerID == "" {
		return platformSAMLProviderWire{}, errPlatformSAMLPersistence
	}
	return platformSAMLProviderWire{Scope: "platform", ProviderID: providerID}, nil
}

func platformSAMLProviderFromWire(value platformSAMLProviderWire) (identity.ProviderContext, error) {
	providerID, err := parseEntityIDWire(value.ProviderID, false)
	if err != nil || value.Scope != "platform" {
		return identity.ProviderContext{}, errPlatformSAMLPersistence
	}
	return identity.ProviderContext{Scope: identity.PlatformProviderScope, ProviderID: providerID}, nil
}

func platformSAMLProtocolPinsToWire(value federatedsaml.TransactionPins) (platformSAMLProtocolPinsWire, error) {
	provider, err := platformSAMLProviderToWire(value.Provider)
	if err != nil || value.Authority != federatedsaml.DirectPlatformCeremonyAuthority ||
		value.BindingID != (identity.EntityID{}) || value.BindingRevision != 0 ||
		value.MappingRevision != 0 || value.AuthorizationRevision != 0 ||
		!validPlatformSAMLRevision(value.ProviderRevision) || !validPlatformSAMLRevision(value.PlatformLoginRevision) ||
		!validPlatformSAMLRevision(value.ConfigurationRevision) || !validPlatformSAMLRevision(value.SecurityRevision) ||
		!validPlatformSAMLRevision(value.PlanRevision) || !validPlatformSAMLRevision(value.AssurancePolicyRevision) ||
		!validPlatformSAMLRevision(value.MetadataRevision) || !validPlatformSAMLRevision(value.SPKeyRevision) ||
		value.MetadataDigest == ([sha256.Size]byte{}) || value.ConfigurationDigest == ([sha256.Size]byte{}) {
		return platformSAMLProtocolPinsWire{}, errPlatformSAMLPersistence
	}
	return platformSAMLProtocolPinsWire{
		Provider: provider, ProviderRevision: value.ProviderRevision,
		PlatformLoginRevision: value.PlatformLoginRevision, ConfigurationRevision: value.ConfigurationRevision,
		SecurityRevision: value.SecurityRevision, PlanRevision: value.PlanRevision,
		AssurancePolicyRevision: value.AssurancePolicyRevision, MetadataRevision: value.MetadataRevision,
		MetadataDigest: append([]byte(nil), value.MetadataDigest[:]...), SPKeyRevision: value.SPKeyRevision,
		ConfigurationDigest: append([]byte(nil), value.ConfigurationDigest[:]...),
	}, nil
}

func platformSAMLProtocolPinsFromWire(value platformSAMLProtocolPinsWire) (federatedsaml.TransactionPins, error) {
	provider, err := platformSAMLProviderFromWire(value.Provider)
	if err != nil || !validPlatformSAMLRevision(value.ProviderRevision) ||
		!validPlatformSAMLRevision(value.PlatformLoginRevision) || !validPlatformSAMLRevision(value.ConfigurationRevision) ||
		!validPlatformSAMLRevision(value.SecurityRevision) || !validPlatformSAMLRevision(value.PlanRevision) ||
		!validPlatformSAMLRevision(value.AssurancePolicyRevision) || !validPlatformSAMLRevision(value.MetadataRevision) ||
		!validPlatformSAMLRevision(value.SPKeyRevision) || len(value.MetadataDigest) != sha256.Size ||
		len(value.ConfigurationDigest) != sha256.Size {
		return federatedsaml.TransactionPins{}, errPlatformSAMLPersistence
	}
	var metadataDigest, configurationDigest [sha256.Size]byte
	copy(metadataDigest[:], value.MetadataDigest)
	copy(configurationDigest[:], value.ConfigurationDigest)
	if metadataDigest == ([sha256.Size]byte{}) || configurationDigest == ([sha256.Size]byte{}) {
		return federatedsaml.TransactionPins{}, errPlatformSAMLPersistence
	}
	return federatedsaml.TransactionPins{
		Authority: federatedsaml.DirectPlatformCeremonyAuthority, Provider: provider,
		ProviderRevision: value.ProviderRevision, PlatformLoginRevision: value.PlatformLoginRevision,
		ConfigurationRevision: value.ConfigurationRevision, SecurityRevision: value.SecurityRevision,
		PlanRevision: value.PlanRevision, AssurancePolicyRevision: value.AssurancePolicyRevision,
		MetadataRevision: value.MetadataRevision, MetadataDigest: metadataDigest,
		SPKeyRevision: value.SPKeyRevision, ConfigurationDigest: configurationDigest,
	}, nil
}

func platformSAMLDirectPinsToWire(value platformsamlauth.DirectSAMLPins) (platformSAMLDirectPinsWire, error) {
	protocol, err := platformSAMLProtocolPinsToWire(value.Protocol)
	if err != nil || !validPlatformSAMLRevision(value.PlatformFloorPolicyRevision) {
		return platformSAMLDirectPinsWire{}, errPlatformSAMLPersistence
	}
	floorID := entityIDWire(value.PlatformFloorPolicyID)
	if floorID == "" {
		return platformSAMLDirectPinsWire{}, errPlatformSAMLPersistence
	}
	return platformSAMLDirectPinsWire{Protocol: protocol, PlatformFloorPolicyID: floorID,
		PlatformFloorPolicyRevision: value.PlatformFloorPolicyRevision}, nil
}

func platformSAMLDirectPinsFromWire(value platformSAMLDirectPinsWire) (platformsamlauth.DirectSAMLPins, error) {
	protocol, err := platformSAMLProtocolPinsFromWire(value.Protocol)
	floorID, floorErr := parseEntityIDWire(value.PlatformFloorPolicyID, false)
	if err != nil || floorErr != nil || !validPlatformSAMLRevision(value.PlatformFloorPolicyRevision) {
		return platformsamlauth.DirectSAMLPins{}, errPlatformSAMLPersistence
	}
	return platformsamlauth.DirectSAMLPins{Protocol: protocol, PlatformFloorPolicyID: floorID,
		PlatformFloorPolicyRevision: value.PlatformFloorPolicyRevision}, nil
}

func platformSAMLConfigurationFromWire(value directPlatformSAMLConfigurationWire) (
	platformsamlauth.ConfigurationSnapshot,
	string,
	error,
) {
	provider, err := platformSAMLProviderFromWire(value.Authentication.Provider)
	observedAt := platformSAMLUTC(value.ObservedAt)
	if err != nil || value.ProviderKey == "" || !validPlatformSAMLInstant(observedAt) ||
		len(value.Metadata.Document) == 0 ||
		len(value.Metadata.Digest) != sha256.Size || value.Metadata.Revision == 0 {
		return platformsamlauth.ConfigurationSnapshot{}, "", errPlatformSAMLPersistence
	}
	metadataDocument := append([]byte(nil), value.Metadata.Document...)
	defer clear(metadataDocument)
	if sha256.Sum256(metadataDocument) != [sha256.Size]byte(value.Metadata.Digest) {
		return platformsamlauth.ConfigurationSnapshot{}, "", errPlatformSAMLPersistence
	}
	metadata, err := federatedsaml.CompileMetadata(federatedsaml.MetadataCompilationRequest{
		Document: metadataDocument, ExpectedEntityID: value.Metadata.ExpectedEntityID,
		Revision: value.Metadata.Revision, RetrievedAt: platformSAMLUTC(value.Metadata.RetrievedAt),
		MaximumValidUntil: platformSAMLUTC(value.Metadata.MaximumValidUntil),
	}, federatedsaml.DefaultLimits())
	if err != nil {
		return platformsamlauth.ConfigurationSnapshot{}, "", errPlatformSAMLPersistence
	}
	subject := federatedsaml.SubjectPolicy{
		Source:              federatedsaml.SubjectSource(value.Authentication.Subject.Source),
		AttributeName:       value.Authentication.Subject.AttributeName,
		AttributeNameFormat: value.Authentication.Subject.AttributeNameFormat,
	}
	trustRules := make([]federatedsaml.AuthnContextTrustRule, len(value.Authentication.TrustRules))
	for index, wire := range value.Authentication.TrustRules {
		level, levelErr := assuranceLevelFromWire(wire.Level)
		if levelErr != nil || !validPlatformSAMLRevision(wire.Revision) ||
			wire.MaximumAuthenticationAgeSeconds < 60 || wire.MaximumAuthenticationAgeSeconds > 86_400 {
			return platformsamlauth.ConfigurationSnapshot{}, "", errPlatformSAMLPersistence
		}
		trustRules[index] = federatedsaml.AuthnContextTrustRule{
			ClassRef: wire.ClassRef, Level: level, Revision: int64(wire.Revision),
			MaxAge: time.Duration(wire.MaximumAuthenticationAgeSeconds) * time.Second,
		}
	}
	slices.Sort(value.Authentication.RequestedAuthnContexts)
	slices.SortFunc(trustRules, func(left, right federatedsaml.AuthnContextTrustRule) int {
		return strings.Compare(left.ClassRef, right.ClassRef)
	})
	configuration := federatedsaml.Configuration{
		Authority: federatedsaml.DirectPlatformCeremonyAuthority, Provider: provider,
		ProviderRevision:      value.Authentication.ProviderRevision,
		PlatformLoginRevision: value.Authentication.PlatformLoginRevision,
		ConfigurationRevision: value.Authentication.ConfigurationRevision,
		SecurityRevision:      value.Authentication.SecurityRevision, PlanRevision: value.Authentication.PlanRevision,
		AssurancePolicyRevision: value.Authentication.AssurancePolicyRevision,
		SPEntityID:              value.Authentication.SPEntityID, ACSURL: value.Authentication.ACSURL,
		Metadata: metadata, SPKeyRevision: value.Authentication.SPKeyRevision,
		RedirectSignatureAlgorithm:           value.Authentication.RedirectSignatureAlgorithm,
		SignaturePolicy:                      value.Authentication.SignaturePolicy,
		EncryptionPolicy:                     value.Authentication.EncryptionPolicy,
		DirectPlatformDecryptionKeyRevisions: append([]uint64(nil), value.Authentication.DirectPlatformDecryptionKeyRevisions...),
		RequestedAuthnContexts:               append([]string(nil), value.Authentication.RequestedAuthnContexts...),
		Subject:                              subject,
		Mapping: federatedsaml.AttributeMappingPolicy{
			Scalars:  append([]federatedsaml.ScalarAttributeRule(nil), value.Authentication.Mapping.Scalars...),
			Profiles: append([]federatedsaml.ProfileAttributeRule(nil), value.Authentication.Mapping.Profiles...),
			Groups:   value.Authentication.Mapping.Groups,
		},
		TrustRules: trustRules, ClockSkew: time.Duration(value.Authentication.ClockSkewNanoseconds),
		MaxAuthenticationAge: time.Duration(value.Authentication.MaxAuthenticationAgeNanoseconds),
	}
	digest := platformSAMLConfigurationDigest(configuration)
	protocolPins := federatedsaml.TransactionPins{
		Authority: federatedsaml.DirectPlatformCeremonyAuthority, Provider: provider,
		ProviderRevision: configuration.ProviderRevision, PlatformLoginRevision: configuration.PlatformLoginRevision,
		ConfigurationRevision: configuration.ConfigurationRevision, SecurityRevision: configuration.SecurityRevision,
		PlanRevision: configuration.PlanRevision, AssurancePolicyRevision: configuration.AssurancePolicyRevision,
		MetadataRevision: metadata.Revision(), MetadataDigest: metadata.Digest(),
		SPKeyRevision: configuration.SPKeyRevision, ConfigurationDigest: digest,
	}
	floor, floorErr := assurancePolicyFromWire(value.PlatformFloor)
	if floorErr != nil || floor.Revision < 1 {
		return platformsamlauth.ConfigurationSnapshot{}, "", errPlatformSAMLPersistence
	}
	pins := platformsamlauth.DirectSAMLPins{
		Protocol: protocolPins, PlatformFloorPolicyID: floor.ID,
		PlatformFloorPolicyRevision: uint64(floor.Revision),
	}
	configurationWirePins := value.Pins
	configurationWirePins.ConfigurationDigest = append([]byte(nil), digest[:]...)
	wirePins, pinsErr := platformSAMLProtocolPinsFromWire(configurationWirePins)
	if pinsErr != nil || wirePins != protocolPins ||
		federatedsaml.ValidatePinnedConfiguration(configuration, protocolPins, observedAt) != nil {
		return platformsamlauth.ConfigurationSnapshot{}, "", errPlatformSAMLPersistence
	}
	return platformsamlauth.ConfigurationSnapshot{
		Pins: pins, ProviderKind: platformsamlauth.ProviderKindSAML, Authentication: configuration,
	}, value.ProviderKey, nil
}

func platformSAMLConfigurationDigest(configuration federatedsaml.Configuration) [sha256.Size]byte {
	fields := make([][]byte, 0, 48)
	metadataDigest := configuration.Metadata.Digest()
	fields = append(fields,
		[]byte{byte(configuration.Provider.Scope)}, configuration.Provider.TenantID[:],
		configuration.Provider.ProviderID[:], configuration.BindingID[:],
		platformSAMLU64(configuration.ProviderRevision), platformSAMLU64(configuration.BindingRevision),
		platformSAMLU64(configuration.ConfigurationRevision), platformSAMLU64(configuration.SecurityRevision),
		platformSAMLU64(configuration.MappingRevision), platformSAMLU64(configuration.AuthorizationRevision),
		platformSAMLU64(configuration.AssurancePolicyRevision), []byte(configuration.SPEntityID),
		[]byte(configuration.ACSURL), platformSAMLU64(configuration.Metadata.Revision()),
		metadataDigest[:], platformSAMLU64(configuration.SPKeyRevision),
		[]byte(configuration.RedirectSignatureAlgorithm), []byte(configuration.SignaturePolicy),
		[]byte(configuration.EncryptionPolicy), platformSAMLU64(uint64(configuration.ClockSkew)),
		platformSAMLU64(uint64(configuration.MaxAuthenticationAge)), []byte(configuration.Subject.Source),
		[]byte(configuration.Subject.AttributeName), []byte(configuration.Subject.AttributeNameFormat),
		[]byte("direct-platform"), platformSAMLU64(configuration.PlatformLoginRevision),
		platformSAMLU64(configuration.PlanRevision),
	)
	for _, revision := range configuration.DirectPlatformDecryptionKeyRevisions {
		fields = append(fields, platformSAMLU64(revision))
	}
	for _, context := range configuration.RequestedAuthnContexts {
		fields = append(fields, []byte(context))
	}
	for _, rule := range configuration.TrustRules {
		fields = append(fields, []byte("trust"), []byte(rule.ClassRef), []byte{byte(rule.Level)},
			platformSAMLU64(uint64(rule.Revision)), platformSAMLU64(uint64(rule.MaxAge)))
	}
	return platformSAMLDigestFields(fields...)
}

func platformSAMLDigestFields(fields ...[]byte) [sha256.Size]byte {
	digest := sha256.New()
	for _, field := range fields {
		platformSAMLWriteField(digest, field)
	}
	var result [sha256.Size]byte
	copy(result[:], digest.Sum(nil))
	return result
}

func platformSAMLWriteField(digest hash.Hash, field []byte) {
	_, _ = digest.Write(platformSAMLU64(uint64(len(field))))
	_, _ = digest.Write(field)
}

func platformSAMLU64(value uint64) []byte {
	result := make([]byte, 8)
	binary.BigEndian.PutUint64(result, value)
	return result
}

func platformSAMLUTC(value time.Time) time.Time { return value.UTC().Truncate(time.Microsecond) }

func validPlatformSAMLInstant(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && value.Nanosecond()%int(time.Microsecond) == 0
}

func validPlatformSAMLRevision(value uint64) bool { return value > 0 && value <= 9_007_199_254_740_991 }

func clearPlatformSAMLProtocolPinsWire(value *platformSAMLProtocolPinsWire) {
	if value == nil {
		return
	}
	clear(value.MetadataDigest)
	clear(value.ConfigurationDigest)
	*value = platformSAMLProtocolPinsWire{}
}

func clearPlatformSAMLConfigurationWire(value *directPlatformSAMLConfigurationWire) {
	if value == nil {
		return
	}
	clear(value.Metadata.Document)
	clear(value.Metadata.Digest)
	clearPlatformSAMLProtocolPinsWire(&value.Pins)
	if value.DirectPins != nil {
		clearPlatformSAMLProtocolPinsWire(&value.DirectPins.Protocol)
	}
	*value = directPlatformSAMLConfigurationWire{}
}
