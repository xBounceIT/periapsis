package dfir

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"
)

type AssetCriticality string

const (
	AssetCriticalityLow      AssetCriticality = "low"
	AssetCriticalityMedium   AssetCriticality = "medium"
	AssetCriticalityHigh     AssetCriticality = "high"
	AssetCriticalityCritical AssetCriticality = "critical"
)

func validAssetCriticality(value AssetCriticality) bool {
	return value == AssetCriticalityLow || value == AssetCriticalityMedium ||
		value == AssetCriticalityHigh || value == AssetCriticalityCritical
}

type NetworkAddress struct {
	original   string
	normalized string
	family     int
}

func (address NetworkAddress) Original() string   { return address.original }
func (address NetworkAddress) Normalized() string { return address.normalized }
func (address NetworkAddress) Family() int        { return address.family }
func (address NetworkAddress) String() string     { return "dfir.NetworkAddress{value:[REDACTED]}" }
func (address NetworkAddress) GoString() string   { return address.String() }

type HardwareAddress struct {
	original   string
	normalized string
}

func (address HardwareAddress) Original() string   { return address.original }
func (address HardwareAddress) Normalized() string { return address.normalized }
func (address HardwareAddress) String() string     { return "dfir.HardwareAddress{value:[REDACTED]}" }
func (address HardwareAddress) GoString() string   { return address.String() }

type AssetInput struct {
	ID               EntityID
	TenantID         EntityID
	Hostname         string
	FQDN             string
	IPAddresses      []string
	MACAddresses     []string
	AssetType        string
	OperatingSystem  string
	Owner            string
	BusinessUnit     string
	Criticality      AssetCriticality
	Environment      string
	ExternalID       string
	Tags             []string
	FirstSeen        time.Time
	LastSeen         time.Time
	CustomAttributes json.RawMessage
}

type Asset struct {
	id                 EntityID
	tenantID           EntityID
	hostname           string
	normalizedHostname string
	fqdn               string
	normalizedFQDN     string
	ipAddresses        []NetworkAddress
	macAddresses       []HardwareAddress
	assetType          string
	operatingSystem    string
	owner              string
	businessUnit       string
	criticality        AssetCriticality
	environment        string
	externalID         string
	tags               []string
	firstSeen          time.Time
	lastSeen           time.Time
	customAttributes   json.RawMessage
}

func NewAsset(input AssetInput) (Asset, error) {
	if !validEntityID(input.ID) || !validEntityID(input.TenantID) ||
		!validSingleLineText(input.Hostname, 253, true) || !validSingleLineText(input.FQDN, 253, true) ||
		!validStableKey(input.AssetType) || !validOptionalText(input.OperatingSystem, 512) ||
		!validSingleLineText(input.Owner, 512, true) || !validSingleLineText(input.BusinessUnit, 256, true) ||
		!validAssetCriticality(input.Criticality) || !validStableKey(input.Environment) ||
		!validSingleLineText(input.ExternalID, 512, true) || !validInstant(input.FirstSeen) ||
		!validInstant(input.LastSeen) || input.LastSeen.Before(input.FirstSeen) ||
		!validEnrichment(input.CustomAttributes) {
		return Asset{}, ErrInvalidAsset
	}

	var normalizedHostname string
	var err error
	if input.Hostname != "" {
		normalizedHostname, err = normalizeDNSName(input.Hostname, false)
		if err != nil {
			return Asset{}, ErrInvalidAsset
		}
	}
	var normalizedFQDN string
	if input.FQDN != "" {
		normalizedFQDN, err = normalizeDNSName(input.FQDN, true)
		if err != nil {
			return Asset{}, ErrInvalidAsset
		}
	}

	ipAddresses, ok := canonicalNetworkAddresses(input.IPAddresses)
	if !ok {
		return Asset{}, ErrInvalidAsset
	}
	macAddresses, ok := canonicalHardwareAddresses(input.MACAddresses)
	if !ok {
		return Asset{}, ErrInvalidAsset
	}
	if input.Hostname == "" && input.FQDN == "" && len(ipAddresses) == 0 &&
		len(macAddresses) == 0 && input.ExternalID == "" {
		return Asset{}, ErrInvalidAsset
	}
	tags, ok := canonicalTags(input.Tags)
	if !ok {
		return Asset{}, ErrInvalidAsset
	}

	return Asset{
		id: input.ID, tenantID: input.TenantID,
		hostname: input.Hostname, normalizedHostname: normalizedHostname,
		fqdn: input.FQDN, normalizedFQDN: normalizedFQDN,
		ipAddresses: ipAddresses, macAddresses: macAddresses,
		assetType: input.AssetType, operatingSystem: input.OperatingSystem,
		owner: input.Owner, businessUnit: input.BusinessUnit,
		criticality: input.Criticality, environment: input.Environment,
		externalID: input.ExternalID, tags: tags,
		firstSeen: input.FirstSeen, lastSeen: input.LastSeen,
		customAttributes: slices.Clone(input.CustomAttributes),
	}, nil
}

func (asset Asset) ID() EntityID                      { return asset.id }
func (asset Asset) TenantID() EntityID                { return asset.tenantID }
func (asset Asset) Hostname() string                  { return asset.hostname }
func (asset Asset) NormalizedHostname() string        { return asset.normalizedHostname }
func (asset Asset) FQDN() string                      { return asset.fqdn }
func (asset Asset) NormalizedFQDN() string            { return asset.normalizedFQDN }
func (asset Asset) IPAddresses() []NetworkAddress     { return slices.Clone(asset.ipAddresses) }
func (asset Asset) MACAddresses() []HardwareAddress   { return slices.Clone(asset.macAddresses) }
func (asset Asset) AssetType() string                 { return asset.assetType }
func (asset Asset) OperatingSystem() string           { return asset.operatingSystem }
func (asset Asset) Owner() string                     { return asset.owner }
func (asset Asset) BusinessUnit() string              { return asset.businessUnit }
func (asset Asset) Criticality() AssetCriticality     { return asset.criticality }
func (asset Asset) Environment() string               { return asset.environment }
func (asset Asset) ExternalID() string                { return asset.externalID }
func (asset Asset) Tags() []string                    { return slices.Clone(asset.tags) }
func (asset Asset) FirstSeen() time.Time              { return asset.firstSeen }
func (asset Asset) LastSeen() time.Time               { return asset.lastSeen }
func (asset Asset) CustomAttributes() json.RawMessage { return slices.Clone(asset.customAttributes) }
func (asset Asset) String() string {
	return fmt.Sprintf(
		"dfir.Asset{criticality:%s,ips:%d,macs:%d,tags:%d,customAttributes:%t,identifiers:[REDACTED],metadata:[REDACTED]}",
		asset.criticality, len(asset.ipAddresses), len(asset.macAddresses), len(asset.tags),
		len(asset.customAttributes) > 0,
	)
}
func (asset Asset) GoString() string { return asset.String() }

func canonicalNetworkAddresses(values []string) ([]NetworkAddress, bool) {
	if len(values) > 256 {
		return nil, false
	}
	result := make([]NetworkAddress, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, original := range values {
		if !validBoundedText(original, 128, false) {
			return nil, false
		}
		address, err := netip.ParseAddr(original)
		if err != nil || address.Zone() != "" || address.Is4In6() {
			return nil, false
		}
		normalized := address.String()
		if _, duplicate := seen[normalized]; duplicate {
			return nil, false
		}
		seen[normalized] = struct{}{}
		family := 6
		if address.Is4() {
			family = 4
		}
		result = append(result, NetworkAddress{original: original, normalized: normalized, family: family})
	}
	slices.SortFunc(result, func(left, right NetworkAddress) int {
		return strings.Compare(left.normalized, right.normalized)
	})
	return result, true
}

func canonicalHardwareAddresses(values []string) ([]HardwareAddress, bool) {
	if len(values) > 256 {
		return nil, false
	}
	result := make([]HardwareAddress, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, original := range values {
		if !validBoundedText(original, 64, false) {
			return nil, false
		}
		address, err := net.ParseMAC(original)
		if err != nil || len(address) != 6 && len(address) != 8 {
			return nil, false
		}
		normalized := strings.ToLower(address.String())
		if _, duplicate := seen[normalized]; duplicate {
			return nil, false
		}
		seen[normalized] = struct{}{}
		result = append(result, HardwareAddress{original: original, normalized: normalized})
	}
	slices.SortFunc(result, func(left, right HardwareAddress) int {
		return strings.Compare(left.normalized, right.normalized)
	})
	return result, true
}

func validOptionalText(value string, maximum int) bool {
	return validBoundedText(value, maximum, true)
}

func validStableKey(value string) bool {
	return validTag(value)
}
