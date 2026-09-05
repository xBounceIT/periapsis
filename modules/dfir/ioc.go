package dfir

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/mail"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/idna"
)

type IndicatorType string

const (
	IndicatorIPv4     IndicatorType = "ipv4"
	IndicatorIPv6     IndicatorType = "ipv6"
	IndicatorDomain   IndicatorType = "domain"
	IndicatorHostname IndicatorType = "hostname"
	IndicatorURL      IndicatorType = "url"
	IndicatorEmail    IndicatorType = "email"
	IndicatorMD5      IndicatorType = "md5"
	IndicatorSHA1     IndicatorType = "sha1"
	IndicatorSHA256   IndicatorType = "sha256"
	IndicatorSHA512   IndicatorType = "sha512"
	IndicatorFilename IndicatorType = "filename"
	IndicatorRegistry IndicatorType = "registry_key"
	IndicatorProcess  IndicatorType = "process"
	IndicatorMutex    IndicatorType = "mutex"
	IndicatorCVE      IndicatorType = "cve"
	IndicatorCustom   IndicatorType = "custom"
)

func validIndicatorType(value IndicatorType) bool {
	switch value {
	case IndicatorIPv4, IndicatorIPv6, IndicatorDomain, IndicatorHostname,
		IndicatorURL, IndicatorEmail, IndicatorMD5, IndicatorSHA1,
		IndicatorSHA256, IndicatorSHA512, IndicatorFilename, IndicatorRegistry,
		IndicatorProcess, IndicatorMutex, IndicatorCVE, IndicatorCustom:
		return true
	default:
		return false
	}
}

type TrafficLightProtocol string

const (
	TLPRed   TrafficLightProtocol = "red"
	TLPAmber TrafficLightProtocol = "amber"
	TLPGreen TrafficLightProtocol = "green"
	TLPClear TrafficLightProtocol = "clear"
)

func validTLP(value TrafficLightProtocol) bool {
	return value == TLPRed || value == TLPAmber || value == TLPGreen || value == TLPClear
}

type MaliciousState string

const (
	MaliciousUnknown    MaliciousState = "unknown"
	MaliciousBenign     MaliciousState = "benign"
	MaliciousSuspicious MaliciousState = "suspicious"
	MaliciousConfirmed  MaliciousState = "confirmed"
)

func validMaliciousState(value MaliciousState) bool {
	return value == MaliciousUnknown || value == MaliciousBenign ||
		value == MaliciousSuspicious || value == MaliciousConfirmed
}

// IndicatorInput keeps original observable text separate from normalized
// lookup text. The constructor owns copies of every slice-backed field.
type IndicatorInput struct {
	ID          EntityID
	TenantID    EntityID
	Type        IndicatorType
	Value       string
	Description string
	Source      string
	Confidence  int
	TLP         TrafficLightProtocol
	FirstSeen   time.Time
	LastSeen    time.Time
	Malicious   MaliciousState
	Tags        []string
	Enrichment  json.RawMessage
}

type Indicator struct {
	id          EntityID
	tenantID    EntityID
	kind        IndicatorType
	value       string
	normalized  string
	description string
	source      string
	confidence  uint8
	tlp         TrafficLightProtocol
	firstSeen   time.Time
	lastSeen    time.Time
	malicious   MaliciousState
	tags        []string
	enrichment  json.RawMessage
}

func NewIndicator(input IndicatorInput) (Indicator, error) {
	if !validEntityID(input.ID) || !validEntityID(input.TenantID) || !validIndicatorType(input.Type) ||
		!validSingleLineText(input.Value, maximumIndicatorValueBytes, false) ||
		!validBoundedText(input.Description, maximumIndicatorDescriptionBytes, true) ||
		!validSingleLineText(input.Source, maximumIndicatorSourceBytes, false) ||
		input.Confidence < 0 || input.Confidence > 100 || !validTLP(input.TLP) ||
		!validMaliciousState(input.Malicious) || !validInstant(input.FirstSeen) ||
		!validInstant(input.LastSeen) || input.LastSeen.Before(input.FirstSeen) {
		return Indicator{}, ErrInvalidIndicator
	}
	normalized, err := normalizeIndicatorValue(input.Type, input.Value)
	if err != nil {
		return Indicator{}, ErrInvalidIndicator
	}
	tags, ok := canonicalTags(input.Tags)
	if !ok || !validEnrichment(input.Enrichment) {
		return Indicator{}, ErrInvalidIndicator
	}
	return Indicator{
		id: input.ID, tenantID: input.TenantID, kind: input.Type,
		value: input.Value, normalized: normalized,
		description: input.Description, source: input.Source,
		confidence: uint8(input.Confidence), tlp: input.TLP,
		firstSeen: input.FirstSeen, lastSeen: input.LastSeen,
		malicious: input.Malicious, tags: tags,
		enrichment: slices.Clone(input.Enrichment),
	}, nil
}

func (indicator Indicator) ID() EntityID                   { return indicator.id }
func (indicator Indicator) TenantID() EntityID             { return indicator.tenantID }
func (indicator Indicator) Type() IndicatorType            { return indicator.kind }
func (indicator Indicator) Value() string                  { return indicator.value }
func (indicator Indicator) NormalizedValue() string        { return indicator.normalized }
func (indicator Indicator) Description() string            { return indicator.description }
func (indicator Indicator) Source() string                 { return indicator.source }
func (indicator Indicator) Confidence() int                { return int(indicator.confidence) }
func (indicator Indicator) TLP() TrafficLightProtocol      { return indicator.tlp }
func (indicator Indicator) FirstSeen() time.Time           { return indicator.firstSeen }
func (indicator Indicator) LastSeen() time.Time            { return indicator.lastSeen }
func (indicator Indicator) MaliciousState() MaliciousState { return indicator.malicious }
func (indicator Indicator) Tags() []string                 { return slices.Clone(indicator.tags) }
func (indicator Indicator) Enrichment() json.RawMessage    { return slices.Clone(indicator.enrichment) }
func (indicator Indicator) String() string {
	return fmt.Sprintf(
		"dfir.Indicator{type:%s,confidence:%d,tlp:%s,malicious:%s,tags:%d,enrichment:%t,value:[REDACTED],normalized:[REDACTED],description:[REDACTED],source:[REDACTED]}",
		indicator.kind, indicator.confidence, indicator.tlp, indicator.malicious,
		len(indicator.tags), len(indicator.enrichment) > 0,
	)
}
func (indicator Indicator) GoString() string { return indicator.String() }

var cvePattern = regexp.MustCompile(`(?i)^CVE-(1999|2[0-9]{3})-[0-9]{4,19}$`)

func normalizeIndicatorValue(kind IndicatorType, value string) (string, error) {
	switch kind {
	case IndicatorIPv4:
		address, err := netip.ParseAddr(value)
		if err != nil || !address.Is4() {
			return "", ErrInvalidIndicator
		}
		return address.String(), nil
	case IndicatorIPv6:
		address, err := netip.ParseAddr(value)
		if err != nil || !address.Is6() || address.Is4In6() || address.Zone() != "" {
			return "", ErrInvalidIndicator
		}
		return address.String(), nil
	case IndicatorDomain:
		return normalizeDNSName(value, true)
	case IndicatorHostname:
		return normalizeDNSName(value, false)
	case IndicatorURL:
		return normalizeURL(value)
	case IndicatorEmail:
		return normalizeEmail(value)
	case IndicatorMD5:
		return normalizeHexDigest(value, 16)
	case IndicatorSHA1:
		return normalizeHexDigest(value, 20)
	case IndicatorSHA256:
		return normalizeHexDigest(value, 32)
	case IndicatorSHA512:
		return normalizeHexDigest(value, 64)
	case IndicatorCVE:
		if !cvePattern.MatchString(value) {
			return "", ErrInvalidIndicator
		}
		return strings.ToUpper(value), nil
	case IndicatorFilename, IndicatorRegistry, IndicatorProcess, IndicatorMutex, IndicatorCustom:
		return value, nil
	default:
		return "", ErrInvalidIndicator
	}
}

func normalizeHexDigest(value string, byteLength int) (string, error) {
	if len(value) != byteLength*2 {
		return "", ErrInvalidIndicator
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != byteLength {
		return "", ErrInvalidIndicator
	}
	return hex.EncodeToString(decoded), nil
}

func normalizeDNSName(value string, requireRegistrableShape bool) (string, error) {
	if strings.HasSuffix(value, "..") {
		return "", ErrInvalidIndicator
	}
	withoutRoot := strings.TrimSuffix(value, ".")
	if withoutRoot == "" {
		return "", ErrInvalidIndicator
	}
	if address, err := netip.ParseAddr(withoutRoot); err == nil && address.IsValid() {
		return "", ErrInvalidIndicator
	}
	ascii, err := idna.Lookup.ToASCII(withoutRoot)
	if err != nil {
		return "", ErrInvalidIndicator
	}
	ascii = strings.ToLower(ascii)
	if len(ascii) == 0 || len(ascii) > 253 {
		return "", ErrInvalidIndicator
	}
	labels := strings.Split(ascii, ".")
	if requireRegistrableShape && len(labels) < 2 {
		return "", ErrInvalidIndicator
	}
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", ErrInvalidIndicator
		}
		for index := range len(label) {
			character := label[index]
			if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-' {
				continue
			}
			return "", ErrInvalidIndicator
		}
	}
	return ascii, nil
}

func normalizeURL(value string) (string, error) {
	parsed, err := url.ParseRequestURI(value)
	if err != nil {
		return "", ErrInvalidIndicator
	}
	scheme := strings.ToLower(parsed.Scheme)
	if parsed.Opaque != "" || parsed.User != nil || parsed.Host == "" ||
		(scheme != "http" && scheme != "https") {
		return "", ErrInvalidIndicator
	}
	parsed.Scheme = scheme
	hostname := parsed.Hostname()
	if hostname == "" {
		return "", ErrInvalidIndicator
	}
	var normalizedHost string
	if address, addressErr := netip.ParseAddr(hostname); addressErr == nil {
		if address.Zone() != "" || address.Is4In6() {
			return "", ErrInvalidIndicator
		}
		normalizedHost = address.String()
	} else {
		normalizedHost, err = normalizeDNSName(hostname, false)
		if err != nil {
			return "", ErrInvalidIndicator
		}
	}
	port := parsed.Port()
	if port != "" {
		portNumber, portErr := strconv.ParseUint(port, 10, 16)
		if portErr != nil || portNumber == 0 {
			return "", ErrInvalidIndicator
		}
		if parsed.Scheme == "http" && portNumber == 80 || parsed.Scheme == "https" && portNumber == 443 {
			port = ""
		}
	}
	if strings.Contains(normalizedHost, ":") {
		normalizedHost = "[" + normalizedHost + "]"
	}
	if port != "" {
		normalizedHost = net.JoinHostPort(strings.Trim(normalizedHost, "[]"), port)
	}
	parsed.Host = normalizedHost
	if parsed.Path == "" {
		parsed.Path = "/"
	}
	return parsed.String(), nil
}

func normalizeEmail(value string) (string, error) {
	parsed, err := mail.ParseAddress(value)
	if err != nil || parsed.Address != value {
		return "", ErrInvalidIndicator
	}
	at := strings.LastIndexByte(value, '@')
	if at < 1 || at > 64 || at == len(value)-1 {
		return "", ErrInvalidIndicator
	}
	domain, err := normalizeDNSName(value[at+1:], false)
	if err != nil {
		return "", ErrInvalidIndicator
	}
	return value[:at+1] + domain, nil
}

func validEnrichment(document json.RawMessage) bool {
	if len(document) == 0 {
		return true
	}
	if len(document) > maximumEnrichmentBytes || !json.Valid(document) {
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.UseNumber()
	values := 0
	if !consumeJSONObject(decoder, 1, &values) {
		return false
	}
	_, err := decoder.Token()
	return err == io.EOF
}

func consumeJSONObject(decoder *json.Decoder, depth int, values *int) bool {
	if depth > maximumEnrichmentDepth {
		return false
	}
	token, err := decoder.Token()
	delimiter, ok := token.(json.Delim)
	if err != nil || !ok || delimiter != '{' {
		return false
	}
	seen := make(map[string]struct{})
	for decoder.More() {
		keyToken, keyErr := decoder.Token()
		key, keyOK := keyToken.(string)
		if keyErr != nil || !keyOK || !validBoundedText(key, 256, false) {
			return false
		}
		if _, duplicate := seen[key]; duplicate {
			return false
		}
		seen[key] = struct{}{}
		(*values)++
		if *values > maximumEnrichmentValues || !consumeJSONValue(decoder, depth+1, values) {
			return false
		}
	}
	end, endErr := decoder.Token()
	endDelimiter, endOK := end.(json.Delim)
	return endErr == nil && endOK && endDelimiter == '}'
}

func consumeJSONValue(decoder *json.Decoder, depth int, values *int) bool {
	if depth > maximumEnrichmentDepth {
		return false
	}
	token, err := decoder.Token()
	if err != nil {
		return false
	}
	delimiter, composite := token.(json.Delim)
	if !composite {
		switch value := token.(type) {
		case nil, bool, json.Number:
			return true
		case string:
			return validBoundedText(value, maximumIndicatorValueBytes, true)
		default:
			return false
		}
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, keyErr := decoder.Token()
			key, keyOK := keyToken.(string)
			if keyErr != nil || !keyOK || !validBoundedText(key, 256, false) {
				return false
			}
			if _, duplicate := seen[key]; duplicate {
				return false
			}
			seen[key] = struct{}{}
			(*values)++
			if *values > maximumEnrichmentValues || !consumeJSONValue(decoder, depth+1, values) {
				return false
			}
		}
		end, endErr := decoder.Token()
		endDelimiter, endOK := end.(json.Delim)
		return endErr == nil && endOK && endDelimiter == '}'
	case '[':
		for decoder.More() {
			(*values)++
			if *values > maximumEnrichmentValues || !consumeJSONValue(decoder, depth+1, values) {
				return false
			}
		}
		end, endErr := decoder.Token()
		endDelimiter, endOK := end.(json.Delim)
		return endErr == nil && endOK && endDelimiter == ']'
	default:
		return false
	}
}
