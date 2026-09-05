package ldapclient

import "strconv"

// String exposes only network configuration shape, never directory hosts,
// TLS names, ports, or custom CA material.
func (configuration Configuration) String() string {
	enabled := 0
	referralAllowed := 0
	for _, endpoint := range configuration.Endpoints {
		if endpoint.Enabled {
			enabled++
		}
		if endpoint.ReferralAllowed {
			referralAllowed++
		}
	}
	return "ldapclient.Configuration{" +
		"endpoints=" + strconv.Itoa(len(configuration.Endpoints)) +
		",enabled=" + strconv.Itoa(enabled) +
		",referral_allowed=" + strconv.Itoa(referralAllowed) +
		",custom_ca=" + strconv.FormatBool(len(configuration.CustomCAPEM) != 0) +
		"}"
}

// GoString applies the same redaction to %#v.
func (configuration Configuration) GoString() string { return configuration.String() }

// String exposes only the stable configured priority and transport category,
// never a directory destination or TLS verification name.
func (endpoint Endpoint) String() string {
	transport := "unknown"
	if endpoint.Transport == TransportLDAPS || endpoint.Transport == TransportStartTLS {
		transport = string(endpoint.Transport)
	}
	return "ldapclient.Endpoint{" +
		"priority=" + strconv.Itoa(endpoint.Priority) +
		",enabled=" + strconv.FormatBool(endpoint.Enabled) +
		",referral_allowed=" + strconv.FormatBool(endpoint.ReferralAllowed) +
		",transport=" + transport +
		"}"
}

// GoString applies the same redaction to %#v.
func (endpoint Endpoint) GoString() string { return endpoint.String() }

// String deliberately exposes only configuration shape. LDAP destinations,
// DNs, filters, attribute names, username material, and custom CA bytes are
// never default-formatted from this boundary.
func (request DirectoryRequest) String() string {
	return "ldapclient.DirectoryRequest{" +
		"endpoints=" + strconv.Itoa(len(request.Configuration.Endpoints)) +
		",user_dn_template=" + strconv.FormatBool(request.UserDNTemplate != nil) +
		",user_attributes=" + strconv.Itoa(len(request.UserAttributes)) +
		",referral_mode=" + safeDirectoryReferralMode(request.ReferralMode) +
		",referral_hops=" + strconv.Itoa(request.ReferralMaxHops) +
		",groups_configured=" + strconv.FormatBool(
		request.Groups.DirectMembershipAttribute != "" || request.Groups.SearchFilter != nil,
	) +
		"}"
}

// GoString applies the same redaction to %#v.
func (request DirectoryRequest) GoString() string { return request.String() }

// String exposes only the known policy category, never a corrupted raw value.
func (mode DirectoryReferralMode) String() string { return safeDirectoryReferralMode(mode) }

// GoString applies the same redaction to %#v.
func (mode DirectoryReferralMode) GoString() string { return mode.String() }

// String exposes only group configuration shape, never a base DN, filter, or
// schema attribute name.
func (configuration DirectoryGroupConfiguration) String() string {
	return "ldapclient.DirectoryGroupConfiguration{" +
		"base_dn=" + strconv.FormatBool(configuration.BaseDN != "") +
		",search_filter=" + strconv.FormatBool(configuration.SearchFilter != nil) +
		",direct_attribute=" + strconv.FormatBool(configuration.DirectMembershipAttribute != "") +
		",gid_attribute=" + strconv.FormatBool(configuration.POSIXGIDNumberAttribute != "") +
		",attributes=" + strconv.Itoa(len(configuration.Attributes)) +
		"}"
}

// GoString applies the same redaction to %#v.
func (configuration DirectoryGroupConfiguration) GoString() string { return configuration.String() }

// String exposes only the number of raw values, never an LDAP schema name or
// value bytes.
func (attribute DirectoryAttribute) String() string {
	return "ldapclient.DirectoryAttribute{values=" + strconv.Itoa(len(attribute.Values)) + "}"
}

// GoString applies the same redaction to %#v.
func (attribute DirectoryAttribute) GoString() string { return attribute.String() }

// String exposes only the attribute count, never a DN or raw attributes.
func (entry DirectoryEntry) String() string {
	return "ldapclient.DirectoryEntry{attributes=" + strconv.Itoa(len(entry.Attributes)) + "}"
}

// GoString applies the same redaction to %#v.
func (entry DirectoryEntry) GoString() string { return entry.String() }

// String exposes only observation presence and bounded counts.
func (observation DirectoryObservation) String() string {
	return "ldapclient.DirectoryObservation{" +
		"user_present=" + strconv.FormatBool(directoryEntryPresent(observation.User)) +
		",user_attributes=" + strconv.Itoa(len(observation.User.Attributes)) +
		",groups=" + strconv.Itoa(len(observation.Groups)) +
		"}"
}

// GoString applies the same redaction to %#v.
func (observation DirectoryObservation) GoString() string { return observation.String() }

// String exposes only the stable category, configured endpoint priority, and
// bounded observation shape. A failed result reports a zero observation even
// if an accidentally populated value is formatted by a caller.
func (result DirectoryResult) String() string {
	userPresent := false
	userAttributeCount := 0
	groupCount := 0
	if result.Category == DirectoryCategorySuccess {
		userPresent = directoryEntryPresent(result.Observation.User)
		userAttributeCount = len(result.Observation.User.Attributes)
		groupCount = len(result.Observation.Groups)
	}
	return "ldapclient.DirectoryResult{" +
		"category=" + safeDirectoryCategory(result.Category) +
		",endpoint_priority=" + strconv.Itoa(result.EndpointPriority) +
		",user_present=" + strconv.FormatBool(userPresent) +
		",user_attributes=" + strconv.Itoa(userAttributeCount) +
		",groups=" + strconv.Itoa(groupCount) +
		"}"
}

// GoString applies the same redaction to %#v.
func (result DirectoryResult) GoString() string { return result.String() }

// String exposes only the closed grammar kind and typed-placeholder presence,
// never literal fragments or a rendered LDAP filter.
func (filter CompiledDirectoryInspectionFilter) String() string {
	return "ldapclient.CompiledDirectoryInspectionFilter{" +
		"kind=" + safeDirectoryInspectionFilterKind(filter.kind) +
		",valid=" + strconv.FormatBool(filter.valid) +
		",username=" + strconv.FormatBool(filter.requirements.Username) +
		",user_dn=" + strconv.FormatBool(filter.requirements.UserDN) +
		",gid_number=" + strconv.FormatBool(filter.requirements.GIDNumber) +
		"}"
}

// GoString applies the same redaction to %#v.
func (filter CompiledDirectoryInspectionFilter) GoString() string { return filter.String() }

// String exposes only the closed grammar category, never a corrupted raw
// string value.
func (kind DirectoryInspectionFilterKind) String() string {
	return safeDirectoryInspectionFilterKind(kind)
}

// GoString applies the same redaction to %#v.
func (kind DirectoryInspectionFilterKind) GoString() string { return kind.String() }

// String exposes only inspection-policy shape. Directory destinations, bind
// DN, trust material, and provider-owned limits are never default-formatted.
func (configuration DirectoryInspectionConfiguration) String() string {
	return "ldapclient.DirectoryInspectionConfiguration{" +
		"endpoints=" + strconv.Itoa(len(configuration.Network.Endpoints)) +
		",bind_dn=" + strconv.FormatBool(configuration.BindDN != "") +
		",referral_mode=" + safeDirectoryReferralMode(configuration.ReferralMode) +
		",referral_hops=" + strconv.Itoa(configuration.ReferralMaxHops) +
		"}"
}

// GoString applies the same redaction to %#v.
func (configuration DirectoryInspectionConfiguration) GoString() string {
	return configuration.String()
}

// String exposes only request shape. It never formats the login candidate,
// base DN, filter source/rendering, projected schema names, or custom CA.
func (request DirectorySearchUserRequest) String() string {
	return "ldapclient.DirectorySearchUserRequest{" +
		"endpoints=" + strconv.Itoa(len(request.Configuration.Network.Endpoints)) +
		",base_dn=" + strconv.FormatBool(request.UserBaseDN != "") +
		",filter=" + strconv.FormatBool(request.UserSearchFilter.valid) +
		",attributes=" + strconv.Itoa(len(request.Attributes)) +
		"}"
}

// GoString applies the same redaction to %#v.
func (request DirectorySearchUserRequest) GoString() string { return request.String() }

// String exposes only request shape and the bounded public result ceiling.
// Runtime values, base DN, filter source/rendering, and attributes stay hidden.
func (request DirectoryFilterTestRequest) String() string {
	baseDNPresent := request.UserBaseDN != "" || request.GroupBaseDN != ""
	attributeCount := len(request.UserAttributes) + len(request.GroupAttributes)
	return "ldapclient.DirectoryFilterTestRequest{" +
		"endpoints=" + strconv.Itoa(len(request.Configuration.Network.Endpoints)) +
		",base_dn=" + strconv.FormatBool(baseDNPresent) +
		",filter=" + strconv.FormatBool(request.Filter.valid) +
		",attributes=" + strconv.Itoa(attributeCount) +
		",max_results=" + strconv.Itoa(request.MaxResults) +
		"}"
}

// GoString applies the same redaction to %#v.
func (request DirectoryFilterTestRequest) GoString() string { return request.String() }

// String exposes only sanitized operation metadata and successful projection
// counts. Accidentally populated failed results format as zero projections.
func (result DirectoryInspectionResult) String() string {
	entryCount := 0
	truncated := false
	if result.Category == DirectoryCategorySuccess {
		entryCount = len(result.Entries)
		truncated = result.Truncated
	}
	return "ldapclient.DirectoryInspectionResult{" +
		"category=" + safeDirectoryCategory(result.Category) +
		",endpoint_priority=" + strconv.Itoa(result.EndpointPriority) +
		",truncated=" + strconv.FormatBool(truncated) +
		",entries=" + strconv.Itoa(entryCount) +
		"}"
}

// GoString applies the same redaction to %#v.
func (result DirectoryInspectionResult) GoString() string { return result.String() }

func directoryEntryPresent(entry DirectoryEntry) bool {
	return entry.DistinguishedName != "" || len(entry.Attributes) != 0
}

func safeDirectoryCategory(category DirectoryCategory) string {
	switch category {
	case DirectoryCategorySuccess,
		DirectoryCategoryDNSFailed,
		DirectoryCategoryDestinationBlocked,
		DirectoryCategoryConnectTimeout,
		DirectoryCategoryConnectFailed,
		DirectoryCategoryTLSFailed,
		DirectoryCategoryCertificateRejected,
		DirectoryCategoryServiceBindRejected,
		DirectoryCategoryCredentialsRejected,
		DirectoryCategoryUserNotFound,
		DirectoryCategoryUserAmbiguous,
		DirectoryCategoryLimitExceeded,
		DirectoryCategoryReferralRejected,
		DirectoryCategoryInvalidEntry,
		DirectoryCategoryProtocolFailed,
		DirectoryCategoryCancelled:
		return string(category)
	default:
		return "unknown"
	}
}

func safeDirectoryReferralMode(mode DirectoryReferralMode) string {
	switch mode {
	case DirectoryReferralModeDisabled, DirectoryReferralModeConfiguredEndpoints:
		return string(mode)
	default:
		return "unknown"
	}
}

func safeDirectoryInspectionFilterKind(kind DirectoryInspectionFilterKind) string {
	switch kind {
	case DirectoryInspectionFilterUser,
		DirectoryInspectionFilterReverseGroup,
		DirectoryInspectionFilterPOSIXGroup:
		return string(kind)
	default:
		return "unknown"
	}
}

func (configuration validatedDirectoryReferrals) String() string {
	return "ldapclient.validatedDirectoryReferrals{" +
		"enabled=" + strconv.FormatBool(configuration.enabled) +
		",max_hops=" + strconv.Itoa(configuration.maxHops) +
		",endpoints=" + strconv.Itoa(len(configuration.endpoints)) +
		"}"
}

func (configuration validatedDirectoryReferrals) GoString() string { return configuration.String() }

func (policy directoryReferralPolicy) String() string {
	return "ldapclient.directoryReferralPolicy{" +
		"configured=" + strconv.FormatBool(policy.configuration.enabled) +
		",endpoints=" + strconv.Itoa(len(policy.configuration.endpoints)) +
		",bind_secret=" + strconv.FormatBool(len(policy.bindSecret) != 0) +
		"}"
}

func (policy directoryReferralPolicy) GoString() string { return policy.String() }
