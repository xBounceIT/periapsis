package federatedhttp

import "strconv"

// String exposes only deployment policy shape, never CIDRs or ports.
func (policy DeploymentEgressPolicy) String() string {
	return "federatedhttp.DeploymentEgressPolicy{" +
		"valid=" + strconv.FormatBool(policy.valid) +
		",private_cidrs=" + strconv.Itoa(len(policy.privateCIDRs)) +
		",https_ports=" + strconv.Itoa(len(policy.ports)) +
		"}"
}

func (policy DeploymentEgressPolicy) GoString() string { return policy.String() }

// String exposes only whether each bounded policy class is configured.
func (limits Limits) String() string {
	return "federatedhttp.Limits{" +
		"timeouts=" + strconv.FormatBool(
		limits.ConnectTimeout > 0 && limits.TLSHandshakeTimeout > 0 &&
			limits.ResponseHeaderTimeout > 0 && limits.OperationTimeout > 0,
	) +
		",response_bounds=" + strconv.FormatBool(
		limits.MaxResponseHeaderBytes > 0 && limits.MaxWireBytes > 0 && limits.MaxDocumentBytes > 0,
	) +
		",max_redirects=" + strconv.Itoa(limits.MaxRedirects) +
		"}"
}

func (limits Limits) GoString() string { return limits.String() }

// String never formats resolver, dialer, root pool, CIDRs, or ports.
func (options Options) String() string {
	return "federatedhttp.Options{" +
		"resolver=" + strconv.FormatBool(options.Resolver != nil) +
		",dialer=" + strconv.FormatBool(options.Dialer != nil) +
		",egress_policy=" + strconv.FormatBool(options.EgressPolicy.valid) +
		",root_pool=" + strconv.FormatBool(options.RootCAs != nil) +
		",max_concurrent=" + strconv.Itoa(options.MaxConcurrent) +
		"}"
}

func (options Options) GoString() string { return options.String() }

// String exposes only the closed document category.
func (kind DocumentKind) String() string { return safeDocumentKind(kind) }

func (kind DocumentKind) GoString() string { return kind.String() }

// String never emits the destination host, port, path, or complete URL.
func (target Target) String() string {
	return "federatedhttp.Target{" +
		"kind=" + safeDocumentKind(target.kind) +
		",valid=" + strconv.FormatBool(target.valid) +
		",url_present=" + strconv.FormatBool(target.canonicalURL != "") +
		"}"
}

func (target Target) GoString() string { return target.String() }

// String exposes only a known sanitized outcome category.
func (category Category) String() string { return safeCategory(category) }

func (category Category) GoString() string { return category.String() }

// String exposes only cache decision shape, never upstream header values.
func (metadata CacheMetadata) String() string {
	return "federatedhttp.CacheMetadata{" +
		"retrieved=" + strconv.FormatBool(!metadata.RetrievedAt.IsZero()) +
		",fresh_until=" + strconv.FormatBool(!metadata.FreshUntil.IsZero()) +
		",cacheable=" + strconv.FormatBool(metadata.Cacheable) +
		",must_revalidate=" + strconv.FormatBool(metadata.MustRevalidate) +
		"}"
}

func (metadata CacheMetadata) GoString() string { return metadata.String() }

// String reports only sanitized metadata and successful document byte count.
func (result Result) String() string {
	bodyBytes := 0
	digestPresent := false
	cacheable := false
	if result.Category == CategorySuccess {
		bodyBytes = len(result.Body)
		digestPresent = result.Digest != ([32]byte{})
		cacheable = result.Cache.Cacheable
	}
	return "federatedhttp.Result{" +
		"category=" + safeCategory(result.Category) +
		",kind=" + safeDocumentKind(result.Kind) +
		",redirects=" + strconv.Itoa(result.Redirects) +
		",body_bytes=" + strconv.Itoa(bodyBytes) +
		",digest=" + strconv.FormatBool(digestPresent) +
		",cacheable=" + strconv.FormatBool(cacheable) +
		"}"
}

func (result Result) GoString() string { return result.String() }

func safeDocumentKind(kind DocumentKind) string {
	switch kind {
	case DocumentOIDCDiscovery, DocumentOIDCJWKS, DocumentSAMLMetadata:
		return string(kind)
	default:
		return "unknown"
	}
}

func safeCategory(category Category) string {
	switch category {
	case CategorySuccess,
		CategoryDNSFailed,
		CategoryDestinationBlocked,
		CategoryConnectTimeout,
		CategoryConnectFailed,
		CategoryTLSTimeout,
		CategoryTLSFailed,
		CategoryCertificateRejected,
		CategoryResponseHeaderTimeout,
		CategoryOperationTimeout,
		CategoryRedirectRejected,
		CategoryHTTPStatusRejected,
		CategoryMediaTypeRejected,
		CategoryEncodingRejected,
		CategoryLimitExceeded,
		CategoryResponseFailed,
		CategoryCancelled:
		return string(category)
	default:
		return "unknown"
	}
}
