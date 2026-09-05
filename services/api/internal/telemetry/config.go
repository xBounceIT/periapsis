// Package telemetry provides the API's bounded OpenTelemetry boundary.
package telemetry

import (
	"errors"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	defaultExportTimeout = 5 * time.Second
	defaultSampleRatio   = 0.1
	maximumEndpointSize  = 2_048
)

var serviceNamePattern = regexp.MustCompile(`^[a-z][a-z0-9._-]{2,63}$`)

// EnvironmentLookup distinguishes a missing variable from an explicitly empty one.
type EnvironmentLookup func(string) (string, bool)

// Config is a closed, validated trace-export configuration.
type Config struct {
	Enabled       bool
	Endpoint      string
	Environment   string
	ExportTimeout time.Duration
	SampleRatio   float64
	ServiceName   string
	Version       string
	validated     bool
}

// LoadConfig loads the supported OTLP/HTTP subset. An explicit
// OTEL_SDK_DISABLED value is mandatory so absence never silently becomes a no-op.
func LoadConfig(environment, expectedServiceName, version string) (Config, error) {
	return LoadConfigFrom(environment, expectedServiceName, version, os.LookupEnv)
}

// LoadConfigFrom is LoadConfig with an injectable environment source for tests.
func LoadConfigFrom(
	environment, expectedServiceName, version string,
	lookup EnvironmentLookup,
) (Config, error) {
	if lookup == nil {
		return Config{}, errors.New("OpenTelemetry environment lookup is required")
	}
	if environment != "development" && environment != "test" && environment != "production" {
		return Config{}, errors.New("OpenTelemetry environment is unsupported")
	}
	if !serviceNamePattern.MatchString(expectedServiceName) {
		return Config{}, errors.New("OpenTelemetry service name is invalid")
	}
	if !boundedPrintable(version, 1, 128) {
		return Config{}, errors.New("OpenTelemetry service version is invalid")
	}

	disabledValue, present := lookup("OTEL_SDK_DISABLED")
	if !present || disabledValue != "true" && disabledValue != "false" {
		return Config{}, errors.New("OTEL_SDK_DISABLED must be explicitly true or false")
	}
	serviceName, servicePresent := lookup("OTEL_SERVICE_NAME")
	if servicePresent && serviceName != expectedServiceName {
		return Config{}, errors.New("OTEL_SERVICE_NAME does not match the process")
	}
	if disabledValue == "true" {
		return Config{
			Enabled: false, Environment: environment,
			ExportTimeout: defaultExportTimeout, SampleRatio: defaultSampleRatio,
			ServiceName: expectedServiceName, Version: version, validated: true,
		}, nil
	}
	if !servicePresent {
		return Config{}, errors.New("OTEL_SERVICE_NAME is required when tracing is enabled")
	}
	protocol, ok := lookup("OTEL_EXPORTER_OTLP_PROTOCOL")
	if !ok || protocol != "http/protobuf" {
		return Config{}, errors.New("OTEL_EXPORTER_OTLP_PROTOCOL must be http/protobuf")
	}
	endpointInput, ok := lookup("OTEL_EXPORTER_OTLP_ENDPOINT")
	if !ok {
		return Config{}, errors.New("OTEL_EXPORTER_OTLP_ENDPOINT is required")
	}
	endpoint, err := canonicalEndpoint(endpointInput)
	if err != nil {
		return Config{}, err
	}
	for _, unsupported := range []string{
		"OTEL_EXPORTER_OTLP_CERTIFICATE",
		"OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE",
		"OTEL_EXPORTER_OTLP_CLIENT_KEY",
		"OTEL_EXPORTER_OTLP_COMPRESSION",
		"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
		"OTEL_EXPORTER_OTLP_TRACES_CERTIFICATE",
		"OTEL_EXPORTER_OTLP_TRACES_CLIENT_CERTIFICATE",
		"OTEL_EXPORTER_OTLP_TRACES_CLIENT_KEY",
		"OTEL_EXPORTER_OTLP_TRACES_COMPRESSION",
		"OTEL_EXPORTER_OTLP_HEADERS",
		"OTEL_EXPORTER_OTLP_TRACES_HEADERS",
		"OTEL_EXPORTER_OTLP_INSECURE",
		"OTEL_EXPORTER_OTLP_TRACES_INSECURE",
		"OTEL_EXPORTER_OTLP_TIMEOUT",
		"OTEL_EXPORTER_OTLP_TRACES_TIMEOUT",
		"OTEL_EXPORTER_OTLP_TRACES_PROTOCOL",
		"OTEL_RESOURCE_ATTRIBUTES",
	} {
		if _, configured := lookup(unsupported); configured {
			return Config{}, errors.New(unsupported + " is not supported")
		}
	}
	if propagators, configured := lookup("OTEL_PROPAGATORS"); configured && propagators != "tracecontext" {
		return Config{}, errors.New("OTEL_PROPAGATORS must be tracecontext")
	}

	sampleRatio := defaultSampleRatio
	if sampler, configured := lookup("OTEL_TRACES_SAMPLER"); configured && sampler != "parentbased_traceidratio" {
		return Config{}, errors.New("OTEL_TRACES_SAMPLER must be parentbased_traceidratio")
	}
	if ratioValue, configured := lookup("OTEL_TRACES_SAMPLER_ARG"); configured {
		if !canonicalRatio(ratioValue) {
			return Config{}, errors.New("OTEL_TRACES_SAMPLER_ARG must be a canonical ratio from 0 to 1")
		}
		sampleRatio, err = strconv.ParseFloat(ratioValue, 64)
		if err != nil || sampleRatio < 0 || sampleRatio > 1 {
			return Config{}, errors.New("OTEL_TRACES_SAMPLER_ARG must be a canonical ratio from 0 to 1")
		}
	}
	exportTimeout := defaultExportTimeout
	if timeoutValue, configured := lookup("PERIAPSIS_OTEL_EXPORT_TIMEOUT_MS"); configured {
		milliseconds, parseErr := strconv.ParseInt(timeoutValue, 10, 64)
		if parseErr != nil || timeoutValue != strconv.FormatInt(milliseconds, 10) || milliseconds < 100 || milliseconds > 30_000 {
			return Config{}, errors.New("PERIAPSIS_OTEL_EXPORT_TIMEOUT_MS must be between 100 and 30000")
		}
		exportTimeout = time.Duration(milliseconds) * time.Millisecond
	}

	return Config{
		Enabled: true, Endpoint: endpoint, Environment: environment,
		ExportTimeout: exportTimeout, SampleRatio: sampleRatio,
		ServiceName: expectedServiceName, Version: version, validated: true,
	}, nil
}

func canonicalEndpoint(input string) (string, error) {
	if !boundedPrintable(input, 1, maximumEndpointSize) || strings.TrimSpace(input) != input {
		return "", errors.New("OTEL_EXPORTER_OTLP_ENDPOINT is invalid")
	}
	parsed, err := url.Parse(input)
	if err != nil || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.RawPath != "" ||
		parsed.Host == "" || parsed.Path != "" && parsed.Path != "/" ||
		parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", errors.New("OTEL_EXPORTER_OTLP_ENDPOINT is invalid")
	}
	if parsed.Hostname() == "" || strings.HasSuffix(parsed.Host, ":") {
		return "", errors.New("OTEL_EXPORTER_OTLP_ENDPOINT is invalid")
	}
	if port := parsed.Port(); port != "" {
		value, parseErr := strconv.Atoi(port)
		if parseErr != nil || value < 1 || value > 65_535 {
			return "", errors.New("OTEL_EXPORTER_OTLP_ENDPOINT is invalid")
		}
	}
	parsed.Path = ""
	return strings.TrimSuffix(parsed.String(), "/"), nil
}

func boundedPrintable(value string, minimum, maximum int) bool {
	if len(value) < minimum || len(value) > maximum {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character > 0x7e {
			return false
		}
	}
	return true
}

func canonicalRatio(value string) bool {
	if value == "0" || value == "1" {
		return true
	}
	if !strings.HasPrefix(value, "0.") || len(value) < 3 || len(value) > 12 {
		return false
	}
	for _, character := range value[2:] {
		if character < '0' || character > '9' {
			return false
		}
	}
	return !strings.HasSuffix(value, "0")
}
