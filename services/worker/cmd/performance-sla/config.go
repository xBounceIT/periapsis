package main

import (
	"errors"
	"flag"
	"io"
	"net"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

type options struct {
	Mode       string
	Timeout    time.Duration
	MaxEvents  int
	MaxBatches int
}

var errInvalidOptions = errors.New("invalid performance SLA options")
var errInvalidDatabaseConfig = errors.New("invalid performance SLA database configuration")

func parseOptions(args []string) (options, error) {
	result := options{Timeout: 15 * time.Minute, MaxEvents: 500_000, MaxBatches: 4}
	flags := flag.NewFlagSet("performance-sla", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	seen := make(map[string]bool)
	register := func(name string, parse func(string) error) {
		flags.Func(name, "", func(value string) error {
			if seen[name] {
				return errInvalidOptions
			}
			seen[name] = true
			return parse(value)
		})
	}
	register("mode", func(value string) error { result.Mode = value; return nil })
	register("timeout", func(value string) error {
		parsed, err := time.ParseDuration(value)
		result.Timeout = parsed
		return err
	})
	register("max-events", func(value string) error {
		parsed, err := strconv.Atoi(value)
		result.MaxEvents = parsed
		return err
	})
	register("max-batches", func(value string) error {
		parsed, err := strconv.Atoi(value)
		result.MaxBatches = parsed
		return err
	})
	if flags.Parse(args) != nil || flags.NArg() != 0 ||
		(result.Mode != "ingress" && result.Mode != "timers") ||
		result.Timeout < time.Second || result.Timeout > 30*time.Minute || result.Timeout%time.Microsecond != 0 ||
		result.MaxEvents < 1 || result.MaxEvents > 500_000 || result.MaxBatches < 1 || result.MaxBatches > 5_000 {
		return options{}, errInvalidOptions
	}
	if result.Mode == "ingress" {
		if seen["max-batches"] {
			return options{}, errInvalidOptions
		}
		result.MaxBatches = 0
	} else if result.MaxEvents < result.MaxBatches*100 {
		return options{}, errInvalidOptions
	}
	return result, nil
}

type databaseConfig struct {
	URL                   string
	Database              string
	ExpectedDataDirectory string
}

func (databaseConfig) String() string {
	return "performanceDatabaseConfig{url:[REDACTED],database:[REDACTED],dataDirectory:[REDACTED]}"
}

func (config databaseConfig) GoString() string { return config.String() }

var performanceDatabaseName = regexp.MustCompile(`^periapsis_performance_[0-9]{13}_[0-9a-f]{12}$`)

func readDatabaseConfig(getenv func(string) string) (databaseConfig, error) {
	if getenv == nil {
		return databaseConfig{}, errInvalidDatabaseConfig
	}
	secretPath := getenv("PERIAPSIS_PERFORMANCE_DATABASE_URL_FILE")
	expected, err := normalizeDataDirectory(getenv("PERIAPSIS_PERFORMANCE_EXPECTED_DATA_DIRECTORY"))
	if err != nil || !validPathText(secretPath) || !filepath.IsAbs(secretPath) {
		return databaseConfig{}, errInvalidDatabaseConfig
	}
	// Reject known special files before opening them. The post-open identity/size
	// check also rejects replaced files; the private harness owns this secret path.
	before, err := os.Lstat(secretPath)
	if err != nil || !before.Mode().IsRegular() || before.Size() < 1 || before.Size() > 16*1024 {
		return databaseConfig{}, errInvalidDatabaseConfig
	}
	file, err := os.Open(secretPath)
	if err != nil {
		return databaseConfig{}, errInvalidDatabaseConfig
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !after.Mode().IsRegular() || !os.SameFile(before, after) || after.Size() > 16*1024 {
		return databaseConfig{}, errInvalidDatabaseConfig
	}
	raw, err := io.ReadAll(io.LimitReader(file, 16*1024+1))
	if err != nil || len(raw) > 16*1024 || !utf8.Valid(raw) {
		return databaseConfig{}, errInvalidDatabaseConfig
	}
	value := strings.TrimSpace(string(raw))
	database, err := validateDatabaseURL(value)
	if err != nil {
		return databaseConfig{}, errInvalidDatabaseConfig
	}
	return databaseConfig{URL: value, Database: database, ExpectedDataDirectory: expected}, nil
}

func validateDatabaseURL(value string) (string, error) {
	if value == "" || len(value) > 16*1024 || !utf8.ValidString(value) ||
		strings.ContainsAny(value, "#\\") || strings.ContainsFunc(value, func(character rune) bool {
		return unicode.IsSpace(character) || unicode.IsControl(character)
	}) {
		return "", errInvalidDatabaseConfig
	}
	parsed, err := url.Parse(value)
	if err != nil || (parsed.Scheme != "postgres" && parsed.Scheme != "postgresql") ||
		parsed.Opaque != "" || parsed.User == nil || parsed.User.Username() != "postgres" ||
		parsed.RawQuery != "sslmode=disable" || parsed.Fragment != "" || parsed.RawFragment != "" ||
		parsed.Path != parsed.EscapedPath() || !strings.HasPrefix(parsed.Path, "/") ||
		!performanceDatabaseName.MatchString(strings.TrimPrefix(parsed.Path, "/")) {
		return "", errInvalidDatabaseConfig
	}
	host, portText, err := net.SplitHostPort(parsed.Host)
	if err != nil || (host != "127.0.0.1" && host != "::1") {
		return "", errInvalidDatabaseConfig
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 || strconv.FormatUint(port, 10) != portText {
		return "", errInvalidDatabaseConfig
	}
	if password, _ := parsed.User.Password(); strings.ContainsFunc(password, unicode.IsControl) {
		return "", errInvalidDatabaseConfig
	}
	return strings.TrimPrefix(parsed.Path, "/"), nil
}

func validPathText(value string) bool {
	return value != "" && len(value) <= 4096 && utf8.ValidString(value) && value == strings.TrimSpace(value) &&
		!strings.ContainsFunc(value, unicode.IsControl)
}

// PostgreSQL reports forward slashes on Windows. Match that representation and
// its case-insensitive drive paths while preserving Unix path case. This is a
// lexical pin, not a filesystem mutation or a substitute for the live DB check.
func normalizeDataDirectory(value string) (string, error) {
	if !validPathText(value) {
		return "", errInvalidDatabaseConfig
	}
	normalized := strings.ReplaceAll(value, "\\", "/")
	windows := len(normalized) >= 3 && isDriveLetter(normalized[0]) && normalized[1:3] == ":/"
	if strings.HasPrefix(normalized, "//") || (!windows && (!strings.HasPrefix(normalized, "/") || strings.Contains(value, "\\"))) {
		return "", errInvalidDatabaseConfig
	}
	components := normalized
	if windows {
		components = normalized[2:]
	}
	for _, component := range strings.Split(components, "/") {
		if component == "." || component == ".." || strings.Contains(component, ":") {
			return "", errInvalidDatabaseConfig
		}
		if windows && (strings.HasSuffix(component, ".") || strings.HasSuffix(component, " ") || strings.ContainsAny(component, "<>|?*")) {
			return "", errInvalidDatabaseConfig
		}
	}
	normalized = path.Clean(normalized)
	if windows {
		normalized = strings.ToLower(normalized)
		if len(normalized) <= 3 {
			return "", errInvalidDatabaseConfig
		}
		local := normalized[2:]
		if local == "/users" || local == "/windows" || local == "/program files" || local == "/programdata" ||
			local == "/temp" || local == "/tmp" || local == "/data" ||
			strings.HasPrefix(local, "/users/") && strings.Count(local, "/") == 2 {
			return "", errInvalidDatabaseConfig
		}
	} else {
		switch normalized {
		case "/", "/tmp", "/var", "/var/lib", "/home", "/root", "/workspace", "/run", "/etc", "/usr", "/opt", "/data", "/mnt":
			return "", errInvalidDatabaseConfig
		}
		if strings.HasPrefix(normalized, "/home/") && strings.Count(normalized, "/") == 2 {
			return "", errInvalidDatabaseConfig
		}
	}
	return normalized, nil
}

func isDriveLetter(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z'
}
