package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	configTestDatabase = "periapsis_performance_1788624313525_082d82ba29f3"
	configTestURL      = "postgres://postgres@127.0.0.1:5432/" + configTestDatabase + "?sslmode=disable"
	configTestSecret   = "synthetic-config-sentinel-do-not-echo"
	configTestFileEnv  = "PERIAPSIS_PERFORMANCE_DATABASE_URL_FILE"
	configTestDataEnv  = "PERIAPSIS_PERFORMANCE_EXPECTED_DATA_DIRECTORY"
)

func TestParseOptionsDefaultsAndBounds(t *testing.T) {
	for _, test := range []struct {
		name string
		args []string
		want options
	}{
		{"ingress defaults", []string{"--mode", "ingress"}, options{"ingress", 15 * time.Minute, 500000, 0}},
		{"timer defaults", []string{"--mode=timers"}, options{"timers", 15 * time.Minute, 500000, 4}},
		{"ingress minima", []string{"--mode=ingress", "--timeout=1s", "--max-events=1"}, options{"ingress", time.Second, 1, 0}},
		{"timer minima", []string{"--mode=timers", "--timeout=1s", "--max-events=100", "--max-batches=1"}, options{"timers", time.Second, 100, 1}},
		{"timer maxima", []string{"--mode=timers", "--timeout=30m", "--max-events=500000", "--max-batches=5000"}, options{"timers", 30 * time.Minute, 500000, 5000}},
		{"microsecond precision", []string{"--mode=ingress", "--timeout=1.000001s"}, options{"ingress", time.Second + time.Microsecond, 500000, 0}},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := parseOptions(test.args)
			if err != nil || got != test.want {
				t.Fatalf("options=%+v, error=%v; want %+v", got, err, test.want)
			}
		})
	}
}

func TestParseOptionsRejectsInvalidOrUnboundedArguments(t *testing.T) {
	for _, test := range []struct {
		name string
		args []string
	}{
		{"mode missing", nil},
		{"mode empty", []string{"--mode="}},
		{"mode unknown", []string{"--mode=" + configTestSecret}},
		{"mode wrong case", []string{"--mode=Ingress"}},
		{"unknown flag", []string{"--mode=ingress", "--" + configTestSecret}},
		{"help", []string{"--help"}},
		{"duplicate mode", []string{"--mode=ingress", "--mode=ingress"}},
		{"duplicate timeout", []string{"--mode=ingress", "--timeout=1s", "--timeout=1s"}},
		{"duplicate events", []string{"--mode=ingress", "--max-events=1", "--max-events=1"}},
		{"duplicate batches", []string{"--mode=timers", "--max-batches=1", "--max-batches=1"}},
		{"positional argument", []string{"--mode=ingress", configTestSecret}},
		{"missing flag value", []string{"--mode=ingress", "--timeout"}},
		{"timeout invalid", []string{"--mode=ingress", "--timeout=" + configTestSecret}},
		{"timeout below minimum", []string{"--mode=ingress", "--timeout=999999us"}},
		{"timeout above maximum", []string{"--mode=ingress", "--timeout=30m1us"}},
		{"timeout negative", []string{"--mode=ingress", "--timeout=-1s"}},
		{"timeout submicrosecond", []string{"--mode=ingress", "--timeout=1.000000001s"}},
		{"events zero", []string{"--mode=ingress", "--max-events=0"}},
		{"events negative", []string{"--mode=ingress", "--max-events=-1"}},
		{"events above maximum", []string{"--mode=ingress", "--max-events=500001"}},
		{"events invalid", []string{"--mode=ingress", "--max-events=" + configTestSecret}},
		{"events overflow", []string{"--mode=ingress", "--max-events=999999999999999999999"}},
		{"ingress explicit default batches", []string{"--mode=ingress", "--max-batches=4"}},
		{"ingress explicit zero batches", []string{"--mode=ingress", "--max-batches=0"}},
		{"timer batches zero", []string{"--mode=timers", "--max-batches=0"}},
		{"timer batches negative", []string{"--mode=timers", "--max-batches=-1"}},
		{"timer batches above maximum", []string{"--mode=timers", "--max-batches=5001"}},
		{"timer batches invalid", []string{"--mode=timers", "--max-batches=" + configTestSecret}},
		{"timer insufficient default event budget", []string{"--mode=timers", "--max-events=399"}},
		{"timer insufficient explicit event budget", []string{"--mode=timers", "--max-events=199", "--max-batches=2"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := parseOptions(test.args)
			assertGenericConfigError(t, err)
			if got != (options{}) || err != errInvalidOptions {
				t.Fatal("invalid options returned partial capability or a nongeneric error")
			}
		})
	}
}

func TestReadDatabaseConfigAcceptsOnlyScopedSecretAndLoopbackURLs(t *testing.T) {
	for _, test := range []struct {
		name string
		url  string
	}{
		{"IPv4", configTestURL},
		{"IPv6", "postgresql://postgres@[::1]:65535/" + configTestDatabase + "?sslmode=disable"},
		{"optional password", "postgres://postgres:" + configTestSecret + "@127.0.0.1:1/" + configTestDatabase + "?sslmode=disable"},
		{"encoded password space", "postgres://postgres:synthetic%20password@127.0.0.1:5432/" + configTestDatabase + "?sslmode=disable"},
	} {
		t.Run(test.name, func(t *testing.T) {
			file := writeConfigSecret(t, " \r\n"+test.url+"\r\n ")
			seen := map[string]bool{}
			got, err := readDatabaseConfig(func(key string) string {
				seen[key] = true
				switch key {
				case configTestFileEnv:
					return file
				case configTestDataEnv:
					return "/tmp/periapsis-performance/pgdata"
				default:
					t.Errorf("configuration read unrelated environment variable %q", key)
					return configTestSecret
				}
			})
			if err != nil || got.URL != test.url || got.Database != configTestDatabase ||
				got.ExpectedDataDirectory != "/tmp/periapsis-performance/pgdata" {
				t.Fatal("valid isolated database configuration was not preserved")
			}
			if !seen[configTestFileEnv] || !seen[configTestDataEnv] || len(seen) != 2 {
				t.Fatal("configuration did not use exactly the two scoped environment variables")
			}
		})
	}
}

func TestReadDatabaseConfigRejectsUnsafeURLs(t *testing.T) {
	base := "postgres://postgres@127.0.0.1:5432/"
	for _, test := range []struct {
		name string
		url  string
	}{
		{"scheme", "https://postgres@127.0.0.1:5432/" + configTestDatabase + "?sslmode=disable"},
		{"missing user", "postgres://127.0.0.1:5432/" + configTestDatabase + "?sslmode=disable"},
		{"wrong user", strings.Replace(configTestURL, "postgres@", configTestSecret+"@", 1)},
		{"encoded password control", strings.Replace(configTestURL, "postgres@", "postgres:synthetic%0Apassword@", 1)},
		{"DNS host", strings.Replace(configTestURL, "127.0.0.1", "localhost", 1)},
		{"remote host", strings.Replace(configTestURL, "127.0.0.1", "192.0.2.1", 1)},
		{"wildcard host", strings.Replace(configTestURL, "127.0.0.1", "0.0.0.0", 1)},
		{"mapped IPv6", strings.Replace(configTestURL, "127.0.0.1", "[::ffff:127.0.0.1]", 1)},
		{"missing port", strings.Replace(configTestURL, ":5432/", "/", 1)},
		{"zero port", strings.Replace(configTestURL, ":5432/", ":0/", 1)},
		{"large port", strings.Replace(configTestURL, ":5432/", ":65536/", 1)},
		{"noncanonical port", strings.Replace(configTestURL, ":5432/", ":05432/", 1)},
		{"signed port", strings.Replace(configTestURL, ":5432/", ":+5432/", 1)},
		{"nonnumeric port", strings.Replace(configTestURL, ":5432/", ":"+configTestSecret+"/", 1)},
		{"missing database", base + "?sslmode=disable"},
		{"ordinary database", base + "postgres?sslmode=disable"},
		{"short timestamp", base + "periapsis_performance_178862431352_082d82ba29f3?sslmode=disable"},
		{"uppercase suffix", base + "periapsis_performance_1788624313525_082D82BA29F3?sslmode=disable"},
		{"short suffix", base + "periapsis_performance_1788624313525_082d82ba29f?sslmode=disable"},
		{"extra path", base + configTestDatabase + "/extra?sslmode=disable"},
		{"escaped database", base + strings.Replace(configTestDatabase, "periapsis", "%70eriapsis", 1) + "?sslmode=disable"},
		{"missing query", base + configTestDatabase},
		{"wrong TLS mode", base + configTestDatabase + "?sslmode=require"},
		{"encoded query", base + configTestDatabase + "?sslmode=dis%61ble"},
		{"extra query", configTestURL + "&application_name=" + configTestSecret},
		{"duplicate query", configTestURL + "&sslmode=disable"},
		{"query override", configTestURL + "&host=192.0.2.1"},
		{"fragment", configTestURL + "#" + configTestSecret},
		{"empty fragment", configTestURL + "#"},
		{"internal newline", strings.Replace(configTestURL, "@", "\n@", 1)},
	} {
		t.Run(test.name, func(t *testing.T) {
			file := writeConfigSecret(t, test.url)
			_, err := readDatabaseConfig(configEnvironment(file, "/tmp/periapsis-performance/pgdata"))
			assertGenericConfigError(t, err, test.url, file)
		})
	}
}

func TestReadDatabaseConfigEnforcesSecretFileAndDirectoryBounds(t *testing.T) {
	valid := writeConfigSecret(t, configTestURL)
	for _, test := range []struct {
		name      string
		file      string
		directory string
	}{
		{"file env missing", "", "/tmp/periapsis-performance/pgdata"},
		{"relative file", "relative-" + configTestSecret, "/tmp/periapsis-performance/pgdata"},
		{"missing file", filepath.Join(t.TempDir(), configTestSecret), "/tmp/periapsis-performance/pgdata"},
		{"directory as file", t.TempDir(), "/tmp/periapsis-performance/pgdata"},
		{"empty file", writeConfigSecret(t, ""), "/tmp/periapsis-performance/pgdata"},
		{"blank file", writeConfigSecret(t, " \r\n\t"), "/tmp/periapsis-performance/pgdata"},
		{"invalid UTF8 file", writeConfigSecret(t, configTestURL+string([]byte{0xff})), "/tmp/periapsis-performance/pgdata"},
		{"file over limit", writeConfigSecret(t, configTestURL+strings.Repeat(" ", 16*1024+1-len(configTestURL))), "/tmp/periapsis-performance/pgdata"},
		{"directory env missing", valid, ""},
		{"relative directory", valid, "relative/" + configTestSecret},
		{"root directory", valid, "/"},
		{"traversal directory", valid, "/tmp/../" + configTestSecret},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := readDatabaseConfig(configEnvironment(test.file, test.directory))
			assertGenericConfigError(t, err, test.file, test.directory)
		})
	}
	boundary := writeConfigSecret(t, configTestURL+strings.Repeat(" ", 16*1024-len(configTestURL)))
	if got, err := readDatabaseConfig(configEnvironment(boundary, "/tmp/periapsis-performance/pgdata")); err != nil || got.URL != configTestURL {
		t.Fatal("exactly 16 KiB regular secret with valid trimmed content was rejected")
	}
}

func TestNormalizeDataDirectory(t *testing.T) {
	for _, test := range []struct {
		name  string
		input string
		want  string
	}{
		{"Unix", "/tmp/periapsis-performance/pgdata", "/tmp/periapsis-performance/pgdata"},
		{"Unix trailing slash", "/tmp/periapsis-performance/pgdata/", "/tmp/periapsis-performance/pgdata"},
		{"Windows backslashes", `C:\Benchmark\PGDATA`, "c:/benchmark/pgdata"},
		{"Windows slashes", "D:/Benchmark/PGDATA/", "d:/benchmark/pgdata"},
		{"Windows dedicated first level", "C:/PgData", "c:/pgdata"},
		{"duplicate separators", "/tmp/performance//pgdata", "/tmp/performance/pgdata"},
		{"Unix case preserved", "/tmp/Performance/PGDATA", "/tmp/Performance/PGDATA"},
		{"directory spaces", "/tmp/performance fixture/pgdata", "/tmp/performance fixture/pgdata"},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := normalizeDataDirectory(test.input)
			if err != nil || got != test.want {
				t.Fatalf("normalization=%q error=%v, want %q", got, err, test.want)
			}
		})
	}
	for _, input := range []string{
		"", " \t\r\n", "/", `C:\`, "d:/", "relative/pgdata", `C:relative\pgdata`,
		"//server/share/pgdata", `\\server\share\pgdata`,
		"/tmp", "/var", "/var/lib", "/home", "/root", "/workspace", "/run", "/etc", "/usr", "/opt", "/data",
		`C:\Users`, "C:/Windows", "C:/Program Files",
		"C:/Windows.", "C:/Users /pgdata", "C:/benchmark?/pgdata", "C:/benchmark/pgdata:stream",
		"/tmp/./pgdata", "/tmp/../pgdata", `C:\benchmark\..\pgdata`,
		"/tmp/" + configTestSecret + "\n/pgdata", "/tmp/pg\x00data", "/tmp/pg\tdata",
	} {
		t.Run("reject "+strings.ReplaceAll(input, "\x00", "NUL"), func(t *testing.T) {
			_, err := normalizeDataDirectory(input)
			assertGenericConfigError(t, err, input)
		})
	}
}

func TestReadDatabaseConfigRejectsSymlinkSecret(t *testing.T) {
	target := writeConfigSecret(t, configTestURL)
	link := filepath.Join(t.TempDir(), "database-url-link.secret")
	if err := os.Symlink(target, link); err != nil {
		t.Skip("operating system does not permit symlinks in the test workspace")
	}
	_, err := readDatabaseConfig(configEnvironment(link, "/tmp/periapsis-performance/pgdata"))
	assertGenericConfigError(t, err, link, target)
}

func TestReadDatabaseConfigRejectsMissingEnvironmentReader(t *testing.T) {
	got, err := readDatabaseConfig(nil)
	assertGenericConfigError(t, err)
	if got != (databaseConfig{}) || err != errInvalidDatabaseConfig {
		t.Fatal("missing environment reader returned partial configuration or a nongeneric error")
	}
}

func TestDatabaseConfigFormattingRedactsValues(t *testing.T) {
	config := databaseConfig{
		URL:      "postgres://postgres:" + configTestSecret + "@127.0.0.1:5432/" + configTestDatabase + "?sslmode=disable",
		Database: configTestDatabase, ExpectedDataDirectory: "/tmp/" + configTestSecret + "/pgdata",
	}
	for _, format := range []string{"%v", "%+v", "%#v"} {
		formatted := fmt.Sprintf(format, config)
		for _, sensitive := range []string{config.URL, config.Database, config.ExpectedDataDirectory, configTestSecret} {
			if strings.Contains(formatted, sensitive) {
				t.Fatal("formatted database configuration disclosed a supplied value")
			}
		}
		if !strings.Contains(formatted, "[REDACTED]") {
			t.Fatal("formatted database configuration omitted its redaction marker")
		}
	}
}

func configEnvironment(file, directory string) func(string) string {
	return func(key string) string {
		switch key {
		case configTestFileEnv:
			return file
		case configTestDataEnv:
			return directory
		default:
			return ""
		}
	}
}

func writeConfigSecret(t *testing.T, value string) string {
	t.Helper()
	file := filepath.Join(t.TempDir(), "database-url.secret")
	if err := os.WriteFile(file, []byte(value), 0o600); err != nil {
		t.Fatal(err)
	}
	return file
}

func assertGenericConfigError(t *testing.T, err error, sensitive ...string) {
	t.Helper()
	if err == nil {
		t.Fatal("unsafe configuration was accepted")
	}
	if err != errInvalidOptions && err != errInvalidDatabaseConfig {
		t.Fatal("configuration returned a nongeneric error")
	}
	for _, value := range append(sensitive, configTestSecret, configTestDatabase) {
		// Single-character invalid paths (such as '/') are not enough to
		// distinguish an echoed value from ordinary generic error wording.
		if len(value) > 2 && strings.Contains(err.Error(), value) {
			t.Fatal("configuration error echoed a supplied value")
		}
	}
}
