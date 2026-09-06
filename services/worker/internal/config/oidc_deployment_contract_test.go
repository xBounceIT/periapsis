package config

import (
	"bufio"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestOIDCMaintenanceConfigurationIsWiredAcrossDeployments(t *testing.T) {
	root := oidcDeploymentRepositoryRoot(t)
	settings := []string{
		"PERIAPSIS_FEDERATED_CA_BUNDLE_FILE",
		"PERIAPSIS_FEDERATED_HTTPS_PORTS",
		"PERIAPSIS_FEDERATED_MAX_CONCURRENT",
		"PERIAPSIS_FEDERATED_OPERATION_TIMEOUT",
		"PERIAPSIS_FEDERATED_PRIVATE_EGRESS_CIDRS",
		"PERIAPSIS_OIDC_MAINTENANCE_BATCH_SIZE",
		"PERIAPSIS_OIDC_MAINTENANCE_LEASE_SAFETY",
		"PERIAPSIS_OIDC_MAINTENANCE_POLL_INTERVAL",
	}
	for _, path := range []string{".env.example", "deploy/compose/.env.example"} {
		document := oidcDeploymentRead(t, root, path)
		for _, setting := range settings {
			if !strings.Contains(document, setting+"=") {
				t.Errorf("%s does not expose %s", path, setting)
			}
		}
	}
	swarmEnvironment := oidcDeploymentRead(t, root, "deploy/swarm/.env.example")
	for _, setting := range settings {
		if setting == "PERIAPSIS_FEDERATED_CA_BUNDLE_FILE" {
			continue
		}
		if !strings.Contains(swarmEnvironment, setting+"=") {
			t.Errorf("deploy/swarm/.env.example does not expose %s", setting)
		}
	}
	if !strings.Contains(swarmEnvironment, "PERIAPSIS_FEDERATED_CA_BUNDLE_SECRET=") ||
		strings.Contains(swarmEnvironment, "PERIAPSIS_FEDERATED_CA_BUNDLE_FILE=") {
		t.Fatal("Swarm must expose a versioned federated CA secret name, not an arbitrary container path")
	}
	for _, path := range []string{"deploy/compose/compose.base.yaml", "deploy/swarm/stack.yml"} {
		document := oidcDeploymentRead(t, root, path)
		worker := oidcDeploymentServiceBlock(t, document, "worker")
		for _, setting := range settings {
			// The shared Compose model intentionally uses system trust. Only the
			// local-TLS layer adds the development CA; both layers are checked below.
			if path == "deploy/compose/compose.base.yaml" && setting == "PERIAPSIS_FEDERATED_CA_BUNDLE_FILE" {
				continue
			}
			if !strings.Contains(worker, "      "+setting+": ") {
				t.Errorf("%s worker does not receive %s", path, setting)
			}
		}
		assertNoDuplicateOIDCWorkerEnvironment(t, path, worker)
	}
	for entrypoint, overlay := range map[string]string{
		"compose.yaml":               "compose.tls.yaml",
		"compose.reverse-proxy.yaml": "reverse-proxy.override.yaml",
	} {
		document := oidcDeploymentRead(t, root, "deploy/compose/"+entrypoint)
		if !oidcComposeEntrypointMatches(document, overlay) {
			t.Errorf("%s must include only the shared model followed by %s", entrypoint, overlay)
		}
	}
	for _, path := range []string{"deploy/compose/compose.base.yaml", "deploy/compose/reverse-proxy.override.yaml"} {
		document := oidcDeploymentRead(t, root, path)
		for _, localTLSSetting := range []string{"PERIAPSIS_FEDERATED_CA_BUNDLE_FILE", "PERIAPSIS_DEV_TLS_", "dev_tls_"} {
			if strings.Contains(document, localTLSSetting) {
				t.Errorf("%s must not require or mount the local development CA/certificates", path)
			}
		}
	}
	for _, path := range []string{"deploy/compose/compose.tls.yaml", "deploy/compose/reverse-proxy.override.yaml"} {
		document := oidcDeploymentRead(t, root, path)
		worker := oidcDeploymentServiceBlock(t, document, "worker")
		assertNoDuplicateOIDCWorkerEnvironment(t, path, worker)
		// Neither overlay may replace/reset the shared environment or override
		// its bounded OIDC maintenance and HTTPS/SSRF settings.
		for _, tag := range []string{"!reset", "!override"} {
			if strings.Contains(document, tag) {
				t.Errorf("%s must preserve inherited runtime settings", path)
			}
		}
		for _, setting := range settings {
			if setting != "PERIAPSIS_FEDERATED_CA_BUNDLE_FILE" && strings.Contains(worker, setting+":") {
				t.Errorf("%s must inherit %s from the shared model", path, setting)
			}
		}
	}
	composeTLS := oidcDeploymentRead(t, root, "deploy/compose/compose.tls.yaml")
	for _, service := range []string{"api", "worker"} {
		block := oidcDeploymentServiceBlock(t, composeTLS, service)
		if !strings.Contains(block, "      PERIAPSIS_FEDERATED_CA_BUNDLE_FILE: /run/secrets/periapsis-dev-tls-ca.crt\n") ||
			!strings.Contains(block, "    secrets:\n      - source: dev_tls_ca\n        target: periapsis-dev-tls-ca.crt\n        uid: \"10001\"\n        gid: \"10001\"\n        mode: 0444\n") {
			t.Errorf("Compose TLS %s must receive the development CA at its fixed path with non-root read access", service)
		}
	}
	if !strings.Contains(composeTLS, "  dev_tls_ca:\n    file: ${PERIAPSIS_DEV_TLS_CA_FILE:?") {
		t.Fatal("Compose TLS must declare the required file-backed development CA")
	}
	composeProxy := oidcDeploymentRead(t, root, "deploy/compose/reverse-proxy.override.yaml")
	proxyWeb := oidcDeploymentServiceBlock(t, composeProxy, "web")
	for _, setting := range []string{
		"      PERIAPSIS_WEB_PROXY_ONLY: \"true\"\n",
		"      PERIAPSIS_PUBLIC_URL: ${PERIAPSIS_PUBLIC_URL:?",
		"      PERIAPSIS_WEB_TRUSTED_PROXY_CIDRS: ${PERIAPSIS_WEB_TRUSTED_PROXY_CIDRS:?",
	} {
		if !strings.Contains(proxyWeb, setting) {
			t.Error("Compose HTTP origin must require proxy-only mode, a public HTTPS origin and explicit proxy trust")
		}
	}
	proxyWorker := oidcDeploymentServiceBlock(t, composeProxy, "worker")
	if !strings.Contains(proxyWorker, "    networks:\n      proxy-egress: {}") ||
		!strings.Contains(composeProxy, "\n  proxy-egress: {}\n") {
		t.Fatal("Compose HTTP origin worker must retain outbound access to the external HTTPS identity provider")
	}
	swarm := oidcDeploymentRead(t, root, "deploy/swarm/stack.yml")
	for _, service := range []string{"api", "worker"} {
		block := oidcDeploymentServiceBlock(t, swarm, service)
		if !strings.Contains(block, "PERIAPSIS_FEDERATED_CA_BUNDLE_FILE: /run/secrets/federated_ca_bundle") ||
			!strings.Contains(block, "source: federated_ca_bundle") ||
			!strings.Contains(block, "target: federated_ca_bundle") {
			t.Errorf("Swarm %s does not mount the versioned federated CA at its fixed path", service)
		}
	}
	if !strings.Contains(swarm, "PERIAPSIS_FEDERATED_CA_BUNDLE_SECRET:-periapsis_federated_ca_bundle_v1") {
		t.Fatal("Swarm does not declare the versioned external federated CA secret")
	}
	kubernetes := oidcDeploymentRead(t, root, "deploy/k8s/base/config-map.yaml")
	for _, setting := range settings {
		if count := strings.Count(kubernetes, setting+":"); count != 1 {
			t.Errorf("Kubernetes runtime config count for %s = %d, want 1", setting, count)
		}
	}
	if !strings.Contains(kubernetes, "PERIAPSIS_FEDERATED_CA_BUNDLE_FILE: /run/secrets/federated-ca-bundle") {
		t.Fatal("Kubernetes does not use the fixed projected federated CA path")
	}
	for _, service := range []string{"api", "worker"} {
		deployment := oidcDeploymentRead(t, root, "deploy/k8s/base/"+service+"-deployment.yaml")
		if !strings.Contains(deployment, "configMapRef:\n                name: periapsis-runtime") {
			t.Errorf("Kubernetes %s does not consume the shared bounded runtime config", service)
		}
		if !strings.Contains(deployment, "- key: federated-ca-bundle\n                path: federated-ca-bundle") {
			t.Errorf("Kubernetes %s does not project the federated CA bundle", service)
		}
	}
}

func TestOIDCDeploymentYAMLHasNoTabsOrDuplicateWorkerSettings(t *testing.T) {
	root := oidcDeploymentRepositoryRoot(t)
	for _, path := range []string{
		"deploy/compose/compose.yaml", "deploy/compose/compose.reverse-proxy.yaml",
		"deploy/compose/compose.base.yaml", "deploy/compose/compose.tls.yaml",
		"deploy/compose/reverse-proxy.override.yaml", "deploy/swarm/stack.yml",
		"deploy/k8s/base/config-map.yaml",
	} {
		document := oidcDeploymentRead(t, root, path)
		if strings.ContainsRune(document, '\t') {
			t.Errorf("%s contains a YAML tab", path)
		}
	}
}

func TestOIDCComposeEntrypointContractRejectsDifferentLayerGraphs(t *testing.T) {
	for _, overlay := range []string{"compose.tls.yaml", "reverse-proxy.override.yaml"} {
		t.Run(overlay, func(t *testing.T) {
			valid := "name: periapsis\ninclude:\n  - path: [./compose.base.yaml, ./" + overlay + "]\n"
			for _, document := range []string{valid, "# An explanatory comment\n\n" + strings.ReplaceAll(valid, "\n", "\r\n")} {
				if !oidcComposeEntrypointMatches(document, overlay) {
					t.Fatal("expected entrypoint, with comments or CRLF, was rejected")
				}
			}
			for name, document := range map[string]string{
				"missing base":     strings.Replace(valid, "./compose.base.yaml, ", "", 1),
				"reversed layers":  strings.Replace(valid, "./compose.base.yaml, ./"+overlay, "./"+overlay+", ./compose.base.yaml", 1),
				"different base":   strings.Replace(valid, "./compose.base.yaml", "./unreviewed.yaml", 1),
				"different layer":  strings.Replace(valid, "./"+overlay, "./unreviewed.yaml", 1),
				"additional layer": strings.Replace(valid, "]", ", ./unreviewed.yaml]", 1),
				"second include":   valid + "  - path: ./unreviewed.yaml\n",
				"inline override":  valid + "services:\n  worker:\n    environment: {}\n",
			} {
				t.Run(name, func(t *testing.T) {
					if oidcComposeEntrypointMatches(document, overlay) {
						t.Fatal("changed Compose layer graph was accepted")
					}
				})
			}
		})
	}
}

// This is a source-layout contract, not a YAML merge implementation. The real
// resolved model is checked separately by scripts/deploy/compose-models.test.mjs.
func oidcComposeEntrypointMatches(document, overlay string) bool {
	var lines []string
	for _, line := range strings.Split(strings.ReplaceAll(document, "\r\n", "\n"), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" && !strings.HasPrefix(trimmed, "#") {
			lines = append(lines, line)
		}
	}
	return strings.Join(lines, "\n") == "name: periapsis\ninclude:\n  - path: [./compose.base.yaml, ./"+overlay+"]"
}

func assertNoDuplicateOIDCWorkerEnvironment(t *testing.T, path, worker string) {
	t.Helper()
	insideEnvironment := false
	seen := make(map[string]struct{})
	scanner := bufio.NewScanner(strings.NewReader(worker))
	for scanner.Scan() {
		line := scanner.Text()
		if line == "    environment:" {
			insideEnvironment = true
			continue
		}
		if !insideEnvironment {
			continue
		}
		if strings.HasPrefix(line, "    ") && !strings.HasPrefix(line, "      ") {
			break
		}
		if !strings.HasPrefix(line, "      PERIAPSIS_") {
			continue
		}
		name, _, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok {
			continue
		}
		if _, duplicate := seen[name]; duplicate {
			t.Errorf("%s worker repeats %s", path, name)
		}
		seen[name] = struct{}{}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
}

func oidcDeploymentServiceBlock(t *testing.T, document, service string) string {
	t.Helper()
	marker := "\n  " + service + ":"
	start := strings.Index(document, marker)
	if start < 0 {
		t.Fatalf("service %s is missing", service)
	}
	remainder := document[start+len(marker):]
	lines := strings.Split(remainder, "\n")
	end := len(lines)
	for index := 1; index < len(lines); index++ {
		line := lines[index]
		if strings.HasPrefix(line, "  ") && !strings.HasPrefix(line, "    ") && strings.HasSuffix(line, ":") {
			end = index
			break
		}
	}
	return strings.Join(lines[:end], "\n")
}

func oidcDeploymentRead(t *testing.T, root, path string) string {
	t.Helper()
	document, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(path)))
	if err != nil {
		t.Fatal(err)
	}
	return strings.ReplaceAll(string(document), "\r\n", "\n")
}

func oidcDeploymentRepositoryRoot(t *testing.T) string {
	t.Helper()
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve test source path")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(source), "..", "..", "..", ".."))
}
