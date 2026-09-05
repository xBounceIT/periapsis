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
	for _, path := range []string{"deploy/compose/compose.yaml", "deploy/swarm/stack.yml"} {
		document := oidcDeploymentRead(t, root, path)
		worker := oidcDeploymentServiceBlock(t, document, "worker")
		for _, setting := range settings {
			if !strings.Contains(worker, setting+":") {
				t.Errorf("%s worker does not receive %s", path, setting)
			}
		}
		assertNoDuplicateOIDCWorkerEnvironment(t, path, worker)
	}
	compose := oidcDeploymentRead(t, root, "deploy/compose/compose.yaml")
	composeWorker := oidcDeploymentServiceBlock(t, compose, "worker")
	if !strings.Contains(composeWorker, "source: dev_tls_ca") ||
		!strings.Contains(composeWorker, "target: periapsis-dev-tls-ca.crt") {
		t.Fatal("Compose worker does not receive the configured federated development CA")
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
		"deploy/compose/compose.yaml", "deploy/swarm/stack.yml", "deploy/k8s/base/config-map.yaml",
	} {
		document := oidcDeploymentRead(t, root, path)
		if strings.ContainsRune(document, '\t') {
			t.Errorf("%s contains a YAML tab", path)
		}
	}
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
	return string(document)
}

func oidcDeploymentRepositoryRoot(t *testing.T) string {
	t.Helper()
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve test source path")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(source), "..", "..", "..", ".."))
}
