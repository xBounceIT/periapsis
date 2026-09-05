const deploymentEnvironments = new Set(["development", "test", "production"]);
const maximumDatabaseUrlBytes = 4_096;

export function parseDeploymentEnvironment(value) {
  const environment = value ?? "production";
  if (!deploymentEnvironments.has(environment)) {
    throw configurationError("INVALID_ENVIRONMENT");
  }
  return environment;
}

export function validateAdministratorDatabaseUrl(value, { production }) {
  if (
    typeof value !== "string" ||
    value.length < 1 ||
    Buffer.byteLength(value, "utf8") > maximumDatabaseUrlBytes ||
    /[\u0000-\u0020\u007f]/u.test(value)
  ) {
    throw configurationError("INVALID_DATABASE_URL");
  }

  let url;
  try {
    url = new URL(value);
  } catch {
    throw configurationError("INVALID_DATABASE_URL");
  }
  if (
    !["postgres:", "postgresql:"].includes(url.protocol) ||
    url.hostname.length === 0 ||
    url.username.length === 0 ||
    url.password.length === 0 ||
    url.pathname.length < 2 ||
    url.hash.length > 0
  ) {
    throw configurationError("INVALID_DATABASE_URL");
  }

  let decodedPassword;
  let decodedUsername;
  try {
    decodedPassword = decodeURIComponent(url.password);
    decodedUsername = decodeURIComponent(url.username);
  } catch {
    throw configurationError("INVALID_DATABASE_URL");
  }
  if (
    decodedPassword.length < 16 ||
    decodedPassword.includes("\0") ||
    decodedUsername.length < 1 ||
    decodedUsername.includes("\0")
  ) {
    throw configurationError("INVALID_DATABASE_URL");
  }

  if (production) {
    const sslModes = url.searchParams.getAll("sslmode");
    if (
      sslModes.length !== 1 ||
      sslModes[0] !== "verify-full" ||
      url.searchParams.has("ssl")
    ) {
      throw configurationError("DATABASE_TLS_REQUIRED");
    }
  }
  return url.toString();
}

function configurationError(code) {
  return Object.assign(new Error("invalid database task configuration"), {
    code,
  });
}
