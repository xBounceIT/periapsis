import {
  Alert,
  AlertDescription,
  AlertTitle,
} from "@periapsis/ui/components/ui/alert";
import { Badge } from "@periapsis/ui/components/ui/badge";
import { Button } from "@periapsis/ui/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@periapsis/ui/components/ui/card";
import { Checkbox } from "@periapsis/ui/components/ui/checkbox";
import { Input } from "@periapsis/ui/components/ui/input";
import { Label } from "@periapsis/ui/components/ui/label";
import { Textarea } from "@periapsis/ui/components/ui/textarea";
import {
  CheckCircle2,
  KeyRound,
  LockKeyhole,
  Plus,
  RefreshCw,
  Trash2,
} from "lucide-react";
import { useEffect, useRef, useState, type FormEvent } from "react";

import type {
  TenantFederationAuthProvider,
  TenantFederationAuthProviderCreateRequest,
  TenantFederationAuthProviderSummary,
  TenantFederationAuthProviderUpdateRequest,
  TenantFederationAssurancePolicy,
  TenantFederationAssurancePolicyReplaceRequest,
  TenantFederationMappingPolicy,
  TenantFederationMappingPolicyReplaceRequest,
  TenantOidcTrustDocumentsRefreshRequest,
} from "@periapsis/contracts";

import { useSession } from "../auth/session-context";
import { useTenantAuthority } from "../auth/tenant-authority-context";
import { FocusedError } from "../components/focused-error";
import { FormField } from "../components/form-field";
import { ServerDenied } from "../components/server-denied";
import {
  describePhaseTwoError,
  PhaseTwoApiError,
} from "../lib/phase-two-types";
import { generateUuidV7 } from "../lib/uuid-v7";
import {
  assertTenantFederationAssurancePolicyReplacement,
  assertTenantFederationMappingPolicyReplacement,
  tenantFederationApi,
  type TenantFederationApi,
  type TenantFederationAssurancePolicyVersioned,
  type TenantFederationMappingPolicyContext,
  type TenantFederationMappingPolicyVersioned,
  type TenantFederationProviderVersioned,
} from "./tenant-federation-api";
// oxlint-disable-next-line import/no-unassigned-import -- Page-scoped federation administration styles.
import "./tenant-federation.css";

type InventoryState =
  | { kind: "loading" }
  | { kind: "error"; message: string }
  | {
      kind: "ready";
      items: readonly TenantFederationAuthProviderSummary[];
      nextCursor?: string;
    };

type DetailState =
  | { kind: "idle" }
  | { kind: "loading"; providerId: string }
  | { kind: "error"; providerId: string; message: string }
  | { kind: "ready"; versioned: TenantFederationProviderVersioned };

type MappingPolicyState =
  | { kind: "idle" | "loading" }
  | { kind: "error"; message: string }
  | {
      kind: "ready";
      versioned: TenantFederationMappingPolicyVersioned;
    };

type AssurancePolicyState =
  | { kind: "idle" | "loading" }
  | { kind: "error"; message: string }
  | {
      kind: "ready";
      versioned: TenantFederationAssurancePolicyVersioned;
    };

interface TenantFederationPageProps {
  api?: TenantFederationApi;
}

type SAMLProvider = Extract<TenantFederationAuthProvider, { kind: "saml" }>;
type SAMLSignatureAlgorithm =
  SAMLProvider["configuration"]["redirectSignatureAlgorithm"];
type SAMLSignaturePolicy = SAMLProvider["configuration"]["signaturePolicy"];
type SAMLSubjectSource = SAMLProvider["configuration"]["subjectSource"];
type OIDCSigningAlgorithm =
  TenantOidcTrustDocumentsRefreshRequest["signingAlgorithms"][number];

const samlSignatureAlgorithms: readonly SAMLSignatureAlgorithm[] = [
  "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
  "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384",
  "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512",
  "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256",
  "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384",
  "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512",
];

const tenantOIDCPostLogoutRedirectPath = "/signed-out";
// HTML maxLength counts UTF-16 code units while the API contract counts Unicode
// code points. Two code units per allowed code point avoids rejecting astral
// characters in the browser; submit validation remains the canonical boundary.
const federationDisplayNameDOMMaxLength = 120 * 2;
const federationDescriptionDOMMaxLength = 1000 * 2;
const federationAuditReasonDOMMaxLength = 500 * 2;

export function TenantFederationPage({
  api = tenantFederationApi,
}: TenantFederationPageProps = {}): React.JSX.Element {
  const { session } = useSession();
  const authority = useTenantAuthority();
  const tenantId = session.activeTenantId;
  const canRead = authority.hasPermission("identity_provider.read", "tenant");

  if (!tenantId || authority.status === "inactive") {
    return (
      <div className="content federation-page">
        <Card>
          <CardHeader>
            <CardTitle>Select a tenant to manage federation.</CardTitle>
            <CardDescription>
              OIDC and SAML providers are always owned by one explicit tenant.
            </CardDescription>
          </CardHeader>
        </Card>
      </div>
    );
  }
  if (authority.status === "forbidden") {
    return <ServerDenied resource="tenant federated identity providers" />;
  }
  if (authority.status === "error") {
    return (
      <div className="content federation-page federation-page__error">
        <FocusedError
          message={authority.message ?? "Tenant authority could not be loaded."}
        />
        <Button type="button" variant="outline" onClick={authority.reload}>
          <RefreshCw aria-hidden="true" /> Reload tenant authority
        </Button>
      </div>
    );
  }
  if (authority.status !== "ready") return <FederationSkeleton />;
  if (!canRead)
    return <ServerDenied resource="tenant federated identity providers" />;

  return (
    <TenantFederationTenantScope key={tenantId} api={api} tenantId={tenantId} />
  );
}

function TenantFederationTenantScope({
  api,
  tenantId,
}: {
  api: TenantFederationApi;
  tenantId: string;
}): React.JSX.Element {
  const { clearSession, session } = useSession();
  const authority = useTenantAuthority();
  const canRead = authority.hasPermission("identity_provider.read", "tenant");
  const canManage = authority.hasPermission(
    "identity_provider.manage",
    "tenant",
  );
  const canReadMapping = authority.hasPermission(
    "identity_mapping.read",
    "tenant",
  );
  const canManageMapping =
    authority.hasPermission("identity_mapping.manage", "tenant") &&
    authority.hasPermission("role.grant", "tenant");
  const canReadAssurance = authority.hasPermission(
    "identity_policy.read",
    "tenant",
  );
  const canManageAssurance = authority.hasPermission(
    "identity_policy.manage",
    "tenant",
  );
  const [inventory, setInventory] = useState<InventoryState>({
    kind: "loading",
  });
  const [detail, setDetail] = useState<DetailState>({ kind: "idle" });
  const [revision, setRevision] = useState(0);
  const [createOpen, setCreateOpen] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [loadingMore, setLoadingMore] = useState(false);
  const inventoryGeneration = useRef(0);
  const loadMoreRequest = useRef<AbortController | null>(null);
  const detailRequest = useRef({
    controller: null as AbortController | null,
    generation: 0,
  });

  useEffect(
    () => () => {
      detailRequest.current.controller?.abort();
      detailRequest.current.generation += 1;
    },
    [api],
  );

  useEffect(() => {
    if (authority.status !== "ready" || !tenantId || !canRead) return undefined;
    const controller = new AbortController();
    const generation = inventoryGeneration.current + 1;
    inventoryGeneration.current = generation;
    loadMoreRequest.current?.abort();
    loadMoreRequest.current = null;
    setLoadingMore(false);
    setInventory({ kind: "loading" });
    void api
      .list(tenantId, { signal: controller.signal })
      .then((page) => {
        if (page.items.some((provider) => provider.tenantId !== tenantId)) {
          throw new Error(
            "The provider inventory did not match its tenant scope.",
          );
        }
        if (
          !controller.signal.aborted &&
          inventoryGeneration.current === generation
        )
          setInventory({ kind: "ready", ...page });
      })
      .catch((caught: unknown) => {
        if (
          controller.signal.aborted ||
          inventoryGeneration.current !== generation
        )
          return;
        handleAuthorityError(caught, authority.reload, () =>
          clearSession(session.id),
        );
        setInventory({
          kind: "error",
          message: describeFederationError(
            caught,
            "The federated provider inventory could not be loaded.",
          ),
        });
      });
    return () => {
      controller.abort();
      loadMoreRequest.current?.abort();
    };
  }, [
    api,
    authority.status,
    canRead,
    clearSession,
    revision,
    session.id,
    tenantId,
  ]);

  async function inspect(providerId: string): Promise<void> {
    detailRequest.current.controller?.abort();
    const controller = new AbortController();
    const generation = detailRequest.current.generation + 1;
    detailRequest.current = { controller, generation };
    setDetail({ kind: "loading", providerId });
    try {
      const versioned = await api.get(tenantId, providerId, controller.signal);
      if (
        controller.signal.aborted ||
        detailRequest.current.generation !== generation
      ) {
        return;
      }
      if (
        versioned.value.tenantId !== tenantId ||
        versioned.value.id !== providerId
      ) {
        throw new Error("The provider detail did not match its tenant scope.");
      }
      setDetail({ kind: "ready", versioned });
    } catch (caught) {
      if (
        controller.signal.aborted ||
        detailRequest.current.generation !== generation
      ) {
        return;
      }
      handleAuthorityError(caught, authority.reload, () =>
        clearSession(session.id),
      );
      setDetail({
        kind: "error",
        providerId,
        message: describeFederationError(
          caught,
          "The provider detail could not be loaded.",
        ),
      });
    } finally {
      if (detailRequest.current.generation === generation) {
        detailRequest.current.controller = null;
      }
    }
  }

  async function loadMore(): Promise<void> {
    if (
      !tenantId ||
      loadingMore ||
      inventory.kind !== "ready" ||
      !inventory.nextCursor
    )
      return;
    const cursor = inventory.nextCursor;
    const generation = inventoryGeneration.current;
    loadMoreRequest.current?.abort();
    const controller = new AbortController();
    loadMoreRequest.current = controller;
    setLoadingMore(true);
    try {
      const page = await api.list(tenantId, {
        after: cursor,
        signal: controller.signal,
      });
      if (
        controller.signal.aborted ||
        inventoryGeneration.current !== generation
      ) {
        return;
      }
      if (page.items.some((provider) => provider.tenantId !== tenantId)) {
        throw new Error(
          "The provider inventory did not match its tenant scope.",
        );
      }
      const seen = new Set(inventory.items.map((item) => item.id));
      if (page.items.some((item) => seen.has(item.id))) {
        throw new Error("The federated provider cursor did not advance.");
      }
      setInventory((current) => {
        if (
          current.kind !== "ready" ||
          current.nextCursor !== cursor ||
          inventoryGeneration.current !== generation
        ) {
          return current;
        }
        return {
          kind: "ready",
          items: [...current.items, ...page.items],
          ...(page.nextCursor ? { nextCursor: page.nextCursor } : {}),
        };
      });
    } catch (caught) {
      if (
        controller.signal.aborted ||
        inventoryGeneration.current !== generation
      ) {
        return;
      }
      setNotice(
        describeFederationError(
          caught,
          "More federated providers could not be loaded.",
        ),
      );
    } finally {
      if (loadMoreRequest.current === controller) {
        loadMoreRequest.current = null;
        if (inventoryGeneration.current === generation) setLoadingMore(false);
      }
    }
  }

  return (
    <div className="content federation-page">
      <section className="page-heading federation-page__heading">
        <div>
          <p className="section-label">Tenant administration</p>
          <h1>Federated identity providers</h1>
          <p>
            Stage tenant-owned OIDC and SAML login, inspect only safe public
            configuration, and rotate credentials through write-only controls.
            The API rechecks live authority for every action.
          </p>
        </div>
        {canManage ? (
          <Button
            type="button"
            onClick={() => setCreateOpen((value) => !value)}
          >
            <Plus aria-hidden="true" />{" "}
            {createOpen ? "Close form" : "Create provider"}
          </Button>
        ) : null}
      </section>

      {notice ? (
        <Alert>
          <CheckCircle2 aria-hidden="true" />
          <AlertTitle>Federation update</AlertTitle>
          <AlertDescription>{notice}</AlertDescription>
        </Alert>
      ) : null}

      {createOpen && canManage ? (
        <CreateFederationProviderForm
          api={api}
          csrfToken={session.csrfToken}
          tenantId={tenantId}
          onCreated={(provider) => {
            if (provider.value.tenantId !== tenantId) {
              setDetail({ kind: "idle" });
              setNotice("The created provider did not match its tenant scope.");
              return;
            }
            setCreateOpen(false);
            setNotice(
              "The provider and login binding were created disabled. Install protected material and review readiness before enabling login.",
            );
            setRevision((value) => value + 1);
            setDetail({ kind: "ready", versioned: provider });
          }}
          onError={(caught) => {
            handleAuthorityError(caught, authority.reload, () =>
              clearSession(session.id),
            );
          }}
        />
      ) : null}

      {inventory.kind === "loading" ? (
        <FederationSkeleton />
      ) : inventory.kind === "error" ? (
        <Card>
          <CardContent className="federation-page__error">
            <FocusedError message={inventory.message} />
            <Button
              type="button"
              variant="outline"
              onClick={() => setRevision((value) => value + 1)}
            >
              <RefreshCw aria-hidden="true" /> Retry inventory
            </Button>
          </CardContent>
        </Card>
      ) : (
        <Card>
          <CardHeader>
            <CardTitle>Tenant federation inventory</CardTitle>
            <CardDescription>
              Presence and revision flags replace credential, token, metadata,
              certificate, assertion, claim, and subject readback.
            </CardDescription>
          </CardHeader>
          <CardContent>
            {inventory.items.length === 0 ? (
              <p className="federation-empty">
                No federated providers are configured for this tenant.
              </p>
            ) : (
              <div
                className="federation-grid"
                role="list"
                aria-label="Federated identity providers"
              >
                {inventory.items.map((provider) => (
                  <article
                    className="federation-provider"
                    role="listitem"
                    key={provider.id}
                  >
                    <div className="federation-provider__header">
                      <div>
                        <span className="federation-provider__kind">
                          {provider.kind.toUpperCase()}
                        </span>
                        <h2>{provider.displayName}</h2>
                        <code>{provider.key}</code>
                      </div>
                      <ProviderBadge provider={provider} />
                    </div>
                    <dl>
                      <div>
                        <dt>Login key</dt>
                        <dd>{provider.binding.loginKey}</dd>
                      </div>
                      <div>
                        <dt>Configuration</dt>
                        <dd>{provider.configured ? "Ready" : "Incomplete"}</dd>
                      </div>
                      <div>
                        <dt>Version</dt>
                        <dd>{provider.version}</dd>
                      </div>
                    </dl>
                    <Button
                      type="button"
                      variant="outline"
                      onClick={() => void inspect(provider.id)}
                    >
                      Inspect and manage
                    </Button>
                  </article>
                ))}
              </div>
            )}
            {inventory.nextCursor ? (
              <Button
                type="button"
                variant="outline"
                disabled={loadingMore}
                onClick={() => void loadMore()}
              >
                {loadingMore ? "Loading more…" : "Load more providers"}
              </Button>
            ) : null}
          </CardContent>
        </Card>
      )}

      <ProviderDetail
        api={api}
        canManage={canManage}
        canManageAssurance={canManageAssurance}
        canManageMapping={canManageMapping}
        canReadAssurance={canReadAssurance}
        canReadMapping={canReadMapping}
        csrfToken={session.csrfToken}
        state={detail}
        tenantId={tenantId}
        onChanged={(message, provider) => {
          if (provider && provider.value.tenantId !== tenantId) {
            setDetail({ kind: "idle" });
            setNotice("The updated provider did not match its tenant scope.");
            return;
          }
          setNotice(message);
          setRevision((value) => value + 1);
          if (provider) setDetail({ kind: "ready", versioned: provider });
          else setDetail({ kind: "idle" });
        }}
        onError={(caught) => {
          handleAuthorityError(caught, authority.reload, () =>
            clearSession(session.id),
          );
        }}
      />
    </div>
  );
}

function CreateFederationProviderForm({
  api,
  csrfToken,
  onCreated,
  onError,
  tenantId,
}: {
  api: TenantFederationApi;
  csrfToken: string;
  onCreated: (provider: TenantFederationProviderVersioned) => void;
  onError: (error: unknown) => void;
  tenantId: string;
}): React.JSX.Element {
  const [kind, setKind] = useState<"oidc" | "saml">("oidc");
  const [key, setKey] = useState("");
  const [loginKey, setLoginKey] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [description, setDescription] = useState("");
  const [issuerOrEntity, setIssuerOrEntity] = useState("");
  const [clientId, setClientId] = useState("");
  const postLogoutRedirectUri = tenantOIDCPostLogoutRedirectURI();
  const [extraScopes, setExtraScopes] = useState("email, profile");
  const [allowRefreshToken, setAllowRefreshToken] = useState(false);
  const [useUserInfo, setUseUserInfo] = useState(false);
  const [jitMode, setJitMode] = useState<"disabled" | "create">("disabled");
  const [noMatchPolicy, setNoMatchPolicy] = useState<
    "deny" | "provider_access_only"
  >("deny");
  const [samlSignatureAlgorithm, setSamlSignatureAlgorithm] =
    useState<SAMLSignatureAlgorithm>(
      "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
    );
  const [samlSignaturePolicy, setSamlSignaturePolicy] = useState<
    "signed_assertion" | "signed_response" | "both"
  >("signed_assertion");
  const [samlRequestedAuthnContexts, setSamlRequestedAuthnContexts] = useState(
    "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
  );
  const [samlSubjectSource, setSamlSubjectSource] = useState<
    "persistent_nameid" | "immutable_attribute"
  >("persistent_nameid");
  const [samlSubjectAttributeName, setSamlSubjectAttributeName] = useState("");
  const [samlSubjectAttributeNameFormat, setSamlSubjectAttributeNameFormat] =
    useState("");
  const [samlClockSkewSeconds, setSamlClockSkewSeconds] = useState(120);
  const [
    samlMaximumAuthenticationAgeSeconds,
    setSamlMaximumAuthenticationAgeSeconds,
  ] = useState(3_600);
  const [reason, setReason] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [idempotencyKey, setIdempotencyKey] = useState(generateUuidV7);

  async function submit(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    setSubmitting(true);
    setError(null);
    try {
      const input: TenantFederationAuthProviderCreateRequest =
        kind === "oidc"
          ? {
              kind,
              key,
              loginKey,
              displayName,
              description,
              jitMode,
              noMatchPolicy,
              reason,
              configuration: {
                issuer: issuerOrEntity,
                clientId,
                postLogoutRedirectUri,
                extraScopes: parseCommaSeparated(extraScopes),
                allowRefreshToken,
                useUserInfo,
              },
            }
          : {
              kind,
              key,
              loginKey,
              displayName,
              description,
              jitMode,
              noMatchPolicy,
              reason,
              configuration: {
                expectedEntityId: issuerOrEntity,
                redirectSignatureAlgorithm: samlSignatureAlgorithm,
                signaturePolicy: samlSignaturePolicy,
                encryptionPolicy: "disabled",
                requestedAuthnContexts: parseLines(samlRequestedAuthnContexts),
                subjectSource: samlSubjectSource,
                subjectAttributeName:
                  samlSubjectSource === "immutable_attribute"
                    ? samlSubjectAttributeName
                    : null,
                subjectAttributeNameFormat:
                  samlSubjectSource === "immutable_attribute"
                    ? samlSubjectAttributeNameFormat
                    : null,
                clockSkewSeconds: samlClockSkewSeconds,
                maxAuthenticationAgeSeconds:
                  samlMaximumAuthenticationAgeSeconds,
              },
            };
      const created = await api.create(
        csrfToken,
        tenantId,
        idempotencyKey,
        input,
      );
      setIdempotencyKey(generateUuidV7());
      onCreated(created);
    } catch (caught) {
      onError(caught);
      setError(
        describeFederationError(caught, "The provider could not be created."),
      );
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <Card className="federation-create-card">
      <CardHeader>
        <CardTitle>Create a staged provider</CardTitle>
        <CardDescription>
          Public configuration is stored separately from protected credentials
          and trust material. New providers and bindings always start disabled.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <form
          className="federation-form"
          aria-label="Create federated identity provider"
          onSubmit={(event) => void submit(event)}
        >
          <FormField htmlFor="federation-kind" label="Protocol">
            <select
              id="federation-kind"
              value={kind}
              onChange={(event) => {
                const value = event.target.value;
                if (value === "oidc" || value === "saml") setKind(value);
              }}
            >
              <option value="oidc">OpenID Connect</option>
              <option value="saml">SAML 2.0</option>
            </select>
          </FormField>
          <FormField htmlFor="federation-name" label="Display name">
            <Input
              id="federation-name"
              required
              maxLength={federationDisplayNameDOMMaxLength}
              value={displayName}
              onChange={(event) => setDisplayName(event.target.value)}
            />
          </FormField>
          <FormField
            htmlFor="federation-key"
            label="Provider key"
            hint="Lowercase stable key, for example workforce_oidc."
          >
            <Input
              id="federation-key"
              required
              pattern="[a-z][a-z0-9_-]{2,63}"
              value={key}
              onChange={(event) => setKey(event.target.value)}
            />
          </FormField>
          <FormField
            htmlFor="federation-login-key"
            label="Login key"
            hint="Anonymous tenant login locator; it grants no authority."
          >
            <Input
              id="federation-login-key"
              required
              pattern="[a-z][a-z0-9_-]{2,63}"
              value={loginKey}
              onChange={(event) => setLoginKey(event.target.value)}
            />
          </FormField>
          <FormField htmlFor="federation-description" label="Description">
            <Textarea
              id="federation-description"
              maxLength={federationDescriptionDOMMaxLength}
              value={description}
              onChange={(event) => setDescription(event.target.value)}
            />
          </FormField>
          <FormField htmlFor="federation-jit-mode" label="JIT user lifecycle">
            <select
              id="federation-jit-mode"
              value={jitMode}
              onChange={(event) =>
                setJitMode(
                  event.target.value === "create" ? "create" : "disabled",
                )
              }
            >
              <option value="disabled">Existing linked identities only</option>
              <option value="create">Create tenant users just in time</option>
            </select>
          </FormField>
          <FormField
            htmlFor="federation-no-match-policy"
            label="No mapping match"
          >
            <select
              id="federation-no-match-policy"
              value={noMatchPolicy}
              onChange={(event) =>
                setNoMatchPolicy(
                  event.target.value === "provider_access_only"
                    ? "provider_access_only"
                    : "deny",
                )
              }
            >
              <option value="deny">Deny login</option>
              <option value="provider_access_only">
                Provider access without mapped roles
              </option>
            </select>
          </FormField>
          <FormField
            htmlFor="federation-authority"
            label={kind === "oidc" ? "HTTPS issuer" : "Expected IdP entity ID"}
          >
            <Input
              id="federation-authority"
              type="url"
              required
              value={issuerOrEntity}
              onChange={(event) => setIssuerOrEntity(event.target.value)}
            />
          </FormField>
          {kind === "oidc" ? (
            <>
              <FormField htmlFor="federation-client-id" label="Client ID">
                <Input
                  id="federation-client-id"
                  required
                  maxLength={512}
                  value={clientId}
                  onChange={(event) => setClientId(event.target.value)}
                />
              </FormField>
              <FormField
                htmlFor="federation-logout-uri"
                label="Post-logout redirect URI"
                hint="Deployment-managed from this app's public origin. Register this exact URI with the provider."
              >
                <Input
                  id="federation-logout-uri"
                  type="url"
                  required
                  readOnly
                  value={postLogoutRedirectUri}
                />
              </FormField>
              <FormField
                htmlFor="federation-extra-scopes"
                label="OIDC extra scopes"
                hint="Comma-separated exact scopes; openid and refresh-related offline_access are managed automatically."
              >
                <Input
                  id="federation-extra-scopes"
                  value={extraScopes}
                  onChange={(event) => setExtraScopes(event.target.value)}
                />
              </FormField>
              <div className="federation-check">
                <Checkbox
                  id="federation-refresh"
                  checked={allowRefreshToken}
                  onCheckedChange={(checked) => {
                    const enabled = checked === true;
                    setAllowRefreshToken(enabled);
                    setExtraScopes((current) =>
                      withOIDCRefreshScope(current, enabled),
                    );
                  }}
                />
                <Label htmlFor="federation-refresh">
                  Allow bounded refresh-token rotation
                </Label>
              </div>
              <div className="federation-check">
                <Checkbox
                  id="federation-userinfo"
                  checked={useUserInfo}
                  onCheckedChange={(checked) =>
                    setUseUserInfo(checked === true)
                  }
                />
                <Label htmlFor="federation-userinfo">
                  Fetch profile claims from the validated UserInfo endpoint
                </Label>
              </div>
            </>
          ) : (
            <>
              <FormField
                htmlFor="federation-saml-signature-algorithm"
                label="SAML redirect signature algorithm"
              >
                <select
                  id="federation-saml-signature-algorithm"
                  value={samlSignatureAlgorithm}
                  onChange={(event) => {
                    if (isSAMLSignatureAlgorithm(event.target.value)) {
                      setSamlSignatureAlgorithm(event.target.value);
                    }
                  }}
                >
                  {samlSignatureAlgorithms.map((algorithm) => (
                    <option value={algorithm} key={algorithm}>
                      {algorithm.slice(algorithm.lastIndexOf("#") + 1)}
                    </option>
                  ))}
                </select>
              </FormField>
              <FormField
                htmlFor="federation-saml-signature-policy"
                label="Required SAML signature"
              >
                <select
                  id="federation-saml-signature-policy"
                  value={samlSignaturePolicy}
                  onChange={(event) => {
                    const value = event.target.value;
                    if (
                      value === "signed_assertion" ||
                      value === "signed_response" ||
                      value === "both"
                    ) {
                      setSamlSignaturePolicy(value);
                    }
                  }}
                >
                  <option value="signed_assertion">Signed assertion</option>
                  <option value="signed_response">Signed response</option>
                  <option value="both">Signed response and assertion</option>
                </select>
              </FormField>
              <FormField
                htmlFor="federation-saml-contexts"
                label="Requested AuthnContext values"
                hint="One exact class reference per line."
              >
                <Textarea
                  id="federation-saml-contexts"
                  required
                  value={samlRequestedAuthnContexts}
                  onChange={(event) =>
                    setSamlRequestedAuthnContexts(event.target.value)
                  }
                />
              </FormField>
              <FormField
                htmlFor="federation-saml-subject-source"
                label="Stable SAML subject"
              >
                <select
                  id="federation-saml-subject-source"
                  value={samlSubjectSource}
                  onChange={(event) =>
                    setSamlSubjectSource(
                      event.target.value === "immutable_attribute"
                        ? "immutable_attribute"
                        : "persistent_nameid",
                    )
                  }
                >
                  <option value="persistent_nameid">Persistent NameID</option>
                  <option value="immutable_attribute">
                    Immutable attribute
                  </option>
                </select>
              </FormField>
              {samlSubjectSource === "immutable_attribute" ? (
                <>
                  <FormField
                    htmlFor="federation-saml-subject-attribute"
                    label="Subject attribute Name"
                  >
                    <Input
                      id="federation-saml-subject-attribute"
                      required
                      value={samlSubjectAttributeName}
                      onChange={(event) =>
                        setSamlSubjectAttributeName(event.target.value)
                      }
                    />
                  </FormField>
                  <FormField
                    htmlFor="federation-saml-subject-format"
                    label="Subject attribute NameFormat"
                  >
                    <Input
                      id="federation-saml-subject-format"
                      required
                      value={samlSubjectAttributeNameFormat}
                      onChange={(event) =>
                        setSamlSubjectAttributeNameFormat(event.target.value)
                      }
                    />
                  </FormField>
                </>
              ) : null}
              <FormField
                htmlFor="federation-saml-skew"
                label="Clock skew seconds"
              >
                <Input
                  id="federation-saml-skew"
                  type="number"
                  min={0}
                  max={300}
                  value={samlClockSkewSeconds}
                  onChange={(event) =>
                    setSamlClockSkewSeconds(Number(event.target.value))
                  }
                />
              </FormField>
              <FormField
                htmlFor="federation-saml-max-age"
                label="Maximum authentication age seconds"
              >
                <Input
                  id="federation-saml-max-age"
                  type="number"
                  min={60}
                  max={86_400}
                  value={samlMaximumAuthenticationAgeSeconds}
                  onChange={(event) =>
                    setSamlMaximumAuthenticationAgeSeconds(
                      Number(event.target.value),
                    )
                  }
                />
              </FormField>
              <Alert className="federation-material-note">
                <LockKeyhole aria-hidden="true" />
                <AlertTitle>Trust remains write-only</AlertTitle>
                <AlertDescription>
                  Raw metadata, certificates, and SP keys never appear in this
                  form or in provider reads. XML encryption remains disabled
                  until a separate encrypted-key ceremony is supported.
                </AlertDescription>
              </Alert>
            </>
          )}
          <FormField htmlFor="federation-create-reason" label="Audit reason">
            <Input
              id="federation-create-reason"
              required
              maxLength={federationAuditReasonDOMMaxLength}
              value={reason}
              onChange={(event) => setReason(event.target.value)}
            />
          </FormField>
          {error ? <FocusedError message={error} /> : null}
          <Button type="submit" disabled={submitting}>
            {submitting ? "Creating…" : "Create disabled provider"}
          </Button>
        </form>
      </CardContent>
    </Card>
  );
}

function ProviderDetail({
  api,
  canManage,
  canManageAssurance,
  canManageMapping,
  canReadAssurance,
  canReadMapping,
  csrfToken,
  onChanged,
  onError,
  state,
  tenantId,
}: {
  api: TenantFederationApi;
  canManage: boolean;
  canManageAssurance: boolean;
  canManageMapping: boolean;
  canReadAssurance: boolean;
  canReadMapping: boolean;
  csrfToken: string;
  onChanged: (
    message: string,
    provider?: TenantFederationProviderVersioned,
  ) => void;
  onError: (error: unknown) => void;
  state: DetailState;
  tenantId: string;
}): React.JSX.Element | null {
  if (state.kind === "idle") return null;
  if (state.kind === "loading") {
    return (
      <Card aria-busy="true">
        <CardContent>Loading provider detail…</CardContent>
      </Card>
    );
  }
  if (state.kind === "error") return <FocusedError message={state.message} />;
  return (
    <ProviderManagementForm
      key={`${tenantId}:${state.versioned.value.id}`}
      api={api}
      canManage={canManage}
      canManageAssurance={canManageAssurance}
      canManageMapping={canManageMapping}
      canReadAssurance={canReadAssurance}
      canReadMapping={canReadMapping}
      csrfToken={csrfToken}
      current={state.versioned}
      onChanged={onChanged}
      onError={onError}
      tenantId={tenantId}
    />
  );
}

function ProviderManagementForm({
  api,
  canManage,
  canManageAssurance,
  canManageMapping,
  canReadAssurance,
  canReadMapping,
  csrfToken,
  current,
  onChanged,
  onError,
  tenantId,
}: {
  api: TenantFederationApi;
  canManage: boolean;
  canManageAssurance: boolean;
  canManageMapping: boolean;
  canReadAssurance: boolean;
  canReadMapping: boolean;
  csrfToken: string;
  current: TenantFederationProviderVersioned;
  onChanged: (
    message: string,
    provider?: TenantFederationProviderVersioned,
  ) => void;
  onError: (error: unknown) => void;
  tenantId: string;
}): React.JSX.Element {
  const provider = current.value;
  const [displayName, setDisplayName] = useState(provider.displayName);
  const [description, setDescription] = useState(provider.description);
  const [enabled, setEnabled] = useState(provider.enabled);
  const [jitMode, setJitMode] = useState(provider.jitMode);
  const [noMatchPolicy, setNoMatchPolicy] = useState(provider.noMatchPolicy);
  const [oidcIssuer, setOIDCIssuer] = useState(
    provider.kind === "oidc" ? provider.configuration.issuer : "",
  );
  const [oidcClientID, setOIDCClientID] = useState(
    provider.kind === "oidc" ? provider.configuration.clientId : "",
  );
  const oidcPostLogoutRedirectURI = tenantOIDCPostLogoutRedirectURI();
  const [oidcExtraScopes, setOIDCExtraScopes] = useState(
    provider.kind === "oidc"
      ? provider.configuration.extraScopes.join(", ")
      : "",
  );
  const [oidcAllowRefreshToken, setOIDCAllowRefreshToken] = useState(
    provider.kind === "oidc" && provider.configuration.allowRefreshToken,
  );
  const [oidcUseUserInfo, setOIDCUseUserInfo] = useState(
    provider.kind === "oidc" && provider.configuration.useUserInfo,
  );
  const [samlExpectedEntityID, setSAMLExpectedEntityID] = useState(
    provider.kind === "saml" ? provider.configuration.expectedEntityId : "",
  );
  const [samlSignatureAlgorithm, setSAMLSignatureAlgorithm] =
    useState<SAMLSignatureAlgorithm>(
      provider.kind === "saml"
        ? provider.configuration.redirectSignatureAlgorithm
        : "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
    );
  const [samlSignaturePolicy, setSAMLSignaturePolicy] =
    useState<SAMLSignaturePolicy>(
      provider.kind === "saml"
        ? provider.configuration.signaturePolicy
        : "signed_assertion",
    );
  const [samlRequestedAuthnContexts, setSAMLRequestedAuthnContexts] = useState(
    provider.kind === "saml"
      ? provider.configuration.requestedAuthnContexts.join("\n")
      : "",
  );
  const [samlSubjectSource, setSAMLSubjectSource] = useState<SAMLSubjectSource>(
    provider.kind === "saml"
      ? provider.configuration.subjectSource
      : "persistent_nameid",
  );
  const [samlSubjectAttributeName, setSAMLSubjectAttributeName] = useState(
    provider.kind === "saml"
      ? (provider.configuration.subjectAttributeName ?? "")
      : "",
  );
  const [samlSubjectAttributeNameFormat, setSAMLSubjectAttributeNameFormat] =
    useState(
      provider.kind === "saml"
        ? (provider.configuration.subjectAttributeNameFormat ?? "")
        : "",
    );
  const [samlClockSkewSeconds, setSAMLClockSkewSeconds] = useState(
    provider.kind === "saml" ? provider.configuration.clockSkewSeconds : 120,
  );
  const [
    samlMaximumAuthenticationAgeSeconds,
    setSAMLMaximumAuthenticationAgeSeconds,
  ] = useState(
    provider.kind === "saml"
      ? provider.configuration.maxAuthenticationAgeSeconds
      : 3_600,
  );
  const [reason, setReason] = useState("");
  const [clientSecret, setClientSecret] = useState("");
  const [trustClientAuthentication, setTrustClientAuthentication] = useState<
    "client_secret_basic" | "client_secret_post"
  >("client_secret_basic");
  const [trustSigningAlgorithms, setTrustSigningAlgorithms] = useState("RS256");
  const [trustReason, setTrustReason] = useState("");
  const [clearSecretConfirmed, setClearSecretConfirmed] = useState(false);
  const [archiveConfirmed, setArchiveConfirmed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setDisplayName(provider.displayName);
    setDescription(provider.description);
    setEnabled(provider.enabled);
    setJitMode(provider.jitMode);
    setNoMatchPolicy(provider.noMatchPolicy);
    if (provider.kind === "oidc") {
      setOIDCIssuer(provider.configuration.issuer);
      setOIDCClientID(provider.configuration.clientId);
      setOIDCExtraScopes(provider.configuration.extraScopes.join(", "));
      setOIDCAllowRefreshToken(provider.configuration.allowRefreshToken);
      setOIDCUseUserInfo(provider.configuration.useUserInfo);
    } else {
      setSAMLExpectedEntityID(provider.configuration.expectedEntityId);
      setSAMLSignatureAlgorithm(
        provider.configuration.redirectSignatureAlgorithm,
      );
      setSAMLSignaturePolicy(provider.configuration.signaturePolicy);
      setSAMLRequestedAuthnContexts(
        provider.configuration.requestedAuthnContexts.join("\n"),
      );
      setSAMLSubjectSource(provider.configuration.subjectSource);
      setSAMLSubjectAttributeName(
        provider.configuration.subjectAttributeName ?? "",
      );
      setSAMLSubjectAttributeNameFormat(
        provider.configuration.subjectAttributeNameFormat ?? "",
      );
      setSAMLClockSkewSeconds(provider.configuration.clockSkewSeconds);
      setSAMLMaximumAuthenticationAgeSeconds(
        provider.configuration.maxAuthenticationAgeSeconds,
      );
    }
  }, [provider]);

  async function mutate(action: () => Promise<void>): Promise<void> {
    setBusy(true);
    setError(null);
    try {
      await action();
    } catch (caught) {
      onError(caught);
      setError(
        describeFederationError(
          caught,
          "The provider mutation could not be completed.",
        ),
      );
    } finally {
      setBusy(false);
    }
  }

  function update(event: FormEvent<HTMLFormElement>): void {
    event.preventDefault();
    void mutate(async () => {
      const common = {
        displayName,
        description,
        enabled,
        jitMode,
        noMatchPolicy,
        reason,
      };
      const input: TenantFederationAuthProviderUpdateRequest =
        provider.kind === "oidc"
          ? {
              ...common,
              kind: "oidc",
              configuration: {
                issuer: oidcIssuer,
                clientId: oidcClientID,
                postLogoutRedirectUri: oidcPostLogoutRedirectURI,
                extraScopes: parseCommaSeparated(oidcExtraScopes),
                allowRefreshToken: oidcAllowRefreshToken,
                useUserInfo: oidcUseUserInfo,
              },
            }
          : {
              ...common,
              kind: "saml",
              configuration: {
                expectedEntityId: samlExpectedEntityID,
                redirectSignatureAlgorithm: samlSignatureAlgorithm,
                signaturePolicy: samlSignaturePolicy,
                encryptionPolicy: "disabled",
                requestedAuthnContexts: parseLines(samlRequestedAuthnContexts),
                subjectSource: samlSubjectSource,
                subjectAttributeName:
                  samlSubjectSource === "immutable_attribute"
                    ? samlSubjectAttributeName
                    : null,
                subjectAttributeNameFormat:
                  samlSubjectSource === "immutable_attribute"
                    ? samlSubjectAttributeNameFormat
                    : null,
                clockSkewSeconds: samlClockSkewSeconds,
                maxAuthenticationAgeSeconds:
                  samlMaximumAuthenticationAgeSeconds,
              },
            };
      const updated = await api.update(
        csrfToken,
        tenantId,
        provider.id,
        current.etag,
        input,
      );
      setReason("");
      onChanged(
        "The public provider configuration and lifecycle state were updated.",
        updated,
      );
    });
  }

  function rotateSecret(event: FormEvent<HTMLFormElement>): void {
    event.preventDefault();
    if (provider.kind !== "oidc") return;
    void mutate(async () => {
      await api.replaceOidcClientSecret(
        csrfToken,
        tenantId,
        provider.id,
        current.etag,
        clientSecret,
        reason,
      );
      setClientSecret("");
      setReason("");
      const refreshed = await api.get(tenantId, provider.id);
      onChanged(
        "The OIDC client secret was rotated without credential readback.",
        refreshed,
      );
    });
  }

  function clearSecret(): void {
    if (provider.kind !== "oidc" || !clearSecretConfirmed) return;
    void mutate(async () => {
      await api.clearOidcClientSecret(
        csrfToken,
        tenantId,
        provider.id,
        current.etag,
        reason,
      );
      setClientSecret("");
      setReason("");
      setClearSecretConfirmed(false);
      const refreshed = await api.get(tenantId, provider.id);
      onChanged(
        "The OIDC client secret was retired without credential readback.",
        refreshed,
      );
    });
  }

  function refreshOIDCTrust(event: FormEvent<HTMLFormElement>): void {
    event.preventDefault();
    if (provider.kind !== "oidc") return;
    void mutate(async () => {
      const signingAlgorithms: OIDCSigningAlgorithm[] = [];
      for (const value of parseCommaSeparated(trustSigningAlgorithms)) {
        if (!isOIDCSigningAlgorithm(value)) {
          throw new PhaseTwoApiError(
            `Unsupported OIDC signing algorithm: ${value}.`,
          );
        }
        signingAlgorithms.push(value);
      }
      const receipt = await api.refreshOidcTrustDocuments(
        csrfToken,
        tenantId,
        provider.id,
        current.etag,
        {
          clientAuthentication: trustClientAuthentication,
          signingAlgorithms,
          reason: trustReason,
        },
      );
      setTrustReason("");
      const refreshed = await api.get(tenantId, provider.id);
      onChanged(
        `OIDC discovery and JWKS were refreshed at revisions ${receipt.discoveryRevision}/${receipt.jwksRevision} with ${receipt.jwksKeyCount} validated signing key(s).`,
        refreshed,
      );
    });
  }

  return (
    <Card
      className="federation-detail"
      aria-label={`${provider.displayName} federation controls`}
    >
      <CardHeader>
        <div className="federation-provider__header">
          <div>
            <span className="federation-provider__kind">
              {provider.kind.toUpperCase()} detail
            </span>
            <CardTitle>{provider.displayName}</CardTitle>
            <CardDescription>
              {provider.description || "No description"}
            </CardDescription>
          </div>
          <ProviderBadge provider={provider} />
        </div>
      </CardHeader>
      <CardContent className="federation-detail__content">
        <dl className="federation-detail__facts">
          <div>
            <dt>Callback / ACS</dt>
            <dd>
              {provider.kind === "oidc"
                ? provider.configuration.redirectUri
                : provider.configuration.acsUrl}
            </dd>
          </div>
          <div>
            <dt>Security revision</dt>
            <dd>{provider.securityRevision}</dd>
          </div>
          <div>
            <dt>Binding</dt>
            <dd>{provider.binding.loginKey}</dd>
          </div>
          {provider.kind === "oidc" ? (
            <div>
              <dt>Client secret</dt>
              <dd>
                {provider.configuration.clientSecretPresent
                  ? `Present · revision ${provider.configuration.clientSecretRevision}`
                  : "Not set"}
              </dd>
            </div>
          ) : (
            <>
              <div>
                <dt>SP entity ID</dt>
                <dd>{provider.configuration.spEntityId}</dd>
              </div>
              <div>
                <dt>IdP metadata</dt>
                <dd>Revision {provider.configuration.metadataRevision}</dd>
              </div>
              <div>
                <dt>SP signing credential</dt>
                <dd>
                  {provider.configuration.spKeyPresent
                    ? `Present · revision ${provider.configuration.spKeyRevision}`
                    : "Not generated"}
                </dd>
              </div>
              <div>
                <dt>Single logout</dt>
                <dd>
                  {provider.configuration.singleLogoutConfigured
                    ? "Configured"
                    : "Local revocation only"}
                </dd>
              </div>
            </>
          )}
        </dl>
        <TenantFederationPolicyControls
          api={api}
          canManageAssurance={canManageAssurance}
          canManageMapping={canManageMapping}
          canReadAssurance={canReadAssurance}
          canReadMapping={canReadMapping}
          csrfToken={csrfToken}
          current={current}
          onChanged={onChanged}
          onError={onError}
          tenantId={tenantId}
        />
        {canManage && provider.archivedAt === null ? (
          <>
            <form
              className="federation-form federation-form--compact"
              aria-label="Update federation provider"
              onSubmit={update}
            >
              <FormField
                htmlFor={`federation-edit-name-${provider.id}`}
                label="Display name"
              >
                <Input
                  id={`federation-edit-name-${provider.id}`}
                  required
                  maxLength={federationDisplayNameDOMMaxLength}
                  value={displayName}
                  onChange={(event) => setDisplayName(event.target.value)}
                />
              </FormField>
              <FormField
                htmlFor={`federation-edit-description-${provider.id}`}
                label="Description"
              >
                <Textarea
                  id={`federation-edit-description-${provider.id}`}
                  maxLength={federationDescriptionDOMMaxLength}
                  value={description}
                  onChange={(event) => setDescription(event.target.value)}
                />
              </FormField>
              <FormField
                htmlFor={`federation-edit-jit-${provider.id}`}
                label="JIT user lifecycle"
              >
                <select
                  id={`federation-edit-jit-${provider.id}`}
                  value={jitMode}
                  onChange={(event) =>
                    setJitMode(
                      event.target.value === "create" ? "create" : "disabled",
                    )
                  }
                >
                  <option value="disabled">
                    Existing linked identities only
                  </option>
                  <option value="create">
                    Create tenant users just in time
                  </option>
                </select>
              </FormField>
              <FormField
                htmlFor={`federation-edit-no-match-${provider.id}`}
                label="No mapping match"
              >
                <select
                  id={`federation-edit-no-match-${provider.id}`}
                  value={noMatchPolicy}
                  onChange={(event) =>
                    setNoMatchPolicy(
                      event.target.value === "provider_access_only"
                        ? "provider_access_only"
                        : "deny",
                    )
                  }
                >
                  <option value="deny">Deny login</option>
                  <option value="provider_access_only">
                    Provider access without mapped roles
                  </option>
                </select>
              </FormField>
              {provider.kind === "oidc" ? (
                <>
                  <FormField
                    htmlFor={`federation-edit-oidc-issuer-${provider.id}`}
                    label="HTTPS issuer"
                  >
                    <Input
                      id={`federation-edit-oidc-issuer-${provider.id}`}
                      type="url"
                      required
                      value={oidcIssuer}
                      onChange={(event) => setOIDCIssuer(event.target.value)}
                    />
                  </FormField>
                  <FormField
                    htmlFor={`federation-edit-oidc-client-${provider.id}`}
                    label="Client ID"
                  >
                    <Input
                      id={`federation-edit-oidc-client-${provider.id}`}
                      required
                      maxLength={512}
                      value={oidcClientID}
                      onChange={(event) => setOIDCClientID(event.target.value)}
                    />
                  </FormField>
                  <FormField
                    htmlFor={`federation-edit-oidc-logout-${provider.id}`}
                    label="Post-logout redirect URI"
                    hint="Deployment-managed from this app's public origin. Register this exact URI with the provider."
                  >
                    <Input
                      id={`federation-edit-oidc-logout-${provider.id}`}
                      type="url"
                      required
                      readOnly
                      value={oidcPostLogoutRedirectURI}
                    />
                  </FormField>
                  <FormField
                    htmlFor={`federation-edit-oidc-scopes-${provider.id}`}
                    label="OIDC extra scopes"
                  >
                    <Input
                      id={`federation-edit-oidc-scopes-${provider.id}`}
                      value={oidcExtraScopes}
                      onChange={(event) =>
                        setOIDCExtraScopes(event.target.value)
                      }
                    />
                  </FormField>
                  <div className="federation-check">
                    <Checkbox
                      id={`federation-edit-oidc-refresh-${provider.id}`}
                      checked={oidcAllowRefreshToken}
                      onCheckedChange={(checked) => {
                        const refreshEnabled = checked === true;
                        setOIDCAllowRefreshToken(refreshEnabled);
                        setOIDCExtraScopes((currentScopes) =>
                          withOIDCRefreshScope(currentScopes, refreshEnabled),
                        );
                      }}
                    />
                    <Label
                      htmlFor={`federation-edit-oidc-refresh-${provider.id}`}
                    >
                      Allow bounded refresh-token rotation
                    </Label>
                  </div>
                  <div className="federation-check">
                    <Checkbox
                      id={`federation-edit-oidc-userinfo-${provider.id}`}
                      checked={oidcUseUserInfo}
                      onCheckedChange={(checked) =>
                        setOIDCUseUserInfo(checked === true)
                      }
                    />
                    <Label
                      htmlFor={`federation-edit-oidc-userinfo-${provider.id}`}
                    >
                      Fetch profile claims from validated UserInfo
                    </Label>
                  </div>
                </>
              ) : (
                <>
                  <FormField
                    htmlFor={`federation-edit-saml-entity-${provider.id}`}
                    label="Expected IdP entity ID"
                  >
                    <Input
                      id={`federation-edit-saml-entity-${provider.id}`}
                      type="url"
                      required
                      value={samlExpectedEntityID}
                      onChange={(event) =>
                        setSAMLExpectedEntityID(event.target.value)
                      }
                    />
                  </FormField>
                  <FormField
                    htmlFor={`federation-edit-saml-algorithm-${provider.id}`}
                    label="SAML redirect signature algorithm"
                  >
                    <select
                      id={`federation-edit-saml-algorithm-${provider.id}`}
                      value={samlSignatureAlgorithm}
                      onChange={(event) => {
                        if (isSAMLSignatureAlgorithm(event.target.value)) {
                          setSAMLSignatureAlgorithm(event.target.value);
                        }
                      }}
                    >
                      {samlSignatureAlgorithms.map((algorithm) => (
                        <option value={algorithm} key={algorithm}>
                          {algorithm.slice(algorithm.lastIndexOf("#") + 1)}
                        </option>
                      ))}
                    </select>
                  </FormField>
                  <FormField
                    htmlFor={`federation-edit-saml-signature-${provider.id}`}
                    label="Required SAML signature"
                  >
                    <select
                      id={`federation-edit-saml-signature-${provider.id}`}
                      value={samlSignaturePolicy}
                      onChange={(event) => {
                        if (isSAMLSignaturePolicy(event.target.value)) {
                          setSAMLSignaturePolicy(event.target.value);
                        }
                      }}
                    >
                      <option value="signed_assertion">Signed assertion</option>
                      <option value="signed_response">Signed response</option>
                      <option value="both">
                        Signed response and assertion
                      </option>
                    </select>
                  </FormField>
                  <FormField
                    htmlFor={`federation-edit-saml-contexts-${provider.id}`}
                    label="Requested AuthnContext values"
                    hint="One exact class reference per line."
                  >
                    <Textarea
                      id={`federation-edit-saml-contexts-${provider.id}`}
                      required
                      value={samlRequestedAuthnContexts}
                      onChange={(event) =>
                        setSAMLRequestedAuthnContexts(event.target.value)
                      }
                    />
                  </FormField>
                  <FormField
                    htmlFor={`federation-edit-saml-subject-${provider.id}`}
                    label="Stable SAML subject"
                  >
                    <select
                      id={`federation-edit-saml-subject-${provider.id}`}
                      value={samlSubjectSource}
                      onChange={(event) =>
                        setSAMLSubjectSource(
                          event.target.value === "immutable_attribute"
                            ? "immutable_attribute"
                            : "persistent_nameid",
                        )
                      }
                    >
                      <option value="persistent_nameid">
                        Persistent NameID
                      </option>
                      <option value="immutable_attribute">
                        Immutable attribute
                      </option>
                    </select>
                  </FormField>
                  {samlSubjectSource === "immutable_attribute" ? (
                    <>
                      <FormField
                        htmlFor={`federation-edit-saml-attribute-${provider.id}`}
                        label="Subject attribute Name"
                      >
                        <Input
                          id={`federation-edit-saml-attribute-${provider.id}`}
                          required
                          value={samlSubjectAttributeName}
                          onChange={(event) =>
                            setSAMLSubjectAttributeName(event.target.value)
                          }
                        />
                      </FormField>
                      <FormField
                        htmlFor={`federation-edit-saml-format-${provider.id}`}
                        label="Subject attribute NameFormat"
                      >
                        <Input
                          id={`federation-edit-saml-format-${provider.id}`}
                          required
                          value={samlSubjectAttributeNameFormat}
                          onChange={(event) =>
                            setSAMLSubjectAttributeNameFormat(
                              event.target.value,
                            )
                          }
                        />
                      </FormField>
                    </>
                  ) : null}
                  <FormField
                    htmlFor={`federation-edit-saml-skew-${provider.id}`}
                    label="Clock skew seconds"
                  >
                    <Input
                      id={`federation-edit-saml-skew-${provider.id}`}
                      type="number"
                      min={0}
                      max={300}
                      value={samlClockSkewSeconds}
                      onChange={(event) =>
                        setSAMLClockSkewSeconds(Number(event.target.value))
                      }
                    />
                  </FormField>
                  <FormField
                    htmlFor={`federation-edit-saml-age-${provider.id}`}
                    label="Maximum authentication age seconds"
                  >
                    <Input
                      id={`federation-edit-saml-age-${provider.id}`}
                      type="number"
                      min={60}
                      max={86_400}
                      value={samlMaximumAuthenticationAgeSeconds}
                      onChange={(event) =>
                        setSAMLMaximumAuthenticationAgeSeconds(
                          Number(event.target.value),
                        )
                      }
                    />
                  </FormField>
                  <p className="federation-policy-editor__permission">
                    XML encryption remains disabled; protected metadata and SP
                    credentials use the write-only controls below.
                  </p>
                </>
              )}
              <div className="federation-check">
                <Checkbox
                  id={`federation-enabled-${provider.id}`}
                  checked={enabled}
                  onCheckedChange={(checked) => setEnabled(checked === true)}
                />
                <Label htmlFor={`federation-enabled-${provider.id}`}>
                  Enable tenant login after protected readiness checks
                </Label>
              </div>
              <FormField
                htmlFor={`federation-reason-${provider.id}`}
                label="Audit reason"
              >
                <Input
                  id={`federation-reason-${provider.id}`}
                  required
                  maxLength={federationAuditReasonDOMMaxLength}
                  value={reason}
                  onChange={(event) => setReason(event.target.value)}
                />
              </FormField>
              <Button type="submit" disabled={busy}>
                Save provider
              </Button>
            </form>
            {provider.kind === "oidc" ? (
              <>
                <form
                  className="federation-secret-form"
                  aria-label="Rotate OIDC client secret"
                  onSubmit={rotateSecret}
                >
                  <div>
                    <h3>
                      <KeyRound aria-hidden="true" /> Write-only client secret
                    </h3>
                    <p>
                      The value is transferred once, encrypted for this
                      tenant/provider/binding row, and immediately cleared from
                      the form.
                    </p>
                  </div>
                  <FormField
                    htmlFor={`federation-secret-${provider.id}`}
                    label="New client secret"
                  >
                    <Input
                      id={`federation-secret-${provider.id}`}
                      type="password"
                      autoComplete="new-password"
                      required
                      value={clientSecret}
                      onChange={(event) => setClientSecret(event.target.value)}
                    />
                  </FormField>
                  {provider.configuration.clientSecretPresent ? (
                    <div className="federation-check">
                      <Checkbox
                        id={`federation-clear-secret-confirm-${provider.id}`}
                        checked={clearSecretConfirmed}
                        onCheckedChange={(checked) =>
                          setClearSecretConfirmed(checked === true)
                        }
                      />
                      <Label
                        htmlFor={`federation-clear-secret-confirm-${provider.id}`}
                      >
                        Confirm permanent retirement of this OIDC client secret
                      </Label>
                    </div>
                  ) : null}
                  <div className="federation-secret-form__actions">
                    <Button
                      type="submit"
                      variant="outline"
                      disabled={busy || reason.length === 0}
                    >
                      Rotate client secret
                    </Button>
                    {provider.configuration.clientSecretPresent ? (
                      <Button
                        type="button"
                        variant="destructive"
                        disabled={
                          busy || reason.length === 0 || !clearSecretConfirmed
                        }
                        onClick={clearSecret}
                      >
                        Clear client secret
                      </Button>
                    ) : null}
                  </div>
                </form>
                <form
                  className="federation-secret-form"
                  aria-label="Refresh OIDC trust documents"
                  onSubmit={refreshOIDCTrust}
                >
                  <div>
                    <h3>
                      <RefreshCw aria-hidden="true" /> Verified OIDC trust
                    </h3>
                    <p>
                      Discovery and JWKS are fetched server-side through the
                      hardened client. Raw trust documents are never accepted or
                      returned here.
                    </p>
                  </div>
                  <div className="federation-form federation-form--compact">
                    <FormField
                      htmlFor={`federation-oidc-client-auth-${provider.id}`}
                      label="Token endpoint client authentication"
                    >
                      <select
                        id={`federation-oidc-client-auth-${provider.id}`}
                        value={trustClientAuthentication}
                        onChange={(event) =>
                          setTrustClientAuthentication(
                            event.target.value === "client_secret_post"
                              ? "client_secret_post"
                              : "client_secret_basic",
                          )
                        }
                      >
                        <option value="client_secret_basic">
                          client_secret_basic
                        </option>
                        <option value="client_secret_post">
                          client_secret_post
                        </option>
                      </select>
                    </FormField>
                    <FormField
                      htmlFor={`federation-oidc-algorithms-${provider.id}`}
                      label="Allowed signing algorithms"
                      hint="Comma-separated exact values, for example RS256,ES256."
                    >
                      <Input
                        id={`federation-oidc-algorithms-${provider.id}`}
                        required
                        value={trustSigningAlgorithms}
                        onChange={(event) =>
                          setTrustSigningAlgorithms(event.target.value)
                        }
                      />
                    </FormField>
                    <FormField
                      htmlFor={`federation-oidc-trust-reason-${provider.id}`}
                      label="OIDC trust audit reason"
                    >
                      <Input
                        id={`federation-oidc-trust-reason-${provider.id}`}
                        required
                        maxLength={federationAuditReasonDOMMaxLength}
                        value={trustReason}
                        onChange={(event) => setTrustReason(event.target.value)}
                      />
                    </FormField>
                  </div>
                  <Button
                    type="submit"
                    variant="outline"
                    disabled={busy || trustReason.length === 0}
                  >
                    Refresh verified trust
                  </Button>
                </form>
              </>
            ) : (
              <TenantSAMLMaterialControls
                api={api}
                busy={busy}
                csrfToken={csrfToken}
                current={current}
                mutate={mutate}
                onChanged={onChanged}
                tenantId={tenantId}
              />
            )}
            <div className="federation-danger">
              <div>
                <h3>Archive provider</h3>
                <p>
                  Archive is terminal and requires the provider to be disabled.
                </p>
                <div className="federation-check">
                  <Checkbox
                    id={`federation-archive-confirm-${provider.id}`}
                    checked={archiveConfirmed}
                    onCheckedChange={(checked) =>
                      setArchiveConfirmed(checked === true)
                    }
                  />
                  <Label htmlFor={`federation-archive-confirm-${provider.id}`}>
                    Confirm permanent archival of this provider
                  </Label>
                </div>
              </div>
              <Button
                type="button"
                variant="destructive"
                disabled={
                  busy ||
                  provider.enabled ||
                  reason.length === 0 ||
                  !archiveConfirmed
                }
                onClick={() => {
                  if (!archiveConfirmed) return;
                  void mutate(async () => {
                    await api.archive(
                      csrfToken,
                      tenantId,
                      provider.id,
                      current.etag,
                      reason,
                    );
                    onChanged(
                      "The provider, binding, and affected local sessions were retired.",
                    );
                    setArchiveConfirmed(false);
                  });
                }}
              >
                <Trash2 aria-hidden="true" /> Archive
              </Button>
            </div>
          </>
        ) : null}
        {error ? <FocusedError message={error} /> : null}
      </CardContent>
    </Card>
  );
}

function TenantFederationPolicyControls({
  api,
  canManageAssurance,
  canManageMapping,
  canReadAssurance,
  canReadMapping,
  csrfToken,
  current,
  onChanged,
  onError,
  tenantId,
}: {
  api: TenantFederationApi;
  canManageAssurance: boolean;
  canManageMapping: boolean;
  canReadAssurance: boolean;
  canReadMapping: boolean;
  csrfToken: string;
  current: TenantFederationProviderVersioned;
  onChanged: (
    message: string,
    provider?: TenantFederationProviderVersioned,
  ) => void;
  onError: (error: unknown) => void;
  tenantId: string;
}): React.JSX.Element | null {
  const provider = current.value;
  const mappingContext = tenantFederationMappingPolicyContext(provider);
  const [mapping, setMapping] = useState<MappingPolicyState>({ kind: "idle" });
  const [assurance, setAssurance] = useState<AssurancePolicyState>({
    kind: "idle",
  });
  const [mappingDocument, setMappingDocument] = useState("");
  const [assuranceDocument, setAssuranceDocument] = useState("");
  const [mappingReason, setMappingReason] = useState("");
  const [assuranceReason, setAssuranceReason] = useState("");
  const [mappingBusy, setMappingBusy] = useState(false);
  const [assuranceBusy, setAssuranceBusy] = useState(false);
  const [reload, setReload] = useState(0);

  useEffect(() => {
    const controller = new AbortController();
    if (canReadMapping) {
      setMapping({ kind: "loading" });
      void api
        .getMappingPolicy(
          tenantId,
          provider.id,
          mappingContext,
          controller.signal,
        )
        .then((versioned) => {
          if (controller.signal.aborted) return;
          if (versioned.value.kind !== provider.kind) {
            throw new PhaseTwoApiError(
              "The mapping policy protocol did not match the provider.",
            );
          }
          setMapping({ kind: "ready", versioned });
          setMappingDocument(formatMappingPolicy(versioned.value));
        })
        .catch((caught: unknown) => {
          if (controller.signal.aborted) return;
          onError(caught);
          setMapping({
            kind: "error",
            message: describeFederationError(
              caught,
              "The current claim-to-role mapping policy could not be loaded.",
            ),
          });
        });
    } else {
      setMapping({ kind: "idle" });
      setMappingDocument("");
    }
    if (canReadAssurance) {
      setAssurance({ kind: "loading" });
      void api
        .getAssurancePolicy(tenantId, provider.id, controller.signal)
        .then((versioned) => {
          if (controller.signal.aborted) return;
          if (versioned.value.kind !== provider.kind) {
            throw new PhaseTwoApiError(
              "The assurance policy protocol did not match the provider.",
            );
          }
          setAssurance({ kind: "ready", versioned });
          setAssuranceDocument(formatAssurancePolicy(versioned.value));
        })
        .catch((caught: unknown) => {
          if (controller.signal.aborted) return;
          onError(caught);
          setAssurance({
            kind: "error",
            message: describeFederationError(
              caught,
              "The current IdP assurance policy could not be loaded.",
            ),
          });
        });
    } else {
      setAssurance({ kind: "idle" });
      setAssuranceDocument("");
    }
    return () => controller.abort();
  }, [
    api,
    canReadAssurance,
    canReadMapping,
    onError,
    provider.id,
    provider.kind,
    provider.kind === "oidc" ? provider.configuration.useUserInfo : false,
    provider.version,
    reload,
    tenantId,
  ]);

  if (!canReadMapping && !canReadAssurance) return null;

  function replaceMapping(event: FormEvent<HTMLFormElement>): void {
    event.preventDefault();
    if (!canManageMapping || mapping.kind !== "ready") return;
    setMappingBusy(true);
    void (async () => {
      try {
        const input = parseMappingPolicy(
          mappingDocument,
          mappingContext,
          mappingReason,
        );
        const receipt = await api.replaceMappingPolicy(
          csrfToken,
          tenantId,
          provider.id,
          mapping.versioned.etag,
          input,
          mappingContext,
        );
        setMappingReason("");
        const refreshed = await api.get(tenantId, provider.id);
        onChanged(
          `The ${provider.kind.toUpperCase()} extraction and claim-to-role mapping policy was replaced at revision ${receipt.revision}. Existing federated sessions were revoked.`,
          refreshed,
        );
        setReload((value) => value + 1);
      } catch (caught) {
        onError(caught);
        setMapping({
          kind: "error",
          message: describeFederationError(
            caught,
            "The mapping policy could not be replaced.",
          ),
        });
      } finally {
        setMappingBusy(false);
      }
    })();
  }

  function replaceAssurance(event: FormEvent<HTMLFormElement>): void {
    event.preventDefault();
    if (!canManageAssurance || assurance.kind !== "ready") return;
    setAssuranceBusy(true);
    void (async () => {
      try {
        const input = parseAssurancePolicy(
          assuranceDocument,
          provider.kind,
          assuranceReason,
        );
        const receipt = await api.replaceAssurancePolicy(
          csrfToken,
          tenantId,
          provider.id,
          assurance.versioned.etag,
          input,
        );
        setAssuranceReason("");
        const refreshed = await api.get(tenantId, provider.id);
        onChanged(
          `The ${provider.kind.toUpperCase()} IdP assurance policy was replaced at revision ${receipt.revision}; unmatched MFA assertions continue to require local step-up.`,
          refreshed,
        );
        setReload((value) => value + 1);
      } catch (caught) {
        onError(caught);
        setAssurance({
          kind: "error",
          message: describeFederationError(
            caught,
            "The IdP assurance policy could not be replaced.",
          ),
        });
      } finally {
        setAssuranceBusy(false);
      }
    })();
  }

  return (
    <section
      className="federation-policies"
      aria-label="Federated mapping and assurance policies"
    >
      <div>
        <h3>Identity mapping and MFA assurance</h3>
        <p>
          Editors are hydrated from protected readback before they can submit.
          Replacing a mapping uses exact security-group, role, and optional
          operator-team assignment UUIDv7 targets; an empty mapping rules array
          explicitly revokes all assignments.
        </p>
      </div>
      {canReadMapping ? (
        <form
          className="federation-policy-editor"
          aria-label="Edit federated mapping policy"
          onSubmit={replaceMapping}
        >
          <div className="federation-policy-editor__heading">
            <div>
              <h4>Claim / attribute mapping</h4>
              <p>
                {mapping.kind === "ready"
                  ? `Provider v${mapping.versioned.value.providerVersion} · mapping revision ${mapping.versioned.mappingRevision}`
                  : "Loading the exact active extraction and mapping rules…"}
              </p>
            </div>
            <Button
              type="button"
              variant="outline"
              disabled={mappingBusy}
              onClick={() => setReload((value) => value + 1)}
            >
              <RefreshCw aria-hidden="true" /> Reload mapping
            </Button>
          </div>
          {mapping.kind === "error" ? (
            <FocusedError message={mapping.message} />
          ) : null}
          <FormField
            htmlFor={`federation-mapping-policy-${provider.id}`}
            label="Mapping policy JSON"
            hint={
              provider.kind === "oidc"
                ? `Includes OIDC claim extraction plus exact scalar/group-to-role targets. UserInfo extraction must be ${provider.configuration.useUserInfo ? "present because UserInfo is enabled" : "absent because UserInfo is disabled"}.`
                : "Includes SAML Name/NameFormat extraction plus exact scalar/group-to-role targets."
            }
          >
            <Textarea
              id={`federation-mapping-policy-${provider.id}`}
              aria-busy={mapping.kind === "loading"}
              disabled={mapping.kind !== "ready"}
              readOnly={!canManageMapping}
              rows={16}
              value={mappingDocument}
              onChange={(event) => setMappingDocument(event.target.value)}
            />
          </FormField>
          {canManageMapping ? (
            <>
              <FormField
                htmlFor={`federation-mapping-reason-${provider.id}`}
                label="Mapping policy audit reason"
              >
                <Input
                  id={`federation-mapping-reason-${provider.id}`}
                  required
                  maxLength={federationAuditReasonDOMMaxLength}
                  value={mappingReason}
                  onChange={(event) => setMappingReason(event.target.value)}
                />
              </FormField>
              <Button
                type="submit"
                disabled={
                  mappingBusy ||
                  mapping.kind !== "ready" ||
                  mappingReason.length === 0 ||
                  provider.archivedAt !== null
                }
              >
                Replace mapping policy
              </Button>
            </>
          ) : (
            <p className="federation-policy-editor__permission">
              Editing requires both identity_mapping.manage and role.grant;
              exact operator-team roster authority is rechecked per target.
            </p>
          )}
        </form>
      ) : null}
      {canReadAssurance ? (
        <form
          className="federation-policy-editor"
          aria-label="Edit federated assurance policy"
          onSubmit={replaceAssurance}
        >
          <div className="federation-policy-editor__heading">
            <div>
              <h4>Trusted IdP MFA assertions</h4>
              <p>
                {assurance.kind === "ready"
                  ? `Provider v${assurance.versioned.value.providerVersion} · assurance revision ${assurance.versioned.assurancePolicyRevision}`
                  : "Loading the exact active assurance rules…"}
              </p>
            </div>
            <Button
              type="button"
              variant="outline"
              disabled={assuranceBusy}
              onClick={() => setReload((value) => value + 1)}
            >
              <RefreshCw aria-hidden="true" /> Reload assurance
            </Button>
          </div>
          {assurance.kind === "error" ? (
            <FocusedError message={assurance.message} />
          ) : null}
          <FormField
            htmlFor={`federation-assurance-policy-${provider.id}`}
            label="Assurance trust policy JSON"
            hint="Only exact OIDC ACR/AMR or SAML AuthnContext matches are trusted; every other login falls back to local MFA step-up."
          >
            <Textarea
              id={`federation-assurance-policy-${provider.id}`}
              aria-busy={assurance.kind === "loading"}
              disabled={assurance.kind !== "ready"}
              readOnly={!canManageAssurance}
              rows={12}
              value={assuranceDocument}
              onChange={(event) => setAssuranceDocument(event.target.value)}
            />
          </FormField>
          {canManageAssurance ? (
            <>
              <FormField
                htmlFor={`federation-assurance-reason-${provider.id}`}
                label="Assurance policy audit reason"
              >
                <Input
                  id={`federation-assurance-reason-${provider.id}`}
                  required
                  maxLength={federationAuditReasonDOMMaxLength}
                  value={assuranceReason}
                  onChange={(event) => setAssuranceReason(event.target.value)}
                />
              </FormField>
              <Button
                type="submit"
                disabled={
                  assuranceBusy ||
                  assurance.kind !== "ready" ||
                  assuranceReason.length === 0 ||
                  provider.archivedAt !== null
                }
              >
                Replace assurance policy
              </Button>
            </>
          ) : (
            <p className="federation-policy-editor__permission">
              Editing requires identity_policy.manage.
            </p>
          )}
        </form>
      ) : null}
    </section>
  );
}

function formatMappingPolicy(value: TenantFederationMappingPolicy): string {
  return JSON.stringify(
    value.kind === "oidc"
      ? {
          kind: value.kind,
          oidcClaimRules: value.oidcClaimRules,
          rules: value.rules,
        }
      : {
          kind: value.kind,
          samlAttributeRules: value.samlAttributeRules,
          rules: value.rules,
        },
    null,
    2,
  );
}

function formatAssurancePolicy(value: TenantFederationAssurancePolicy): string {
  return JSON.stringify({ kind: value.kind, rules: value.rules }, null, 2);
}

function parseMappingPolicy(
  document: string,
  context: TenantFederationMappingPolicyContext,
  reason: string,
): TenantFederationMappingPolicyReplaceRequest {
  const value: unknown = JSON.parse(document);
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new PhaseTwoApiError(
      "The mapping editor must contain the current provider kind and a rules array.",
    );
  }
  const candidate = { ...value, reason };
  assertTenantFederationMappingPolicyReplacement(candidate, context);
  if (candidate.kind !== context.kind) {
    throw new PhaseTwoApiError(
      "The mapping editor must contain the current provider kind and a rules array.",
    );
  }
  return candidate;
}

function tenantFederationMappingPolicyContext(
  provider: TenantFederationAuthProvider,
): TenantFederationMappingPolicyContext {
  return provider.kind === "oidc"
    ? { kind: "oidc", useUserInfo: provider.configuration.useUserInfo }
    : { kind: "saml" };
}

function parseAssurancePolicy(
  document: string,
  providerKind: "oidc" | "saml",
  reason: string,
): TenantFederationAssurancePolicyReplaceRequest {
  const value: unknown = JSON.parse(document);
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new PhaseTwoApiError(
      "The assurance editor must contain the current provider kind and a rules array.",
    );
  }
  const candidate = { ...value, reason };
  assertTenantFederationAssurancePolicyReplacement(candidate);
  if (candidate.kind !== providerKind) {
    throw new PhaseTwoApiError(
      "The assurance editor must contain the current provider kind and a rules array.",
    );
  }
  return candidate;
}

function TenantSAMLMaterialControls({
  api,
  busy,
  csrfToken,
  current,
  mutate,
  onChanged,
  tenantId,
}: {
  api: TenantFederationApi;
  busy: boolean;
  csrfToken: string;
  current: TenantFederationProviderVersioned;
  mutate: (action: () => Promise<void>) => Promise<void>;
  onChanged: (
    message: string,
    provider?: TenantFederationProviderVersioned,
  ) => void;
  tenantId: string;
}): React.JSX.Element | null {
  const provider = current.value;
  const [metadataSource, setMetadataSource] = useState<"url" | "xml">("url");
  const [metadataURL, setMetadataURL] = useState("");
  const [metadataXML, setMetadataXML] = useState("");
  const [approveTrustReset, setApproveTrustReset] = useState(false);
  const [reason, setReason] = useState("");
  const [clearCredentialConfirmed, setClearCredentialConfirmed] =
    useState(false);
  if (provider.kind !== "saml") return null;

  function replaceMetadata(event: FormEvent<HTMLFormElement>): void {
    event.preventDefault();
    void mutate(async () => {
      const input =
        metadataSource === "url"
          ? {
              source: "url" as const,
              metadataUrl: metadataURL,
              approveTrustReset,
              reason,
            }
          : {
              source: "xml" as const,
              metadataXml: metadataXML,
              approveTrustReset,
              reason,
            };
      const receipt = await api.replaceSamlMetadata(
        csrfToken,
        tenantId,
        provider.id,
        current.etag,
        input,
      );
      setMetadataURL("");
      setMetadataXML("");
      setApproveTrustReset(false);
      setReason("");
      const refreshed = await api.get(tenantId, provider.id);
      onChanged(
        `SAML IdP metadata was replaced write-only at revision ${receipt.materialRevision}.`,
        refreshed,
      );
    });
  }

  function rotateCredential(): void {
    void mutate(async () => {
      const receipt = await api.replaceSamlSpCredential(
        csrfToken,
        tenantId,
        provider.id,
        current.etag,
        reason,
      );
      setReason("");
      const refreshed = await api.get(tenantId, provider.id);
      onChanged(
        `A new SAML SP credential was generated server-side at revision ${receipt.materialRevision}. No key material was returned.`,
        refreshed,
      );
    });
  }

  function clearCredential(): void {
    if (!clearCredentialConfirmed) return;
    void mutate(async () => {
      const receipt = await api.clearSamlSpCredential(
        csrfToken,
        tenantId,
        provider.id,
        current.etag,
        reason,
      );
      setReason("");
      setClearCredentialConfirmed(false);
      const refreshed = await api.get(tenantId, provider.id);
      onChanged(
        `The SAML SP credential was retired at revision ${receipt.materialRevision}.`,
        refreshed,
      );
    });
  }

  const live = provider.enabled || provider.binding.enabled;
  return (
    <section
      className="federation-saml-material"
      aria-label="SAML protected material"
    >
      <div>
        <h3>
          <LockKeyhole aria-hidden="true" /> SAML protected material
        </h3>
        <p>
          IdP metadata is accepted write-only. SP keys are generated and
          encrypted by the service; this page never accepts or reads a private
          key or certificate.
        </p>
      </div>
      <dl className="federation-detail__facts">
        <div>
          <dt>Public SP metadata</dt>
          <dd>{provider.configuration.spEntityId}</dd>
        </div>
      </dl>
      <form
        className="federation-form federation-form--compact"
        aria-label="Replace tenant SAML IdP metadata"
        onSubmit={replaceMetadata}
      >
        <FormField
          htmlFor={`federation-saml-metadata-source-${provider.id}`}
          label="Metadata source"
        >
          <select
            id={`federation-saml-metadata-source-${provider.id}`}
            value={metadataSource}
            onChange={(event) =>
              setMetadataSource(event.target.value === "xml" ? "xml" : "url")
            }
          >
            <option value="url">Protected HTTPS fetch</option>
            <option value="xml">Write-only XML</option>
          </select>
        </FormField>
        {metadataSource === "url" ? (
          <FormField
            htmlFor={`federation-saml-metadata-url-${provider.id}`}
            label="IdP metadata HTTPS URL"
          >
            <Input
              id={`federation-saml-metadata-url-${provider.id}`}
              type="url"
              required
              maxLength={4096}
              value={metadataURL}
              onChange={(event) => setMetadataURL(event.target.value)}
            />
          </FormField>
        ) : (
          <FormField
            htmlFor={`federation-saml-metadata-xml-${provider.id}`}
            label="Write-only IdP metadata XML"
          >
            <Textarea
              id={`federation-saml-metadata-xml-${provider.id}`}
              required
              value={metadataXML}
              onChange={(event) => setMetadataXML(event.target.value)}
            />
          </FormField>
        )}
        <div className="federation-check">
          <Checkbox
            id={`federation-saml-trust-reset-${provider.id}`}
            checked={approveTrustReset}
            onCheckedChange={(checked) =>
              setApproveTrustReset(checked === true)
            }
          />
          <Label htmlFor={`federation-saml-trust-reset-${provider.id}`}>
            Approve a verified signing-trust reset when certificate continuity
            is absent
          </Label>
        </div>
        <FormField
          htmlFor={`federation-saml-material-reason-${provider.id}`}
          label="SAML material audit reason"
        >
          <Input
            id={`federation-saml-material-reason-${provider.id}`}
            required
            maxLength={federationAuditReasonDOMMaxLength}
            value={reason}
            onChange={(event) => setReason(event.target.value)}
          />
        </FormField>
        <Button type="submit" variant="outline" disabled={busy}>
          Replace IdP metadata
        </Button>
      </form>
      <div className="federation-saml-material__credential">
        <div>
          <h3>
            <KeyRound aria-hidden="true" /> Server-generated SP credential
          </h3>
          <p>
            Rotation and retirement require both provider and binding to be
            disabled so an in-flight SAML transaction cannot lose its pinned
            signing key.
          </p>
        </div>
        {provider.configuration.spKeyPresent ? (
          <div className="federation-check">
            <Checkbox
              id={`federation-clear-saml-credential-confirm-${provider.id}`}
              checked={clearCredentialConfirmed}
              onCheckedChange={(checked) =>
                setClearCredentialConfirmed(checked === true)
              }
            />
            <Label
              htmlFor={`federation-clear-saml-credential-confirm-${provider.id}`}
            >
              Confirm permanent retirement of this SAML SP credential
            </Label>
          </div>
        ) : null}
        <div className="federation-secret-form__actions">
          <Button
            type="button"
            variant="outline"
            disabled={busy || live || reason.length === 0}
            onClick={rotateCredential}
          >
            Generate SP credential
          </Button>
          {provider.configuration.spKeyPresent ? (
            <Button
              type="button"
              variant="destructive"
              disabled={
                busy || live || reason.length === 0 || !clearCredentialConfirmed
              }
              onClick={clearCredential}
            >
              Clear SP credential
            </Button>
          ) : null}
        </div>
      </div>
    </section>
  );
}

function parseCommaSeparated(value: string): string[] {
  return value
    .split(",")
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0);
}

function withOIDCRefreshScope(value: string, enabled: boolean): string {
  const scopes = parseCommaSeparated(value).filter(
    (scope) => scope !== "offline_access",
  );
  if (enabled) scopes.push("offline_access");
  return scopes.join(", ");
}

function tenantOIDCPostLogoutRedirectURI(): string {
  try {
    const publicOrigin = globalThis.location?.origin;
    return publicOrigin && publicOrigin !== "null"
      ? `${publicOrigin}${tenantOIDCPostLogoutRedirectPath}`
      : "";
  } catch {
    return "";
  }
}

function parseLines(value: string): string[] {
  return value
    .split(/\r?\n/u)
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0);
}

function isSAMLSignatureAlgorithm(
  value: string,
): value is SAMLSignatureAlgorithm {
  return samlSignatureAlgorithms.some((algorithm) => algorithm === value);
}

function isOIDCSigningAlgorithm(value: string): value is OIDCSigningAlgorithm {
  return (
    value === "RS256" ||
    value === "RS384" ||
    value === "RS512" ||
    value === "PS256" ||
    value === "PS384" ||
    value === "PS512" ||
    value === "ES256" ||
    value === "ES384" ||
    value === "ES512" ||
    value === "EdDSA"
  );
}

function isSAMLSignaturePolicy(value: string): value is SAMLSignaturePolicy {
  return (
    value === "signed_assertion" ||
    value === "signed_response" ||
    value === "both"
  );
}

function ProviderBadge({
  provider,
}: {
  provider: Pick<
    TenantFederationAuthProviderSummary,
    "archivedAt" | "configured" | "enabled"
  >;
}): React.JSX.Element {
  if (provider.archivedAt) return <Badge variant="outline">Archived</Badge>;
  if (provider.enabled && !provider.configured)
    return <Badge variant="destructive">Enabled · unavailable</Badge>;
  if (provider.enabled) return <Badge>Enabled</Badge>;
  if (provider.configured)
    return <Badge variant="secondary">Ready · disabled</Badge>;
  return <Badge variant="outline">Setup required</Badge>;
}

function FederationSkeleton(): React.JSX.Element {
  return (
    <div
      className="content federation-page"
      aria-busy="true"
      aria-label="Loading federated identity providers"
    >
      <Card>
        <CardContent className="federation-skeleton">
          <span />
          <span />
          <span />
        </CardContent>
      </Card>
    </div>
  );
}

function handleAuthorityError(
  error: unknown,
  reloadAuthority: () => void,
  clearSession: () => void,
): void {
  if (!(error instanceof PhaseTwoApiError)) return;
  if (error.status === 401) clearSession();
  else if (error.status === 403) reloadAuthority();
}

function describeFederationError(error: unknown, fallback: string): string {
  return describePhaseTwoError(error, fallback);
}
