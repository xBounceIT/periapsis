import { Badge } from "@periapsis/ui/components/ui/badge";
import { Button } from "@periapsis/ui/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@periapsis/ui/components/ui/card";
import { Textarea } from "@periapsis/ui/components/ui/textarea";
import {
  ArrowDown,
  Eye,
  KeyRound,
  Network,
  Plus,
  RotateCw,
} from "lucide-react";
import { FocusedError } from "../components/focused-error";
import { FormField } from "../components/form-field";
import {
  type ServiceAccountCredentialPageView,
  type ServiceAccountCredentialView,
  type ServiceAccountView,
  type VersionedView,
} from "../lib/phase-two-types";
import {
  capitalize,
  formatTimestamp,
  type PaginationState,
} from "./service-account-model";

export function CredentialPanel(props: {
  account: ServiceAccountView;
  canManageCredentials: boolean;
  credentialActionError: string | null;
  credentialDetail:
    | { kind: "error"; message: string }
    | { kind: "loading" }
    | {
        credential: VersionedView<ServiceAccountCredentialView>;
        kind: "ready";
      }
    | null;
  credentialPagination: PaginationState;
  credentialRevokeReason: string;
  credentialRevoking: boolean;
  credentials: ServiceAccountCredentialPageView;
  hidden: boolean;
  id: string;
  onCloseCredential: () => void;
  onIssue: () => void;
  onLoadMore: () => void;
  onOpenCredential: (credential: ServiceAccountCredentialView) => void;
  onRevoke: () => void;
  onRevokeReasonChange: (reason: string) => void;
  onRotate: (credential: ServiceAccountCredentialView) => void;
  selectedCredentialId: string | null;
}): React.JSX.Element {
  const model = useCredentialPanelModel(props);
  return <CredentialPanelView model={model.data} />;
}

function useCredentialPanelModel({
  account,
  canManageCredentials,
  credentialActionError,
  credentialDetail,
  credentialPagination,
  credentialRevokeReason,
  credentialRevoking,
  credentials,
  hidden,
  id,
  onCloseCredential,
  onIssue,
  onLoadMore,
  onOpenCredential,
  onRevoke,
  onRevokeReasonChange,
  onRotate,
  selectedCredentialId,
}: {
  account: ServiceAccountView;
  canManageCredentials: boolean;
  credentialActionError: string | null;
  credentialDetail:
    | { kind: "error"; message: string }
    | { kind: "loading" }
    | {
        credential: VersionedView<ServiceAccountCredentialView>;
        kind: "ready";
      }
    | null;
  credentialPagination: PaginationState;
  credentialRevokeReason: string;
  credentialRevoking: boolean;
  credentials: ServiceAccountCredentialPageView;
  hidden: boolean;
  id: string;
  onCloseCredential: () => void;
  onIssue: () => void;
  onLoadMore: () => void;
  onOpenCredential: (credential: ServiceAccountCredentialView) => void;
  onRevoke: () => void;
  onRevokeReasonChange: (reason: string) => void;
  onRotate: (credential: ServiceAccountCredentialView) => void;
  selectedCredentialId: string | null;
}) {
  return {
    kind: "ready" as const,
    data: {
      account,
      canManageCredentials,
      credentialActionError,
      credentialDetail,
      credentialPagination,
      credentialRevokeReason,
      credentialRevoking,
      credentials,
      hidden,
      id,
      onCloseCredential,
      onIssue,
      onLoadMore,
      onOpenCredential,
      onRevoke,
      onRevokeReasonChange,
      onRotate,
      selectedCredentialId,
    },
  };
}

function CredentialPanelView({
  model,
}: {
  model: Extract<
    ReturnType<typeof useCredentialPanelModel>,
    { kind: "ready" }
  >["data"];
}): React.JSX.Element {
  const {
    credentialActionError,
    credentialDetail,
    credentialPagination,
    hidden,
    id,
    selectedCredentialId,
  } = model;
  return (
    <section
      id={`${id}-credentials-panel`}
      role="tabpanel"
      aria-labelledby={`${id}-credentials-tab`}
      hidden={hidden}
      tabIndex={0}
      className="service-account-tab-panel service-account-credential-panel"
    >
      <CredentialInventoryHeading model={model} />
      <p className="capability-note">
        Inventory never contains a bearer token, locator, or digest. Empty
        network restrictions mean any trusted resolved client address.
      </p>
      {<CredentialPanelNoCredentialMetadataReturned model={model} />}
      {credentialPagination.error ? (
        <FocusedError
          title="More credentials could not be loaded"
          message={credentialPagination.error}
        />
      ) : null}
      {<CredentialPagination model={model} />}

      {selectedCredentialId ? (
        <Card className="service-account-credential-detail">
          <CredentialDetailHeading model={model} />
          <CardContent>
            {credentialDetail?.kind === "loading" ? (
              <div
                className="service-account-inline-skeleton"
                aria-label="Loading redacted credential detail"
              >
                <span />
                <span />
              </div>
            ) : null}
            {credentialDetail?.kind === "error" ? (
              <FocusedError message={credentialDetail.message} />
            ) : null}
            {credentialDetail?.kind === "ready" ? (
              <>
                <CredentialFacts model={model} />
                {credentialActionError ? (
                  <FocusedError
                    title="Credential action not completed"
                    message={credentialActionError}
                  />
                ) : null}
                {<CredentialActions model={model} />}
              </>
            ) : null}
          </CardContent>
        </Card>
      ) : null}
    </section>
  );
}

function CredentialPanelNoCredentialMetadataReturned({
  model,
}: {
  model: React.ComponentProps<typeof CredentialPanelView>["model"];
}): React.ReactNode {
  const { account, canManageCredentials, credentials, onOpenCredential } =
    model;
  return credentials.items.length === 0 ? (
    <div className="service-account-empty service-account-empty--inline">
      <KeyRound aria-hidden="true" />
      <h4>No credential metadata returned</h4>
      <p>
        {canManageCredentials && account.state === "active"
          ? "Issue a credential only after its exact alert.create@tenant authority is live."
          : "No redacted credential records are visible for this account."}
      </p>
    </div>
  ) : (
    <div className="service-account-credential-grid">
      {credentials.items.map((credential) => (
        <Card className="service-account-credential-card" key={credential.id}>
          <CardHeader>
            <span className="service-account-credential-mark">
              <KeyRound aria-hidden="true" />
            </span>
            <div>
              <CardTitle>{credential.label}</CardTitle>
              <CardDescription>
                Expires {formatTimestamp(credential.expiresAt)}
              </CardDescription>
            </div>
            <Badge
              variant={credential.state === "active" ? "secondary" : "outline"}
            >
              {capitalize(credential.state)}
            </Badge>
          </CardHeader>
          <CardContent>
            <p>
              <Network aria-hidden="true" />
              {credential.allowedNetworks.length === 0
                ? "Any trusted source address"
                : `${credential.allowedNetworks.length} source network${credential.allowedNetworks.length === 1 ? "" : "s"}`}
            </p>
            <Button
              type="button"
              size="sm"
              variant="outline"
              aria-label={`View credential ${credential.label} (${credential.id})`}
              onClick={() => onOpenCredential(credential)}
            >
              <Eye aria-hidden="true" /> View redacted detail
            </Button>
          </CardContent>
        </Card>
      ))}
    </div>
  );
}

function CredentialFacts({
  model,
}: {
  model: React.ComponentProps<typeof CredentialPanelView>["model"];
}): React.ReactNode {
  const { credentialDetail } = model;
  if (!credentialDetail) return null;
  if (credentialDetail.kind !== "ready") return null;
  return (
    <dl className="service-account-facts service-account-credential-facts">
      <div>
        <dt>Label</dt>
        <dd>{credentialDetail.credential.value.label}</dd>
      </div>
      <div>
        <dt>Permission</dt>
        <dd>
          <code>alert.create@tenant</code>
        </dd>
      </div>
      <div>
        <dt>Issued</dt>
        <dd>{formatTimestamp(credentialDetail.credential.value.issuedAt)}</dd>
      </div>
      <div>
        <dt>Last used</dt>
        <dd>
          {credentialDetail.credential.value.lastUsedAt
            ? `${formatTimestamp(credentialDetail.credential.value.lastUsedAt)} · ${String(credentialDetail.credential.value.lastUsedIp)}`
            : "Never"}
        </dd>
      </div>
      <div>
        <dt>ETag</dt>
        <dd>
          <code>{credentialDetail.credential.etag}</code>
        </dd>
      </div>
      <div>
        <dt>Networks</dt>
        <dd>
          {credentialDetail.credential.value.allowedNetworks.length === 0
            ? "Unrestricted"
            : credentialDetail.credential.value.allowedNetworks.join(", ")}
        </dd>
      </div>
    </dl>
  );
}

function CredentialActions({
  model,
}: {
  model: React.ComponentProps<typeof CredentialPanelView>["model"];
}): React.ReactNode {
  const {
    account,
    canManageCredentials,
    credentialDetail,
    credentialRevokeReason,
    credentialRevoking,
    id,
    onRevoke,
    onRevokeReasonChange,
    onRotate,
  } = model;
  if (!credentialDetail) return null;
  if (credentialDetail.kind !== "ready") return null;
  return canManageCredentials &&
    account.state === "active" &&
    credentialDetail.credential.value.state === "active" ? (
    <div className="service-account-credential-actions">
      <Button
        type="button"
        variant="outline"
        onClick={() => onRotate(credentialDetail.credential.value)}
      >
        <RotateCw aria-hidden="true" /> Rotate credential
      </Button>
      <form
        className="service-account-inline-revoke"
        onSubmit={(event) => {
          event.preventDefault();
          onRevoke();
        }}
      >
        <FormField
          htmlFor={`${id}-credential-revoke-reason`}
          label="Revoke reason"
        >
          <Textarea
            id={`${id}-credential-revoke-reason`}
            maxLength={500}
            disabled={credentialRevoking}
            value={credentialRevokeReason}
            onChange={(event) => onRevokeReasonChange(event.target.value)}
          />
        </FormField>
        <Button
          type="submit"
          variant="destructive"
          disabled={credentialRevoking}
        >
          {credentialRevoking ? "Revoking credential…" : "Revoke credential"}
        </Button>
      </form>
    </div>
  ) : null;
}

function CredentialInventoryHeading({
  model,
}: {
  model: React.ComponentProps<typeof CredentialPanelView>["model"];
}): React.ReactNode {
  const { account, canManageCredentials, onIssue } = model;
  return (
    <div className="service-account-panel-heading">
      <div>
        <p className="section-label">Redacted inventory</p>
        <h3>API credentials</h3>
      </div>
      {canManageCredentials && account.state === "active" ? (
        <Button type="button" onClick={onIssue}>
          <Plus aria-hidden="true" /> Issue credential
        </Button>
      ) : null}
    </div>
  );
}

function CredentialPagination({
  model,
}: {
  model: React.ComponentProps<typeof CredentialPanelView>["model"];
}): React.ReactNode {
  const { credentialPagination, credentials, onLoadMore } = model;
  return credentials.nextCursor ? (
    <Button
      type="button"
      variant="outline"
      disabled={credentialPagination.loading}
      onClick={onLoadMore}
    >
      <ArrowDown aria-hidden="true" />
      {credentialPagination.loading
        ? "Loading credentials…"
        : "Load more credentials"}
    </Button>
  ) : null;
}

function CredentialDetailHeading({
  model,
}: {
  model: React.ComponentProps<typeof CredentialPanelView>["model"];
}): React.ReactNode {
  const { onCloseCredential } = model;
  return (
    <CardHeader>
      <div>
        <CardTitle>Redacted credential detail</CardTitle>
        <CardDescription>
          Loaded directly from the tenant-scoped detail operation.
        </CardDescription>
      </div>
      <Button
        type="button"
        variant="ghost"
        size="sm"
        onClick={onCloseCredential}
      >
        Close detail
      </Button>
    </CardHeader>
  );
}
