import { Badge } from "@periapsis/ui/components/ui/badge";
import { Button } from "@periapsis/ui/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@periapsis/ui/components/ui/card";
import { Input } from "@periapsis/ui/components/ui/input";
import { Textarea } from "@periapsis/ui/components/ui/textarea";
import { ArrowDown, Bot, KeyRound, ShieldCheck } from "lucide-react";

import { FocusedError } from "../components/focused-error";
import { FormField } from "../components/form-field";
import type {
  ServiceAccountRoleGrantPageView,
  ServiceAccountRoleGrantView,
  ServiceAccountView,
} from "../lib/phase-two-types";
import {
  capitalize,
  formatTimestamp,
  type MachineRoleState,
  type PaginationState,
  type ServiceAccountDetailReady,
} from "./service-account-model";

export function ServiceAccountAuthorityRail({
  detail,
}: {
  detail: ServiceAccountDetailReady;
}): React.JSX.Element {
  const liveGrants = detail.grants.items.filter(
    (grant) => grant.state === "active",
  ).length;
  const liveCredentials = detail.credentials.items.filter(
    (credential) => credential.state === "active",
  ).length;
  return (
    <div
      className="service-account-authority-rail"
      aria-label="Machine authority path"
    >
      <span className="service-account-authority-node">
        <Bot aria-hidden="true" />
        <span>
          <small>Identity</small>
          <strong>{capitalize(detail.account.value.state)}</strong>
        </span>
      </span>
      <span
        className="service-account-authority-connector"
        aria-hidden="true"
      />
      <span className="service-account-authority-node">
        <ShieldCheck aria-hidden="true" />
        <span>
          <small>Machine roles</small>
          <strong>{liveGrants} live</strong>
        </span>
      </span>
      <span
        className="service-account-authority-connector"
        aria-hidden="true"
      />
      <span className="service-account-authority-node">
        <KeyRound aria-hidden="true" />
        <span>
          <small>Credentials</small>
          <strong>{liveCredentials} live</strong>
        </span>
      </span>
    </div>
  );
}

export function RoleAuthorityPanel({
  account,
  canGrantRoles,
  grantError,
  grantExpiresAt,
  grantPagination,
  grantReason,
  grantRevokeReasons,
  grantRevokingId,
  grants,
  grantRoleId,
  grantSaving,
  hidden,
  id,
  machineRoles,
  onGrantExpiresAtChange,
  onGrantReasonChange,
  onGrantRevokeReasonChange,
  onGrantRoleIdChange,
  onGrantSubmit,
  onLoadMoreGrants,
  onLoadMoreRoles,
  onRevoke,
  rolePagination,
}: {
  account: ServiceAccountView;
  canGrantRoles: boolean;
  grantError: string | null;
  grantExpiresAt: string;
  grantPagination: PaginationState;
  grantReason: string;
  grantRevokeReasons: Readonly<Record<string, string>>;
  grantRevokingId: string | null;
  grants: ServiceAccountRoleGrantPageView;
  grantRoleId: string;
  grantSaving: boolean;
  hidden: boolean;
  id: string;
  machineRoles: MachineRoleState;
  onGrantExpiresAtChange: (value: string) => void;
  onGrantReasonChange: (value: string) => void;
  onGrantRevokeReasonChange: (grantId: string, reason: string) => void;
  onGrantRoleIdChange: (value: string) => void;
  onGrantSubmit: (event: React.FormEvent<HTMLFormElement>) => void;
  onLoadMoreGrants: () => void;
  onLoadMoreRoles: () => void;
  onRevoke: (grant: ServiceAccountRoleGrantView) => void;
  rolePagination: PaginationState;
}): React.JSX.Element {
  return (
    <section
      id={`${id}-roles-panel`}
      role="tabpanel"
      aria-labelledby={`${id}-roles-tab`}
      hidden={hidden}
      tabIndex={0}
      className="service-account-tab-panel service-account-role-panel"
    >
      <div className="service-account-panel-heading">
        <div>
          <p className="section-label">Exact machine authority</p>
          <h3>Role grants</h3>
        </div>
        <Badge variant="outline">{grants.items.length} loaded</Badge>
      </div>
      {grantError ? (
        <FocusedError title="Role action not completed" message={grantError} />
      ) : null}
      {canGrantRoles && account.state === "active" ? (
        <form
          className="service-account-edge-form"
          onSubmit={onGrantSubmit}
          noValidate
        >
          <div>
            <h4>Grant a machine-only role</h4>
            <p>
              The selector excludes every human role. The server repeats the
              exact delegation consequence check.
            </p>
          </div>
          {machineRoles.kind === "loading" ? (
            <p className="capability-note">Loading machine roles…</p>
          ) : null}
          {machineRoles.kind === "error" ? (
            <FocusedError
              title="Machine roles unavailable"
              message={machineRoles.message}
            />
          ) : null}
          {machineRoles.kind === "ready" ? (
            <>
              <FormField htmlFor={`${id}-machine-role`} label="Machine role">
                <select
                  id={`${id}-machine-role`}
                  className="service-account-select"
                  value={grantRoleId}
                  disabled={grantSaving}
                  onChange={(event) => onGrantRoleIdChange(event.target.value)}
                >
                  <option value="">Select a machine-only role</option>
                  {machineRoles.items.map((role) => (
                    <option key={role.id} value={role.id}>
                      {role.name} ({role.key})
                    </option>
                  ))}
                </select>
              </FormField>
              {machineRoles.items.length === 0 ? (
                <p className="capability-note">
                  No service_account role appears in the loaded role pages.
                </p>
              ) : null}
              {rolePagination.error ? (
                <FocusedError
                  title="More roles could not be loaded"
                  message={rolePagination.error}
                />
              ) : null}
              {machineRoles.nextCursor ? (
                <Button
                  type="button"
                  size="sm"
                  variant="outline"
                  disabled={rolePagination.loading}
                  onClick={onLoadMoreRoles}
                >
                  <ArrowDown aria-hidden="true" />
                  {rolePagination.loading
                    ? "Loading roles…"
                    : "Load more machine roles"}
                </Button>
              ) : null}
            </>
          ) : null}
          <div className="service-account-two-column-form">
            <FormField
              htmlFor={`${id}-grant-expiry`}
              label="Grant expiry"
              optional
            >
              <Input
                id={`${id}-grant-expiry`}
                type="datetime-local"
                disabled={grantSaving}
                value={grantExpiresAt}
                onChange={(event) => onGrantExpiresAtChange(event.target.value)}
              />
            </FormField>
            <FormField htmlFor={`${id}-grant-reason`} label="Grant reason">
              <Textarea
                id={`${id}-grant-reason`}
                maxLength={500}
                disabled={grantSaving}
                value={grantReason}
                onChange={(event) => onGrantReasonChange(event.target.value)}
              />
            </FormField>
          </div>
          <Button
            type="submit"
            disabled={
              grantSaving || machineRoles.kind !== "ready" || !grantRoleId
            }
          >
            <ShieldCheck aria-hidden="true" />
            {grantSaving ? "Granting role…" : "Grant machine role"}
          </Button>
        </form>
      ) : (
        <p className="capability-note">
          Role mutation requires both service_account.manage@tenant and
          role.grant@tenant. Archived identities cannot receive new grants.
        </p>
      )}

      {grants.items.length === 0 ? (
        <div className="service-account-empty service-account-empty--inline">
          <ShieldCheck aria-hidden="true" />
          <h4>No role grants returned</h4>
          <p>Credentials cannot be useful until live role authority exists.</p>
        </div>
      ) : (
        <div className="service-account-edge-list">
          {grants.items.map((grant) => (
            <Card className="service-account-edge-card" key={grant.id}>
              <CardHeader>
                <div>
                  <CardTitle>{grant.role.name}</CardTitle>
                  <CardDescription>
                    {grant.role.key} · {grant.provenance.sourceKind}
                  </CardDescription>
                </div>
                <Badge
                  variant={grant.state === "active" ? "secondary" : "outline"}
                >
                  {capitalize(grant.state)}
                </Badge>
              </CardHeader>
              <CardContent>
                <dl className="service-account-edge-facts">
                  <div>
                    <dt>Granted</dt>
                    <dd>{formatTimestamp(grant.provenance.grantedAt)}</dd>
                  </div>
                  <div>
                    <dt>Expires</dt>
                    <dd>
                      {grant.provenance.expiresAt
                        ? formatTimestamp(grant.provenance.expiresAt)
                        : "Dependency-derived / unbounded edge"}
                    </dd>
                  </div>
                  <div>
                    <dt>ETag</dt>
                    <dd>
                      <code>{grant.etag}</code>
                    </dd>
                  </div>
                </dl>
                <blockquote>{grant.provenance.reason}</blockquote>
                {canGrantRoles &&
                grant.state === "active" &&
                grant.managedByServiceAccountApi ? (
                  <form
                    className="service-account-inline-revoke"
                    onSubmit={(event) => {
                      event.preventDefault();
                      onRevoke(grant);
                    }}
                  >
                    <FormField
                      htmlFor={`${id}-revoke-grant-${grant.id}`}
                      label={`Revoke ${grant.role.name}`}
                    >
                      <Textarea
                        id={`${id}-revoke-grant-${grant.id}`}
                        maxLength={500}
                        disabled={grantRevokingId === grant.id}
                        value={grantRevokeReasons[grant.id] ?? ""}
                        onChange={(event) =>
                          onGrantRevokeReasonChange(
                            grant.id,
                            event.target.value,
                          )
                        }
                      />
                    </FormField>
                    <Button
                      type="submit"
                      size="sm"
                      variant="destructive"
                      disabled={grantRevokingId === grant.id}
                    >
                      {grantRevokingId === grant.id
                        ? "Revoking role…"
                        : "Revoke role grant"}
                    </Button>
                  </form>
                ) : null}
              </CardContent>
            </Card>
          ))}
        </div>
      )}
      {grantPagination.error ? (
        <FocusedError
          title="More grants could not be loaded"
          message={grantPagination.error}
        />
      ) : null}
      {grants.nextCursor ? (
        <Button
          type="button"
          variant="outline"
          disabled={grantPagination.loading}
          onClick={onLoadMoreGrants}
        >
          <ArrowDown aria-hidden="true" />
          {grantPagination.loading
            ? "Loading role grants…"
            : "Load more role grants"}
        </Button>
      ) : null}
    </section>
  );
}
