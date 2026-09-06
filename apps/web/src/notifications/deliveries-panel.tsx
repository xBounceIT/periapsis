import type {
  NotificationDelivery,
  NotificationDeliveryDetail,
  NotificationDeliveryStatus,
} from "@periapsis/contracts";
import { Badge } from "@periapsis/ui/components/ui/badge";
import { Button } from "@periapsis/ui/components/ui/button";
import { Input } from "@periapsis/ui/components/ui/input";
import {
  Table,
  TableBody,
  TableCell,
  TableRow,
} from "@periapsis/ui/components/ui/table";
import { ArrowUpRight, RotateCw, TriangleAlert } from "lucide-react";
import { useCallback, useRef, useState } from "react";
import { TableColumnHeaders } from "../components/table-column-headers";
import { requiresSubmissionUncertainConfirmation } from "./deliveries-panel-model";

import { FormField } from "../components/form-field";
import { TenantInstant } from "../lib/tenant-date-time-context";
import {
  bindMutationAttempt,
  compactNotificationId,
  resetMutationAttempt,
  type MutationAttemptReference,
} from "./model";
import type { NotificationAdminApi } from "./notification-api";
import {
  InventoryHeading,
  NotificationEmpty,
  NotificationError,
  NotificationLoading,
} from "./notification-primitives";
import {
  useCursorInventory,
  type CursorInventory,
} from "./use-cursor-inventory";

const deliveryStatuses = [
  "queued",
  "leased",
  "reserved",
  "retry_scheduled",
  "delivered",
  "dead_lettered",
] as const satisfies readonly NotificationDeliveryStatus[];

interface DeliveriesPanelProps {
  api: NotificationAdminApi;
  csrfToken: string;
  tenantId: string;
}

export function DeliveriesPanel({
  api,
  csrfToken,
  tenantId,
}: DeliveriesPanelProps) {
  const [status, setStatus] = useState<NotificationDeliveryStatus | "all">(
    "all",
  );
  const load = useCallback(
    (after: string | undefined, signal: AbortSignal) =>
      api.listDeliveries({
        ...(after ? { after } : {}),
        signal,
        ...(status === "all" ? {} : { status: [status] }),
        tenantId,
      }),
    [api, status, tenantId],
  );
  const inventory = useCursorInventory(load);
  const [detail, setDetail] = useState<NotificationDeliveryDetail | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [reason, setReason] = useState("");
  const [confirmSubmissionUncertain, setConfirmSubmissionUncertain] =
    useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const retryAttempt = useRef<MutationAttemptReference>({ current: null });

  async function openDelivery(id: string): Promise<void> {
    setBusy(true);
    setError(null);
    try {
      setDetail(await api.getDelivery({ id, tenantId }));
      setConfirmSubmissionUncertain(false);
      setReason("");
      resetMutationAttempt(retryAttempt.current);
    } catch (caught: unknown) {
      setError(caught);
    } finally {
      setBusy(false);
    }
  }

  async function retryDelivery(): Promise<void> {
    if (!detail) return;
    const mustConfirm = requiresSubmissionUncertainConfirmation(detail);
    if (mustConfirm && !confirmSubmissionUncertain) return;
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const body = {
        expectedAttempt: detail.attemptCount,
        acknowledgeUncertainSubmission:
          mustConfirm && confirmSubmissionUncertain,
        reason: reason.trim(),
      };
      const retried = await api.retryDelivery({
        body,
        csrfToken,
        id: detail.id,
        idempotencyKey: bindMutationAttempt(
          retryAttempt.current,
          "notification-delivery.retry",
          tenantId,
          body,
        ),
        tenantId,
      });
      inventory.upsert(retried, (item) => item.id);
      setNotice(
        `Linked retry ${retried.id} was created. Original history is unchanged.`,
      );
      resetMutationAttempt(retryAttempt.current);
      setReason("");
      setConfirmSubmissionUncertain(false);
    } catch (caught: unknown) {
      setError(caught);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="notification-panel-grid">
      <DeliveryInventory
        busy={busy}
        inventory={inventory}
        openDelivery={openDelivery}
        setStatus={setStatus}
        status={status}
      />

      <DeliveryDetail
        busy={busy}
        confirmSubmissionUncertain={confirmSubmissionUncertain}
        detail={detail}
        error={error}
        notice={notice}
        reason={reason}
        retryAttempt={retryAttempt}
        retryDelivery={retryDelivery}
        setConfirmSubmissionUncertain={setConfirmSubmissionUncertain}
        setReason={setReason}
      />
    </div>
  );
}

function DeliveryRow({
  busy,
  delivery,
  onOpen,
}: {
  busy: boolean;
  delivery: NotificationDelivery;
  onOpen: (id: string) => Promise<void>;
}) {
  return (
    <TableRow>
      <TableCell>
        <strong>{compactNotificationId(delivery.id)}</strong>
        <small>
          <TenantInstant value={delivery.createdAt} precision="second" />
        </small>
      </TableCell>
      <TableCell>
        {delivery.destinationRedacted}
        <small>
          {delivery.channel} · {delivery.audience}
        </small>
      </TableCell>
      <TableCell>
        <Badge
          variant={
            delivery.status === "dead_lettered"
              ? "destructive"
              : delivery.status === "delivered"
                ? "secondary"
                : "outline"
          }
        >
          {delivery.status.replaceAll("_", " ")}
        </Badge>
        {delivery.failureClass ? <small>{delivery.failureClass}</small> : null}
      </TableCell>
      <TableCell>
        {delivery.attemptCount} / {delivery.maximumAttempts}
      </TableCell>
      <TableCell>
        <Button
          type="button"
          size="sm"
          variant="ghost"
          disabled={busy}
          onClick={() => void onOpen(delivery.id)}
        >
          Inspect <ArrowUpRight aria-hidden="true" />
        </Button>
      </TableCell>
    </TableRow>
  );
}

function isDeliveryStatus(value: string): value is NotificationDeliveryStatus {
  return deliveryStatuses.some((status) => status === value);
}

interface DeliveryDetailProps {
  busy: boolean;
  confirmSubmissionUncertain: boolean;
  detail: NotificationDeliveryDetail | null;
  error: unknown;
  notice: string | null;
  reason: string;
  retryAttempt: React.RefObject<MutationAttemptReference>;
  retryDelivery: () => Promise<void>;
  setConfirmSubmissionUncertain: React.Dispatch<React.SetStateAction<boolean>>;
  setReason: React.Dispatch<React.SetStateAction<string>>;
}

function DeliveryDetail(props: DeliveryDetailProps): React.JSX.Element {
  const { detail, error, notice } = props;
  return (
    <aside
      className="notification-editor notification-delivery-detail"
      aria-label="Delivery detail"
    >
      {!detail ? (
        <NotificationEmpty
          title="Select a delivery"
          detail="Inspect append-only attempts and sanitized provider receipts. Full destinations and message bodies are never projected."
        />
      ) : (
        <>
          <header>
            <div>
              <p className="section-label">Immutable delivery</p>
              <h2>{compactNotificationId(detail.id)}</h2>
            </div>
            <Badge
              variant={
                detail.status === "dead_lettered" ? "destructive" : "outline"
              }
            >
              {detail.status.replaceAll("_", " ")}
            </Badge>
          </header>
          {error ? (
            <NotificationError
              error={error}
              fallback="The delivery action could not be completed."
            />
          ) : null}
          {notice ? (
            <p className="notification-notice" role="status">
              {notice}
            </p>
          ) : null}
          <dl className="notification-definition-list">
            <div>
              <dt>Channel</dt>
              <dd>{detail.channel}</dd>
            </div>
            <div>
              <dt>Audience</dt>
              <dd>{detail.audience}</dd>
            </div>
            <div>
              <dt>Destination</dt>
              <dd>{detail.destinationRedacted}</dd>
            </div>
            <div>
              <dt>Event</dt>
              <dd>{compactNotificationId(detail.eventId)}</dd>
            </div>
            <div>
              <dt>Created</dt>
              <dd>
                <TenantInstant value={detail.createdAt} precision="second" />
              </dd>
            </div>
            {detail.failureClass ? (
              <div>
                <dt>Failure class</dt>
                <dd>{detail.failureClass}</dd>
              </div>
            ) : null}
          </dl>
          <DeliveryAttemptHistory detail={detail} />
          {detail.status === "dead_lettered" ? (
            <DeliveryRetryForm {...props} detail={detail} />
          ) : null}
        </>
      )}
    </aside>
  );
}

interface DeliveryInventoryProps {
  busy: boolean;
  inventory: CursorInventory<NotificationDelivery>;
  openDelivery: (id: string) => Promise<void>;
  setStatus: React.Dispatch<
    React.SetStateAction<NotificationDeliveryStatus | "all">
  >;
  status: NotificationDeliveryStatus | "all";
}

function DeliveryInventory({
  busy,
  inventory,
  openDelivery,
  setStatus,
  status,
}: DeliveryInventoryProps): React.JSX.Element {
  return (
    <section
      className="notification-inventory"
      aria-busy={inventory.kind === "loading"}
    >
      <InventoryHeading
        busy={inventory.kind === "loading"}
        count={inventory.items.length}
        label="Delivery ledger"
        onRefresh={inventory.refresh}
      />
      <label className="notification-filter">
        Status
        <select
          value={status}
          onChange={(event) => {
            const next = event.target.value;
            if (next === "all" || isDeliveryStatus(next)) setStatus(next);
          }}
        >
          <option value="all">All states</option>
          {deliveryStatuses.map((value) => (
            <option key={value} value={value}>
              {value.replaceAll("_", " ")}
            </option>
          ))}
        </select>
      </label>
      {inventory.kind === "loading" ? (
        <NotificationLoading label="Loading redacted deliveries" />
      ) : null}
      {inventory.error ? (
        <NotificationError
          error={inventory.error}
          fallback="Delivery history could not be loaded."
        />
      ) : null}
      {inventory.kind === "ready" && inventory.items.length === 0 ? (
        <NotificationEmpty
          title="No matching deliveries"
          detail="The immutable delivery ledger has no jobs in this filter."
        />
      ) : null}
      {inventory.items.length > 0 ? (
        <div className="notification-table-wrap">
          <Table>
            <TableColumnHeaders
              columns={["Delivery", "Destination", "Status", "Attempts"]}
              actionLabel="Actions"
            />
            <TableBody>
              {inventory.items.map((delivery) => (
                <DeliveryRow
                  key={delivery.id}
                  delivery={delivery}
                  busy={busy}
                  onOpen={openDelivery}
                />
              ))}
            </TableBody>
          </Table>
        </div>
      ) : null}
      {inventory.nextCursor ? (
        <Button
          type="button"
          variant="outline"
          disabled={inventory.loadingMore}
          onClick={() => void inventory.loadMore()}
        >
          Load more deliveries
        </Button>
      ) : null}
    </section>
  );
}

function DeliveryAttemptHistory({
  detail,
}: {
  detail: NonNullable<DeliveryDetailProps["detail"]>;
}): React.JSX.Element {
  return (
    <section
      className="notification-attempts"
      aria-labelledby="delivery-attempts-title"
    >
      <h3 id="delivery-attempts-title">Attempt history</h3>
      <ol>
        {detail.attempts.map((attempt) => (
          <li key={attempt.number}>
            <span className="notification-attempt-marker">
              {attempt.number}
            </span>
            <div>
              <strong>{attempt.outcome}</strong>
              <small>
                <TenantInstant value={attempt.startedAt} precision="second" />
              </small>
              {attempt.failureClass ? (
                <span>Failure: {attempt.failureClass}</span>
              ) : null}
              {attempt.providerReceipt ? (
                <code>
                  Receipt{" "}
                  {compactNotificationId(attempt.providerReceipt.receiptDigest)}
                </code>
              ) : null}
            </div>
          </li>
        ))}
      </ol>
    </section>
  );
}

function DeliveryRetryForm({
  busy,
  confirmSubmissionUncertain,
  detail,
  reason,
  retryAttempt,
  retryDelivery,
  setConfirmSubmissionUncertain,
  setReason,
}: DeliveryDetailProps & {
  detail: NonNullable<DeliveryDetailProps["detail"]>;
}): React.JSX.Element {
  return (
    <section className="notification-toolbox">
      <h3>Create linked retry</h3>
      <p>The original delivery and all attempts remain immutable.</p>
      <FormField htmlFor="delivery-retry-reason" label="Audited reason">
        <Input
          id="delivery-retry-reason"
          required
          maxLength={500}
          value={reason}
          onChange={(event) => {
            setReason(event.target.value);
            resetMutationAttempt(retryAttempt.current);
          }}
        />
      </FormField>
      {requiresSubmissionUncertainConfirmation(detail) ? (
        <label className="notification-uncertain-confirm">
          <TriangleAlert aria-hidden="true" />
          <input
            type="checkbox"
            checked={confirmSubmissionUncertain}
            onChange={(event) => {
              setConfirmSubmissionUncertain(event.target.checked);
              resetMutationAttempt(retryAttempt.current);
            }}
          />
          <span>
            <strong>Provider submission is uncertain</strong>I understand the
            provider may already have accepted this submission.
          </span>
        </label>
      ) : null}
      <Button
        type="button"
        variant="destructive"
        disabled={
          busy ||
          !reason.trim() ||
          (requiresSubmissionUncertainConfirmation(detail) &&
            !confirmSubmissionUncertain)
        }
        onClick={() => void retryDelivery()}
      >
        <RotateCw aria-hidden="true" /> Create retry
      </Button>
    </section>
  );
}
