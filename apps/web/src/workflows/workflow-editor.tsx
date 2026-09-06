import { Badge } from "@periapsis/ui/components/ui/badge";
import { Button } from "@periapsis/ui/components/ui/button";
import { Input } from "@periapsis/ui/components/ui/input";
import { Textarea } from "@periapsis/ui/components/ui/textarea";
import { ArrowRight, FileDiff, Save, ShieldCheck } from "lucide-react";
import { useState } from "react";
import {
  workflowDesignFromDraft,
  type WorkflowDraft,
} from "./workflow-editor-model";

import { FormField } from "../components/form-field";
import {
  WorkflowInputError,
  boundedWorkflowText,
  normalizeWorkflowCatalogKey,
  type ManagedWorkflow,
  type WorkflowDesign,
  type WorkflowKind,
} from "./model";

interface WorkflowDiff {
  states: { added: string[]; changed: string[]; removed: string[] };
  transitions: { added: string[]; changed: string[]; removed: string[] };
}

export function WorkflowEditor({
  busy,
  canManage,
  draft,
  resource,
  setDraft,
  onCreate,
  onPublish,
  onUpdateMetadata,
}: {
  busy: boolean;
  canManage: boolean;
  draft: WorkflowDraft;
  resource?: ManagedWorkflow | undefined;
  setDraft: (draft: WorkflowDraft) => void;
  onCreate: (input: {
    kind: WorkflowKind;
    key: string;
    displayName: string;
    description: string;
    design: WorkflowDesign;
  }) => Promise<void>;
  onPublish: (design: WorkflowDesign) => Promise<void>;
  onUpdateMetadata: (input: {
    displayName: string;
    description: string;
  }) => Promise<void>;
}): React.JSX.Element {
  const [review, setReview] = useState<{
    design: WorkflowDesign;
    fingerprint: string;
    diff: WorkflowDiff;
  } | null>(null);
  const [error, setError] = useState<unknown>(null);
  const immutable = !canManage || resource?.status === "archived";
  const locked = busy || immutable;

  function update(next: Partial<WorkflowDraft>): void {
    if (locked) return;
    setDraft({ ...draft, ...next });
    setReview(null);
    setError(null);
  }

  function reviewDesign(): void {
    setError(null);
    try {
      const design = workflowDesignFromDraft(draft);
      setReview({
        design,
        fingerprint: workflowDraftFingerprint(draft),
        diff: workflowDesignDiff(resource?.current, design),
      });
    } catch (caught: unknown) {
      setReview(null);
      setError(caught);
    }
  }

  async function confirmDesign(): Promise<void> {
    if (
      !review ||
      review.fingerprint !== workflowDraftFingerprint(draft) ||
      locked
    ) {
      setReview(null);
      return;
    }
    setError(null);
    try {
      if (resource) {
        await onPublish(review.design);
      } else {
        const metadata = workflowMetadataFromDraft(draft);
        await onCreate({
          ...metadata,
          kind: draft.kind,
          design: review.design,
        });
      }
      setReview(null);
    } catch (caught: unknown) {
      setError(caught);
    }
  }

  async function saveMetadata(): Promise<void> {
    if (!resource || locked) return;
    setError(null);
    try {
      await onUpdateMetadata(workflowMetadataFromDraft(draft));
    } catch (caught: unknown) {
      setError(caught);
    }
  }

  return (
    <section
      className="workflow-editor"
      aria-label="Workflow definition editor"
    >
      <header className="workflow-editor__heading">
        <div>
          <p className="section-label">Closed declarative state machine</p>
          <h2>
            {resource ? resource.displayName : `New ${draft.kind} workflow`}
          </h2>
        </div>
        <div className="workflow-editor__badges">
          <Badge variant="outline">{draft.kind}</Badge>
          {resource ? (
            <Badge variant="secondary">version {resource.currentVersion}</Badge>
          ) : null}
        </div>
      </header>

      {error ? (
        <div className="workflow-inline-error" role="alert">
          <strong>Definition needs attention</strong>
          <span>{workflowErrorMessage(error)}</span>
        </div>
      ) : null}

      <div className="workflow-form-grid">
        <FormField htmlFor="workflow-key" label="Stable key">
          <Input
            id="workflow-key"
            required
            readOnly={Boolean(resource) || immutable}
            disabled={busy}
            value={draft.key}
            onChange={(event) => update({ key: event.target.value })}
          />
        </FormField>
        <FormField htmlFor="workflow-name" label="Display name">
          <Input
            id="workflow-name"
            required
            maxLength={120}
            readOnly={immutable}
            disabled={busy}
            value={draft.displayName}
            onChange={(event) => update({ displayName: event.target.value })}
          />
        </FormField>
        <div className="workflow-form-grid__wide">
          <FormField
            htmlFor="workflow-description"
            label="Description"
            hint="Administrative metadata; never copied to audit or outbox payloads."
          >
            <Textarea
              id="workflow-description"
              rows={3}
              maxLength={1000}
              readOnly={immutable}
              disabled={busy}
              value={draft.description}
              onChange={(event) => update({ description: event.target.value })}
            />
          </FormField>
        </div>
        <div className="workflow-form-grid__wide">
          <FormField
            htmlFor="workflow-states"
            label="States"
            hint="2–64 states; exactly one initial state and at least one terminal state."
          >
            <Textarea
              id="workflow-states"
              rows={14}
              spellCheck={false}
              readOnly={immutable}
              disabled={busy}
              value={draft.statesJson}
              onChange={(event) => update({ statesJson: event.target.value })}
            />
          </FormField>
        </div>
        <div className="workflow-form-grid__wide">
          <FormField
            htmlFor="workflow-transitions"
            label="Transitions"
            hint="Conditions are typed data only; JavaScript, SQL, regex, and templates are not accepted."
          >
            <Textarea
              id="workflow-transitions"
              rows={18}
              spellCheck={false}
              readOnly={immutable}
              disabled={busy}
              value={draft.transitionsJson}
              onChange={(event) =>
                update({ transitionsJson: event.target.value })
              }
            />
          </FormField>
        </div>
      </div>

      {canManage && resource?.status !== "archived" ? (
        <div className="workflow-editor__actions">
          {resource ? (
            <Button
              type="button"
              variant="outline"
              disabled={busy}
              onClick={() => void saveMetadata()}
            >
              <Save aria-hidden="true" /> Save metadata
            </Button>
          ) : null}
          <Button type="button" disabled={busy} onClick={reviewDesign}>
            <FileDiff aria-hidden="true" /> Review{" "}
            {resource ? "publication" : "creation"}
          </Button>
        </div>
      ) : null}

      {review && canManage && resource?.status !== "archived" ? (
        <WorkflowReview
          diff={review.diff}
          resource={resource}
          disabled={busy}
          onConfirm={() => void confirmDesign()}
        />
      ) : null}
    </section>
  );
}

function WorkflowReview({
  diff,
  resource,
  disabled,
  onConfirm,
}: {
  diff: WorkflowDiff;
  resource?: ManagedWorkflow | undefined;
  disabled: boolean;
  onConfirm: () => void;
}): React.JSX.Element {
  return (
    <section
      className="workflow-review"
      aria-label="Structural publication review"
    >
      <header>
        <div>
          <ShieldCheck aria-hidden="true" />
          <div>
            <p className="section-label">Immutable publish gate</p>
            <h3>Review the structural change</h3>
          </div>
        </div>
        <Badge variant="outline">
          {resource
            ? `v${resource.currentVersion} → v${resource.currentVersion + 1}`
            : "new lineage"}
        </Badge>
      </header>
      <div className="workflow-review__grid">
        <DiffColumn label="States" change={diff.states} />
        <DiffColumn label="Transitions" change={diff.transitions} />
      </div>
      <p>
        Publishing appends a complete immutable definition. Existing tickets
        remain pinned to the version under which they were created.
      </p>
      <Button type="button" disabled={disabled} onClick={onConfirm}>
        Confirm and {resource ? "publish" : "create"}
        <ArrowRight aria-hidden="true" />
      </Button>
    </section>
  );
}

function DiffColumn({
  label,
  change,
}: {
  label: string;
  change: WorkflowDiff["states"];
}): React.JSX.Element {
  return (
    <div>
      <strong>{label}</strong>
      <dl>
        <div>
          <dt>Added</dt>
          <dd>{change.added.join(", ") || "None"}</dd>
        </div>
        <div>
          <dt>Changed</dt>
          <dd>{change.changed.join(", ") || "None"}</dd>
        </div>
        <div>
          <dt>Removed</dt>
          <dd>{change.removed.join(", ") || "None"}</dd>
        </div>
      </dl>
    </div>
  );
}

function workflowMetadataFromDraft(draft: WorkflowDraft): {
  key: string;
  displayName: string;
  description: string;
} {
  return {
    key: normalizeWorkflowCatalogKey(draft.key),
    displayName: boundedWorkflowText(
      draft.displayName,
      120,
      "Workflow display name",
    ),
    description: boundedWorkflowText(
      draft.description,
      1000,
      "Workflow description",
      true,
    ),
  };
}

function workflowDesignDiff(
  current: WorkflowDesign | undefined,
  next: WorkflowDesign,
): WorkflowDiff {
  return {
    states: keyedDiff(current?.states ?? [], next.states),
    transitions: keyedDiff(current?.transitions ?? [], next.transitions),
  };
}

function keyedDiff<T extends { key: string }>(
  current: T[],
  next: T[],
): WorkflowDiff["states"] {
  const before = new Map(
    current.map((item) => [item.key, JSON.stringify(item)]),
  );
  const after = new Map(next.map((item) => [item.key, JSON.stringify(item)]));
  return {
    added: [...after.keys()].filter((key) => !before.has(key)).toSorted(),
    changed: [...after.keys()]
      .filter((key) => before.has(key) && before.get(key) !== after.get(key))
      .toSorted(),
    removed: [...before.keys()].filter((key) => !after.has(key)).toSorted(),
  };
}

function workflowDraftFingerprint(draft: WorkflowDraft): string {
  return JSON.stringify(draft);
}

function workflowErrorMessage(error: unknown): string {
  return error instanceof WorkflowInputError
    ? error.message
    : "The workflow operation could not be completed.";
}
