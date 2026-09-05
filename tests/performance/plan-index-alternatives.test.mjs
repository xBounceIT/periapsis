import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { Script } from "node:vm";

import {
  assertPlanBudget,
  summarizePlan,
} from "../../scripts/performance/plan-budget.mjs";

const runner = await readFile(
  new URL(
    "../../scripts/performance/run-ticketing-hot-paths.mjs",
    import.meta.url,
  ),
  "utf8",
);
const startMarker = "const planBudgets = Object.freeze({";
const endMarker = "const loadBudgets = Object.freeze({";
const start = runner.indexOf(startMarker);
const end = runner.indexOf(endMarker, start + startMarker.length);
assert.ok(
  start >= 0 && end > start,
  "actual plan budget boundaries must exist",
);
assert.equal(runner.indexOf(startMarker, start + startMarker.length), -1);
assert.equal(runner.indexOf(endMarker, end + endMarker.length), -1);
const budgets = JSON.parse(
  new Script(
    `${runner.slice(start, end)}\nJSON.stringify(planBudgets)`,
  ).runInNewContext(),
);
const alternatives = {
  relation: "alerts",
  indexes: ["alerts_tenant_created_idx", "alerts_tenant_state_priority_idx"],
};
const stateBudget = {
  maxExecutionMs: 500,
  maxPlanningMs: 100,
  maxSharedBlocks: 20_000,
  maxTempBlocks: 0,
  minResultRows: 101,
  maxResultRows: 101,
  requiredIndexAlternatives: alternatives,
  forbiddenSequentialScans: ["alerts"],
};

// Reduced structural reproduction of the retained native 100k plan
// periapsis_performance_1788636376158_54b2296ad3c9: keep its measured root
// counters, in-memory top-N sort and contributing selective Alert index scan.
// Workflow/creator joins and their unrelated indexes are intentionally omitted.
function statePlan(index = "alerts_tenant_state_priority_idx", scan = {}) {
  return [
    {
      Plan: {
        "Node Type": "Limit",
        "Actual Rows": 101,
        "Actual Loops": 1,
        "Shared Hit Blocks": 2984,
        "Shared Read Blocks": 0,
        "Temp Read Blocks": 0,
        "Temp Written Blocks": 0,
        Plans: [
          {
            "Node Type": "Sort",
            "Actual Rows": 101,
            "Actual Loops": 1,
            "Sort Key": ["ticket.created_at DESC", "ticket.id DESC"],
            "Sort Method": "top-N heapsort",
            "Sort Space Used": 426,
            "Sort Space Type": "Memory",
            Plans: [
              {
                "Node Type": "Index Scan",
                "Relation Name": "alerts",
                "Index Name": index,
                "Actual Rows": 1000,
                "Actual Loops": 1,
                ...scan,
              },
            ],
          },
        ],
      },
      "Planning Time": 5.351,
      "Execution Time": 10.832,
    },
  ];
}

test("state filter accepts either contributing Alert index with unchanged budgets", () => {
  assert.deepEqual(budgets.alert_state_page, stateBudget);
  for (const index of alternatives.indexes) {
    const summary = summarizePlan(statePlan(index));
    assert.doesNotThrow(() =>
      assertPlanBudget("alert_state_page", summary, budgets.alert_state_page),
    );
  }
  const selective = summarizePlan(statePlan());
  assert.throws(
    () =>
      assertPlanBudget("alert_state_page", selective, {
        ...stateBudget,
        requiredIndexes: ["alerts_tenant_created_idx"],
      }),
    /required index alerts_tenant_created_idx was not used/,
    "alternatives must not replace an additional exact-index requirement",
  );
});

test("only the state-only gate admits alternatives and all other plan gates stay pinned", () => {
  assert.deepEqual(
    Object.entries(budgets)
      .filter(([, budget]) =>
        Object.hasOwn(budget, "requiredIndexAlternatives"),
      )
      .map(([name]) => name),
    ["alert_state_page"],
  );
  const expected = [
    [
      "alert_updated_page",
      500,
      20_000,
      101,
      "alerts_tenant_updated_idx",
      ["alerts"],
    ],
    [
      "alert_created_page",
      500,
      20_000,
      101,
      "alerts_tenant_created_idx",
      ["alerts"],
    ],
    [
      "case_updated_page",
      500,
      20_000,
      101,
      "cases_tenant_updated_idx",
      ["cases"],
    ],
    [
      "alert_state_severity_page",
      750,
      30_000,
      101,
      "alerts_tenant_state_priority_idx",
      ["alerts"],
    ],
    [
      "alert_severity_page",
      500,
      20_000,
      101,
      "alerts_tenant_created_idx",
      ["alerts"],
    ],
    [
      "alert_assignee_page",
      500,
      20_000,
      101,
      "alerts_tenant_assignment_idx",
      ["alerts"],
    ],
    [
      "alert_custom_integer_filter",
      1000,
      50_000,
      101,
      "custom_field_values_definition_integer_idx",
      ["alerts", "custom_field_values"],
    ],
    [
      "alert_sla_due_sort",
      1000,
      60_000,
      101,
      "sla_materialized_projection_instant_sort_idx",
      ["alerts", "sla_materialized_column_values"],
    ],
    [
      "sla_worker_claim_candidates",
      500,
      10_000,
      100,
      "sla_evaluation_jobs_claim_idx",
      ["sla_evaluation_jobs"],
    ],
    [
      "notification_fanout_claim_candidates",
      500,
      20_000,
      100,
      "outbox_events_dequeue_idx",
      ["outbox_events"],
    ],
  ];
  assert.equal(Object.keys(budgets).length, expected.length + 1);
  for (const [
    name,
    maxExecutionMs,
    maxSharedBlocks,
    rows,
    index,
    forbiddenSequentialScans,
  ] of expected) {
    assert.deepEqual(
      budgets[name],
      {
        maxExecutionMs,
        maxPlanningMs: 100,
        maxSharedBlocks,
        maxTempBlocks: 0,
        minResultRows: rows,
        maxResultRows: rows,
        requiredIndexes: [index],
        forbiddenSequentialScans,
      },
      name,
    );
  }
});

test("alternatives reject wrong relations, unrelated indexes and noncontributing scans", () => {
  for (const scan of [
    { "Relation Name": "cases" },
    { "Relation Name": undefined },
    { "Index Name": "alerts_tenant_updated_idx" },
    { "Actual Loops": 0 },
    { "Actual Rows": 0 },
    { "Node Type": "Bitmap Index Scan", "Relation Name": undefined },
    { "Node Type": "Sort" },
  ]) {
    const summary = summarizePlan(statePlan(undefined, scan));
    assert.throws(
      () => assertPlanBudget("alert_state_page", summary, stateBudget),
      /required index alternative for alerts was not used/,
    );
  }
  const summary = summarizePlan(statePlan());
  assert.throws(
    () =>
      assertPlanBudget(
        "alert_state_page",
        { ...summary, scans: [] },
        stateBudget,
      ),
    /required index alternative for alerts was not used/,
    "a globally credited index name alone does not prove an Alert scan",
  );
});

test("alternatives cannot hide incomplete windows, latency, buffer or spill failures", () => {
  const summary = summarizePlan(statePlan());
  for (const [override, expected] of [
    [{ actualRows: 0 }, /result rows 0 is below 101/],
    [{ actualRows: 100 }, /result rows 100 is below 101/],
    [{ actualRows: 102 }, /result rows 102 exceeds 101/],
    [{ actualLoops: 0 }, /root loops 0 differs from 1/],
    [{ executionMs: 501 }, /execution time 501 exceeds 500/],
    [{ planningMs: 101 }, /planning time 101 exceeds 100/],
    [{ sharedBlocks: 20_001 }, /shared blocks 20001 exceeds 20000/],
    [{ tempBlocks: 1 }, /temporary blocks 1 exceeds 0/],
    [{ sequentialScans: ["alerts"] }, /sequential scan used on alerts/],
    [
      { diskSorts: [{ method: "external merge", spaceKilobytes: 1 }] },
      /spilled a sort to disk/,
    ],
  ]) {
    assert.throws(
      () =>
        assertPlanBudget(
          "alert_state_page",
          { ...summary, ...override },
          stateBudget,
        ),
      expected,
    );
  }
});

test("alternatives reject empty, ambiguous and malformed configuration", () => {
  const summary = summarizePlan(statePlan());
  const sparseIndexes = ["alerts_tenant_created_idx"];
  sparseIndexes.length = 2;
  for (const malformed of [
    undefined,
    null,
    [],
    {},
    "alerts",
    1,
    { relation: "alerts" },
    { indexes: alternatives.indexes },
    { ...alternatives, relation: "" },
    { ...alternatives, relation: "public.alerts" },
    { ...alternatives, relation: ["alerts"] },
    { ...alternatives, relation: "a".repeat(64) },
    { ...alternatives, indexes: [] },
    { ...alternatives, indexes: sparseIndexes },
    { ...alternatives, indexes: "alerts_tenant_created_idx" },
    { ...alternatives, indexes: ["alerts_tenant_created_idx", ""] },
    { ...alternatives, indexes: ["alerts_tenant_created_idx", null] },
    { ...alternatives, indexes: ["alerts_tenant_created_idx", 1] },
    { ...alternatives, indexes: ["a".repeat(64)] },
    {
      ...alternatives,
      indexes: ["alerts_tenant_created_idx", "alerts_tenant_created_idx"],
    },
    { ...alternatives, ignored: true },
  ]) {
    assert.throws(
      () =>
        assertPlanBudget("alert_state_page", summary, {
          ...stateBudget,
          requiredIndexAlternatives: malformed,
        }),
      /plan index alternative budget is malformed/,
    );
  }
});

test("alternatives fail closed for malformed scan evidence", () => {
  const summary = summarizePlan(statePlan());
  for (const scans of [
    undefined,
    null,
    {},
    [null],
    [[]],
    [summary.scans[0], null],
  ]) {
    assert.throws(
      () =>
        assertPlanBudget(
          "alert_state_page",
          { ...summary, scans },
          stateBudget,
        ),
      /plan index alternative scan evidence is malformed/,
    );
  }
  for (const override of [
    { actualRows: "1000" },
    { actualLoops: -1 },
    { actualRows: Number.NaN },
    { totalRows: Number.POSITIVE_INFINITY },
    { totalRows: 999 },
  ]) {
    assert.throws(
      () =>
        assertPlanBudget(
          "alert_state_page",
          {
            ...summary,
            scans: [{ ...summary.scans[0], ...override }],
          },
          stateBudget,
        ),
      /required index alternative for alerts was not used/,
    );
  }
});
