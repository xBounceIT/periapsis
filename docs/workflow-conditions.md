# Declarative workflow conditions

Alert and Case workflow transitions may include an optional, version-pinned
`condition`. Conditions are data, not code: the runtime never evaluates
JavaScript, SQL, regular expressions, templates, property paths, or user-defined
functions.

## Expression model

A condition is a bounded tree made from four node kinds:

- `predicate` compares one allowlisted fact with typed scalar values;
- `all` requires every child;
- `any` requires at least one child;
- `not` negates one determinate child.

The supported scalar types are `text`, finite `number`, `boolean`, and an ISO
8601 `instant`. Operators are `equal`, `not_equal`, `in`, `not_in`,
`less_than`, `less_than_or_equal`, `greater_than`,
`greater_than_or_equal`, `exists`, and `not_exists`. Ordering is available only
for numbers and instants. String matching is exact and case-sensitive; regex and
substring execution are intentionally absent.

The tree is limited to 8 levels, 128 nodes, 32 children per compound node, and
32 values per membership predicate. Text values are limited to 2 KiB. These
limits are enforced again when a stored workflow version is loaded.

## Facts

Core facts use a closed vocabulary: aggregate kind, state, severity, priority,
category, classification, source, source type, customer visibility, assignment
and claim presence, comment presence, and the ticket timestamps. A custom-field
fact is named `custom.<field-key>`. A present ticket tag is exposed as the
boolean fact `tag.<tag-key>`.

Only scalar custom-field values are comparable. Arrays, objects, explicit null,
overlong strings, non-finite numbers, or integers that cannot be represented
exactly remain marked as present but non-comparable. Therefore `exists` is true,
`not_exists` is false, and every value comparison is denied.

Transition evaluation uses the current stored ticket plus custom-field values
proposed by that same command. The repository still applies the resulting plan
with optimistic concurrency in the same transaction as activity, audit, SLA,
and notification side effects.

## Fail-closed semantics

A missing or type-mismatched fact is indeterminate, not false. Indeterminate
comparisons never satisfy a condition, including when nested under `not`.
Absence can be tested only with the explicit `not_exists` operator. This
three-valued evaluation prevents a missing or malformed fact from satisfying a
negative condition accidentally.

Workflow versions created before conditions existed omit the property and remain
unconditional. Once published, a version and its condition are immutable; a
change requires a new workflow version so existing Alert and Case aggregates
remain pinned to the rules under which they were created.
