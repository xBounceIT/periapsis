# Periapsis Conceptual ERD

Status: conceptual companion to the release-candidate Drizzle schema
Last updated: 2026-09-02

## 1. Reading this document

These diagrams define intended entities, ownership, and cardinality. They are not a second
SQL schema. `packages/db` Drizzle definitions are the canonical PostgreSQL schema and
generated migrations are the only deployment path. If a diagram and the
canonical schema diverge, the schema change requires a documentation update and, when the
decision is architectural, an ADR.

Conventions:

- IDs are UUIDv7 unless an entity explicitly uses a stable textual key.
- Every entity marked **tenant-owned** has `tenant_id NOT NULL`.
- Tenant-owned primary entities also expose `UNIQUE (tenant_id, id)` so dependent tables
  can use composite foreign keys and cannot connect rows from different tenants.
- Every tenant-owned table has forced RLS and tenant-leading indexes for real query paths.
- All instants use `timestamptz` in UTC; an IANA time-zone identifier is stored separately
  where display or calendar semantics require it.
- JSONB is limited to validated raw payloads, enrichment, declarative definitions,
  immutable snapshots, or versioned event envelopes.
- Platform-only catalogs and tenant-owned records are physically separate where nullable
  tenant ownership would weaken RLS, notably authentication providers, audit, and outbox.
- The diagrams omit repeated metadata such as `created_at`, `updated_at`, actor IDs, and
  optimistic versions when their presence is already stated in the domain model.

## Implemented ADR-0008 physical slice

This smaller diagram records the authentication, platform-administration, direct-human
tenant-RBAC, tenant-security-group, operator-team, service-principal, and minimal Alert
relationships that are physically present now. The broader diagram below remains the
forward model.

Tenant security groups are direct-only and retain independent membership-edge and
role-grant sources. Global operator teams use tenant-owned immutable assignment epochs and
exact-epoch source-owned rosters.

```mermaid
erDiagram
    USERS ||--o| LOCAL_BREAK_GLASS_CREDENTIALS : authenticates_with
    USERS ||--o| TOTP_CREDENTIALS : proves_mfa_with
    TOTP_CREDENTIALS ||--o{ RECOVERY_CODES : issues
    USERS ||--o{ AUTH_CHALLENGES : receives
    USERS ||--o{ AUTH_SESSIONS : owns
    AUTH_SESSIONS o|--o{ AUTH_SESSIONS : rotates_to
    USERS ||--o{ TENANT_MEMBERSHIPS : receives
    TENANTS ||--o{ TENANT_MEMBERSHIPS : grants
    USERS ||--o{ USER_PLATFORM_ROLES : receives
    PLATFORM_ROLES ||--o{ USER_PLATFORM_ROLES : binds
    PLATFORM_ROLES ||--o{ PLATFORM_ROLE_PERMISSIONS : contains
    PLATFORM_PERMISSIONS ||--o{ PLATFORM_ROLE_PERMISSIONS : grants
    PLATFORM_BOOTSTRAP_STATE ||--o| PLATFORM_BOOTSTRAP_ENROLLMENTS : completes_with
    USERS o|--o| PLATFORM_BOOTSTRAP_STATE : completes
    PLATFORM_AUDIT_CHAIN_HEAD ||--o{ PLATFORM_AUDIT_EVENTS : seals
    TENANTS ||--|| TENANT_AUTHORIZATION_STATES : serializes
    TENANTS ||--o{ TENANT_AUTHORIZATION_SOURCES : owns
    TENANTS ||--o{ TENANT_ROLES : owns
    TENANT_PERMISSIONS ||--o{ TENANT_PERMISSION_SCOPES : allows
    TENANT_ROLES ||--o{ TENANT_ROLE_PERMISSIONS : contains
    TENANT_ROLE_PERMISSIONS ||--o| TENANT_ROLE_DELEGATION_CEILINGS : delegates
    TENANT_MEMBERSHIPS ||--o{ TENANT_MEMBERSHIP_ROLE_GRANTS : receives
    TENANT_ROLES ||--o{ TENANT_MEMBERSHIP_ROLE_GRANTS : grants
    TENANT_AUTHORIZATION_SOURCES ||--o{ TENANT_MEMBERSHIP_ROLE_GRANTS : owns
    TENANTS ||--o{ TENANT_SECURITY_GROUPS : owns
    TENANT_SECURITY_GROUPS ||--o{ TENANT_SECURITY_GROUP_MEMBERSHIPS : contains
    TENANT_MEMBERSHIPS ||--o{ TENANT_SECURITY_GROUP_MEMBERSHIPS : joins
    TENANT_AUTHORIZATION_SOURCES ||--o{ TENANT_SECURITY_GROUP_MEMBERSHIPS : owns
    TENANT_SECURITY_GROUPS ||--o{ TENANT_SECURITY_GROUP_ROLE_GRANTS : receives
    TENANT_ROLES ||--o{ TENANT_SECURITY_GROUP_ROLE_GRANTS : grants
    TENANT_AUTHORIZATION_SOURCES ||--o{ TENANT_SECURITY_GROUP_ROLE_GRANTS : owns
    TENANTS ||--o{ OPERATOR_TEAM_ASSIGNMENT_EPOCHS : authorizes
    OPERATOR_TEAMS ||--o{ OPERATOR_TEAM_ASSIGNMENT_EPOCHS : serves
    OPERATOR_TEAM_ASSIGNMENT_EPOCHS ||--o{ OPERATOR_TEAM_ROSTER_ENTRIES : scopes
    TENANT_MEMBERSHIPS ||--o{ OPERATOR_TEAM_ROSTER_ENTRIES : joins
    TENANT_AUTHORIZATION_SOURCES ||--o{ OPERATOR_TEAM_ROSTER_ENTRIES : owns
    TENANT_MEMBERSHIPS ||--o{ TENANT_AUTHORIZATION_COMMANDS : replays
    TENANTS ||--o{ TENANT_SERVICE_ACCOUNTS : owns
    TENANT_MEMBERSHIPS ||--o{ TENANT_SERVICE_ACCOUNTS : creates_or_archives
    TENANT_SERVICE_ACCOUNTS ||--o{ TENANT_SERVICE_ACCOUNT_ROLE_GRANTS : receives
    TENANT_ROLES ||--o{ TENANT_SERVICE_ACCOUNT_ROLE_GRANTS : grants
    TENANT_AUTHORIZATION_SOURCES ||--o{ TENANT_SERVICE_ACCOUNT_ROLE_GRANTS : owns
    TENANT_SERVICE_ACCOUNTS ||--o{ TENANT_API_CREDENTIALS : authenticates_with
    TENANT_API_CREDENTIALS ||--o{ TENANT_API_CREDENTIAL_PERMISSIONS : narrows
    TENANT_API_CREDENTIALS ||--o{ TENANT_API_CREDENTIAL_NETWORKS : restricts
    TENANT_SERVICE_ACCOUNTS ||--o{ TENANT_API_CREDENTIAL_COMMANDS : replays
    TENANT_API_CREDENTIAL_COMMANDS }o--|| TENANT_API_CREDENTIALS : returns
    TENANTS ||--o{ ALERTS : owns
    TENANT_MEMBERSHIPS o|--o{ ALERTS : creates_as_human
    TENANT_SERVICE_ACCOUNTS o|--o{ ALERTS : creates_as_machine
    ALERTS ||--o{ ALERT_ACTIVITIES : records
    ALERTS ||--o{ ALERT_COMMANDS : replays
```

## 2. Tenancy, identity, authentication, and RBAC

```mermaid
erDiagram
    TENANTS {
        uuid id PK
        string slug UK
        string name
        string status
        string timezone
        string locale
        jsonb branding
        timestamptz created_at
    }

    USERS {
        uuid id PK
        string username UK
        string email
        string status
        timestamptz created_at
    }

    TENANT_USER_PROFILES {
        uuid id PK
        uuid tenant_id FK
        uuid user_id FK
        string display_name
        string timezone
        string locale
    }

    TENANT_MEMBERSHIPS {
        uuid id PK
        uuid tenant_id FK
        uuid user_id FK
        string status
        string provisioning_source
        timestamptz revoked_at
    }

    CUSTOMER_CONTACTS {
        uuid id PK
        uuid tenant_id FK
        uuid linked_user_id FK
        string first_name
        string last_name
        string email
        string language
        string timezone
        int escalation_priority
        boolean active
    }

    PERMISSIONS {
        string key PK
        string resource
        string action
    }

    ROLES {
        uuid id PK
        uuid tenant_id FK
        string key
        string name
        boolean system_role
    }

    ROLE_PERMISSIONS {
        uuid tenant_id FK
        uuid role_id FK
        string permission_key FK
        string scope
    }

    TENANT_AUTHORIZATION_SOURCES {
        uuid id PK
        uuid tenant_id FK
        string kind
        string owner_reference
        string status
    }

    TENANT_SECURITY_GROUPS {
        uuid id PK
        uuid tenant_id FK
        string name
        string status
    }

    TENANT_SECURITY_GROUP_MEMBERSHIPS {
        uuid id PK
        uuid tenant_id FK
        uuid group_id FK
        uuid tenant_membership_id FK
        uuid authorization_source_id FK
        timestamptz expires_at
        timestamptz revoked_at
    }

    TENANT_SECURITY_GROUP_ROLE_GRANTS {
        uuid id PK
        uuid tenant_id FK
        uuid group_id FK
        uuid role_id FK
        uuid authorization_source_id FK
        timestamptz expires_at
        timestamptz revoked_at
    }

    OPERATOR_TEAMS {
        uuid id PK
        string key UK
        string display_name
        timestamptz archived_at
    }

    OPERATOR_TEAM_ASSIGNMENT_EPOCHS {
        uuid id PK
        uuid tenant_id FK
        uuid operator_team_id FK
        timestamptz assigned_at
        timestamptz ended_at
        int version
    }

    OPERATOR_TEAM_ROSTER_ENTRIES {
        uuid id PK
        uuid tenant_id FK
        uuid operator_team_id FK
        uuid assignment_epoch_id FK
        uuid membership_id FK
        uuid source_id FK
        timestamptz expires_at
        timestamptz revoked_at
        int version
    }

    PLATFORM_ROLE_BINDINGS {
        uuid id PK
        uuid user_id FK
        string platform_role_key
        timestamptz expires_at
    }

    TENANT_AUTH_PROVIDERS {
        uuid id PK
        uuid tenant_id FK
        string type
        string name
        string status
        bytes encrypted_config
    }

    PLATFORM_AUTH_PROVIDERS {
        uuid id PK
        string type
        string name
        string status
        bytes encrypted_config
    }

    EXTERNAL_IDENTITIES {
        uuid id PK
        uuid user_id FK
        uuid tenant_id FK
        uuid tenant_provider_id FK
        string immutable_subject
        timestamptz last_login_at
    }

    LDAP_MAPPING_RULES {
        uuid id PK
        uuid tenant_id FK
        uuid provider_id FK
        uuid tenant_security_group_id FK
        uuid operator_team_id FK
        int priority
        string match_mode
        string grant_mode
        boolean enabled
    }

    SESSIONS {
        uuid id PK
        uuid user_id FK
        bytes token_hash
        string auth_method
        string assurance_level
        timestamptz idle_expires_at
        timestamptz absolute_expires_at
        timestamptz revoked_at
    }

    MFA_CREDENTIALS {
        uuid id PK
        uuid user_id FK
        string type
        bytes protected_secret
        timestamptz revoked_at
    }

    SERVICE_ACCOUNTS {
        uuid id PK
        uuid tenant_id FK
        string key
        string display_name
        string description
        uuid created_by_membership_id FK
        timestamptz archived_at
        int version
    }

    SERVICE_ACCOUNT_ROLE_GRANTS {
        uuid id PK
        uuid tenant_id FK
        uuid service_account_id FK
        uuid role_id FK
        uuid source_id FK
        timestamptz expires_at
        timestamptz revoked_at
        int version
    }

    API_CREDENTIALS {
        uuid id PK
        uuid tenant_id FK
        uuid service_account_id FK
        string label
        int format_version
        bytes locator UK
        int key_version
        bytes secret_digest
        timestamptz expires_at
        uuid rotated_from_credential_id FK
        timestamptz revoked_at
        timestamptz last_used_at
        inet last_used_ip
        int version
    }

    API_CREDENTIAL_PERMISSIONS {
        uuid tenant_id PK, FK
        uuid credential_id PK, FK
        uuid permission_id PK, FK
        string scope PK, FK
    }

    API_CREDENTIAL_NETWORKS {
        uuid tenant_id PK, FK
        uuid credential_id PK, FK
        cidr network PK
    }

    API_CREDENTIAL_COMMANDS {
        uuid id PK
        uuid tenant_id FK
        uuid service_account_id FK
        uuid actor_membership_id FK
        string operation
        bytes key_digest
        bytes request_digest
        uuid result_credential_id FK
        int result_version
    }

    TENANTS ||--o{ TENANT_USER_PROFILES : owns
    USERS ||--o{ TENANT_USER_PROFILES : has
    TENANTS ||--o{ TENANT_MEMBERSHIPS : grants
    USERS ||--o{ TENANT_MEMBERSHIPS : receives
    TENANTS ||--o{ CUSTOMER_CONTACTS : owns
    USERS o|--o{ CUSTOMER_CONTACTS : may_link
    TENANTS ||--o{ ROLES : owns
    ROLES ||--o{ ROLE_PERMISSIONS : grants
    PERMISSIONS ||--o{ ROLE_PERMISSIONS : included_by
    TENANTS ||--o{ TENANT_AUTHORIZATION_SOURCES : owns
    TENANTS ||--o{ TENANT_SECURITY_GROUPS : owns
    TENANT_SECURITY_GROUPS ||--o{ TENANT_SECURITY_GROUP_MEMBERSHIPS : contains
    TENANT_MEMBERSHIPS ||--o{ TENANT_SECURITY_GROUP_MEMBERSHIPS : joins
    TENANT_AUTHORIZATION_SOURCES ||--o{ TENANT_SECURITY_GROUP_MEMBERSHIPS : owns
    TENANT_SECURITY_GROUPS ||--o{ TENANT_SECURITY_GROUP_ROLE_GRANTS : receives
    ROLES ||--o{ TENANT_SECURITY_GROUP_ROLE_GRANTS : assigned
    TENANT_AUTHORIZATION_SOURCES ||--o{ TENANT_SECURITY_GROUP_ROLE_GRANTS : owns
    TENANTS ||--o{ OPERATOR_TEAM_ASSIGNMENT_EPOCHS : authorizes
    OPERATOR_TEAMS ||--o{ OPERATOR_TEAM_ASSIGNMENT_EPOCHS : serves
    OPERATOR_TEAM_ASSIGNMENT_EPOCHS ||--o{ OPERATOR_TEAM_ROSTER_ENTRIES : scopes
    TENANT_MEMBERSHIPS ||--o{ OPERATOR_TEAM_ROSTER_ENTRIES : joins
    TENANT_AUTHORIZATION_SOURCES ||--o{ OPERATOR_TEAM_ROSTER_ENTRIES : owns
    USERS ||--o{ PLATFORM_ROLE_BINDINGS : has
    TENANTS ||--o{ TENANT_AUTH_PROVIDERS : configures
    USERS ||--o{ EXTERNAL_IDENTITIES : resolves_to
    TENANT_AUTH_PROVIDERS ||--o{ EXTERNAL_IDENTITIES : authenticates
    TENANT_AUTH_PROVIDERS ||--o{ LDAP_MAPPING_RULES : defines
    TENANT_SECURITY_GROUPS ||--o{ LDAP_MAPPING_RULES : maps_to
    OPERATOR_TEAMS o|--o{ LDAP_MAPPING_RULES : optionally_maps_to
    USERS ||--o{ SESSIONS : opens
    USERS ||--o{ MFA_CREDENTIALS : enrolls
    TENANTS ||--o{ SERVICE_ACCOUNTS : owns
    SERVICE_ACCOUNTS ||--o{ SERVICE_ACCOUNT_ROLE_GRANTS : receives
    ROLES ||--o{ SERVICE_ACCOUNT_ROLE_GRANTS : grants
    TENANT_AUTHORIZATION_SOURCES ||--o{ SERVICE_ACCOUNT_ROLE_GRANTS : owns
    SERVICE_ACCOUNTS ||--o{ API_CREDENTIALS : authenticates_with
    API_CREDENTIALS ||--o{ API_CREDENTIAL_PERMISSIONS : narrows
    PERMISSIONS ||--o{ API_CREDENTIAL_PERMISSIONS : allows
    API_CREDENTIALS ||--o{ API_CREDENTIAL_NETWORKS : restricts
    SERVICE_ACCOUNTS ||--o{ API_CREDENTIAL_COMMANDS : replays
    API_CREDENTIAL_COMMANDS }o--|| API_CREDENTIALS : returns
```

`EXTERNAL_IDENTITIES` above represents tenant-provider identities. Platform-provider
identities use a physically separate platform table so tenant-owned rows never have a
nullable `tenant_id`. Recovery codes are stored in a child table as one-use hashes, not in
plaintext or reversible form. Provider secret configuration is encrypted and write-only
through the API.

`TENANT_SECURITY_GROUP_MEMBERSHIPS` has no self/group parent reference: Phase 2B.2a is a
direct-only graph. The membership and role-grant edges retain separate authorization
sources. Their join explains the `group` authority path, while those source
rows identify who may reconcile each contribution.

`OPERATOR_TEAMS` is the global platform-owned identity. Its assignment epochs and roster
entries are tenant-owned and forced-RLS records. A new assignment uses a new epoch and
cannot inherit old roster rows. A future provider rule may name a team only through the
protected reconciliation planner for the current tenant assignment epoch rather than
writing a global membership. Global team lifecycle is
platform-audited, while assignment and roster changes are tenant-audited with correlated
events for cross-boundary commands.

## 3. Alerts, Cases, workflow, and comments

```mermaid
erDiagram
    TENANTS {
        uuid id PK
    }

    ALERTS {
        uuid id PK
        uuid tenant_id FK
        string alert_number
        string external_id
        string deduplication_key
        string source
        string title
        string status
        string severity
        string priority
        uuid assigned_team_id FK
        uuid assignee_user_id FK
        timestamptz claimed_at
        uuid claimed_by FK
        boolean customer_visible
        bigint lock_version
    }

    CASES {
        uuid id PK
        uuid tenant_id FK
        string case_number
        string title
        string status
        string severity
        string priority
        uuid assigned_team_id FK
        uuid assignee_user_id FK
        timestamptz claimed_at
        uuid claimed_by FK
        boolean customer_visible
        bigint lock_version
    }

    ALERT_CASE_LINKS {
        uuid id PK
        uuid tenant_id FK
        uuid alert_id FK
        uuid case_id FK
        string relation_type
        string escalation_reason
        uuid linked_by FK
        bigint source_alert_version
        jsonb copied_field_snapshot
        timestamptz linked_at
    }

    COMMENTS {
        uuid id PK
        uuid tenant_id FK
        uuid alert_id FK
        uuid case_id FK
        uuid author_id FK
        string visibility
        string sanitized_markdown
        int revision
        timestamptz created_at
    }

    COMMENT_REVISIONS {
        uuid id PK
        uuid tenant_id FK
        uuid comment_id FK
        int revision
        string sanitized_markdown
        uuid edited_by FK
        timestamptz edited_at
    }

    ALERT_ASSIGNMENT_HISTORY {
        uuid id PK
        uuid tenant_id FK
        uuid alert_id FK
        string action
        uuid team_id FK
        uuid assignee_id FK
        uuid actor_id FK
        timestamptz occurred_at
    }

    CASE_ASSIGNMENT_HISTORY {
        uuid id PK
        uuid tenant_id FK
        uuid case_id FK
        string action
        uuid team_id FK
        uuid assignee_id FK
        uuid actor_id FK
        timestamptz occurred_at
    }

    DOMAIN_ACTIVITIES {
        uuid id PK
        uuid tenant_id FK
        string subject_type
        uuid subject_id
        string activity_type
        string visibility
        uuid actor_id FK
        jsonb safe_details
        timestamptz occurred_at
    }

    WORKFLOW_DEFINITIONS {
        uuid id PK
        uuid tenant_id FK
        string object_type
        string name
        uuid active_version_id FK
    }

    WORKFLOW_VERSIONS {
        uuid id PK
        uuid tenant_id FK
        uuid definition_id FK
        int version
        string status
        jsonb validated_definition
        timestamptz published_at
    }

    WORKFLOW_STATES {
        uuid id PK
        uuid tenant_id FK
        uuid workflow_version_id FK
        string key
        boolean initial
        boolean terminal
        boolean customer_visible
    }

    WORKFLOW_TRANSITIONS {
        uuid id PK
        uuid tenant_id FK
        uuid workflow_version_id FK
        uuid from_state_id FK
        uuid to_state_id FK
        string key
        jsonb validated_conditions
        jsonb validated_actions
    }

    TENANTS ||--o{ ALERTS : owns
    TENANTS ||--o{ CASES : owns
    ALERTS ||--o{ ALERT_CASE_LINKS : linked
    CASES ||--o{ ALERT_CASE_LINKS : linked
    ALERTS o|--o{ COMMENTS : has
    CASES o|--o{ COMMENTS : has
    COMMENTS ||--o{ COMMENT_REVISIONS : retains
    ALERTS ||--o{ ALERT_ASSIGNMENT_HISTORY : records
    CASES ||--o{ CASE_ASSIGNMENT_HISTORY : records
    TENANTS ||--o{ DOMAIN_ACTIVITIES : owns
    TENANTS ||--o{ WORKFLOW_DEFINITIONS : owns
    WORKFLOW_DEFINITIONS ||--|{ WORKFLOW_VERSIONS : versions
    WORKFLOW_VERSIONS ||--|{ WORKFLOW_STATES : defines
    WORKFLOW_VERSIONS ||--o{ WORKFLOW_TRANSITIONS : allows
```

The physical `COMMENTS` constraint requires exactly one of `alert_id` or `case_id`, and
each optional reference uses a composite `(tenant_id, id)` foreign key. If PostgreSQL
constraints are clearer with dedicated Alert/Case comment tables, the Drizzle schema may
split them while retaining the domain concept. `DOMAIN_ACTIVITIES` similarly requires a
database-enforced subject registry or type-specific tables; an unconstrained polymorphic
ID is not acceptable merely for convenience.

## 4. Custom fields and DFIR records

```mermaid
erDiagram
    TENANTS {
        uuid id PK
    }

    CUSTOM_FIELD_DEFINITIONS {
        uuid id PK
        uuid tenant_id FK
        string object_type
        string stable_key
        string label
        string data_type
        int schema_version
        jsonb validation
        jsonb visibility
        boolean archived
    }

    CUSTOM_FIELD_OPTIONS {
        uuid id PK
        uuid tenant_id FK
        uuid definition_id FK
        string stable_key
        string label
        int sort_order
        boolean archived
    }

    CUSTOM_FIELD_VALUES {
        uuid id PK
        uuid tenant_id FK
        uuid definition_id FK
        string subject_type
        uuid subject_id
        string value_text
        decimal value_number
        boolean value_boolean
        date value_date
        timestamptz value_instant
        uuid value_reference_id
        jsonb value_structured
    }

    IOCS {
        uuid id PK
        uuid tenant_id FK
        string type
        string original_value
        string normalized_value
        int confidence
        string tlp
        string malicious_state
        jsonb enrichment
    }

    ASSETS {
        uuid id PK
        uuid tenant_id FK
        string hostname
        string fqdn
        inet ip_address
        macaddr mac_address
        string asset_type
        string criticality
        jsonb custom_attributes
    }

    ALERT_IOCS {
        uuid tenant_id FK
        uuid alert_id FK
        uuid ioc_id FK
    }

    CASE_IOCS {
        uuid tenant_id FK
        uuid case_id FK
        uuid ioc_id FK
    }

    ALERT_ASSETS {
        uuid tenant_id FK
        uuid alert_id FK
        uuid asset_id FK
    }

    CASE_ASSETS {
        uuid tenant_id FK
        uuid case_id FK
        uuid asset_id FK
    }

    STORAGE_OBJECTS {
        uuid id PK
        uuid tenant_id FK
        string bucket
        string object_key
        string sha256
        bigint size_bytes
        string detected_mime
        string scan_state
        string classification
        timestamptz verified_at
    }

    EVIDENCE {
        uuid id PK
        uuid tenant_id FK
        uuid case_id FK
        uuid storage_object_id FK
        string title
        string evidence_type
        string classification
        timestamptz collected_at
        uuid collected_by FK
        string source
        boolean legal_hold
    }

    EVIDENCE_CUSTODY_EVENTS {
        uuid id PK
        uuid tenant_id FK
        uuid evidence_id FK
        string action
        uuid actor_id FK
        string reason
        string previous_hash
        string event_hash
        timestamptz occurred_at
    }

    TIMELINE_EVENTS {
        uuid id PK
        uuid tenant_id FK
        uuid case_id FK
        timestamptz event_time
        timestamptz ingested_at
        string original_timezone
        string time_precision
        string source
        string category
        string title
    }

    TASKS {
        uuid id PK
        uuid tenant_id FK
        uuid case_id FK
        string title
        string status
        string priority
        uuid assignee_id FK
        uuid team_id FK
        timestamptz due_at
        timestamptz completed_at
    }

    ATTACHMENTS {
        uuid id PK
        uuid tenant_id FK
        uuid storage_object_id FK
        string subject_type
        uuid subject_id
        string visibility
        uuid uploaded_by FK
    }

    TYPED_RELATIONSHIPS {
        uuid id PK
        uuid tenant_id FK
        string source_type
        uuid source_id
        string target_type
        uuid target_id
        string relation_type
        jsonb metadata
    }

    TENANTS ||--o{ CUSTOM_FIELD_DEFINITIONS : owns
    CUSTOM_FIELD_DEFINITIONS ||--o{ CUSTOM_FIELD_OPTIONS : offers
    CUSTOM_FIELD_DEFINITIONS ||--o{ CUSTOM_FIELD_VALUES : validates
    TENANTS ||--o{ IOCS : owns
    TENANTS ||--o{ ASSETS : owns
    IOCS ||--o{ ALERT_IOCS : linked
    IOCS ||--o{ CASE_IOCS : linked
    ASSETS ||--o{ ALERT_ASSETS : linked
    ASSETS ||--o{ CASE_ASSETS : linked
    TENANTS ||--o{ STORAGE_OBJECTS : owns
    STORAGE_OBJECTS ||--o| EVIDENCE : backs
    EVIDENCE ||--|{ EVIDENCE_CUSTODY_EVENTS : records
    TENANTS ||--o{ TIMELINE_EVENTS : owns
    TENANTS ||--o{ TASKS : owns
    STORAGE_OBJECTS ||--o| ATTACHMENTS : backs
    TENANTS ||--o{ TYPED_RELATIONSHIPS : owns
```

Alert/Case foreign-key endpoints omitted from this visual use the same composite tenant
keys shown in the previous diagram. `CUSTOM_FIELD_VALUES`, `ATTACHMENTS`, and
`TYPED_RELATIONSHIPS` require either a tenant-owned object registry or generated
type-specific tables/constraints. The implementation must not accept dangling or
cross-tenant polymorphic references.

Only one type-appropriate value column in `CUSTOM_FIELD_VALUES` may be populated, with a
constraint derived from the definition's data type. Missing, explicit null, and empty
values remain distinguishable. Evidence custody events are append-only; storage object
deletion is blocked while evidence, retention, or legal hold requires the bytes.

## 5. SLA, notifications, webhooks, outbox, and audit

```mermaid
erDiagram
    TENANTS {
        uuid id PK
    }

    BUSINESS_CALENDARS {
        uuid id PK
        uuid tenant_id FK
        string name
        uuid active_version_id FK
    }

    BUSINESS_CALENDAR_VERSIONS {
        uuid id PK
        uuid tenant_id FK
        uuid calendar_id FK
        int version
        string timezone
        jsonb intervals
        jsonb holidays
        timestamptz published_at
    }

    SLA_POLICIES {
        uuid id PK
        uuid tenant_id FK
        string object_type
        string name
        int match_priority
        uuid active_version_id FK
    }

    SLA_POLICY_VERSIONS {
        uuid id PK
        uuid tenant_id FK
        uuid policy_id FK
        int version
        jsonb match_expression
        timestamptz published_at
    }

    SLA_METRIC_DEFINITIONS {
        uuid id PK
        uuid tenant_id FK
        uuid policy_version_id FK
        uuid calendar_version_id FK
        string stable_key
        string timing_mode
        bigint target_seconds
        jsonb conditions
        jsonb thresholds
    }

    SLA_INSTANCES {
        uuid id PK
        uuid tenant_id FK
        string subject_type
        uuid subject_id
        uuid policy_version_id FK
        string state
        timestamptz created_at
    }

    SLA_METRIC_INSTANCES {
        uuid id PK
        uuid tenant_id FK
        uuid sla_instance_id FK
        uuid metric_definition_id FK
        string state
        timestamptz started_at
        timestamptz due_at
        timestamptz completed_at
        timestamptz breached_at
        bigint consumed_seconds
        timestamptz next_evaluation_at
    }

    SLA_OVERRIDES {
        uuid id PK
        uuid tenant_id FK
        uuid metric_instance_id FK
        string action
        string reason
        jsonb before_value
        jsonb after_value
        uuid actor_id FK
        timestamptz occurred_at
    }

    NOTIFICATION_RULES {
        uuid id PK
        uuid tenant_id FK
        string event_type
        uuid template_id FK
        int version
        jsonb conditions
        jsonb recipient_rules
        jsonb retry_policy
        boolean enabled
    }

    NOTIFICATION_TEMPLATES {
        uuid id PK
        uuid tenant_id FK
        string name
        uuid active_version_id FK
    }

    NOTIFICATION_TEMPLATE_VERSIONS {
        uuid id PK
        uuid tenant_id FK
        uuid template_id FK
        int version
        string language
        string subject_template
        string html_template
        string text_template
        timestamptz published_at
    }

    NOTIFICATION_JOBS {
        uuid id PK
        uuid tenant_id FK
        uuid outbox_event_id FK
        uuid rule_id FK
        string recipient_key
        string status
        int attempts
        timestamptz available_at
        timestamptz lease_expires_at
    }

    DELIVERY_ATTEMPTS {
        uuid id PK
        uuid tenant_id FK
        uuid job_id FK
        int attempt_number
        string outcome
        string provider_code
        timestamptz attempted_at
    }

    WEBHOOK_SUBSCRIPTIONS {
        uuid id PK
        uuid tenant_id FK
        string endpoint
        bytes encrypted_secret
        jsonb event_types
        boolean enabled
    }

    WEBHOOK_DELIVERIES {
        uuid id PK
        uuid tenant_id FK
        uuid subscription_id FK
        uuid outbox_event_id FK
        string status
        int attempts
        timestamptz available_at
    }

    TENANT_OUTBOX_EVENTS {
        uuid id PK
        uuid tenant_id FK
        string event_type
        int schema_version
        string aggregate_type
        uuid aggregate_id
        bigint aggregate_version
        uuid correlation_id
        uuid causation_id
        string idempotency_key
        jsonb payload
        string status
        int attempts
        timestamptz available_at
        timestamptz lease_expires_at
    }

    TENANT_AUDIT_EVENTS {
        uuid id PK
        uuid tenant_id FK
        bigint tenant_sequence
        timestamptz occurred_at
        string actor_type
        uuid actor_id
        string action
        string resource_type
        uuid resource_id
        string outcome
        jsonb redacted_diff
        string previous_hash
        string event_hash
    }

    TENANTS ||--o{ BUSINESS_CALENDARS : owns
    BUSINESS_CALENDARS ||--|{ BUSINESS_CALENDAR_VERSIONS : versions
    TENANTS ||--o{ SLA_POLICIES : owns
    SLA_POLICIES ||--|{ SLA_POLICY_VERSIONS : versions
    SLA_POLICY_VERSIONS ||--|{ SLA_METRIC_DEFINITIONS : defines
    BUSINESS_CALENDAR_VERSIONS ||--o{ SLA_METRIC_DEFINITIONS : times
    SLA_POLICY_VERSIONS ||--o{ SLA_INSTANCES : pins
    SLA_INSTANCES ||--|{ SLA_METRIC_INSTANCES : materializes
    SLA_METRIC_DEFINITIONS ||--o{ SLA_METRIC_INSTANCES : instantiates
    SLA_METRIC_INSTANCES ||--o{ SLA_OVERRIDES : records
    TENANTS ||--o{ NOTIFICATION_RULES : owns
    TENANTS ||--o{ NOTIFICATION_TEMPLATES : owns
    NOTIFICATION_TEMPLATES ||--|{ NOTIFICATION_TEMPLATE_VERSIONS : versions
    NOTIFICATION_RULES }o--|| NOTIFICATION_TEMPLATES : selects
    TENANT_OUTBOX_EVENTS ||--o{ NOTIFICATION_JOBS : causes
    NOTIFICATION_RULES ||--o{ NOTIFICATION_JOBS : creates
    NOTIFICATION_JOBS ||--o{ DELIVERY_ATTEMPTS : attempts
    TENANTS ||--o{ WEBHOOK_SUBSCRIPTIONS : owns
    WEBHOOK_SUBSCRIPTIONS ||--o{ WEBHOOK_DELIVERIES : receives
    TENANT_OUTBOX_EVENTS ||--o{ WEBHOOK_DELIVERIES : causes
    TENANTS ||--o{ TENANT_OUTBOX_EVENTS : owns
    TENANTS ||--o{ TENANT_AUDIT_EVENTS : owns
```

Platform audit and platform outbox events use separate tables with platform-only access
policies. Runtime application roles have `INSERT` but not `UPDATE` or `DELETE` on audit
records. Outbox rows contain minimal, versioned, visibility-safe payloads; they never store
provider secrets or unrestricted aggregate snapshots.

## 6. Database constraints and indexes

The canonical schema includes, at minimum:

- `tenant_id NOT NULL` and `FORCE ROW LEVEL SECURITY` on every tenant-owned table;
- composite foreign keys that repeat `tenant_id` on every tenant-owned relationship;
- tenant-specific uniqueness for Alert/Case numbers, stable custom-field keys, workflow
  versions, SLA keys/versions, idempotency keys, and provider subjects;
- checks for exactly-one comment subject and type-correct custom-field values;
- conditional claim updates guarded by tenant, ID, expected version, eligible status, and
  unclaimed/current-assignment state;
- immutable published workflow, SLA, calendar, and template versions;
- append-only permissions for audit/custody history;
- tenant-leading indexes for status/severity/priority, assignee/team, SLA due/state,
  received/opened time, full-text search, and custom fields used by actual list queries;
- partial queue indexes on outbox/job `status`, `available_at`, and expired leases;
- recipient/delivery and command idempotency unique constraints;
- object key uniqueness and evidence SHA-256/scan-state lookup indexes scoped by tenant;
- retention-aware indexes and partitions only when observed data volume justifies them.

RLS policy tests must exercise direct ID access, joins, search, filters, export, job claims,
and object metadata. Database constraints and RLS are defense in depth; they do not remove
the requirement for backend authorization and visibility policy.

## 7. Delivery sequence

The diagrams span the completed staged order: Tenant/User/Membership/RBAC primitives plus
audit/outbox; authentication; Alert/Case; DFIR/custom fields; SLA;
notifications/webhooks; bulk/export; and platform/audit operations. No later entity may
weaken tenant ownership, and no placeholder table or migration is committed without the use
case and verification that consume it.
