import { sql } from "drizzle-orm";

/**
 * The API must set app.tenant_id with SET LOCAL inside every transaction.
 * A missing or reset setting evaluates to NULL, so every tenant policy denies access.
 * Malformed UUID text raises an error instead of broadening access.
 */
export const currentTenantId = sql`nullif(current_setting('app.tenant_id', true), '')::uuid`;

export const currentUserId = sql`nullif(current_setting('app.user_id', true), '')::uuid`;
