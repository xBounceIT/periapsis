import { customType } from "drizzle-orm/pg-core";

/** PostgreSQL binary data. Authentication code treats values as opaque bytes. */
export const bytea = customType<{
  data: Uint8Array;
  driverData: Uint8Array;
}>({
  dataType() {
    return "bytea";
  },
});
