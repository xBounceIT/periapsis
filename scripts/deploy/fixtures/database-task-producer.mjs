// Test-only process boundary: execute the real driver while replacing every
// filesystem, subprocess and database operation it can perform. No SQL is run.
import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { registerHooks } from "node:module";
import { basename } from "node:path";

const scenario = JSON.parse(process.argv[2]);
const trace = [];
const canary = "private-producer-canary-never-emit";
const mountedSecret = scenario.quotePassword ? `${canary}'"\\quoted` : canary;
const administratorUrl = `postgresql://fixture:${canary}@database.invalid/fixture?sslmode=verify-full`;
for (const name of Object.keys(process.env)) {
  if (/^(?:DATABASE_URL(?:_FILE)?|PERIAPSIS_.*)$/iu.test(name))
    delete process.env[name];
}
process.env.PERIAPSIS_ENV = scenario.environment ?? "production";
process.env.PERIAPSIS_DATABASE_ADMIN_URL_FILE = "/fixture/admin-url";
process.argv[2] = scenario.mode ?? "migrate";

function failure(at) {
  trace.push(at);
  if (scenario.failure !== at) return;
  if (scenario.codeGetter) {
    throw Object.defineProperty(new Error(canary), "code", {
      get() {
        throw new Error(canary);
      },
    });
  }
  throw Object.assign(new Error(canary), {
    code: scenario.code,
    cause: { code: "EACCES", query: canary },
    detail: canary,
    parameters: [canary],
  });
}

const fixture = {
  async stat(path) {
    assert.equal(path, "/fixture/admin-url");
    failure("configuration");
    return { size: administratorUrl.length, isFile: () => true };
  },
  async readFile(path, encoding) {
    assert.equal(encoding, "utf8");
    if (path === "/fixture/admin-url") {
      trace.push("read_admin");
      return administratorUrl;
    }
    assert.match(
      path,
      /^\/run\/secrets\/(api|worker|notifier)_database_password$/u,
    );
    failure(`read_${basename(path).split("_")[0]}`);
    return mountedSecret;
  },
  spawn(executable, args, options) {
    assert.equal(executable, process.execPath);
    assert.equal(args.length, 1);
    assert.equal(options.stdio, "inherit");
    assert.equal(options.env.DATABASE_URL, administratorUrl);
    const stage = basename(args[0]) === "migrate.js" ? "migration" : "seed";
    assert.equal(
      basename(args[0]),
      stage === "migration" ? "migrate.js" : "seed.js",
    );
    trace.push(stage);
    const child = new EventEmitter();
    queueMicrotask(() => {
      if (scenario.failure === stage) {
        if (scenario.childError) {
          child.emit(
            "error",
            Object.assign(new Error(canary), { code: scenario.code }),
          );
        } else {
          child.emit("exit", scenario.exitCode ?? 1, scenario.signal ?? null);
        }
      } else child.emit("exit", 0, null);
    });
    return child;
  },
  postgres(url, options) {
    assert.equal(url, administratorUrl);
    assert.equal(options.connect_timeout, 10);
    assert.equal(options.max, 1);
    assert.equal(typeof options.onnotice, "function");
    failure("connect");
    const transaction = async (strings, ...parameters) => {
      const query = strings.join("?");
      if (query.includes("to_regclass")) {
        trace.push("webhook_surface");
        return [{ exists: false }];
      }
      if (query.includes("FROM pg_catalog.pg_auth_members")) {
        trace.push("membership_lookup");
        return [];
      }
      assert.ok(query.includes("SELECT format("));
      const operation = query.includes("RESET ALL")
        ? "reset"
        : query.includes("GRANT %I")
          ? "grant"
          : "alter";
      // Observe the actual driver's tagged query and parameter boundaries. The
      // PostgreSQL variadic format arguments must arrive with explicit types;
      // even quote-bearing passwords remain values, never interpolated SQL.
      const formats = {
        alter:
          "SELECT format( 'ALTER ROLE %I WITH LOGIN NOSUPERUSER INHERIT NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT %s VALID UNTIL ''infinity'' PASSWORD %L', ?::text, ?::integer, ?::text ) AS statement",
        grant:
          "SELECT format( 'GRANT %I TO %I WITH ADMIN FALSE, INHERIT TRUE, SET TRUE', ?::text, ?::text ) AS statement",
        reset: "SELECT format('ALTER ROLE %I RESET ALL', ?::text) AS statement",
      };
      assert.equal(query.replace(/\s+/gu, " ").trim(), formats[operation]);
      assert.ok(!query.includes(mountedSecret));
      if (operation === "alter") {
        assert.equal(parameters.length, 3);
        assert.match(parameters[0], /^periapsis_(api|worker|notifier)_login$/u);
        assert.equal(
          parameters[1],
          parameters[0] === "periapsis_api_login" ? 40 : 20,
        );
        assert.equal(parameters[2], mountedSecret);
      } else {
        assert.equal(parameters.length, operation === "grant" ? 2 : 1);
        for (const parameter of parameters)
          assert.match(
            parameter,
            /^periapsis_(api|worker|notifier)(?:_login)?$/u,
          );
      }
      trace.push(operation);
      return [{ statement: `fixture_${operation}` }];
    };
    transaction.unsafe = async (query) => {
      assert.ok(
        query.includes("DO $provision$") ||
          query === "SET LOCAL password_encryption = 'scram-sha-256'" ||
          /^fixture_(alter|reset|grant)$/u.test(query),
      );
      failure("provision_statement");
    };
    return {
      async begin(operation) {
        failure("begin");
        await operation(transaction);
      },
      async end(endOptions) {
        assert.deepEqual(endOptions, { timeout: 5 });
        failure("cleanup");
      },
    };
  },
};
globalThis.databaseTaskProducerFixture = fixture;
const modules = {
  "node:fs/promises": [
    "module",
    "export const { readFile, stat } = globalThis.databaseTaskProducerFixture;",
  ],
  "node:child_process": [
    "module",
    "export const { spawn } = globalThis.databaseTaskProducerFixture;",
  ],
  postgres: [
    "commonjs",
    "module.exports = globalThis.databaseTaskProducerFixture.postgres;",
  ],
};
registerHooks({
  resolve(specifier, context, nextResolve) {
    return Object.hasOwn(modules, specifier)
      ? { url: `fixture:${specifier}`, shortCircuit: true }
      : nextResolve(specifier, context);
  },
  load(url, context, nextLoad) {
    if (!url.startsWith("fixture:")) return nextLoad(url, context);
    const [format, source] = modules[url.slice("fixture:".length)];
    return { format, source, shortCircuit: true };
  },
});
await import("../../../deploy/compose/database-task.mjs");
process.stdout.write(`${JSON.stringify(trace)}\n`);
