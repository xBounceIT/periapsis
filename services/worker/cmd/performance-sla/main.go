// performance-sla is a bounded diagnostic adapter for the canonical SLA workers.
// It never creates databases, publishes configuration, or repairs queue state.
package main

import (
	"context"
	"encoding/json"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	result := execute(ctx, os.Args[1:], os.Getenv, openDatabaseBackend)
	stop()
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil || result.Status != "passed" {
		os.Exit(1)
	}
}

type backendFactory func(context.Context, databaseConfig, string) (backend, error)

func execute(ctx context.Context, args []string, getenv func(string) string, open backendFactory) report {
	started := time.Now()
	result := report{SchemaVersion: 1, Status: "failed"}
	opts, err := parseOptions(args)
	if err != nil {
		result.ErrorCode = "invalid_arguments"
		return result
	}
	result.Mode = opts.Mode
	cfg, err := readDatabaseConfig(getenv)
	if err != nil {
		result.ErrorCode = "invalid_connection"
		return result
	}
	ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()
	store, err := open(ctx, cfg, opts.Mode)
	if err != nil {
		result.ErrorCode = "database_preflight"
		result.DurationMS = time.Since(started).Milliseconds()
		return result
	}
	defer store.Close()
	result = run(ctx, opts, store)
	result.DurationMS = time.Since(started).Milliseconds()
	return result
}
