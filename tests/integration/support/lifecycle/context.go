//go:build integration

// Package lifecycle provides common lifecycle policies for integration-test
// infrastructure.
package lifecycle

import (
	"context"
	"time"
)

// CleanupTimeout bounds infrastructure cleanup operations.
//
// Cleanup must not use an unbounded context because a stalled Docker daemon
// or container runtime would otherwise prevent the test process from
// terminating indefinitely.
const CleanupTimeout = 30 * time.Second

// CleanupContext returns a bounded context for integration infrastructure
// cleanup.
//
// The caller must invoke the returned cancel function.
func CleanupContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(
		context.Background(),
		CleanupTimeout,
	)
}
