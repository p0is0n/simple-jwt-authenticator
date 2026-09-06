//go:build integration

// Package services provides integration-test infrastructure for shared
// external services used by multiple integration suites.
package services

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"simple-jwt-authenticator/tests/integration/support/network"
)

// protectedImage is the pinned go-httpbin image used as the protected
// upstream by integration tests.
const protectedImage = "ghcr.io/mccutchen/go-httpbin:2.25.0"

// protectedPort is the port the protected upstream listens on inside the
// container.
const protectedPort = "8080/tcp"

// protectedStartupTimeout bounds how long the upstream may take to become
// ready after its container has started.
const protectedStartupTimeout = time.Minute

// ProtectedOptions configures protected upstream container startup.
type ProtectedOptions struct {
	// Network is the isolated Docker network the container is attached
	// to.
	Network network.Network

	// Alias is the stable network alias inside Network, for example
	// "upstream".
	Alias string
}

// Protected is a running generic upstream service used behind an
// authentication adapter.
//
// Adapter integration tests normally do not access this container directly.
// They reach it through the proxy under test.
type Protected struct {
	container testcontainers.Container
}

// CreateProtected starts the generic protected upstream on the supplied
// Docker network.
//
// The caller owns the returned service and must call Close.
func CreateProtected(
	ctx context.Context,
	opts ProtectedOptions,
) (*Protected, error) {
	if opts.Network.Name == "" {
		return nil, errors.New("protected service requires a network")
	}

	if opts.Alias == "" {
		return nil, errors.New("protected service requires a network alias")
	}

	container, err := testcontainers.GenericContainer(
		ctx,
		testcontainers.GenericContainerRequest{
			ContainerRequest: testcontainers.ContainerRequest{
				Image: protectedImage,
				ExposedPorts: []string{
					protectedPort,
				},
				Networks: []string{
					opts.Network.Name,
				},
				NetworkAliases: map[string][]string{
					opts.Network.Name: {
						opts.Alias,
					},
				},
				WaitingFor: wait.ForHTTP("/").
					WithPort(protectedPort).
					WithStatusCodeMatcher(
						func(status int) bool {
							return status == http.StatusOK
						},
					).
					WithStartupTimeout(protectedStartupTimeout),
			},
			Started: true,
		},
	)
	if err != nil {
		return nil, fmt.Errorf(
			"start protected service container: %w",
			err,
		)
	}

	return &Protected{
		container: container,
	}, nil
}

// StartProtected starts a protected upstream owned by the current test and
// registers automatic cleanup through t.Cleanup.
//
// Package-level integration environments such as TestMain should use
// CreateProtected directly and own the lifecycle explicitly.
func StartProtected(
	t testing.TB,
	opts ProtectedOptions,
) *Protected {
	t.Helper()

	protected, err := CreateProtected(
		context.Background(),
		opts,
	)
	if err != nil {
		t.Fatalf("start protected service: %v", err)
	}

	t.Cleanup(func() {
		if err := protected.Close(context.Background()); err != nil {
			t.Errorf("close protected service: %v", err)
		}
	})

	return protected
}

// Close terminates the protected upstream container.
func (p *Protected) Close(ctx context.Context) error {
	if p == nil || p.container == nil {
		return nil
	}

	if err := p.container.Terminate(ctx); err != nil {
		return fmt.Errorf(
			"terminate protected service container: %w",
			err,
		)
	}

	p.container = nil

	return nil
}
