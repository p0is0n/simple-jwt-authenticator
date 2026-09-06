//go:build integration

// Package network provides isolated Docker networks used by integration
// test environments.
package network

import (
	"context"
	"testing"

	testcontainers "github.com/testcontainers/testcontainers-go"
	tcnetwork "github.com/testcontainers/testcontainers-go/network"
)

// Network identifies an isolated Docker network used by an integration-test
// environment.
//
// The zero value represents no network and is safe to remove.
type Network struct {
	Name string

	dockerNetwork *testcontainers.DockerNetwork
}

// Create creates a new isolated Docker network.
//
// The caller owns the returned network and must call Remove.
func Create(ctx context.Context) (Network, error) {
	dockerNetwork, err := tcnetwork.New(ctx)
	if err != nil {
		return Network{}, err
	}

	return Network{
		Name:          dockerNetwork.Name,
		dockerNetwork: dockerNetwork,
	}, nil
}

// New creates a network owned by the current test and registers automatic
// cleanup through t.Cleanup.
//
// Package-level environments such as TestMain should use Create directly and
// own the lifecycle explicitly.
func New(t testing.TB) Network {
	t.Helper()

	net, err := Create(context.Background())
	if err != nil {
		t.Fatalf("create integration network: %v", err)
	}

	t.Cleanup(func() {
		if err := net.Remove(context.Background()); err != nil {
			t.Errorf("remove integration network: %v", err)
		}
	})

	return net
}

// Remove removes the Docker network.
//
// Removing a zero-value Network is a no-op. This allows environment cleanup
// code to safely handle partially constructed environments.
func (n Network) Remove(ctx context.Context) error {
	if n.dockerNetwork == nil {
		return nil
	}

	return n.dockerNetwork.Remove(ctx)
}
