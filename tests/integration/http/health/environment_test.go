//go:build integration

package health_test

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"testing"
	"time"

	"simple-jwt-authenticator/tests/integration/support/authenticator"
	"simple-jwt-authenticator/tests/integration/support/lifecycle"
	"simple-jwt-authenticator/tests/integration/support/network"
)

type environment struct {
	authenticator *authenticator.Authenticator
	network       network.Network

	authURL string
	client  *http.Client
}

var testEnv *environment

func TestMain(m *testing.M) {
	ctx := context.Background()

	env, err := startEnvironment(ctx)
	if err != nil {
		log.Printf(
			"start health integration environment: %v",
			err,
		)
		os.Exit(1)
	}

	testEnv = env

	code := m.Run()

	cleanupCtx, cancel := lifecycle.CleanupContext()
	defer cancel()

	if err := env.Close(cleanupCtx); err != nil {
		log.Printf(
			"close health integration environment: %v",
			err,
		)

		if code == 0 {
			code = 1
		}
	}

	os.Exit(code)
}

func startEnvironment(ctx context.Context) (*environment, error) {
	net, err := network.Create(ctx)
	if err != nil {
		return nil, fmt.Errorf(
			"create integration network: %w",
			err,
		)
	}

	env := &environment{
		network: net,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}

	success := false

	defer func() {
		if success {
			return
		}

		cleanupCtx, cancel := lifecycle.CleanupContext()
		defer cancel()

		_ = env.Close(cleanupCtx)
	}()

	auth, err := authenticator.Create(
		ctx,
		authenticator.Options{
			Network: net,
			Alias:   "authenticator",
		},
	)
	if err != nil {
		return nil, fmt.Errorf(
			"create authenticator: %w",
			err,
		)
	}

	env.authenticator = auth
	env.authURL = auth.URL()

	success = true

	return env, nil
}

func (e *environment) Close(ctx context.Context) error {
	if e == nil {
		return nil
	}

	var cleanupErrors []error

	if e.authenticator != nil {
		if err := e.authenticator.Close(ctx); err != nil {
			cleanupErrors = append(
				cleanupErrors,
				fmt.Errorf(
					"close authenticator: %w",
					err,
				),
			)
		}

		e.authenticator = nil
	}

	if e.network.Name != "" {
		if err := e.network.Remove(ctx); err != nil {
			cleanupErrors = append(
				cleanupErrors,
				fmt.Errorf(
					"remove integration network: %w",
					err,
				),
			)
		}

		e.network = network.Network{}
	}

	return errors.Join(cleanupErrors...)
}
