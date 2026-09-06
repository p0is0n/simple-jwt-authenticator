//go:build integration

// Package authenticator provides integration-test infrastructure for the
// simple-jwt-authenticator application itself: building the production
// test image, generating RSA test keys, writing the server configuration,
// starting the container, and signing test tokens.
//
// The package is adapter-independent. It must never know about Nginx,
// Apache, Traefik, HTTPBin, or protected upstreams: reverse proxies are
// owned by their own adapter test packages.
package authenticator

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"simple-jwt-authenticator/tests/integration/support/build"
	"simple-jwt-authenticator/tests/integration/support/network"
)

// dockerfilePath is the test Dockerfile relative to the build context. It
// mirrors the production image and ships both binaries.
const dockerfilePath = "Dockerfile.test"

// internalPort is the port the authenticator listens on inside the
// container.
const internalPort = "8080/tcp"

// startupTimeout bounds how long the authenticator may take to become
// healthy after its container has started. Image build time is not part
// of this deadline.
const startupTimeout = 2 * time.Minute

// Options configures the authenticator container startup.
type Options struct {
	// Network is the isolated Docker network the container is attached
	// to.
	Network network.Network

	// Alias is the stable network alias inside Network, for example
	// "authenticator".
	Alias string
}

// Authenticator is a running simple-jwt-authenticator integration-test
// instance.
//
// It owns the container and temporary filesystem resources created during
// startup. Call Close when the instance is no longer needed.
//
// Tests normally use Start, which registers Close through t.Cleanup.
// Package-level integration environments, such as TestMain, use Create
// directly and own the lifecycle explicitly.
type Authenticator struct {
	container testcontainers.Container
	tempDir   string

	baseURL      string
	keys         KeyPair
	tokenBuilder *TokenBuilder
}

// Create generates RSA test keys, writes the server-mode configuration,
// builds the authenticator image from Dockerfile.test, and starts the
// container on the supplied Docker network.
//
// The caller owns the returned Authenticator and must call Close.
//
// If startup fails after some resources have already been created, Create
// removes those resources before returning the error.
func Create(
	ctx context.Context,
	opts Options,
) (_ *Authenticator, err error) {
	if opts.Network.Name == "" {
		return nil, errors.New("authenticator requires a network")
	}

	if opts.Alias == "" {
		return nil, errors.New("authenticator requires a network alias")
	}

	tempDir, err := os.MkdirTemp(
		"",
		"simple-jwt-authenticator-integration-*",
	)
	if err != nil {
		return nil, fmt.Errorf(
			"create authenticator temporary directory: %w",
			err,
		)
	}

	// Until ownership has been transferred to the returned Authenticator,
	// Create itself is responsible for removing the temporary directory.
	success := false

	defer func() {
		if success {
			return
		}

		_ = os.RemoveAll(tempDir)
	}()

	keyPair, err := GenerateKeyPair(tempDir)
	if err != nil {
		return nil, fmt.Errorf("generate RSA test key pair: %w", err)
	}

	configPath, err := writeConfig(tempDir)
	if err != nil {
		return nil, fmt.Errorf("write authenticator configuration: %w", err)
	}

	buildContext, err := build.Root()
	if err != nil {
		return nil, fmt.Errorf("resolve repository root: %w", err)
	}

	container, err := testcontainers.GenericContainer(
		ctx,
		testcontainers.GenericContainerRequest{
			ContainerRequest: testcontainers.ContainerRequest{
				FromDockerfile: testcontainers.FromDockerfile{
					Context:    buildContext,
					Dockerfile: dockerfilePath,
				},
				ExposedPorts: []string{
					internalPort,
				},
				Networks: []string{
					opts.Network.Name,
				},
				NetworkAliases: map[string][]string{
					opts.Network.Name: {
						opts.Alias,
					},
				},
				Files: []testcontainers.ContainerFile{
					{
						HostFilePath:      configPath,
						ContainerFilePath: containerConfigPath,
						FileMode:          configFileMode,
					},
					{
						HostFilePath:      keyPair.PublicKeyPath,
						ContainerFilePath: containerPublicKeyPath,
						FileMode:          configFileMode,
					},
				},
				Cmd: []string{
					containerConfigPath,
				},
				WaitingFor: wait.ForHTTP("/healthz").
					WithPort(internalPort).
					WithStatusCodeMatcher(
						func(status int) bool {
							return status == http.StatusOK
						},
					).
					WithStartupTimeout(startupTimeout),
			},
			Started: true,
		},
	)
	if err != nil {
		return nil, fmt.Errorf(
			"start authenticator container: %w",
			err,
		)
	}

	// From this point Create owns a running container. If anything below
	// fails, terminate it before returning.
	defer func() {
		if success {
			return
		}

		_ = container.Terminate(context.Background())
	}()

	host, err := container.Host(ctx)
	if err != nil {
		return nil, fmt.Errorf(
			"resolve authenticator host: %w",
			err,
		)
	}

	mappedPort, err := container.MappedPort(ctx, internalPort)
	if err != nil {
		return nil, fmt.Errorf(
			"resolve authenticator mapped port: %w",
			err,
		)
	}

	tokenBuilder, err := NewTokenBuilder(
		keyPair.PrivateKey,
		DefaultIssuer,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"create authenticator token builder: %w",
			err,
		)
	}

	auth := &Authenticator{
		container: container,
		tempDir:   tempDir,
		baseURL: "http://" + net.JoinHostPort(
			host,
			mappedPort.Port(),
		),
		keys:         keyPair,
		tokenBuilder: tokenBuilder,
	}

	success = true

	return auth, nil
}

// Start creates an authenticator instance owned by the current test and
// registers automatic cleanup through t.Cleanup.
//
// Use Create instead when the lifecycle belongs to a package-level test
// environment such as TestMain.
func Start(
	t testing.TB,
	opts Options,
) *Authenticator {
	t.Helper()

	auth, err := Create(context.Background(), opts)
	if err != nil {
		t.Fatalf("start authenticator: %v", err)
	}

	t.Cleanup(func() {
		if err := auth.Close(context.Background()); err != nil {
			t.Errorf("close authenticator: %v", err)
		}
	})

	return auth
}

// Stop stops the authenticator process without removing the container or
// its temporary resources.
//
// This is intentionally narrower than exposing the underlying Testcontainers
// container. Integration suites may use Stop to verify fail-closed behavior
// when the authentication dependency becomes unavailable while keeping
// container ownership inside this package.
//
// Close remains required after Stop and performs the final container and
// filesystem cleanup.
func (a *Authenticator) Stop(ctx context.Context) error {
	if a == nil || a.container == nil {
		return nil
	}

	if err := a.container.Stop(ctx, nil); err != nil {
		return fmt.Errorf(
			"stop authenticator container: %w",
			err,
		)
	}

	return nil
}

// Close terminates the authenticator container and removes temporary
// filesystem resources owned by the instance.
//
// Cleanup attempts all operations even if one of them fails. Multiple
// cleanup failures are returned together.
func (a *Authenticator) Close(ctx context.Context) error {
	if a == nil {
		return nil
	}

	var cleanupErrors []error

	if a.container != nil {
		if err := a.container.Terminate(ctx); err != nil {
			cleanupErrors = append(
				cleanupErrors,
				fmt.Errorf(
					"terminate authenticator container: %w",
					err,
				),
			)
		}

		a.container = nil
	}

	if a.tempDir != "" {
		if err := os.RemoveAll(a.tempDir); err != nil {
			cleanupErrors = append(
				cleanupErrors,
				fmt.Errorf(
					"remove authenticator temporary directory: %w",
					err,
				),
			)
		}

		a.tempDir = ""
	}

	return errors.Join(cleanupErrors...)
}

// URL returns the host-mapped base URL of the authenticator. It is meant
// for suites that test application endpoints such as health and metrics
// directly; authentication-adapter tests must go through their proxy
// instead.
func (a *Authenticator) URL() string {
	return a.baseURL
}

// KeyPair returns the RSA key pair backing this authenticator instance so
// tests can sign tokens against it, including intentionally invalid ones
// such as tokens with a wrong issuer.
func (a *Authenticator) KeyPair() KeyPair {
	return a.keys
}

// TokenBuilder returns a builder that produces valid tokens accepted by
// this authenticator instance.
func (a *Authenticator) TokenBuilder() *TokenBuilder {
	return a.tokenBuilder
}
