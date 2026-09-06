//go:build integration

package nginx_test

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"simple-jwt-authenticator/tests/integration/support/authenticator"
	"simple-jwt-authenticator/tests/integration/support/lifecycle"
	"simple-jwt-authenticator/tests/integration/support/network"
	"simple-jwt-authenticator/tests/integration/support/services"
)

const validAudience = "internal-services"

type nginxConfig string

const (
	nginxConfigDefault                 nginxConfig = "nginx.conf"
	nginxConfigClaimExpressionHeader   nginxConfig = "nginx.claim-expression-header.conf"
	nginxConfigClaimExpressionQuery    nginxConfig = "nginx.claim-expression-query.conf"
	nginxConfigClaimExpressionMultiple nginxConfig = "nginx.claim-expression-multiple.conf"
	nginxConfigClaimExpressionTrusted  nginxConfig = "nginx.claim-expression-trusted.conf"
)

var nginxConfigs = []nginxConfig{
	nginxConfigDefault,
	nginxConfigClaimExpressionHeader,
	nginxConfigClaimExpressionQuery,
	nginxConfigClaimExpressionMultiple,
	nginxConfigClaimExpressionTrusted,
}

const nginxImage = "nginx:stable-alpine"
const nginxPort = "80/tcp"
const nginxStartupTimeout = time.Minute

type environment struct {
	net           network.Network
	authenticator *authenticator.Authenticator
	protected     *services.Protected

	nginx map[nginxConfig]*nginxContainer

	// baseURL remains the default production-like Nginx endpoint so existing
	// integration tests do not need to know about specialized fixtures.
	baseURL string

	client *http.Client
	tokens *authenticator.TokenBuilder
	keys   authenticator.KeyPair
}

var testEnv *environment

func TestMain(m *testing.M) {
	ctx := context.Background()

	env, err := startEnvironment(ctx)
	if err != nil {
		log.Printf(
			"start Nginx integration environment: %v",
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
			"close Nginx integration environment: %v",
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
		net: net,
		nginx: make(
			map[nginxConfig]*nginxContainer,
			len(nginxConfigs),
		),
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

	protected, err := services.CreateProtected(
		ctx,
		services.ProtectedOptions{
			Network: net,
			Alias:   "upstream",
		},
	)
	if err != nil {
		return nil, fmt.Errorf(
			"create protected upstream: %w",
			err,
		)
	}

	env.protected = protected

	for _, config := range nginxConfigs {
		nginx, err := startNginx(
			ctx,
			nginxOptions{
				Network: net,
			},
			config,
		)
		if err != nil {
			return nil, fmt.Errorf(
				"start Nginx with config %q: %w",
				config,
				err,
			)
		}

		env.nginx[config] = nginx
	}

	defaultNginx, ok := env.nginx[nginxConfigDefault]
	if !ok {
		return nil, errors.New(
			"default Nginx container was not started",
		)
	}

	env.baseURL = defaultNginx.baseURL
	env.tokens = auth.TokenBuilder()
	env.keys = auth.KeyPair()

	success = true

	return env, nil
}

func (e *environment) baseURLFor(
	t testing.TB,
	config nginxConfig,
) string {
	t.Helper()

	if e == nil {
		t.Fatal(
			"integration environment is nil",
		)
	}

	nginx, ok := e.nginx[config]
	if !ok || nginx == nil {
		t.Fatalf(
			"Nginx config %q is not available",
			config,
		)
	}

	return nginx.baseURL
}

func (e *environment) Close(ctx context.Context) error {
	if e == nil {
		return nil
	}

	var cleanupErrors []error

	// Close Nginx containers before their dependencies. Iterate over the
	// declared configuration order rather than the map so shutdown behavior
	// remains deterministic.
	for _, config := range nginxConfigs {
		nginx := e.nginx[config]
		if nginx == nil {
			continue
		}

		if err := nginx.Close(ctx); err != nil {
			cleanupErrors = append(
				cleanupErrors,
				fmt.Errorf(
					"close Nginx with config %q: %w",
					config,
					err,
				),
			)
		}

		delete(e.nginx, config)
	}

	if e.protected != nil {
		if err := e.protected.Close(ctx); err != nil {
			cleanupErrors = append(
				cleanupErrors,
				fmt.Errorf(
					"close protected upstream: %w",
					err,
				),
			)
		}

		e.protected = nil
	}

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

	if e.net.Name != "" {
		if err := e.net.Remove(ctx); err != nil {
			cleanupErrors = append(
				cleanupErrors,
				fmt.Errorf(
					"remove integration network: %w",
					err,
				),
			)
		}

		e.net = network.Network{}
	}

	return errors.Join(cleanupErrors...)
}

type nginxOptions struct {
	Network network.Network
}

type nginxContainer struct {
	container testcontainers.Container
	baseURL   string
}

func startNginx(
	ctx context.Context,
	opts nginxOptions,
	config nginxConfig,
) (_ *nginxContainer, err error) {
	if opts.Network.Name == "" {
		return nil, errors.New(
			"Nginx requires a network",
		)
	}

	configPath, err := fixtureNginxConfig(config)
	if err != nil {
		return nil, fmt.Errorf(
			"resolve Nginx fixture: %w",
			err,
		)
	}

	container, err := testcontainers.GenericContainer(
		ctx,
		testcontainers.GenericContainerRequest{
			ContainerRequest: testcontainers.ContainerRequest{
				Image: nginxImage,
				ExposedPorts: []string{
					nginxPort,
				},
				Networks: []string{
					opts.Network.Name,
				},
				Files: []testcontainers.ContainerFile{
					{
						HostFilePath: configPath,
						ContainerFilePath: "/etc/nginx/conf.d/" +
							"default.conf",
						FileMode: 0o644,
					},
				},
				WaitingFor: wait.ForHTTP("/_health").
					WithPort(nginxPort).
					WithStatusCodeMatcher(
						func(status int) bool {
							return status == http.StatusOK
						},
					).
					WithStartupTimeout(
						nginxStartupTimeout,
					),
			},
			Started: true,
		},
	)
	if err != nil {
		return nil, fmt.Errorf(
			"start Nginx container: %w",
			err,
		)
	}

	success := false

	defer func() {
		if success {
			return
		}

		cleanupCtx, cancel := lifecycle.CleanupContext()
		defer cancel()

		_ = container.Terminate(cleanupCtx)
	}()

	host, err := container.Host(ctx)
	if err != nil {
		return nil, fmt.Errorf(
			"resolve Nginx host: %w",
			err,
		)
	}

	mappedPort, err := container.MappedPort(
		ctx,
		nginxPort,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"resolve Nginx mapped port: %w",
			err,
		)
	}

	nginx := &nginxContainer{
		container: container,
		baseURL: "http://" + net.JoinHostPort(
			host,
			mappedPort.Port(),
		),
	}

	success = true

	return nginx, nil
}

func (n *nginxContainer) Close(ctx context.Context) error {
	if n == nil || n.container == nil {
		return nil
	}

	if err := n.container.Terminate(ctx); err != nil {
		return fmt.Errorf(
			"terminate Nginx container: %w",
			err,
		)
	}

	n.container = nil

	return nil
}

func fixtureNginxConfig(
	config nginxConfig,
) (string, error) {
	if !supportedNginxConfig(config) {
		return "", fmt.Errorf(
			"unsupported Nginx fixture config %q",
			config,
		)
	}

	path, err := filepath.Abs(
		filepath.Join(
			"fixtures",
			string(config),
		),
	)
	if err != nil {
		return "", fmt.Errorf(
			"resolve fixture path: %w",
			err,
		)
	}

	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf(
			"stat fixture %q: %w",
			path,
			err,
		)
	}

	if !info.Mode().IsRegular() {
		return "", fmt.Errorf(
			"Nginx fixture %q is not a regular file",
			path,
		)
	}

	return path, nil
}

func supportedNginxConfig(config nginxConfig) bool {
	switch config {
	case nginxConfigDefault,
		nginxConfigClaimExpressionHeader,
		nginxConfigClaimExpressionQuery,
		nginxConfigClaimExpressionMultiple,
		nginxConfigClaimExpressionTrusted:
		return true

	default:
		return false
	}
}
