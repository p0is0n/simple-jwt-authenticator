// Package nginx owns the Nginx auth_request adapter. It implements the
// complete transport boundary flow: HTTP policy extraction, credential
// extraction, transport-independent authentication, response mapping, and
// adapter-level authentication observability.
package nginx

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	stdhttp "net/http"

	"simple-jwt-authenticator/internal/authentication"
	"simple-jwt-authenticator/internal/metrics"
	"simple-jwt-authenticator/internal/transport/http/claimexpression"
	"simple-jwt-authenticator/internal/transport/http/credential"
)

// Adapter is the stable Nginx authentication adapter identifier.
const Adapter = "http-auth-nginx"

// Path is the route owned by the Nginx authentication adapter.
const Path = "/auth/nginx"

// Handler is the Nginx auth_request adapter.
type Handler struct {
	authenticator    authenticator
	credentials      credentialProvider
	claimExpressions claimExpressionProvider
	recorder         metrics.AuthenticationRecorder
	headers          headerMapper
	logger           *slog.Logger
}

// authenticator is the consumer-owned narrow authentication contract required
// by the adapter.
type authenticator interface {
	Authenticate(
		ctx context.Context,
		request authentication.Request,
	) (authentication.Identity, error)
}

// credentialProvider is the consumer-owned narrow credential extraction
// contract required by the adapter.
type credentialProvider interface {
	Extract(
		request *stdhttp.Request,
	) (credential.Result, error)
}

// claimExpressionProvider is the consumer-owned narrow dynamic-policy
// extraction contract required by the adapter.
type claimExpressionProvider interface {
	Extract(
		request *stdhttp.Request,
	) (claimexpression.Result, error)
}

// NewHandler constructs the Nginx authentication adapter.
//
// Mandatory dependency failures are rejected during application construction
// rather than being deferred to request handling.
func NewHandler(
	authenticator authenticator,
	credentials credentialProvider,
	claimExpressions claimExpressionProvider,
	recorder metrics.AuthenticationRecorder,
	logger *slog.Logger,
) (*Handler, error) {
	if authenticator == nil {
		return nil, fmt.Errorf(
			"%w: authenticator is required",
			errInvalidHandlerConfiguration,
		)
	}

	if credentials == nil {
		return nil, fmt.Errorf(
			"%w: credential provider is required",
			errInvalidHandlerConfiguration,
		)
	}

	if claimExpressions == nil {
		return nil, fmt.Errorf(
			"%w: claim expression provider is required",
			errInvalidHandlerConfiguration,
		)
	}

	if recorder == nil {
		return nil, fmt.Errorf(
			"%w: authentication recorder is required",
			errInvalidHandlerConfiguration,
		)
	}

	if logger == nil {
		return nil, fmt.Errorf(
			"%w: logger is required",
			errInvalidHandlerConfiguration,
		)
	}

	return &Handler{
		authenticator:    authenticator,
		credentials:      credentials,
		claimExpressions: claimExpressions,
		recorder:         recorder,
		headers:          defaultHeaderMapper{},
		logger:           logger,
	}, nil
}

// Name returns the stable handler name.
func (Handler) Name() string {
	return Adapter
}

// Path returns the route owned by the handler.
func (Handler) Path() string {
	return Path
}

// Adapter returns the stable adapter identity.
func (Handler) Adapter() string {
	return Adapter
}

// ServeHTTP implements http.Handler.
func (h *Handler) ServeHTTP(
	writer stdhttp.ResponseWriter,
	request *stdhttp.Request,
) {
	if request.Method != stdhttp.MethodGet {
		writeMethodNotAllowed(writer)

		return
	}

	start := time.Now()

	result, err := h.authenticate(request)
	if err != nil {
		classification := classifyError(err)

		h.recordFailure(
			request,
			result,
			classification.reason,
			time.Since(start),
		)

		switch classification.disposition {
		case failureDispositionBadRequest:
			writeBadRequest(writer)

		case failureDispositionUnauthorized:
			writeUnauthorized(writer)

		case failureDispositionInternal:
			h.logInternalFailure(
				request,
				"authenticate",
			)

			writeInternalError(writer)

		default:
			h.logInternalFailure(
				request,
				"classify_authentication_failure",
			)

			writeInternalError(writer)
		}

		return
	}

	if err := h.headers.Apply(
		writer.Header(),
		result.identity,
	); err != nil {
		h.recordFailure(
			request,
			result,
			failureReasonInternal,
			time.Since(start),
		)

		h.logInternalFailure(
			request,
			"map_identity_headers",
		)

		writeInternalError(writer)

		return
	}

	writeSuccess(writer)

	h.recorder.RecordAuth(
		request.Context(),
		Adapter,
		metrics.ResultSuccess,
		metricCredentialSource(result.source),
		"",
		time.Since(start),
	)
}

// authResult carries the extracted credential source and authenticated
// adapter-local identity.
type authResult struct {
	source   credential.Source
	identity identity
}

// authenticate performs HTTP policy extraction, credential extraction and
// transport-independent authentication.
//
// Dynamic policy is resolved before credential authentication. A malformed or
// ambiguous claim-expression source therefore fails before expensive token
// parsing and cannot silently degrade into an authentication request without
// the requested policy.
func (h *Handler) authenticate(
	request *stdhttp.Request,
) (authResult, error) {
	policy, err := h.claimExpressions.Extract(
		request,
	)
	if err != nil {
		return authResult{
			source: credential.SourceUnknown,
		}, err
	}

	extraction, err := h.credentials.Extract(
		request,
	)
	if err != nil {
		return authResult{
			source: extraction.Source,
		}, err
	}

	if !extraction.Extracted {
		return authResult{
			source: extraction.Source,
		}, credential.ErrMissingCredential
	}

	authenticated, err := h.authenticator.Authenticate(
		request.Context(),
		authentication.Request{
			Credential:      extraction.Credential,
			ClaimExpression: policy.Expression,
		},
	)
	if err != nil {
		return authResult{
			source: extraction.Source,
		}, err
	}

	return authResult{
		source: extraction.Source,
		identity: identity{
			Subject:  authenticated.Subject,
			Username: authenticated.Username,
			Email:    authenticated.Email,
		},
	}, nil
}

// recordFailure records only bounded adapter-derived metric labels.
//
// Raw errors and unvalidated source strings must never reach the metrics
// backend.
func (h *Handler) recordFailure(
	request *stdhttp.Request,
	result authResult,
	reason failureReason,
	duration time.Duration,
) {
	h.recorder.RecordAuth(
		request.Context(),
		Adapter,
		metrics.ResultFailure,
		metricCredentialSource(result.source),
		metricFailureReason(reason),
		duration,
	)
}

// logInternalFailure records bounded operational context without logging the
// raw authentication error chain.
func (h *Handler) logInternalFailure(
	request *stdhttp.Request,
	stage string,
) {
	h.logger.ErrorContext(
		request.Context(),
		"nginx authentication adapter internal failure",
		"adapter",
		Adapter,
		"stage",
		stage,
	)
}
