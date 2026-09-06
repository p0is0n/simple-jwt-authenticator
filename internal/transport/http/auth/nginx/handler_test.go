package nginx

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"simple-jwt-authenticator/internal/authentication"
	"simple-jwt-authenticator/internal/metrics"
	"simple-jwt-authenticator/internal/token/claim"
	"simple-jwt-authenticator/internal/token/validator"
	"simple-jwt-authenticator/internal/transport/http/claimexpression"
	"simple-jwt-authenticator/internal/transport/http/credential"
)

type authenticatorFunc func(
	ctx context.Context,
	request authentication.Request,
) (authentication.Identity, error)

func (f authenticatorFunc) Authenticate(
	ctx context.Context,
	request authentication.Request,
) (authentication.Identity, error) {
	return f(ctx, request)
}

type credentialProviderFunc func(
	request *http.Request,
) (credential.Result, error)

func (f credentialProviderFunc) Extract(
	request *http.Request,
) (credential.Result, error) {
	return f(request)
}

type claimExpressionProviderFunc func(
	request *http.Request,
) (claimexpression.Result, error)

func (f claimExpressionProviderFunc) Extract(
	request *http.Request,
) (claimexpression.Result, error) {
	return f(request)
}

func newTestHandler(
	t *testing.T,
	auth authenticator,
	creds credentialProvider,
) *Handler {
	t.Helper()

	logger := slog.New(
		slog.NewTextHandler(
			io.Discard,
			nil,
		),
	)

	handler, err := NewHandler(
		auth,
		creds,
		testClaimExpressionProvider(),
		metrics.NoopAuthenticationRecorder{},
		logger,
	)
	if err != nil {
		t.Fatalf("create handler: %v", err)
	}

	return handler
}

func testAuthenticator() authenticator {
	return authenticatorFunc(
		func(
			_ context.Context,
			_ authentication.Request,
		) (authentication.Identity, error) {
			return authentication.Identity{
				Subject: "camera-front",
			}, nil
		},
	)
}

func testCredentialProvider() credentialProvider {
	return credentialProviderFunc(
		func(_ *http.Request) (credential.Result, error) {
			return credential.Result{
				Credential: authentication.Credential{
					Value: "token",
				},
				Source:    credential.SourceAuthorizationHeader,
				Extracted: true,
			}, nil
		},
	)
}

func testClaimExpressionProvider() claimExpressionProvider {
	return claimExpressionProviderFunc(
		func(_ *http.Request) (claimexpression.Result, error) {
			return claimexpression.Result{}, nil
		},
	)
}

func mustClaimExpression(
	t *testing.T,
) claim.Expression {
	t.Helper()

	expression, err := claim.NewAll(
		mustClaimMatch(
			t,
			claim.NameSubject,
			claim.OperatorEqual,
			"camera-front",
		),
		mustClaimMatch(
			t,
			claim.NameAudience,
			claim.OperatorEqual,
			"frigate",
		),
	)
	if err != nil {
		t.Fatalf(
			"create claim expression: %v",
			err,
		)
	}

	return expression
}

func mustClaimMatch(
	t *testing.T,
	name claim.Name,
	operator claim.Operator,
	value string,
) claim.Expression {
	t.Helper()

	expression, err := claim.NewMatch(
		name,
		operator,
		value,
	)
	if err != nil {
		t.Fatalf(
			"create claim match: %v",
			err,
		)
	}

	return expression
}

func TestNewHandler_RejectsMissingDependencies(t *testing.T) {
	logger := slog.New(
		slog.NewTextHandler(
			io.Discard,
			nil,
		),
	)

	cases := []struct {
		name        string
		auth        authenticator
		creds       credentialProvider
		expressions claimExpressionProvider
		rec         metrics.AuthenticationRecorder
		log         *slog.Logger
	}{
		{
			name:        "authenticator",
			auth:        nil,
			creds:       testCredentialProvider(),
			expressions: testClaimExpressionProvider(),
			rec:         metrics.NoopAuthenticationRecorder{},
			log:         logger,
		},
		{
			name:        "credential provider",
			auth:        testAuthenticator(),
			creds:       nil,
			expressions: testClaimExpressionProvider(),
			rec:         metrics.NoopAuthenticationRecorder{},
			log:         logger,
		},
		{
			name:        "claim expression provider",
			auth:        testAuthenticator(),
			creds:       testCredentialProvider(),
			expressions: nil,
			rec:         metrics.NoopAuthenticationRecorder{},
			log:         logger,
		},
		{
			name:        "recorder",
			auth:        testAuthenticator(),
			creds:       testCredentialProvider(),
			expressions: testClaimExpressionProvider(),
			rec:         nil,
			log:         logger,
		},
		{
			name:        "logger",
			auth:        testAuthenticator(),
			creds:       testCredentialProvider(),
			expressions: testClaimExpressionProvider(),
			rec:         metrics.NoopAuthenticationRecorder{},
			log:         nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			handler, err := NewHandler(
				tc.auth,
				tc.creds,
				tc.expressions,
				tc.rec,
				tc.log,
			)

			if !errors.Is(
				err,
				errInvalidHandlerConfiguration,
			) {
				t.Fatalf(
					"expected errInvalidHandlerConfiguration, got %v",
					err,
				)
			}

			if handler != nil {
				t.Fatalf(
					"expected nil handler, got %+v",
					handler,
				)
			}
		})
	}
}

func TestHandler_ValidAuthenticationReturns204(t *testing.T) {
	handler := newTestHandler(
		t,
		authenticatorFunc(
			func(
				_ context.Context,
				_ authentication.Request,
			) (authentication.Identity, error) {
				return authentication.Identity{
					Subject:  "camera-front",
					Username: "front",
					Email:    "front@example.com",
				}, nil
			},
		),
		testCredentialProvider(),
	)

	request := httptest.NewRequest(
		http.MethodGet,
		Path,
		nil,
	)
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(
		recorder,
		request,
	)

	if recorder.Code != http.StatusNoContent {
		t.Fatalf(
			"unexpected status: got %d, want %d",
			recorder.Code,
			http.StatusNoContent,
		)
	}

	if recorder.Body.Len() != 0 {
		t.Fatalf(
			"response body must be empty, got %q",
			recorder.Body.String(),
		)
	}

	if recorder.Header().Get(HeaderSubject) != "camera-front" {
		t.Fatalf(
			"unexpected subject header: %q",
			recorder.Header().Get(HeaderSubject),
		)
	}
}

func TestHandler_KnownAuthenticationRejectionReturns401(
	t *testing.T,
) {
	handler := newTestHandler(
		t,
		authenticatorFunc(
			func(
				_ context.Context,
				_ authentication.Request,
			) (authentication.Identity, error) {
				return authentication.Identity{},
					errors.Join(
						authentication.ErrAuthentication,
						validator.ErrExpired,
					)
			},
		),
		testCredentialProvider(),
	)

	recorder := httptest.NewRecorder()

	handler.ServeHTTP(
		recorder,
		httptest.NewRequest(
			http.MethodGet,
			Path,
			nil,
		),
	)

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf(
			"unexpected status: got %d, want %d",
			recorder.Code,
			http.StatusUnauthorized,
		)
	}

	if recorder.Body.Len() != 0 {
		t.Fatalf(
			"response body must be empty, got %q",
			recorder.Body.String(),
		)
	}
}

func TestHandler_BareAuthenticationFailureFailsClosedWith500(
	t *testing.T,
) {
	handler := newTestHandler(
		t,
		authenticatorFunc(
			func(
				_ context.Context,
				_ authentication.Request,
			) (authentication.Identity, error) {
				return authentication.Identity{},
					authentication.ErrAuthentication
			},
		),
		testCredentialProvider(),
	)

	recorder := httptest.NewRecorder()

	handler.ServeHTTP(
		recorder,
		httptest.NewRequest(
			http.MethodGet,
			Path,
			nil,
		),
	)

	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf(
			"unexpected status: got %d, want %d",
			recorder.Code,
			http.StatusInternalServerError,
		)
	}
}

func TestHandler_UnknownAuthenticationErrorReturns500(
	t *testing.T,
) {
	handler := newTestHandler(
		t,
		authenticatorFunc(
			func(
				_ context.Context,
				_ authentication.Request,
			) (authentication.Identity, error) {
				return authentication.Identity{},
					errors.New("unexpected internal failure")
			},
		),
		testCredentialProvider(),
	)

	recorder := httptest.NewRecorder()

	handler.ServeHTTP(
		recorder,
		httptest.NewRequest(
			http.MethodGet,
			Path,
			nil,
		),
	)

	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf(
			"unexpected status: got %d, want %d",
			recorder.Code,
			http.StatusInternalServerError,
		)
	}
}

func TestHandler_MissingCredentialReturns401(t *testing.T) {
	handler := newTestHandler(
		t,
		testAuthenticator(),
		credentialProviderFunc(
			func(_ *http.Request) (credential.Result, error) {
				return credential.Result{
					Source: credential.SourceAuthorizationHeader,
				}, credential.ErrMissingCredential
			},
		),
	)

	recorder := httptest.NewRecorder()

	handler.ServeHTTP(
		recorder,
		httptest.NewRequest(
			http.MethodGet,
			Path,
			nil,
		),
	)

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf(
			"unexpected status: got %d, want %d",
			recorder.Code,
			http.StatusUnauthorized,
		)
	}
}

func TestHandler_RejectsUnsafeIdentityWithoutPartialHeaders(
	t *testing.T,
) {
	handler := newTestHandler(
		t,
		authenticatorFunc(
			func(
				_ context.Context,
				_ authentication.Request,
			) (authentication.Identity, error) {
				return authentication.Identity{
					Subject:  "camera-front",
					Username: "front\r\nX-Injected: evil",
				}, nil
			},
		),
		testCredentialProvider(),
	)

	recorder := httptest.NewRecorder()

	handler.ServeHTTP(
		recorder,
		httptest.NewRequest(
			http.MethodGet,
			Path,
			nil,
		),
	)

	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf(
			"unexpected status: got %d, want %d",
			recorder.Code,
			http.StatusInternalServerError,
		)
	}

	if recorder.Header().Get(HeaderSubject) != "" {
		t.Fatal(
			"authentication headers must not be partially written",
		)
	}

	if recorder.Header().Get("X-Injected") != "" {
		t.Fatal("header injection succeeded")
	}
}

func TestHandler_MissingIdentitySubjectReturns500(
	t *testing.T,
) {
	handler := newTestHandler(
		t,
		authenticatorFunc(
			func(
				_ context.Context,
				_ authentication.Request,
			) (authentication.Identity, error) {
				return authentication.Identity{
					Username: "front",
				}, nil
			},
		),
		testCredentialProvider(),
	)

	recorder := httptest.NewRecorder()

	handler.ServeHTTP(
		recorder,
		httptest.NewRequest(
			http.MethodGet,
			Path,
			nil,
		),
	)

	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf(
			"unexpected status: got %d, want %d",
			recorder.Code,
			http.StatusInternalServerError,
		)
	}
}

func TestHandler_MethodNotAllowed(t *testing.T) {
	handler := newTestHandler(
		t,
		testAuthenticator(),
		testCredentialProvider(),
	)

	recorder := httptest.NewRecorder()

	handler.ServeHTTP(
		recorder,
		httptest.NewRequest(
			http.MethodPost,
			Path,
			nil,
		),
	)

	if recorder.Code != http.StatusMethodNotAllowed {
		t.Fatalf(
			"unexpected status: got %d, want %d",
			recorder.Code,
			http.StatusMethodNotAllowed,
		)
	}

	if recorder.Header().Get("Allow") != http.MethodGet {
		t.Fatalf(
			"unexpected Allow header: got %q, want %q",
			recorder.Header().Get("Allow"),
			http.MethodGet,
		)
	}

	if recorder.Body.Len() != 0 {
		t.Fatalf(
			"response body must be empty, got %q",
			recorder.Body.String(),
		)
	}
}

func TestHandler_AdapterIdentity(t *testing.T) {
	handler := newTestHandler(
		t,
		testAuthenticator(),
		testCredentialProvider(),
	)

	if handler.Name() != Adapter {
		t.Fatalf(
			"unexpected name: got %q, want %q",
			handler.Name(),
			Adapter,
		)
	}

	if handler.Adapter() != Adapter {
		t.Fatalf(
			"unexpected adapter: got %q, want %q",
			handler.Adapter(),
			Adapter,
		)
	}

	if handler.Path() != Path {
		t.Fatalf(
			"unexpected path: got %q, want %q",
			handler.Path(),
			Path,
		)
	}
}

func TestHandler_ForwardsClaimExpressionToAuthenticator(
	t *testing.T,
) {
	var gotRequest authentication.Request

	expression := mustClaimExpression(t)

	logger := slog.New(
		slog.NewTextHandler(
			io.Discard,
			nil,
		),
	)

	handler, err := NewHandler(
		authenticatorFunc(
			func(
				_ context.Context,
				request authentication.Request,
			) (authentication.Identity, error) {
				gotRequest = request

				return authentication.Identity{
					Subject: "camera-front",
				}, nil
			},
		),
		testCredentialProvider(),
		claimExpressionProviderFunc(
			func(
				_ *http.Request,
			) (claimexpression.Result, error) {
				return claimexpression.Result{
					Expression: expression,
					Source:     claimexpression.SourceHeader,
					Extracted:  true,
				}, nil
			},
		),
		metrics.NoopAuthenticationRecorder{},
		logger,
	)
	if err != nil {
		t.Fatalf("create handler: %v", err)
	}

	recorder := httptest.NewRecorder()

	handler.ServeHTTP(
		recorder,
		httptest.NewRequest(
			http.MethodGet,
			Path,
			nil,
		),
	)

	if recorder.Code != http.StatusNoContent {
		t.Fatalf(
			"unexpected status: got %d, want %d",
			recorder.Code,
			http.StatusNoContent,
		)
	}

	if gotRequest.ClaimExpression == nil {
		t.Fatal(
			"ClaimExpression = nil, want forwarded expression",
		)
	}

	if !claim.Evaluate(
		gotRequest.ClaimExpression,
		claim.Claims{
			Subject: "camera-front",
			Audience: []string{
				"frigate",
			},
		},
	) {
		t.Fatal(
			"forwarded expression rejected matching claims",
		)
	}
}

func TestHandler_OmittedClaimExpressionForwardsNil(
	t *testing.T,
) {
	var gotRequest authentication.Request

	handler := newTestHandler(
		t,
		authenticatorFunc(
			func(
				_ context.Context,
				request authentication.Request,
			) (authentication.Identity, error) {
				gotRequest = request

				return authentication.Identity{
					Subject: "camera-front",
				}, nil
			},
		),
		testCredentialProvider(),
	)

	recorder := httptest.NewRecorder()

	handler.ServeHTTP(
		recorder,
		httptest.NewRequest(
			http.MethodGet,
			Path,
			nil,
		),
	)

	if recorder.Code != http.StatusNoContent {
		t.Fatalf(
			"unexpected status: got %d, want %d",
			recorder.Code,
			http.StatusNoContent,
		)
	}

	if gotRequest.ClaimExpression != nil {
		t.Fatal(
			"ClaimExpression != nil, want nil",
		)
	}
}

func TestHandler_MalformedClaimExpressionReturns400BeforeAuthentication(
	t *testing.T,
) {
	authCalled := false
	credentialCalled := false

	logger := slog.New(
		slog.NewTextHandler(
			io.Discard,
			nil,
		),
	)

	handler, err := NewHandler(
		authenticatorFunc(
			func(
				_ context.Context,
				_ authentication.Request,
			) (authentication.Identity, error) {
				authCalled = true

				return authentication.Identity{
					Subject: "camera-front",
				}, nil
			},
		),
		credentialProviderFunc(
			func(
				_ *http.Request,
			) (credential.Result, error) {
				credentialCalled = true

				return credential.Result{}, nil
			},
		),
		claimExpressionProviderFunc(
			func(
				_ *http.Request,
			) (claimexpression.Result, error) {
				return claimexpression.Result{
						Source: claimexpression.SourceQuery,
					},
					claimexpression.ErrMalformedExpression
			},
		),
		metrics.NoopAuthenticationRecorder{},
		logger,
	)
	if err != nil {
		t.Fatalf("create handler: %v", err)
	}

	recorder := httptest.NewRecorder()

	handler.ServeHTTP(
		recorder,
		httptest.NewRequest(
			http.MethodGet,
			Path,
			nil,
		),
	)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf(
			"unexpected status: got %d, want %d",
			recorder.Code,
			http.StatusBadRequest,
		)
	}

	if recorder.Body.Len() != 0 {
		t.Fatalf(
			"response body must be empty, got %q",
			recorder.Body.String(),
		)
	}

	if credentialCalled {
		t.Fatal(
			"credential provider must not be called after malformed claim expression",
		)
	}

	if authCalled {
		t.Fatal(
			"authenticator must not be called after malformed claim expression",
		)
	}
}

func TestHandler_MultipleClaimExpressionsReturns400(
	t *testing.T,
) {
	authCalled := false

	logger := slog.New(
		slog.NewTextHandler(
			io.Discard,
			nil,
		),
	)

	handler, err := NewHandler(
		authenticatorFunc(
			func(
				_ context.Context,
				_ authentication.Request,
			) (authentication.Identity, error) {
				authCalled = true

				return authentication.Identity{
					Subject: "camera-front",
				}, nil
			},
		),
		testCredentialProvider(),
		claimExpressionProviderFunc(
			func(
				_ *http.Request,
			) (claimexpression.Result, error) {
				return claimexpression.Result{},
					claimexpression.ErrMultipleExpressions
			},
		),
		metrics.NoopAuthenticationRecorder{},
		logger,
	)
	if err != nil {
		t.Fatalf("create handler: %v", err)
	}

	recorder := httptest.NewRecorder()

	handler.ServeHTTP(
		recorder,
		httptest.NewRequest(
			http.MethodGet,
			Path,
			nil,
		),
	)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf(
			"unexpected status: got %d, want %d",
			recorder.Code,
			http.StatusBadRequest,
		)
	}

	if authCalled {
		t.Fatal(
			"authenticator must not be called when multiple claim expressions are present",
		)
	}
}

func TestHandler_InvalidClaimExpressionProviderResultReturns500(
	t *testing.T,
) {
	logger := slog.New(
		slog.NewTextHandler(
			io.Discard,
			nil,
		),
	)

	handler, err := NewHandler(
		testAuthenticator(),
		testCredentialProvider(),
		claimExpressionProviderFunc(
			func(
				_ *http.Request,
			) (claimexpression.Result, error) {
				return claimexpression.Result{},
					claimexpression.ErrInvalidExtractorResult
			},
		),
		metrics.NoopAuthenticationRecorder{},
		logger,
	)
	if err != nil {
		t.Fatalf("create handler: %v", err)
	}

	recorder := httptest.NewRecorder()

	handler.ServeHTTP(
		recorder,
		httptest.NewRequest(
			http.MethodGet,
			Path,
			nil,
		),
	)

	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf(
			"unexpected status: got %d, want %d",
			recorder.Code,
			http.StatusInternalServerError,
		)
	}
}

func TestHandler_UnsatisfiedClaimExpressionReturns401(
	t *testing.T,
) {
	handler := newTestHandler(
		t,
		authenticatorFunc(
			func(
				_ context.Context,
				_ authentication.Request,
			) (authentication.Identity, error) {
				return authentication.Identity{},
					errors.Join(
						authentication.ErrAuthentication,
						validator.ErrClaimExpressionNotSatisfied,
					)
			},
		),
		testCredentialProvider(),
	)

	recorder := httptest.NewRecorder()

	handler.ServeHTTP(
		recorder,
		httptest.NewRequest(
			http.MethodGet,
			Path,
			nil,
		),
	)

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf(
			"unexpected status: got %d, want %d",
			recorder.Code,
			http.StatusUnauthorized,
		)
	}

	if recorder.Body.Len() != 0 {
		t.Fatalf(
			"response body must be empty, got %q",
			recorder.Body.String(),
		)
	}
}
