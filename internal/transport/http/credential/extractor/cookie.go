package extractor

import (
	"errors"
	"fmt"
	"strings"

	stdhttp "net/http"

	"simple-jwt-authenticator/internal/authentication"
	"simple-jwt-authenticator/internal/token"
	"simple-jwt-authenticator/internal/transport/http/credential"
)

// Cookie extracts a credential from a configured cookie.
//
// Cookie extraction is configuration-controlled. An empty cookie name is
// rejected at construction because it would make the extractor invalid.
type Cookie struct {
	name string
}

// NewCookie constructs a Cookie extractor.
func NewCookie(name string) (Cookie, error) {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return Cookie{}, fmt.Errorf(
			"create cookie extractor: %w",
			errEmptyCookieName,
		)
	}

	return Cookie{
		name: trimmed,
	}, nil
}

// Extract implements credential.Extractor.
func (c Cookie) Extract(
	request *stdhttp.Request,
) (credential.Result, error) {
	cookies := request.CookiesNamed(c.name)
	if len(cookies) == 0 {
		return notApplicableCookie(), nil
	}

	if len(cookies) > 1 {
		return credential.Result{
				Source: credential.SourceCookie,
			},
			errors.Join(
				credential.ErrMalformedCredential,
			)
	}

	cookie := cookies[0]
	value := strings.TrimSpace(cookie.Value)
	if value == "" {
		return credential.Result{
				Source: credential.SourceCookie,
			},
			errors.Join(
				credential.ErrMalformedCredential,
				errEmptyCookieValue,
			)
	}

	return extractedCookie(value), nil
}

// notApplicableCookie returns a not-applicable result for the cookie source.
func notApplicableCookie() credential.Result {
	return credential.Result{
		Source:        credential.SourceCookie,
		NotApplicable: true,
	}
}

// extractedCookie returns an extracted result for the cookie source.
func extractedCookie(value string) credential.Result {
	return credential.Result{
		Credential: authentication.Credential{
			Value: token.Value(value),
		},
		Source:    credential.SourceCookie,
		Extracted: true,
	}
}

var (
	errEmptyCookieName  = errors.New("cookie name must be non-empty")
	errEmptyCookieValue = errors.New("cookie credential is empty")
)
