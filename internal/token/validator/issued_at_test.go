package validator

import (
	"context"
	"errors"
	"testing"
	"time"

	"simple-jwt-authenticator/internal/token"
	"simple-jwt-authenticator/internal/token/claim"
)

func TestIssuedAt(t *testing.T) {
	now := time.Date(
		2026,
		time.January,
		1,
		12,
		0,
		0,
		0,
		time.UTC,
	)

	const skew = 30 * time.Second

	tests := []struct {
		name     string
		issuedAt *time.Time
		wantErr  error
	}{
		{
			name: "absent",
		},
		{
			name:     "in the past",
			issuedAt: timePointer(now.Add(-time.Hour)),
		},
		{
			name:     "at current time",
			issuedAt: timePointer(now),
		},
		{
			name:     "within future skew",
			issuedAt: timePointer(now.Add(29 * time.Second)),
		},
		{
			name:     "at future skew boundary",
			issuedAt: timePointer(now.Add(skew)),
		},
		{
			name:     "beyond future skew",
			issuedAt: timePointer(now.Add(31 * time.Second)),
			wantErr:  ErrIssuedAtFuture,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			issuedAt := IssuedAt{
				Now: func() time.Time {
					return now
				},
				Skew: skew,
			}

			err := issuedAt.Validate(
				context.Background(),
				Request{
					Token: token.Token{
						Claims: claim.Claims{
							IssuedAt: test.issuedAt,
						},
					},
				},
			)

			if !errors.Is(err, test.wantErr) {
				t.Fatalf(
					"Validate() error = %v, want %v",
					err,
					test.wantErr,
				)
			}
		})
	}
}
