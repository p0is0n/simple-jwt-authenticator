package validator

import (
	"context"
	"errors"
	"testing"
	"time"

	"simple-jwt-authenticator/internal/token"
	"simple-jwt-authenticator/internal/token/claim"
)

func TestNotBefore(t *testing.T) {
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
		name      string
		notBefore *time.Time
		wantErr   error
	}{
		{
			name: "absent",
		},
		{
			name:      "in the past",
			notBefore: timePointer(now.Add(-time.Hour)),
		},
		{
			name:      "at current time",
			notBefore: timePointer(now),
		},
		{
			name:      "within future skew",
			notBefore: timePointer(now.Add(29 * time.Second)),
		},
		{
			name:      "at future skew boundary",
			notBefore: timePointer(now.Add(skew)),
		},
		{
			name:      "beyond future skew",
			notBefore: timePointer(now.Add(31 * time.Second)),
			wantErr:   ErrNotActive,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			notBefore := NotBefore{
				Now: func() time.Time {
					return now
				},
				Skew: skew,
			}

			err := notBefore.Validate(
				context.Background(),
				Request{
					Token: token.Token{
						Claims: claim.Claims{
							NotBefore: test.notBefore,
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
