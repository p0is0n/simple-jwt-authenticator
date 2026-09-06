package validator

import (
	"context"
	"errors"
	"testing"
	"time"

	"simple-jwt-authenticator/internal/token"
	"simple-jwt-authenticator/internal/token/claim"
)

func TestExpiration(t *testing.T) {
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

	tests := []struct {
		name      string
		expiresAt *time.Time
		skew      time.Duration
		wantErr   error
	}{
		{
			name:    "missing expiration",
			wantErr: ErrMissingClaim,
		},
		{
			name:      "future expiration",
			expiresAt: timePointer(now.Add(time.Hour)),
			skew:      30 * time.Second,
		},
		{
			name:      "expiration at current time within skew",
			expiresAt: timePointer(now),
			skew:      30 * time.Second,
		},
		{
			name:      "expiration within skew",
			expiresAt: timePointer(now.Add(-29 * time.Second)),
			skew:      30 * time.Second,
		},
		{
			name:      "expiration at skew boundary",
			expiresAt: timePointer(now.Add(-30 * time.Second)),
			skew:      30 * time.Second,
			wantErr:   ErrExpired,
		},
		{
			name:      "expiration beyond skew",
			expiresAt: timePointer(now.Add(-31 * time.Second)),
			skew:      30 * time.Second,
			wantErr:   ErrExpired,
		},
		{
			name:      "expiration at current time without skew",
			expiresAt: timePointer(now),
			wantErr:   ErrExpired,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			expiration := Expiration{
				Now: func() time.Time {
					return now
				},
				Skew: test.skew,
			}

			err := expiration.Validate(
				context.Background(),
				Request{
					Token: token.Token{
						Claims: claim.Claims{
							ExpiresAt: test.expiresAt,
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

func timePointer(value time.Time) *time.Time {
	return &value
}
