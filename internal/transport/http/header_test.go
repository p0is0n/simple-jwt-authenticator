package http

import "testing"

func TestIsSafeHeaderValue(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  bool
	}{
		{
			name:  "simple ASCII",
			value: "camera-front",
			want:  true,
		},
		{
			name:  "email",
			value: "front@example.com",
			want:  true,
		},
		{
			name:  "unicode",
			value: "камера",
			want:  true,
		},
		{
			name:  "empty",
			value: "",
			want:  true,
		},
		{
			name:  "CR",
			value: "camera\rfront",
			want:  false,
		},
		{
			name:  "LF",
			value: "camera\nfront",
			want:  false,
		},
		{
			name:  "tab",
			value: "camera\tfront",
			want:  false,
		},
		{
			name:  "NUL",
			value: "camera\x00front",
			want:  false,
		},
		{
			name:  "DEL",
			value: "camera\x7ffront",
			want:  false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := IsSafeHeaderValue(
				tc.value,
			)

			if got != tc.want {
				t.Fatalf(
					"IsSafeHeaderValue(%q) = %v, want %v",
					tc.value,
					got,
					tc.want,
				)
			}
		})
	}
}
