package http

// IsSafeHeaderValue reports whether value is safe for use as an HTTP response
// header value under the application's stricter authentication-data policy.
//
// All ASCII control bytes are rejected. Authentication-derived values do not
// require control characters, so accepting them would provide no useful
// behavior while increasing header-injection risk.
func IsSafeHeaderValue(
	value string,
) bool {
	for i := 0; i < len(value); i++ {
		b := value[i]

		if b < 0x20 || b == 0x7f {
			return false
		}
	}

	return true
}
