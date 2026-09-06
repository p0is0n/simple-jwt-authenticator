package credential

import (
	stdhttp "net/http"
)

// Extractor extracts a credential from an HTTP request. It distinguishes
// "not applicable" (no error, NotApplicable=true) from a terminal extraction
// error (returned error), as required for ordered fallback behavior.
//
// The interface lives in the credential package because the Provider
// consumes it; concrete implementations live in the extractor subpackage.
type Extractor interface {
	Extract(
		request *stdhttp.Request,
	) (Result, error)
}
