package claimexpression

import (
	stdhttp "net/http"
)

// Extractor extracts a raw claim expression from one HTTP request source.
//
// A missing source is not an error. A present but malformed source is a
// terminal error.
type Extractor interface {
	Extract(
		request *stdhttp.Request,
	) (Extraction, error)
}
