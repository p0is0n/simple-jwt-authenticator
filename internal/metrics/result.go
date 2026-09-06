package metrics

// Result is a bounded operation result value suitable for use as a metric
// label.
//
// Result describes only the normalized outcome of an observed operation.
// It must never contain arbitrary error messages, transport-specific status
// values, or other unbounded input.
type Result string

const (
	// ResultSuccess means the observed operation completed successfully.
	ResultSuccess Result = "success"

	// ResultFailure means the observed operation completed unsuccessfully.
	ResultFailure Result = "failure"
)
