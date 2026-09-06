// Package buildinfo provides build metadata injected at link time.
//
// The server and CLI binaries use the same metadata source so version
// information is reported consistently across all executable entry points.
package buildinfo

// Default values are used for local and development builds where build
// metadata is not supplied by the linker.
var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

// Info describes the metadata associated with a binary build.
type Info struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
	Date    string `json:"date"`
}

// Current returns the metadata associated with the current binary.
//
// Build pipelines may override the package variables at link time using
// -ldflags=-X. The returned value is a snapshot and cannot mutate the
// package-level build metadata.
func Current() Info {
	return Info{
		Version: version,
		Commit:  commit,
		Date:    date,
	}
}
