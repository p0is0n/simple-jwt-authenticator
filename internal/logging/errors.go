package logging

import "errors"

var (
	// errUnsupportedLevel indicates that a logging level is outside the
	// explicitly supported set.
	errUnsupportedLevel = errors.New(
		"unsupported logging level",
	)

	// errUnsupportedFormat indicates that a logging output format is outside
	// the explicitly supported set.
	errUnsupportedFormat = errors.New(
		"unsupported logging format",
	)
)
