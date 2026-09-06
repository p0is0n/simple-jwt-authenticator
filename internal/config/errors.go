package config

import "errors"

// ErrInvalidConfig is the sentinel for semantic configuration validation
// failures.
//
// Concrete server and CLI configuration packages wrap their validation
// failures with this sentinel so callers can classify configuration errors
// without depending on individual validation messages.
var ErrInvalidConfig = errors.New("invalid configuration")
