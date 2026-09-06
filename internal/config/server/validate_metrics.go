package server

import (
	"fmt"
	pathpkg "path"
	"strings"
)

const (
	reservedHealthPath = "/healthz"
	reservedNginxPath  = "/auth/nginx"
)

func validateMetrics(metrics Metrics) error {
	if !metrics.Enabled {
		return nil
	}

	return validateMetricsPath(metrics.Path)
}

func validateMetricsPath(value string) error {
	if value == "" {
		return fmt.Errorf(
			"metrics.path must be non-empty",
		)
	}

	if strings.TrimSpace(value) != value {
		return fmt.Errorf(
			"metrics.path must not contain leading or trailing whitespace",
		)
	}

	if !strings.HasPrefix(value, "/") {
		return fmt.Errorf(
			"metrics.path must start with %q, got %q",
			"/",
			value,
		)
	}

	if value == "/" {
		return fmt.Errorf(
			"metrics.path must identify a concrete endpoint, got root path",
		)
	}

	if strings.ContainsAny(
		value,
		" \t\r\n?#{}",
	) {
		return fmt.Errorf(
			"metrics.path must be a static URL path, got %q",
			value,
		)
	}

	if cleaned := pathpkg.Clean(value); cleaned != value {
		return fmt.Errorf(
			"metrics.path must be canonical, got %q, canonical form is %q",
			value,
			cleaned,
		)
	}

	switch value {
	case reservedHealthPath,
		reservedNginxPath:
		return fmt.Errorf(
			"metrics.path must not collide with reserved route %q",
			value,
		)
	}

	return nil
}
