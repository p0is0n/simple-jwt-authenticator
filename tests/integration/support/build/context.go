//go:build integration

// Package build provides integration-test infrastructure for resolving the
// project build context.
package build

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Root resolves the project root directory by walking up from the current
// working directory until a regular go.mod file is found.
//
// This is necessary because go test runs each package with that package's
// directory as its working directory.
func Root() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf(
			"get working directory: %w",
			err,
		)
	}

	for {
		goModPath := filepath.Join(
			dir,
			"go.mod",
		)

		info, err := os.Stat(goModPath)

		switch {
		case err == nil && info.Mode().IsRegular():
			return dir, nil

		case err == nil:
			// A non-regular object named go.mod does not identify a Go
			// module root. Continue walking upward.

		case !errors.Is(err, os.ErrNotExist):
			return "", fmt.Errorf(
				"stat %q: %w",
				goModPath,
				err,
			)
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf(
				"could not find project root from current working directory: regular go.mod not found",
			)
		}

		dir = parent
	}
}
