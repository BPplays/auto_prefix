//go:build !linux
// +build !linux

package main

import (
	"context"
	"errors"
)

func restartSystemdServices(ctx context.Context, config Service) ([]error) {
	var errs []error
	errs = append(errs, errors.ErrUnsupported)
	return errs
}
