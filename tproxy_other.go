//go:build !linux && !darwin
// +build !linux,!darwin

package tproxy

import (
	"fmt"
)

func newTProxy(byPassRoutes []string) (TProxy, error) {
	return nil, fmt.Errorf("unsupported yet")
}
