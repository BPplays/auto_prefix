//go:build windows
package main

func setNiceness(n int) error {
	// no-op on Windows
	return nil
}
