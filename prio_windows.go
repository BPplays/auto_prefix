//go:build windows
package main

import "os"
import "tailscale.com/atomicfile"

func setNiceness(n int) error {
	// no-op on Windows
	return nil
}


func atomicWrite(filename string, data []byte, perm os.FileMode) (error) {
	return atomicfile.WriteFile(filename, data, perm)
}
