//go:build !windows

package main

import (
	"os"

	"github.com/google/renameio"
	"golang.org/x/sys/unix"
)

func setNiceness(n int) error {
	return unix.Setpriority(unix.PRIO_PROCESS, 0, n)
}

func atomicWrite(filename string, data []byte, perm os.FileMode) (error) {
	return renameio.WriteFile(filename, data, perm)
}

