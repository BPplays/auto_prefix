//go:build !windows
package main

import "golang.org/x/sys/unix"

func setNiceness(n int) error {
	return unix.Setpriority(unix.PRIO_PROCESS, 0, n)
}

