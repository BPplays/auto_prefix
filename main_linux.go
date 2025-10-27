//go:build linux
// +build linux

package main

import (
	"context"
	"fmt"
	"time"

	"github.com/coreos/go-systemd/v22/dbus"
)

func restartSystemdServices(ctx context.Context, config Service) ([]error) {
	var errs []error

	for _, targetSystemdUnit := range config.RestartSystemdServices {
		// Connect to systemd
		// Specifically this will look DBUS_SYSTEM_BUS_ADDRESS environment variable
		// For example: `unix:path=/run/dbus/system_bus_socket`
		systemdConnection, err := dbus.NewSystemConnectionContext(ctx)
		if err != nil {
			errs = append(errs, err)
		}
		defer systemdConnection.Close()

		listOfUnits, err := systemdConnection.ListUnitsContext(ctx)
		if err != nil {
			fmt.Printf("Failed to list units: %v\n", err)
		}

		found := false
		// targetUnit := dbus.UnitStatus{}
		for _, unit := range listOfUnits {
			if unit.Name == targetSystemdUnit {
				fmt.Printf("Found systemd unit %s\n", targetSystemdUnit)
				found = true
				// targetUnit = unit
				break
			}
		}
		if !found {
			fmt.Printf("Expected systemd unit %s not found\n", targetSystemdUnit)
		}

		completedRestartCh := make(chan string)
		jobID, err := systemdConnection.RestartUnitContext(
			ctx,
			targetSystemdUnit,
			restartMode,
			completedRestartCh,
		)

		if err != nil {
			errs = append(errs, err)
		}
		fmt.Printf("Restart job id: %d\n", jobID)

		// Wait for the restart to complete
		select {
		case <-completedRestartCh:
			fmt.Printf("Restart job completed for unit: %s\n", targetSystemdUnit)
		case <-time.After(time.Duration(config.RestartTimeout) * time.Second):
			fmt.Printf("Timed out waiting for restart job to complete for unit: %s\n", targetSystemdUnit)
		}

	}

	return errs
}
