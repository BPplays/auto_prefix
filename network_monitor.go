package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"
)

// NetworkMonitor manages network monitoring and failover logic for DNS services
type NetworkMonitor struct {
	config       NetworkMonitorConfig
	logger       *slog.Logger
	ctx          context.Context
	cancelFunc   context.CancelFunc
	wg           sync.WaitGroup
	listener     net.Listener
	isActive     bool
	currentIndex int
}

// NewNetworkMonitor creates a new NetworkMonitor instance
func NewNetworkMonitor(config NetworkMonitorConfig, logger *slog.Logger) (*NetworkMonitor, error) {
	ctx, cancel := context.WithCancel(context.Background())
	
	// Validate the configuration
	if len(config.PriorityList) == 0 {
		return nil, fmt.Errorf("priority list cannot be empty")
	}
	
	if config.CheckInterval <= 0 {
		config.CheckInterval = time.Second // Default to 1 second if not specified
	}

	monitor := &NetworkMonitor{
		config:     config,
		logger:     logger,
		ctx:        ctx,
		cancelFunc: cancel,
		isActive:   false,
	}
	
	return monitor, nil
}

// Start begins the network monitoring process
func (n *NetworkMonitor) Start() error {
	n.logger.Info("Starting network monitor")
	
	if err := n.setupListener(); err != nil {
		return fmt.Errorf("failed to setup listener: %w", err)
	}
	
	n.isActive = true
	
	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		n.runMonitoringLoop()
	}()
	
	return nil
}

// Stop stops the network monitoring process
func (n *NetworkMonitor) Stop() error {
	n.logger.Info("Stopping network monitor")
	
	n.cancelFunc()
	n.isActive = false
	
	if n.listener != nil {
		n.listener.Close()
	}
	
	n.wg.Wait()
	
	return nil
}

// setupListener initializes the listener on the current host's address
func (n *NetworkMonitor) setupListener() error {
	hostIP, err := getLocalIPAddress(n.config.PriorityList)
	if err != nil {
		return fmt.Errorf("failed to determine local IP: %w", err)
	}
	
	n.logger.Info("Detected local IP address", "ip", hostIP)
	
	// Find the index of our own IP in the priority list
	index := -1
	for i, addr := range n.config.PriorityList {
		// Extract just the IP part from [addr]:port format
		parts := strings.Split(addr, "]") // For IPv6 addresses like [2001:db8::1]:20455
		if len(parts) != 2 {
			parts = strings.Split(addr, ":") // For IPv4 addresses or non-bracketed IPv6
		}
		
		var ipWithoutPort string
		if len(parts) >= 2 { // If we found : as a separator
			ipWithoutPort = parts[0]
		} else {
			ipWithoutPort = addr
		}
		
		// Remove brackets if they exist at start and end
		ipWithoutPort = strings.Trim(ipWithoutPort, "[]")
		
		if ipWithoutPort == hostIP {
			index = i
			n.currentIndex = i
			break
		}
	}
	
	if index == -1 {
		return fmt.Errorf("local IP %s not found in priority list", hostIP)
	}
	
	// Determine address to listen on
	listenAddr := ""
	if n.config.ListenOverride != "" {
		listenAddr = n.config.ListenOverride
	} else {
		// Listen on the port for this host's specific entry
		parts := strings.Split(n.config.PriorityList[index], "]") // For IPv6 addresses like [2001:db8::1]:20455
		if len(parts) == 2 {
			// IPv6 address
			listenAddr = parts[0] + "]:" + n.getPortFromAddress(n.config.PriorityList[index])
		} else {
			// IPv4 address or simple address
			parts = strings.Split(n.config.PriorityList[index], ":")
			if len(parts) == 2 {
				listenAddr = parts[0] + ":" + n.getPortFromAddress(n.config.PriorityList[index])
			} else {
				// Just an IP address provided, no port, so we'll need to handle this differently
				return fmt.Errorf("unexpected address format in priority list: %s", n.config.PriorityList[index])
			}
		}
	}
	
	n.logger.Info("Setting up listener", "address", listenAddr)
	
	// Create a TCP listener for health checks
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("failed to create TCP listener on %s: %w", listenAddr, err)
	}
	
	n.listener = listener
	
	// Start the listener goroutine to handle requests
	go func() {
		for {
			select {
			case <-n.ctx.Done():
				return
			default:
				conn, err := listener.Accept()
				if err != nil {
					// Log error but don't stop since connection error should be handled gracefully
					n.logger.Error("Failed to accept connection", "error", err)
					continue
				}
				conn.Close() // Close immediately as we're just validating connectivity
			}
		}
	}()
	
	return nil
}

// runMonitoringLoop continuously checks the health of higher priority hosts
func (n *NetworkMonitor) runMonitoringLoop() {
	n.logger.Info("Network monitoring loop started")

	for {
		select {
		case <-n.ctx.Done():
			n.logger.Info("Monitoring loop stopped")
			return
			
		default:
			if err := n.checkAndHandleFailover(); err != nil {
				n.logger.Error("Error during failover check", "error", err)
			}
			
			time.Sleep(n.config.CheckInterval)
		}
	}
}

// checkAndHandleFailover checks the health of higher priority hosts
func (n *NetworkMonitor) checkAndHandleFailover() error {
	// If we're at index 0, no higher priority hosts exist to check
	if n.currentIndex <= 0 {
		return nil
	}
	
	// Check priority items above us in the list
	for i := n.currentIndex - 1; i >= 0; i-- {
		addr := n.config.PriorityList[i]
		
		if err := n.isHostResponding(addr); err != nil {
			n.logger.Warn("Higher priority host not responding, triggering DNS synchronization", "address", addr)
			return n.triggerSync()
		}
	}
	
	return nil
}

// isHostResponding checks if a given host and port are reachable using ping or HTTP
func (n *NetworkMonitor) isHostResponding(addr string) error {
	// Try ICMP ping first for basic network connectivity check
	conn, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid address format: %s", addr)
	}
	
	ctx, cancel := context.WithTimeout(n.ctx, time.Second*2)
	defer cancel()
	
	dialer := &net.Dialer{}
	c, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(conn, port))
	if err != nil {
		return fmt.Errorf("host %s unreachable: %w", addr, err)
	}
	
	c.Close()
	n.logger.Debug("Host responding at", "address", addr)
	return nil
}

// triggerSync triggers DNS synchronization - this should run the DnsService sync processes for affected services
func (n *NetworkMonitor) triggerSync() error {
	// In a real implementation, we would:
	// 1. Iterate over Services that have DnsServices
	// 2. For each DnsService, trigger their sync process
	
	// Placeholder - in reality this would need reference to active services 
	n.logger.Info("Triggering DNS synchronization for failover event")
	
	// This is where we'd call into DnsServiceSync logic or signal the sync processes
	return nil
}

// getLocalIPAddress finds the local IP address matching one of the addresses in priority list
func getLocalIPAddress(priorityList []string) (string, error) {
	conn, err := net.Dial("udp", "8.8.8.8:53")
	if err != nil {
		return "", fmt.Errorf("failed to determine local IP: %w", err)
	}
	defer conn.Close()
	
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	
	// Try to find the exact match or close match in priority list
	for _, addr := range priorityList {
		parts := strings.Split(addr, "]") // For IPv6 addresses like [2001:db8::1]:20455
		var ipAddr string
		if len(parts) == 2 {
			// IPv6 with brackets 
			ipAddr = strings.Trim(parts[0], "[")
		} else {
			// Try to handle various formats
			parts = strings.Split(addr, ":") 
			if len(parts) >= 1 {
				ipAddr = parts[0]
			}
		}
		
		// Handle bracketed format for IPv6 addresses if they exist
		ipAddr = strings.Trim(ipAddr, "[]")
		
		if ipAddr == localAddr.IP.String() {
			return ipAddr, nil
		}
	}
	
	// If we don't match exactly, return the local address used for connectivity test
	return localAddr.IP.String(), nil
}

// getPortFromAddress extracts port from an [addr]:port or addr:port string
func (n *NetworkMonitor) getPortFromAddress(addr string) string {
	parts := strings.Split(addr, ":")
	if len(parts) >= 2 {
		// Handle bracketed IPv6 addresses like [2001:db8::1]:20455
		// Get last element which should be the port
		return parts[len(parts)-1]
	}
	
	return ""
}

// IsActive returns whether the network monitor is running
func (n *NetworkMonitor) IsActive() bool {
	return n.isActive
}