package main

import (
	"fmt"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
    zonesMasterDir = "/etc/bind/zones.master/"
    zonesDir       = "/etc/bind/zones/"
    configFile     = "/etc/bind/.ipv6_prefix"
	interfaceName = "ens33"
    checkInterval  = 50 * time.Second
)

func main() {
    var lastIPv6Prefix string = ""

    // Start an infinite loop
    for {
        // Get the current IPv6 prefix
        currentIPv6Prefix, err := getCurrentIPv6Prefix()
        if err != nil {
            fmt.Println("Error:", err)
            return
        }

        // If the current prefix is different from the last one, update the zone files and reload services
        if currentIPv6Prefix != lastIPv6Prefix {
			fmt.Printf("prefix: %v\n", currentIPv6Prefix)

            err := loadAndSaveZoneFiles(currentIPv6Prefix)
            if err != nil {
                fmt.Println("Error:", err)
                return
            }

            err = reloadServices()
            if err != nil {
                fmt.Println("Error:", err)
                return
            }

            lastIPv6Prefix = currentIPv6Prefix
            fmt.Println("Zone files updated successfully.")
        }

        // Sleep for the specified interval before checking again
        time.Sleep(checkInterval)
    }
}

// Function to get the current IPv6 prefix
func getCurrentIPv6Prefix() (string, error) {
    // Specify the network interface name
    // interfaceName := "eth0" // Change this to your desired interface name

    // Get network interface
    iface, err := net.InterfaceByName(interfaceName)
    if err != nil {
        return "", err
    }

    // Get addresses for the interface
    addrs, err := iface.Addrs()
    if err != nil {
        return "", err
    }

    // Initialize variables to store the IPv6 prefix
    var ipv6Prefix string

    // Iterate over addresses to find the IPv6 prefix
    for _, addr := range addrs {
        // Check if it's an IPv6 address and not temporary
        if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() == nil && !ipnet.IP.IsLinkLocalUnicast() {
            ipv6Prefix = getIPv6Prefix(ipnet)
            break
        }
    }

    // If no IPv6 prefix found, return an error
    if ipv6Prefix == "" {
        return "", fmt.Errorf("no IPv6 prefix found")
    }

    return ipv6Prefix, nil
}

// Function to extract the IPv6 prefix from an IPNet object and pad it to /64 length
func getIPv6Prefix(ipnet *net.IPNet) string {
    // Get the network portion of the IP
    network := ipnet.IP.Mask(ipnet.Mask)

    // Convert the network portion to a string representation
    ipv6Prefix := network.String()

    // If the prefix length is less than 64, pad it with zeros
    if len(ipv6Prefix) < len("xxxx:xxxx:xxxx:xxxx") {
        ipv6Prefix = strings.TrimSuffix(ipv6Prefix, ":") // Remove trailing ":"
        padding := "0000:0000:0000:0000:0000:0000:0000:"   // Pad with zeros
        ipv6Prefix += padding[len(ipv6Prefix):]          // Add padding to reach /64 length
    }

    // Ensure it ends with a single colon
    if !strings.HasSuffix(ipv6Prefix, ":") {
        ipv6Prefix += ":"
    }

    // Remove one colon until the character before the last is not a colon
    for strings.HasSuffix(ipv6Prefix, "::") {
        ipv6Prefix = strings.TrimSuffix(ipv6Prefix, ":")
    }

    return ipv6Prefix
}

// Function to load files from zones.master directory, replace '#@ipv6_prefix@#::@' with the obtained prefix,
// and save them to the zones directory
func loadAndSaveZoneFiles(ipv6Prefix string) error {
    // // Open the zones.master directory
    // files, err := ioutil.ReadDir(zonesMasterDir)
    // if err != nil {
    //     return err
    // }

	entries, err := os.ReadDir(zonesMasterDir)
    if err != nil {
        return err
    }
	files := make([]fs.FileInfo, 0, len(entries))
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			return err
		}
		files = append(files, info)
	}

    // Iterate over files in the zones.master directory
    for _, file := range files {
        // Skip directories
        if file.IsDir() {
            continue
        }

        // Read the contents of the file
        filePath := filepath.Join(zonesMasterDir, file.Name())
        content, err := os.ReadFile(filePath)
        if err != nil {
            return err
        }

        // Replace '#@ipv6_prefix@#::@' with the obtained prefix
        replacedContent := strings.ReplaceAll(string(content), "#@ipv6_prefix@#::@", ipv6Prefix)

        // Save the modified content to the zones directory with the same filename
        outputFile := filepath.Join(zonesDir, file.Name())
        err = os.WriteFile(outputFile, []byte(replacedContent), 0644)
        if err != nil {
            return err
        }
    }

    return nil
}

// Function to reload bind9.service and named.service
func reloadServices() error {
    // Reload bind9.service
    err := exec.Command("systemctl", "reload", "bind9.service").Run()
    if err != nil {
        return err
    }

    // Reload named.service
    err = exec.Command("systemctl", "reload", "named.service").Run()
    if err != nil {
        return err
    }

    return nil
}
