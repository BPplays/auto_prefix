package main

import (
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"strings"
)

const (
    zonesMasterDir = "/etc/bind/zones.master/"
    zonesDir       = "/etc/bind/zones/"
)

func main() {
    // Specify the network interface name
    interfaceName := "eth0" // Change this to your desired interface name

    // Get network interface
    iface, err := net.InterfaceByName(interfaceName)
    if err != nil {
        fmt.Println("Error:", err)
        return
    }

    // Get addresses for the interface
    addrs, err := iface.Addrs()
    if err != nil {
        fmt.Println("Error:", err)
        return
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

    // If no IPv6 prefix found, exit
    if ipv6Prefix == "" {
        fmt.Println("Error: No IPv6 prefix found")
        return
    }

    // Load files from zones.master directory, replace '#@ipv6_prefix@#' with the obtained prefix,
    // and save them to the zones directory
    err = loadAndSaveZoneFiles(ipv6Prefix)
    if err != nil {
        fmt.Println("Error:", err)
        return
    }

    fmt.Println("Zone files updated successfully!")
}

// Function to extract the IPv6 prefix from an IPNet object
func getIPv6Prefix(ipnet *net.IPNet) string {
    // Get the network prefix length
    prefixLen, _ := ipnet.Mask.Size()
    // Extract the network portion of the IP and return it as a string
    return ipnet.IP.Mask(ipnet.Mask).String() + "/" + fmt.Sprint(prefixLen)
}

// Function to load files from zones.master directory, replace '#@ipv6_prefix@#' with the obtained prefix,
// and save them to the zones directory
func loadAndSaveZoneFiles(ipv6Prefix string) error {
    // Open the zones.master directory
    files, err := ioutil.ReadDir(zonesMasterDir)
    if err != nil {
        return err
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

        // Replace '#@ipv6_prefix@#' with the obtained prefix
        replacedContent := strings.ReplaceAll(string(content), "#@ipv6_prefix@#", ipv6Prefix)

        // Save the modified content to the zones directory with the same filename
        outputFile := filepath.Join(zonesDir, file.Name())
        err = os.WriteFile(outputFile, []byte(replacedContent), 0644)
        if err != nil {
            return err
        }
    }

    return nil
}
