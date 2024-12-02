package main

import (
	"fmt"
	"io/fs"
	"log"
	"math"
	"math/rand"
	"net"
	"os"
	// "os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/seancfoley/ipaddress-go/ipaddr"
	"gopkg.in/yaml.v3"
	"github.com/coreos/go-systemd/v22/dbus"
	"context"
)

const (
	// zonesMasterDir = "/etc/bind/zones.master/"
	// zonesDir       = "/etc/bind/zones/"
	// named_master = "/etc/bind/named.conf.master"
	// named = "/etc/bind/named.conf"
	// dnsmasq_master = "/etc/dnsmasq.conf.master"
	// dnsmasq = "/etc/dnsmasq.conf"
	// configFile     = "/etc/bind/.ipv6_prefix"
	configDir = "/etc/auto_prefix/config.d"
	prefix_len = 60
	prefix_full_subnet_len = 64
	restartMode       = "replace" // or "force-reload"
	if_file = "/etc/main_interface"
	// interfaceName = "ens33"
	checkInterval  = 5 * time.Second

)

var interfaceName = ""
var ut string = ""

type FileMapping struct {
	From string `yaml:"from"`
	To   string `yaml:"to"`
}

type Config struct {
	Name                 string        `yaml:"name"`
	Files                []FileMapping `yaml:"files"`
	Folders              []FileMapping `yaml:"folders"`
	RestartCmds          []string      `yaml:"restart_cmds"`
	RestartSystemdServices []string    `yaml:"restart_systemd_services"`
	RestartTimeHost      float64           `yaml:"restart_time_host"`
	RestartTimeout      int           `yaml:"restart_timeout"`
}


func get_interfaceName() error {
	content, err := os.ReadFile(if_file)
	if err != nil {
		return err
	}

	interfaceName = string(content)

	return nil
}

// func loadAndSaveNamedConf(ipv6Prefix net.IP) error {
// 	reverseDNS := IPv6PrefixToReverseDNS(ipv6Prefix, 64, 0) // todo make use prefix len
// 	fmt.Printf("setting reverse dns to: %v\n", reverseDNS)
//
//
//
// 	content, err := os.ReadFile(named_master)
// 	if err != nil {
// 		return err
// 	}
//
// 	replacedContent := strings.ReplaceAll(string(content), "@::#@ipv6_revdns_prefix@#", reverseDNS)
//
// 	err = os.WriteFile(named, []byte(replacedContent), 0644)
// 	if err != nil {
// 		return err
// 	}
//
// 	return nil
// }
//
// func loadAndSaveDnsmasqConf(ipv6Prefix net.IP, ipv6PrefixStr string) error {
//
// 	fmt.Println("loading dnsmasq")
//
// 	content, err := os.ReadFile(dnsmasq_master)
// 	if err != nil {
// 		return err
// 	}
//
// 	// Replace '#@ipv6_prefix@#::@' with the obtained prefix
// 	// replacedContent := strings.ReplaceAll(string(content), "#@ipv6_prefix@#::@", ipv6Prefix)
// 	reverseDNS := IPv6PrefixToReverseDNS(ipv6Prefix, 64, 0) // todo make use prefix len
// 	replacedContent := replace_vars(&content, &ipv6PrefixStr, &reverseDNS)
//
// 	err = os.WriteFile(dnsmasq, []byte(replacedContent), 0644)
// 	if err != nil {
// 		return err
// 	}
//
// 	fmt.Println("saving dnsmasq")
//
// 	return nil
// }

// SetBit sets or clears a specific bit in the IP address based on the value of setToOne.
func SetBit(ip_bytes []byte, bit int, setToOne bool) net.IP {
	// ip_bytes = ip_bytes.To16() // Convert to 16-byte IPv6 format to handle both IPv4 and IPv6
	if ip_bytes == nil {
		return nil // Return nil if the IP address is invalid
	}

	byteIndex := bit / 8  // Calculate the byte position
	bitIndex := bit % 8   // Calculate the bit position within that byte

	if setToOne {
		ip_bytes[byteIndex] |= 1 << (7 - bitIndex) // Set the bit to 1
	} else {
		ip_bytes[byteIndex] &^= 1 << (7 - bitIndex) // Clear the bit (set to 0)
	}

	return ip_bytes
}

func set_ipaddr_bits(addr net.IP, subnet_uint64 uint64, start int, end int) net.IP {
	var addr_output net.IP

	// if end - 64 > start {
	// 	start = end - 64
	// }


	var addr_bytes []byte
	addr_bytes = addr.To16()
	fmt.Println("addr_bytes:", addr_bytes)

	fmt.Printf("set bits: start: %v, end: %v\n", start, end)
	for i := end; i >= start; i-- {
		if i == start {
			break
		}

		subnet_bit_pos := (-i) + end
		bit := (int(subnet_uint64) >> subnet_bit_pos) & 1
		addr_output = SetBit(addr_bytes, i, bit == 1)
		// fmt.Printf("Bit %d: %d\n", i, bit)
	}

	return addr_output
}

func replaceIPv6Prefix(content, interfaceName string) string {
	// Define the regular expression pattern
	pattern := `#@ipv6_prefix_([0-9a-fA-F]+)@#`
	re := regexp.MustCompile(pattern)
	fmt.Println("starting regex conv")

	// Find all matches in the content
	matches := re.FindAllStringSubmatch(content, -1)
	var vlan uint64
	var err error
	// Replace each match
	for _, match := range matches {
		fullMatch := match[0]
		vlanStr := match[1] // Extract the VLAN number
		vlan, err = strconv.ParseUint(vlanStr, 16, 64)
		if err != nil {
			// Handle conversion error
			fmt.Println("Error converting VLAN number:", err)
			continue
		}
		// Call get_prefix function with interfaceName and vlan
		replacement, _, err := get_prefix(interfaceName, vlan)
		if err != nil {
			log.Fatalln(err)
		}
		content = strings.ReplaceAll(content, fullMatch, replacement)
	}

	return content
}

// loadConfigs loads and parses all YAML files from a directory
func loadConfigs(dir string) ([]Config, error) {
	var configs []Config

	// Walk through the directory
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("error walking directory: %w", err)
		}

		// Only process regular files with .yaml or .yml extensions
		if !d.IsDir() && (filepath.Ext(path) == ".yaml" || filepath.Ext(path) == ".yml") {
			fileConfigs, err := parseConfigFile(path)
			if err != nil {
				log.Printf("Error parsing file %s: %v", path, err)
				return nil // Skip invalid files but continue processing others
			}
			configs = append(configs, fileConfigs...)
		}
		return nil
	})

	return configs, err
}

// parseConfigFile parses a single YAML file into a slice of Config objects
func parseConfigFile(filePath string) ([]Config, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("error opening file %s: %w", filePath, err)
	}
	defer file.Close()

	var configs []Config
	decoder := yaml.NewDecoder(file)
	if err := decoder.Decode(&configs); err != nil {
		return nil, fmt.Errorf("error decoding YAML file %s: %w", filePath, err)
	}

	return configs, nil
}


func main() {
	var lastIPv6Prefix string = ""

	var sleep_sec float64
	var sleep_dur time.Duration
	var sleep_ut int64


	fmt.Println("starting program")
	get_interfaceName()
	fmt.Println("using if:", interfaceName)


	// Load all configs from the directory
	configs, err := loadConfigs(configDir)
	if err != nil {
		log.Fatalf("Error loading configs: %v", err)
	}

	// Print the parsed configurations
	for _, config := range configs {
		fmt.Printf("Name: %s\n", config.Name)
		fmt.Printf("Files: %v\n", config.Files)
		fmt.Printf("Restart Commands: %v\n", config.RestartCmds)
		fmt.Printf("Systemd Services: %v\n", config.RestartSystemdServices)
		fmt.Printf("Restart Time Host: %v\n\n", config.RestartTimeHost)
		fmt.Printf("Restart timeout: %v\n\n", config.RestartTimeout)
	}

	// Start an infinite loop
	for {
		sleep_sec = ((math.Mod(float64(time.Now().Unix()), checkInterval.Seconds())) - checkInterval.Seconds() ) * -1

		// if sleep_sec >= checkInterval.Seconds() {
		// 	sleep_sec = 0
		// }

		sleep_dur = time.Duration(sleep_sec * float64(time.Second))
		sleep_ut = time.Now().Add(sleep_dur).Unix()


		time.Sleep(sleep_dur)


		ut = get_dns_ut()

		// Get the current IPv6 prefix
		currentIPv6Prefix_str, currentIPv6Prefix, err := get_prefix(interfaceName, 0)
		if err != nil {
			fmt.Println("Error:", err)
			return
		}

		// If the current prefix is different from the last one, update the zone files and reload services
		if currentIPv6Prefix_str != lastIPv6Prefix {
			fmt.Print("\n\n\n\n")
			fmt.Println(strings.Repeat("=", 50))
			fmt.Println(strings.Repeat("=", 50))
			fmt.Print("\n")

			fmt.Printf("slept until: %v\n\n", sleep_ut)
			fmt.Printf("prefix: %v\n", currentIPv6Prefix)


			// err := loadAndSaveZoneFiles(currentIPv6Prefix, currentIPv6Prefix_str)
			// if err != nil {
			// 	fmt.Println("Error:", err)
			// 	return
			// }
			// err = loadAndSaveNamedConf(currentIPv6Prefix)
			// if err != nil {
			// 	fmt.Println("Error:", err)
			// 	return
			// }
			//
			// err = loadAndSaveDnsmasqConf(currentIPv6Prefix, currentIPv6Prefix_str)
			// if err != nil {
			// 	fmt.Println("Error:", err)
			// 	return
			// }

			for _, config := range configs {
				err := repSaveFile(config, currentIPv6Prefix_str, currentIPv6Prefix)
				if err != nil {
					fmt.Println("Error:", err)
					// return
				}

				restart_services(config)
			}

			// err = restart_dns()
			// if err != nil {
			// 	fmt.Println("Error:", err)
			// 	return
			// }

			lastIPv6Prefix = currentIPv6Prefix_str
			fmt.Printf("Files updated successfully.\n\n")


			fmt.Println(strings.Repeat("=", 50))
			fmt.Println(strings.Repeat("=", 50))
		}

		// Sleep for the specified interval before checking again
		// time.Sleep(checkInterval)
	}
}

func get_dns_date8() (string) {
	// Get the current date
	currentDate := time.Now()

	// Format the date as YYYYMMDD
	formattedDate := currentDate.Format("20060102")

	// Trim or pad the date to 8 characters
	if len(formattedDate) > 8 {
		formattedDate = formattedDate[:8]
	} else {
		formattedDate = fmt.Sprintf("%-8s", formattedDate)
	}

	return formattedDate
}


func get_dns_ut() (string) {
	// Get the current date
	currentDate := time.Now()

	ut := fmt.Sprint(currentDate.Unix())

	// Trim or pad the date to 10 characters
	if len(ut) > 10 {
		ut = ut[:10]
	} else {
		ut = fmt.Sprintf("%-10s", ut)
	}

	return ut
}

func replace_vars(content *[]byte, prefix *string, rev_dns *string) (string) {
	if prefix == nil {
		log.Fatal("prefix is nil")
	}
	fmt.Println("rep vars")
	replacedContent := replaceIPv6Prefix(string(*content), interfaceName)
	fmt.Println("repped vars dyn vlan")

	replacedContent = strings.ReplaceAll(replacedContent, "#@ipv6_prefix@#", *prefix)
	fmt.Println("repped vars main")
	replacedContent = strings.ReplaceAll(replacedContent, "#@ut_10@#", ut)
	fmt.Println("repped vars ut10")
	replacedContent = strings.ReplaceAll(replacedContent, "@::#@ipv6_revdns_prefix@#", *rev_dns)
	fmt.Println("repped vars reverse")

	return replacedContent
}

// Function to load files from zones.master directory, replace '#@ipv6_prefix@#::@' with the obtained prefix,
// and save them to the zones directory
// func loadAndSaveZoneFiles(ipv6Prefix net.IP, ipv6PrefixStr string) error {
// 	// // Open the zones.master directory
// 	// files, err := ioutil.ReadDir(zonesMasterDir)
// 	// if err != nil {
// 	//     return err
// 	// }
//
// 	entries, err := os.ReadDir(zonesMasterDir)
// 	if err != nil {
// 		return err
// 	}
// 	files := make([]fs.FileInfo, 0, len(entries))
// 	for _, entry := range entries {
// 		info, err := entry.Info()
// 		if err != nil {
// 			return err
// 		}
// 		files = append(files, info)
// 	}
//
// 	// Iterate over files in the zones.master directory
// 	for _, file := range files {
// 		// Skip directories
// 		if file.IsDir() {
// 			continue
// 		}
//
// 		// Read the contents of the file
// 		filePath := filepath.Join(zonesMasterDir, file.Name())
// 		content, err := os.ReadFile(filePath)
// 		if err != nil {
// 			return err
// 		}
//
// 		// Replace '#@ipv6_prefix@#::@' with the obtained prefix
// 		// replacedContent := strings.ReplaceAll(string(content), "#@ipv6_prefix@#::@", ipv6Prefix)
// 		reverseDNS := IPv6PrefixToReverseDNS(ipv6Prefix, 64, 0) // todo make use prefix len
// 		replacedContent := replace_vars(&content, &ipv6PrefixStr, &reverseDNS)
//
// 		// Save the modified content to the zones directory with the same filename
// 		outputFile := filepath.Join(zonesDir, file.Name())
// 		err = os.WriteFile(outputFile, []byte(replacedContent), 0644)
// 		if err != nil {
// 			return err
// 		}
// 	}
//
// 	return nil
// }

// // Function to reload bind9.service and named.service
// func reloadServices() error {
//     // Reload bind9.service
//     err := exec.Command("systemctl", "reload", "bind9.service").Run()
//     if err != nil {
//         return err
//     }

//     // Reload named.service
//     err = exec.Command("systemctl", "reload", "named.service").Run()
//     if err != nil {
//         return err
//     }

//     return nil
// }

func restart_services(config Config) {

	if config.RestartTimeout <= 0 {
		config.RestartTimeout = 10
	}

	dev_name := ""
	wait_time := 0.0
	wait_time_mul := config.RestartTimeHost
	wait_time_def := rand.Float64() * 15

	hostname, err := os.Hostname()
	if err != nil {
		fmt.Println("cant get hostname. Error:", err)
		wait_time = wait_time_def
	} else {
		spl := strings.Split(hostname, ".")
		dev_name = spl[0]

		numericStr := ""
		for _, char := range dev_name {
			if (char >= '0' && char <= '9') || char == '.' {
				numericStr += string(char)
			}
		}

		// Convert string to float64
		num, err := strconv.ParseFloat(numericStr, 64)
		if err != nil {
			fmt.Println("Error converting string to float64:", err)
			wait_time = wait_time_def
		} else {
			wait_time = (num-1) * wait_time_mul
		}
	}

	time.Sleep(time.Duration(wait_time * float64(time.Second)))

	for _, targetSystemdUnit := range config.RestartSystemdServices {
		ctx := context.Background()
		// Connect to systemd
		// Specifically this will look DBUS_SYSTEM_BUS_ADDRESS environment variable
		// For example: `unix:path=/run/dbus/system_bus_socket`
		systemdConnection, err := dbus.NewSystemConnectionContext(ctx)
		if err != nil {
			fmt.Printf("Failed to connect to systemd: %v\n", err)
			panic(err)
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
			fmt.Printf("Failed to restart unit: %v\n", err)
			panic(err)
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
}

func repSaveFile(config Config, ipv6PrefixStr string, ipv6Prefix net.IP) (error) {

	for _, folder := range config.Folders {

		entries, err := os.ReadDir(folder.From)
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
			filePath := filepath.Join(folder.From, file.Name())
			content, err := os.ReadFile(filePath)
			if err != nil {
				return err
			}

			// Replace '#@ipv6_prefix@#::@' with the obtained prefix
			// replacedContent := strings.ReplaceAll(string(content), "#@ipv6_prefix@#::@", ipv6Prefix)
			reverseDNS := IPv6PrefixToReverseDNS(ipv6Prefix, 64, 0) // todo make use prefix len
			fmt.Printf("repping: %v, file: %v", config.Name, file.Name())
			replacedContent := replace_vars(&content, &ipv6PrefixStr, &reverseDNS)

			// Save the modified content to the zones directory with the same filename
			outputFile := filepath.Join(folder.To, file.Name())
			err = os.WriteFile(outputFile, []byte(replacedContent), 0644)
			if err != nil {
				return err
			}
		}
	}

	for _, file := range config.Files {
		fmt.Printf("reading: %v\n", file.From)
		content, err := os.ReadFile(file.From)
		if err != nil {
			return err
		}

		// Replace '#@ipv6_prefix@#::@' with the obtained prefix
		// replacedContent := strings.ReplaceAll(string(content), "#@ipv6_prefix@#::@", ipv6Prefix)
		reverseDNS := IPv6PrefixToReverseDNS(ipv6Prefix, 64, 0) // todo make use prefix len
		replacedContent := replace_vars(&content, &ipv6PrefixStr, &reverseDNS)

		err = os.WriteFile(file.To, []byte(replacedContent), 0644)
		if err != nil {
			return err
		}

		fmt.Printf("saving: %v\n", file.To)

		return nil

	}

	return nil
}

// Function to get the current IPv6 prefix
func get_prefix(interfaceName string, vlan uint64) (string, net.IP, error) {
	// Specify the network interface name
	// interfaceName := "eth0" // Change this to your desired interface name

	var netip net.IP
	// Get network interface
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return "", netip, err
	}

	// Get addresses for the interface
	addrs, err := iface.Addrs()
	if err != nil {
		return "", netip, err
	}

	// Initialize variables to store the IPv6 prefix
	var ipv6Prefix net.IP
	var ipv6PrefixStr string

	// Iterate over addresses to find the IPv6 prefix
	var ip net.IP
	for _, addr := range addrs {
		// Check if it's an IPv6 address and not temporary
		ip, err = addrToIP(addr)
		if err != nil {
			continue
		}
		if isValidIPAddress(ip) {
			ipnet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			// (*ipnet).Mask = net.CIDRMask(prefix_len, 128)
			ipv6Prefix = set_ipaddr_bits(ipnet.IP.Mask(net.CIDRMask(prefix_len, 128)), vlan, prefix_len, prefix_full_subnet_len)
			// ipv6Prefix = get_prefix_padded(ipnet, vlan)
			break
		}
	}

	ipv6PrefixStr = ipv6Prefix.Mask(net.CIDRMask(prefix_full_subnet_len, 128)).String()

	// if strings.HasSuffix(ipv6PrefixStr, "::") {
	// 	ipv6PrefixStr = strings.TrimSuffix(ipv6PrefixStr, "::") + ":"
	// }

	ipv6PrefixStr = strings.TrimSuffix(ipv6PrefixStr, "::")
	ipv6PrefixStr = strings.TrimSuffix(ipv6PrefixStr, ":")
	ipv6PrefixStr = strings.TrimSuffix(ipv6PrefixStr, ":")
	fmt.Println("ipv6Prefix:", ipv6PrefixStr)

	// If no IPv6 prefix found, return an error
	if ipv6PrefixStr == "" {
		return "", netip, fmt.Errorf("no IPv6 prefix found")
	}

	return ipv6PrefixStr, ipv6Prefix, nil
}

// // Convert IPv6 address to a big integer
// func IPv6ToBigInt(ipv6Addr string) (*big.Int, error) {
// 	ip := net.ParseIP(ipv6Addr)
// 	if ip == nil {
// 		return nil, fmt.Errorf("invalid IP address")
// 	}

// 	// Extract the IPv6 bytes
// 	ip = ip.To16()
// 	if ip == nil {
// 		return nil, fmt.Errorf("not an IPv6 address")
// 	}

// 	// Convert bytes to big integer
// 	bigInt := new(big.Int)
// 	bigInt.SetBytes(ip)

// 	return bigInt, nil
// }

// // Convert big integer to an IPv6 address
// func BigIntToIPv6(bigInt *big.Int) (string, error) {
// 	// Convert big integer to bytes
// 	bytes := bigInt.Bytes()

// 	// IPv6 address must be 16 bytes
// 	if len(bytes) > 16 {
// 		return "", fmt.Errorf("integer too large for an IPv6 address")
// 	}

// 	// Pad with leading zeros if necessary
// 	paddedBytes := make([]byte, 16)
// 	copy(paddedBytes[16-len(bytes):], bytes)

// 	// Convert bytes to IP
// 	ip := net.IP(paddedBytes)
// 	return ip.String(), nil
// }


// Function to extract the IPv6 prefix from an IPNet object and pad it to /64 length
func get_prefix_padded(ipnet *net.IPNet, vlan uint64) string {
	// Get the network portion of the IP
	network := ipnet.IP.Mask(ipnet.Mask)

	// Convert the network portion to a string representation
	ipv6Prefix := network.String()


	// If the prefix length is less than 64, pad it with zeros
	requiredLength := int(math.Floor(float64(prefix_len / 4)))
	// if len(ipv6Prefix) < len("xxxx:xxxx:xxxx:xxxx") - (64 - prefix_len) {
	// 	ipv6Prefix = strings.TrimSuffix(ipv6Prefix, ":") // Remove trailing ":"
	// 	padding := "0000:0000:0000:0000:0000:0000:0000:"   // Pad with zeros
	// 	ipv6Prefix += padding[len(ipv6Prefix):requiredLength]          // Add padding to reach /64 length
	// }

	var ipv6psb strings.Builder
	for strings.HasSuffix(ipv6Prefix, ":") {
		ipv6Prefix = strings.TrimSuffix(ipv6Prefix, ":")
	}

	i := 0
	times_nocol := 0

	// Split the string by ":"
	parts := strings.Split(ipv6Prefix, ":")

	// Pad each part with leading zeros
	for i, part := range parts {
		parts[i] = fmt.Sprintf("%04s", part)
	}

	// Join the parts with ":"
	output := strings.Join(parts, ":")
	ipv6Prefixrn := []rune(output)

	for index := 0; i <= requiredLength-1; {
		if index >= 0 && index < len(ipv6Prefixrn) {
			if ipv6Prefixrn[index] != ':' {
				i +=1
				times_nocol += 1
			} else {
				println("adding nocol bef: ", i)
				i += 4 - times_nocol
				println("adding nocol: ", i, 4 - times_nocol)
				times_nocol = 0
			}
			ipv6psb.WriteRune(ipv6Prefixrn[index])
		} else {
			i +=1

			ipv6psb.WriteRune('0')
		}
		index +=1
	}
	println("fkldjs ", ipv6psb.String(), string(ipv6Prefixrn), ipv6Prefix)

	ipv6Prefix = ipv6psb.String()


	maxVLANs := uint64(math.Pow(2, float64(64-prefix_len)))


	// for vlan > maxVLANs {
	// 	vlan -= int16(math.Pow(2, float64(64-prefix_len)))
	// 	fmt.Println("trimming vlan to VLAN:", vlan)
	// }
	vlan %= maxVLANs
	fmt.Println("VLAN hex:", fmt.Sprintf("%X", vlan))


	ipv6Prefix += fmt.Sprintf("%X", vlan)

	// Ensure it ends with a single colon
	if !strings.HasSuffix(ipv6Prefix, ":") {
		ipv6Prefix += ":"
	}

	// Remove one colon until the character before the last is not a colon
	for strings.HasSuffix(ipv6Prefix, "::") {
		ipv6Prefix = strings.TrimSuffix(ipv6Prefix, ":")
	}
	fmt.Println("VLAN:", vlan)
	return ipv6Prefix
}


func ConvertIPToIPNet(ip net.IP, prefixLength int) *net.IPNet {
	// Determine the appropriate mask for the IP address (IPv4 or IPv6).
	var mask net.IPMask
	if ip.To4() != nil {
		mask = net.CIDRMask(prefixLength, 32)
	} else {
		mask = net.CIDRMask(prefixLength, 128)
	}

	return &net.IPNet{
		IP:   ip,
		Mask: mask,
	}
}

func IPv6PrefixToReverseDNS(prefix net.IP, prefLen int, vlan uint64) string {
	// exp := ipaddr.NewIPAddressString(prefix + ":").GetAddress()
	exp, err := ipaddr.NewIPAddressFromNetIP(prefix)
	if err != nil {
		return ""
	}

	// exp := ConvertIPToIPNet(prefix, prefix_len)
	// exp := get_prefix_padded(tmp, vlan)
	// exp = exp.AdjustPrefixLen(ipaddr.BitCount(uint32(prefLen)))

	// Get the reverse DNS string
	revdns, err := exp.GetSection().ToReverseDNSString()
	if err != nil {
		log.Fatalln(err)
	}

	// Calculate the number of nibbles to include in the prefix
	numNibbles := prefLen / 4

	// Split the reverse DNS string by dots
	parts := strings.Split(revdns, ".")

	// Include only the necessary parts up to the prefix length
	// Reverse DNS entries are reversed, so take from the start
	prefixParts := parts[numNibbles:]

	// Join the prefix parts back into a reverse DNS string
	prefixPart := strings.Join(prefixParts, ".")

	return prefixPart
}











// // Function to reload bind9.service and named.service
// func restart_dns() error {
// 	dev_name := ""
// 	wait_time := 0.0
// 	wait_time_mul := 5.0
// 	wait_time_def := rand.Float64() * 15
//
// 	hostname, err := os.Hostname()
// 	if err != nil {
// 		fmt.Println("cant get hostname. Error:", err)
// 		wait_time = wait_time_def
// 	} else {
// 		spl := strings.Split(hostname, ".")
// 		dev_name = spl[0]
//
// 		numericStr := ""
// 		for _, char := range dev_name {
// 			if (char >= '0' && char <= '9') || char == '.' {
// 				numericStr += string(char)
// 			}
// 		}
//
// 		// Convert string to float64
// 		num, err := strconv.ParseFloat(numericStr, 64)
// 		if err != nil {
// 			fmt.Println("Error converting string to float64:", err)
// 			wait_time = wait_time_def
// 		} else {
// 			wait_time = (num-1) * wait_time_mul
// 		}
// 	}
//
// 	time.Sleep(time.Duration(wait_time * float64(time.Second)))
//
// 	// // Reload bind9.service
// 	// err = exec.Command("systemctl", "restart", "bind9.service").Run()
// 	// if err != nil {
// 	//     return err
// 	// }
//
//
// 	// Reload named.service
// 	err = exec.Command("systemctl", "restart", "named.service").Run()
// 	if err != nil {
// 		fmt.Println(err)
// 	}
// 	fmt.Println("reloading dnsmasq")
// 	// err = exec.Command("systemctl", "reload", "dnsmasq.service").Run()
// 	err = exec.Command("systemctl", "restart", "dnsmasq.service").Run()
// 	if err != nil {
// 		fmt.Println(err)
// 	}
//
//
// 	return nil
// }














//! ====== ip part starts




// isULA checks if the given IP address is a Unique Local Address (ULA).
func isULA(ip net.IP) bool {
	// ULA range is fc00::/7
	ula := &net.IPNet{
		IP:   net.ParseIP("fc00::"),
		Mask: net.CIDRMask(7, 128),
	}
	return ula.Contains(ip)
}

// isLinkLocal checks if the given IP address is a link-local address.
func isLinkLocal(ip net.IP) bool {
	// Link-local range is fe80::/10
	linkLocal := &net.IPNet{
		IP:   net.ParseIP("fe80::"),
		Mask: net.CIDRMask(10, 128),
	}
	return linkLocal.Contains(ip)
}

// isValidIPAddress checks if an IP address is not link-local, not ULA, and not loopback.
func isValidIPAddress(ip net.IP) bool {
	if ip == nil {
		return false // Invalid IP address
	}

	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsLinkLocalUnicast() || !ip.IsGlobalUnicast() || ip.To4() != nil || isLinkLocal(ip) || isULA(ip) {
		return false
	}

	return true
}


// addrToIP converts a net.Addr to a net.IP if possible.
func addrToIP(addr net.Addr) (net.IP, error) {
	switch v := addr.(type) {
	case *net.IPAddr:
		return v.IP, nil
	case *net.IPNet:
		return v.IP, nil
	case *net.TCPAddr:
		return v.IP, nil
	case *net.UDPAddr:
		return v.IP, nil
	default:
		return nil, fmt.Errorf("unsupported address type: %T", addr)
	}
}

// Function to get the current IPv6 prefix
func getCurrentIPv6Prefix(interfaceName string) (string, error) {
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
	var ip net.IP
	for _, addr := range addrs {
		// Check if it's an IPv6 address and not temporary
		ip, err = addrToIP(addr)
		if err != nil {
			continue
		}
		if isValidIPAddress(ip) {
			ipnet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
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
