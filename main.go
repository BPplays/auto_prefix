package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"math"
	"math/rand"
	"net"
	"net/http"
	"net/netip"
	"os"
	"reflect"
	"bytes"

	// "os/exec"
	"encoding/json"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	// "io/ioutil"

	"context"

	"github.com/coreos/go-systemd/v22/dbus"
	"github.com/seancfoley/ipaddress-go/ipaddr"
	"gopkg.in/yaml.v3"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"text/template"

	"github.com/BPplays/auto_prefix/source"
)

const (
	configFile     = "/etc/auto_prefix/config.yml"
	serviceDir = "/etc/auto_prefix/config.d"
	prefix_store = "/etc/auto_prefix/prefix.json"
	Prefix_length_default = 56
	prefix_full_subnet_len = 64
	restartMode       = "replace" // or "force-reload"
	if_file = "/etc/main_interface"
	pd_file = "/etc/pd_size"
	checkInterval  = 5 * time.Second

)
var (
	Prefix_length = Prefix_length_default

	errNilPrefix = errors.New("prefix is nil")
)

var prefixNotFound error = errors.New("no prefix found")

var interfaceName = ""
var ut string = ""


type FileMapping struct {
	From string `yaml:"from"`
	To   string `yaml:"to"`
}

type jsonIPv6Prefix struct {
	Prefix netip.Prefix `json:"prefix"`
}


type Config struct {
	Source                 string        `yaml:"source"`
	Url                 string        `yaml:"url"`
}

type Service struct {
	Name                 string        `yaml:"name"`
	Files                []FileMapping `yaml:"files"`
	Folders              []FileMapping `yaml:"folders"`
	RestartCmds          []string      `yaml:"restart_cmds"`
	RestartSystemdServices []string    `yaml:"restart_systemd_services"`
	RestartTimeHost      float64           `yaml:"restart_time_host"`
	RestartTimeout      int           `yaml:"restart_timeout"`
}

func sprintBytesAsBinary(data interface{}) (string) {
	v := reflect.ValueOf(data)
	kind := v.Kind()
	if kind != reflect.Slice && kind != reflect.Array {
		return "unsupported type"
		// panic(fmt.Sprintf("unsupported type: %s; want slice or array of bytes", kind))
	}

	var sb strings.Builder
	for i := 0; i < v.Len(); i++ {
		elem := v.Index(i)
		// Ensure element is a byte (uint8)
		if elem.Kind() != reflect.Uint8 {
			// panic(fmt.Sprintf("element %d has type %s; want uint8", i, elem.Kind()))
			return "element somehow not uint8?"
		}
		sb.WriteString(fmt.Sprintf("%08b ", elem.Uint()))
	}
	return sb.String()
}


func get_interfaceName_file() error {
	content, err := os.ReadFile(if_file)
	if err != nil {
		return err
	}

	interfaceName = string(content)

	return nil
}

func get_pd_size_file(pd_file string) (error, int) {
	content, err := os.ReadFile(pd_file)
	if err != nil {
		return err, -1
	}

	Prefix_length, err = strconv.Atoi(string(content))

	if err != nil {
		return err, -1
	}

	return nil, Prefix_length


}

func GetBit(ip_bytes [16]byte, bit int) bool {
	if bit < 1 || bit > 128 {
		return false
	}
	byteIndex := (bit - 1) / 8
	bitIndex := (bit - 1) % 8
	mask := byte(1 << (7 - bitIndex))
	return (ip_bytes[byteIndex] & mask) != 0
}


// SetBit sets or clears a specific bit in the IP address based on the value of setToOne.
func SetBit(ip_bytes [16]byte, bit int, setToOne bool) ([16]byte) {
	// fmt.Println("bit:", bit)
	byteIndex := int(math.Ceil(float64(bit) / (8))+1)  // Calculate the byte position
	bitIndex := (bit-1) % 8   // Calculate the bit position within that byte

	// fmt.Printf("biti %v, bytei %v\n", bitIndex, byteIndex)
	if setToOne {
		ip_bytes[byteIndex] |= 1 << (7 - bitIndex) // Set the bit to 1
	} else {
		ip_bytes[byteIndex] &^= 1 << (7 - bitIndex) // Clear the bit (set to 0)
	}

	return ip_bytes
}


func mixPrefixIP(prefix netip.Prefix, suffix netip.Addr) netip.Prefix {
    prefixBits := prefix.Bits()
    if prefixBits >= 128 {
        return prefix
    }

    prefixBytes := prefix.Addr().As16()
    suffixBytes := suffix.As16()

    fullBytes := prefixBits / 8     // how many full bytes the prefix occupies
    rem := prefixBits % 8           // leftover bits in the partial byte (0..7)

    if rem == 0 {
        copy(prefixBytes[fullBytes:], suffixBytes[fullBytes:])
    } else {
        mask := byte(0xFF) << uint(8-rem) // mask has top `rem` bits set
        prefixBytes[fullBytes] = (prefixBytes[fullBytes] & mask) | (suffixBytes[fullBytes] & ^mask)
        if fullBytes+1 <= 15 {
            copy(prefixBytes[fullBytes+1:], suffixBytes[fullBytes+1:])
        }
    }

    out := netip.AddrFrom16(prefixBytes)
    return netip.PrefixFrom(out, prefixBits)
}

func set_ipaddr_bits(prefix netip.Prefix, subnet_uint64 uint64, start int, end int) netip.Prefix {
	var addr_output netip.Addr
	var addr_sl [16]byte


	var addr_bytes [16]byte
	addr_bytes = prefix.Addr().As16()
	// fmt.Printf("addr: %v,\naddr subnet uint64: %v,\naddr_bytes: %v\n\n\n\n", prefix.Addr().String(), subnet_uint64, sprintBytesAsBinary(addr_bytes))

	// fmt.Printf("set bits: start: %v, end: %v\n", start, end)
	for i := end; i >= start; i-- {
		if i == start {
			break
		}

		subnet_bit_pos := (-i) + end
		bit := (int(subnet_uint64) >> subnet_bit_pos) & 1
		addr_sl = SetBit(addr_bytes, i, bit == 1)
		// fmt.Printf("output nonfin: %v\n\n output_nonfin bits: %v\n", addr_output.String(),sprintBytesAsBinary(addr_sl))
		// fmt.Printf("Bit %d: %d\n", i, bit)
	}

	addr_output = netip.AddrFrom16(addr_sl)

	// fmt.Printf("output fin: %v\n\n output_fin bits: %v\n", addr_output.String(),sprintBytesAsBinary(addr_output.As16()))
	// fmt.Println("")
	// fmt.Println("")
	// fmt.Println("")
	return netip.PrefixFrom(addr_output, prefix.Bits())
}

func getIpv6Subnet(prefix *netip.Prefix, vlan uint64) string {
	// Call get_prefix function with interfaceName and vlan
	ip := get_network_from_prefix(*prefix, vlan)
	ipstr := strings.TrimSuffix(ip.Addr().String(), "::")
	ipstr = strings.TrimSuffix(ipstr, ":")
	return ipstr
}

func replaceIPv6Prefix(content string, prefix netip.Prefix) string {
	// Define the regular expression pattern
	pattern := `#@ipv6_prefix_([0-9a-fA-F]+)@#`
	re := regexp.MustCompile(pattern)
	// fmt.Println("starting regex conv")

	// Find all matches in the content
	matches := re.FindAllStringSubmatch(content, -1)
	var repped string = content
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

		ipstr := getIpv6Subnet(&prefix, vlan)

		replacement_ip := ipstr
		repped = strings.ReplaceAll(repped, fullMatch, replacement_ip)
		// fmt.Printf("full match: %v, vlan %v, repped: %v\n", fullMatch, vlan, replacement_ip.Addr().String())
	}

	return repped
}

func parseConfigFile(filePath string) (Config, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return Config{}, fmt.Errorf("error opening file %s: %w", filePath, err)
	}
	defer file.Close()

	var config Config
	decoder := yaml.NewDecoder(file)
	if err := decoder.Decode(&config); err != nil {
		return Config{}, fmt.Errorf("error decoding YAML file %s: %w", filePath, err)
	}

	return config, nil
}

// loadServices loads and parses all YAML files from a directory
func loadServices(dir string) ([]Service, error) {
	var configs []Service

	// Walk through the directory
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("error walking directory: %w", err)
		}

		// Only process regular files with .yaml or .yml extensions
		if !d.IsDir() && (filepath.Ext(path) == ".yaml" || filepath.Ext(path) == ".yml") {
			fileConfigs, err := parseServiceFile(path)
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

// parseServiceFile parses a single YAML file into a slice of Config objects
func parseServiceFile(filePath string) ([]Service, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("error opening file %s: %w", filePath, err)
	}
	defer file.Close()

	var configs []Service
	decoder := yaml.NewDecoder(file)
	if err := decoder.Decode(&configs); err != nil {
		return nil, fmt.Errorf("error decoding YAML file %s: %w", filePath, err)
	}

	return configs, nil
}


func main() {
	var lastIPv6Prefix netip.Prefix = netip.PrefixFrom(netip.IPv6Unspecified(), 0)

	var sleep_sec float64
	var sleep_dur time.Duration
	var sleep_ut int64


	fmt.Println("starting program")
	// fmt.Println("using if:", interfaceName)



	// Start an infinite loop
	for {
		fmt.Println("starting loop")
		err := get_interfaceName_file()
		if err != nil {
			if interfaceName == "" {
				time.Sleep(2 * time.Second)
				continue
			}
		}

		sleep_sec = ((math.Mod(float64(time.Now().Unix()), checkInterval.Seconds())) - checkInterval.Seconds() ) * -1

		// if sleep_sec >= checkInterval.Seconds() {
		// 	sleep_sec = 0
		// }

		sleep_dur = time.Duration(sleep_sec * float64(time.Second))
		sleep_ut = time.Now().Add(sleep_dur).Unix()


		time.Sleep(sleep_dur)

		config, err := parseConfigFile(configFile)
		if err != nil {
			log.Fatalf("Error loading configs: %v", err)
		}

		services, err := loadServices(serviceDir)
		if err != nil {
			log.Fatalf("Error loading configs: %v", err)
		}

		// // Print the parsed configurations
		// for _, config := range services {
		// 	fmt.Printf("Name: %s\n", config.Name)
		// 	fmt.Printf("Files: %v\n", config.Files)
		// 	fmt.Printf("Restart Commands: %v\n", config.RestartCmds)
		// 	fmt.Printf("Systemd Services: %v\n", config.RestartSystemdServices)
		// 	fmt.Printf("Restart Time Host: %v\n\n", config.RestartTimeHost)
		// 	fmt.Printf("Restart timeout: %v\n\n", config.RestartTimeout)
		// }


		ut = get_dns_ut()

		// Get the current IPv6 prefix
		currentIPv6Prefix, err := get_prefix(config, false)
		if err != nil {
			fmt.Println("Error:", err)
			return
		}


		// If the current prefix is different from the last one, update the zone files and reload services
		if currentIPv6Prefix != lastIPv6Prefix {
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

			for _, service := range services {
				err := repSaveFileAndFolder(service, currentIPv6Prefix)
				if err != nil {
					fmt.Println("Error:", err)
					// return
				}

				restart_services(service)
			}

			// err = restart_dns()
			// if err != nil {
			// 	fmt.Println("Error:", err)
			// 	return
			// }

			lastIPv6Prefix = currentIPv6Prefix
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

func replace_vars(content *[]byte, prefix *netip.Prefix) (string, error) {
	if prefix == nil {
		return "", errNilPrefix
	}

	ipstr := getIpv6Subnet(prefix, 0)
	rev_dns := IPv6PrefixToReverseDNS(*prefix, 64, 0)

	prefixCache := make(map[string]string)
	vars := map[string]any{
		"ut_10":  ut,
		"ipv6_prefix":   ipstr,
		"ipv6_revdns_prefix": rev_dns,
	}

    tpl := template.New("zonefile.tmpl").
        Funcs(template.FuncMap{
			"get_ipv6_subnet": func(vlanStr string) (string) {
				if pref, exists := prefixCache[vlanStr]; exists {
					return pref
				}
				vlan, err := strconv.ParseUint(vlanStr, 16, 64)
				if err != nil {
					// Handle conversion error
					return "2001::db8"
					// return "2001::db8", fmt.Errorf("Error converting VLAN number: %w", err)
				}

				pref := getIpv6Subnet(prefix, vlan)
				prefixCache[vlanStr] = pref

				return pref
			},

			"mix_prefix_ip": func(vlanStr string) (string) {
				if pref, exists := prefixCache[vlanStr]; exists {
					return pref
				}
				vlan, err := strconv.ParseUint(vlanStr, 16, 64)
				if err != nil {
					// Handle conversion error
					return "2001::db8"
					// return "2001::db8", fmt.Errorf("Error converting VLAN number: %w", err)
				}

				pref := getIpv6Subnet(prefix, vlan)
				prefixCache[vlanStr] = pref

				return pref
			},
		},
	)

    tpl, err := tpl.Parse(string(*content))
    if err != nil {
        return "", fmt.Errorf("error parsing template: %v", err)
    }

    var out bytes.Buffer
    if err := tpl.Execute(&out, vars); err != nil {
        return "", fmt.Errorf("template execution failed: %w", err)
    }



	// fmt.Println("rep vars")
	// replacedContent := replaceIPv6Prefix(string(*content), *prefix)
	// fmt.Println("repped vars dyn vlan")
	//
	// replacedContent = strings.ReplaceAll(replacedContent, "#@ipv6_prefix@#", ipstr)
	// fmt.Println("repped vars main")
	// replacedContent = strings.ReplaceAll(replacedContent, "#@ut_10@#", ut)
	// fmt.Println("repped vars ut10")
	// replacedContent = strings.ReplaceAll(replacedContent, "@::#@ipv6_revdns_prefix@#", rev_dns)
	// fmt.Println("repped vars reverse")

	return out.String(), nil
}

func restart_services(config Service) {

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

func repSaveFileAndFolder(service Service, prefix netip.Prefix) (error) {
	var allFiles []FileMapping = service.Files

	for _, folder := range service.Folders {

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
			if file.IsDir() {
				continue
			}

			filePath := filepath.Join(folder.From, file.Name())
			filePathTo := filepath.Join(folder.To, file.Name())
			allFiles = append(allFiles, FileMapping{From: filePath, To: filePathTo})
		}
	}

	for _, file := range allFiles {
		fmt.Printf("reading: %v\n", file.From)
		content, err := os.ReadFile(file.From)
		if err != nil {
			return err
		}

		replacedContent, err := replace_vars(&content, &prefix)
		if err != nil {
			continue
		}

		err = os.WriteFile(file.To, []byte(replacedContent), 0644)
		if err != nil {
			return err
		}

		fmt.Printf("saving: %v\n", file.To)

		return nil

	}

	return nil
}

func get_prefix(config Config, noFile bool) (netip.Prefix, error)  {
	var prefix netip.Prefix
	var found_prefix bool = false

	tsource, err := source.FromString(config.Source)
	if err != nil {
		log.Fatalln("config source error")
		return netip.Prefix{}, err
	}


	for range 5 {

		if tsource == source.File {
			var prefix_len int

			addr, err := get_addr_from_if(interfaceName)
			if err == nil {
				found_prefix = true
			}

			err, prefix_len = get_pd_size_file(pd_file)
			if err != nil {
				prefix_len = Prefix_length_default
			}

			prefix = netip.PrefixFrom(addr, prefix_len)

		} else if tsource == source.Url {
			tr := &http3.Transport{
				TLSClientConfig: &tls.Config{},  // set a TLS client config, if desired
				QUICConfig:      &quic.Config{}, // QUIC connection options
			}
			defer tr.Close()
			client := &http.Client{
				Transport: tr,
			}

			resp, err := client.Get(config.Url)
			if err != nil {
				log.Println(err)
				continue
			}
			defer resp.Body.Close()

			var pr struct{ Prefix netip.Prefix `json:"prefix"` }
			if err := json.NewDecoder(resp.Body).Decode(&pr); err != nil {
				log.Println(err)
			} else {
				found_prefix = true
			}

			prefix = pr.Prefix
		}


		if found_prefix {
			log.Printf("found new prefix: %v\n", prefix.String())
			if !noFile {
				updateIPv6Prefix(prefix)
			}
			break
		} else if !noFile {
			log.Println("did not find new prefix")
			prefix, err := readIPv6PrefixFromFile()
			if err != nil {
				continue
				// if os.IsNotExist(err) {
				// 	continue
				// 	// return netip.Prefix{}, os.ErrNotExist
				// }
				//
				// return netip.Prefix{}, err
			}
			return *prefix, nil
		}

	}
	if found_prefix {
		return prefix, nil

	} else {
		return netip.Prefix{}, prefixNotFound
	}

}

func get_network_from_prefix(prefix netip.Prefix, vlan uint64) (netip.Prefix) {
	outputPrefix := set_ipaddr_bits(prefix, vlan, Prefix_length, prefix_full_subnet_len)
	return outputPrefix
}


func get_addr_from_if(interfaceName string) (netip.Addr, error) {
	// Specify the network interface name
	// interfaceName := "eth0" // Change this to your desired interface name

	var addr netip.Addr
	// Get network interface
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return addr, err
	}

	// Get addresses for the interface
	addrs, err := iface.Addrs()
	if err != nil {
		return addr, err
	}

	// Initialize variables to store the IPv6 prefix
	var ipv6Prefix_addr netip.Addr
	var ipv6Prefix *netip.Prefix
	var found_addr bool = false

	// Iterate over addresses to find the IPv6 prefix
	var ip netip.Addr
	for _, addr := range addrs {
		ip, err = addrToNetIPaddr(addr)
		if err != nil {
			log.Fatalln("can't parse addr")
		}

		if isValidIPprefixAddress(ip) {
			p := netip.PrefixFrom(ip, Prefix_length)
			ipv6Prefix = &p
			fmt.Printf("ipnet: %v\n", ipv6Prefix.Addr().String())

			// ipv6Prefix = get_prefix_padded(ipnet, vlan)
			found_addr = true
			break
		}
	}

	if found_addr {
		updateIPv6Prefix(*ipv6Prefix)
	} else {
		ipv6Prefix, err = readIPv6PrefixFromFile()
		if err != nil {
			return netip.Addr{}, err
		}
	}

	return ipv6Prefix_addr, nil
}


func readIPv6PrefixFromFile() (*netip.Prefix, error) {
	file, err := os.Open(prefix_store)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	data, err := os.ReadFile(prefix_store)
	if err != nil {
		return nil, err
	}

	var prefix jsonIPv6Prefix
	if err := json.Unmarshal(data, &prefix); err != nil {
		return nil, err
	}

	return &prefix.Prefix, nil
}

func writeIPv6PrefixToFile(prefix jsonIPv6Prefix) error {
	data, err := json.MarshalIndent(prefix, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(prefix_store, data, 0644)
}

func updateIPv6Prefix(newPrefix netip.Prefix) error {
	var no_stored bool
	storedPrefix, err := readIPv6PrefixFromFile()
	if err != nil {
		fmt.Println("can't read prefix", err)
		return writeIPv6PrefixToFile(jsonIPv6Prefix{Prefix: newPrefix})
	}

	if storedPrefix == nil {
		no_stored = true
		p := netip.PrefixFrom(netip.IPv6Unspecified(), 0)
		storedPrefix = &p
	}


	// If no prefix exists or the prefix is different, write new one
	if no_stored || *storedPrefix != newPrefix {
		fmt.Println("Updating IPv6 prefix to:", newPrefix.String())
		return writeIPv6PrefixToFile(jsonIPv6Prefix{Prefix: newPrefix})
	}

	fmt.Println("IPv6 prefix is unchanged.")
	return nil
}



func IPv6PrefixToReverseDNS(prefix netip.Prefix, prefLen int, vlan uint64) string {
	prefix_vlan := get_network_from_prefix(prefix, vlan)

	exp, err := ipaddr.NewIPAddressFromNetNetIPPrefix(prefix_vlan)
	if err != nil {
		return ""
	}

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

func addrTo_net_IP(addr net.Addr) (net.IP, error) {
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

func addrToNetIPaddr(addr net.Addr) (netip.Addr, error) {
	net_IP, err := addrTo_net_IP(addr)
	if err != nil {
		return netip.Addr{}, err
	}

	return netip.AddrFrom16([16]byte(net_IP.To16())), nil
}









//! ====== ip part starts




// isULA checks if the given IP address is a Unique Local Address (ULA).
func isULA(ip netip.Addr) bool {
	// ULA range is fc00::/7
	ula, err := netip.ParsePrefix("fc00::/7")
	if err != nil {

	}
	return ula.Contains(ip)
}

// isLinkLocal checks if the given IP address is a link-local address.
func isLinkLocal(ip netip.Addr) bool {
	// Link-local range is fe80::/10
	linkLocal, err := netip.ParsePrefix("fe80::/10")
	if err != nil {

	}
	return linkLocal.Contains(ip)
}

// isValidIPprefixAddress checks if an IP address is not link-local, not ULA, and not loopback.
func isValidIPprefixAddress(ip netip.Addr) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsLinkLocalUnicast() || !ip.IsGlobalUnicast() || ip.Is4() || isLinkLocal(ip) || isULA(ip) {
		return false
	}

	return true
}

