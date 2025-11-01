package main

import (
	"bytes"
	"crypto/sha3"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log/slog"
	"maps"
	"math"
	"math/rand"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"os/user"
	"reflect"
	"runtime"
	"slices"
	"sync"

	// "os/exec"
	"encoding/json"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	// "io/ioutil"

	"context"

	"github.com/seancfoley/ipaddress-go/ipaddr"
	"gopkg.in/yaml.v3"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"text/template"

	"github.com/BPplays/auto_prefix/source"
	"github.com/prometheus-community/pro-bing"
	"github.com/sevlyar/go-daemon"
	"gopkg.in/natefinch/lumberjack.v2"
	"github.com/mattn/go-runewidth"
	"github.com/lmittmann/tint"
)

var (
	ConfigFile     = "/etc/auto_prefix/config.yml"
	ServiceDir = "/etc/auto_prefix/config.d"
	PrefixStore = "/etc/auto_prefix/prefix.json"
	IfFile = "/etc/main_interface"
	PdFile = "/etc/pd_size"
)

const (
	progName = "auto_prefix"
	Prefix_length_default = 56
	prefix_full_subnet_len = 64
	checkInterval  = 5 * time.Second
	ipv6MaxAddr = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"

)
var (
	Prefix_length = Prefix_length_default

	ErrNilPrefix = errors.New("prefix is nil")
	ErrStdErrNotEmpty = errors.New("stderr is not empty")

)

var logFileWriter lumberjack.Logger
var globalStartTime time.Time

var filesInvalid int = 1
var filesInvalidMu sync.RWMutex

var globalConfig Config
var globalServices []Service
var globalConfigMu sync.RWMutex
var globalServicesMu sync.RWMutex

var HostFound map[HostCheck]bool = make(map[HostCheck]bool)
var hostFoundMu sync.RWMutex

var prefixNotFound error = errors.New("no prefix found")

var interfaceName = ""
var ut string = ""


type FileMapping struct {
	From string `yaml:"from"`
	To   string `yaml:"to"`
	Perms   FileMode `yaml:"perms"`
	Owner   string `yaml:"owner"`
	Group   string `yaml:"group"`
}

type jsonIPv6Prefix struct {
	Prefix netip.Prefix `json:"prefix"`
}


type HostCheck struct {
	VarName                 string        `yaml:"var_name"`
	Host                 string        `yaml:"host"`
	Type                 string        `yaml:"type"`
	Port                 int        `yaml:"port"`

}

type Config struct {
	Source                 string        `yaml:"source"`
	Url                 string        `yaml:"url"`
	Hosts                 []HostCheck        `yaml:"hosts"`
	HostsCheckTime                 float64        `yaml:"hosts_check_time"`
}

type Service struct {
	Name                 string        `yaml:"name"`
	Files                []FileMapping `yaml:"files"`
	Folders              []FileMapping `yaml:"folders"`
	RestartCmds          [][]string      `yaml:"restart_cmds"`

	SystemdEnable bool    `yaml:"systemd_enable"`
	SystemdEnableCmdFallback bool    `yaml:"systemd_enable_cmd_fallback"`
	RestartSystemdServices []string    `yaml:"restart_systemd_services"`

	FreebsdServiceEnable bool    `yaml:"freebsd_service_enable"`
	FreebsdServiceEnableCmdFallback bool    `yaml:"freebsd_service_enable_cmd_fallback"`
	RestartFreebsdServices []string    `yaml:"restart_freebsd_services"`

	RestartTimeHost      float64           `yaml:"restart_time_host"`
	RestartTimeout      int           `yaml:"restart_timeout"`
	HostIndex      int           `yaml:"host_index"`
	Vars      map[string]any           `yaml:"vars"`
}

// FileMode is a thin wrapper so we can implement custom unmarshalling.
type FileMode os.FileMode

// UnmarshalYAML supports either a numeric YAML value (e.g. 420) or a string
// like "0644", "0755", or "0o644".
func (m *FileMode) UnmarshalYAML(node *yaml.Node) error {

	var s string
	if err := node.Decode(&s); err != nil {
		return err
		// var i int64
		// if err := node.Decode(&i); err != nil {
		// 	return err
		// }
		// s = fmt.Sprintf("%v", i)
	}

	// log.Printf("[fmum] string is %v\n", s)

	s = strings.TrimSpace(s)
	// accept 0o644 as a convenience -> convert to 0644
	if strings.HasPrefix(s, "0o") || strings.HasPrefix(s, "0O") {
		s = "0" + s[2:]
	}
	// strconv.ParseUint with base 0 understands leading 0 as octal and 0x as hex.
	v, err := strconv.ParseUint(s, 0, 32)
	if err != nil {
		return fmt.Errorf("parse filemode %q: %w", s, err)
	}
	// log.Printf("[fmum] v is %#o\n", v)

	// log.Printf("[fmum] m before is %v\n", *m)
	*m = FileMode(os.FileMode(v))
	// log.Printf("[fmum] m after is %v\n", *m)
	return nil
}

// Convenience to get the real os.FileMode
func (m FileMode) FileMode() os.FileMode { return os.FileMode(m) }

func filesInvalidAdd1() () {
	filesInvalidMu.Lock()
	defer filesInvalidMu.Unlock()
	if filesInvalid < 0 { filesInvalid = 0 }
	filesInvalid += 1
}

func filesInvalidAdd(i int) () {
	filesInvalidMu.Lock()
	defer filesInvalidMu.Unlock()
	if filesInvalid < 0 { filesInvalid = 0 }
	filesInvalid += i
}

func filesInvalidDone(i int) () {
	filesInvalidMu.Lock()
	defer filesInvalidMu.Unlock()
	filesInvalid -= i
	if filesInvalid < 0 { filesInvalid = 0 }
}

func getIsFilesInvalid() (bool) {
	filesInvalidMu.RLock()
	defer filesInvalidMu.RUnlock()
	return filesInvalid > 0
}

func getFilesInvalid() (int) {
	filesInvalidMu.RLock()
	defer filesInvalidMu.RUnlock()
	return filesInvalid
}

func setHostFound(newHostCheck map[HostCheck]bool) () {
	hostFoundMu.Lock()
	defer hostFoundMu.Unlock()
	HostFound = maps.Clone(newHostCheck)
}

// func getHostFoundVal(s string) (bool) {
// 	hostFoundMu.RLock()
// 	defer hostFoundMu.RUnlock()
// 	return hostFound[s]
// }


func getHostFound() (map[HostCheck]bool) {
	hostFoundMu.RLock()
	defer hostFoundMu.RUnlock()
	return maps.Clone(HostFound)
}


func setGlobalConfig(conf Config) () {
	globalConfigMu.Lock()
	defer globalConfigMu.Unlock()
	globalConfig = conf
}


func getGlobalConfig() (Config) {
	globalConfigMu.RLock()
	defer globalConfigMu.RUnlock()
	return globalConfig
}

func setGlobalServices(srvs []Service) () {
	globalServicesMu.Lock()
	defer globalServicesMu.Unlock()
	globalServices = srvs
}

func getGlobalServices() ([]Service) {
	globalServicesMu.RLock()
	defer globalServicesMu.RUnlock()
	return globalServices
}

func setEtcDirs() {
	var etcBase string

	switch strings.ToLower(runtime.GOOS) {
	default:
		etcBase = "/etc/"
	case "freebsd":
		etcBase = "/usr/local/etc/"

	}


	ConfigFile     = filepath.Join(etcBase, "auto_prefix/config.yml")
	ServiceDir = filepath.Join(etcBase, "auto_prefix/config.d")
	PrefixStore = filepath.Join(etcBase, "auto_prefix/prefix.json")
	IfFile = filepath.Join(etcBase, "main_interface")
	PdFile = filepath.Join(etcBase, "pd_size")
}

func logTitleln(v ...any) {
	var strs []string

	for _, an := range v {
		strs = append(strs, fmt.Sprint(an))
	}

	lg := fmt.Sprintf("=== %v ===", strings.Join(strs, " "))

	topBot := strings.Repeat("=", runewidth.StringWidth(lg))

	slog.Info(fmt.Sprintf("\"%v\"", topBot))
	slog.Info(lg, slog.Duration("開始以来", time.Since(globalStartTime)))
	slog.Info(fmt.Sprintf("\"%v\"", topBot))
}

func defHashFile(path string) (*[]byte, error) {
	file, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}


	hash, err := defHash(&file)

	return hash, nil
}


func defHashCompare(a, b *[]byte) (bool, error) {

	aHash, err := defHash(a)
	if err != nil { return false, err }

	bHash, err := defHash(b)
	if err != nil { return false, err }

	return slices.Equal((*aHash), (*bHash)), nil
}

func defHash(input *[]byte) (*[]byte, error) {

	hash := sha3.New512()
	_, err := hash.Write(*input)
	if err != nil {
		return nil, err
	}

	sum := hash.Sum(nil)

	return &sum, nil
}

func sprintBytesAsBinary(data any) (string) {
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


func getInterfaceNameFile() error {
	content, err := os.ReadFile(IfFile)
	if err != nil {
		return err
	}

	interfaceName = string(content)

	return nil
}

func getPdSizeFile(pd_file string) (error, int) {
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
	// log.Println("bit:", bit)
	byteIndex := int(math.Ceil(float64(bit) / (8))+1)  // Calculate the byte position
	bitIndex := (bit-1) % 8   // Calculate the bit position within that byte

	// log.Printf("biti %v, bytei %v\n", bitIndex, byteIndex)
	if setToOne {
		ip_bytes[byteIndex] |= 1 << (7 - bitIndex) // Set the bit to 1
	} else {
		ip_bytes[byteIndex] &^= 1 << (7 - bitIndex) // Clear the bit (set to 0)
	}

	return ip_bytes
}


func mixPrefixIP(prefix *netip.Prefix, suffix *netip.Addr) *netip.Prefix {
    prefixBits := prefix.Bits()
    if prefixBits >= 128 {
        return prefix
    }

    prefixBytes := (*prefix).Addr().As16()
    suffixBytes := (*suffix).As16()

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
	outPrefix := netip.PrefixFrom(out, prefixBits)
    return &outPrefix
}

func setIpaddrBits(
	prefix netip.Prefix,
	subnet_uint64 uint64,
	start int,
	end int,
) netip.Prefix {
	var addr_output netip.Addr
	var addr_sl [16]byte
	var addr_bytes [16]byte

	addr_bytes = prefix.Addr().As16()

	for i := end; i >= start; i-- {
		if i == start {
			break
		}

		subnet_bit_pos := (-i) + end
		bit := (int(subnet_uint64) >> subnet_bit_pos) & 1
		addr_sl = SetBit(addr_bytes, i, bit == 1)
	}

	addr_output = netip.AddrFrom16(addr_sl)

	return netip.PrefixFrom(addr_output, prefix.Bits())
}

func getIpv6Subnet(prefix *netip.Prefix, vlan uint64) string {
	// Call get_prefix function with interfaceName and vlan
	ip := get_network_from_prefix(*prefix, vlan)
	ipstr := strings.TrimSuffix(ip.Addr().String(), "::")
	ipstr = strings.TrimSuffix(ipstr, ":")
	return ipstr
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

func loadServices(dir string) ([]Service, error) {
	var configs []Service

	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("error walking directory: %w", err)
		}

		if !d.IsDir() && (filepath.Ext(path) == ".yaml" || filepath.Ext(path) == ".yml") {
			fileConfigs, err := parseServiceFile(path)
			if err != nil {
				slog.Error(fmt.Sprintf("Error parsing file %s: %v", path, err))
				return nil
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

func appendVarMap(a *map[string]any, b *map[string]any) *map[string]any {
	out := make(map[string]any)

	maps.Copy(out, *a)
	maps.Copy(out, *b)

	return &out
}

func varHostFoundAdd(
	a *map[string]any,
	hostFound *map[HostCheck]bool,
) *map[string]any {
	out := make(map[string]any)

	maps.Copy(out, *a)

	for k, v := range *hostFound {
		out[k.VarName] = v
	}

	return &out
}

func looseParseSuffix(ipStr string) (netip.Addr, error) {
	var ip netip.Addr
	var firstErr error

	for _, prepend := range []string{"", ":", "::"} {
		var err error

		ip, err = netip.ParseAddr(fmt.Sprintf("%v%v", prepend, ipStr))
		if err == nil {
			return ip, nil
		} else {
			if firstErr == nil {
				firstErr = err
			}
		}

	}

	return ip, firstErr
}

func replaceVars(
	content *[]byte,
	prefix *netip.Prefix,
	service Service,
) (string, error) {
	if prefix == nil {
		return "", ErrNilPrefix
	}
	cacheHostFound := getHostFound()
	// fmt.Printf("cacheHostFound from replaceVars: %v\n", cacheHostFound)

	ipstr := getIpv6Subnet(prefix, 0)
	// rev_dns := IPv6PrefixToReverseDNSprefixOnly(*prefix, 64, 0)
	revPrefix, _, err := IPv6PrefixToReverseDnsPrefixSuffix(*prefix)
	if err != nil {
		revPrefix = "3.2.1.f.f.f.f.8.b.d.0.1.0.0.2"
	}

	revPrefix48, _, err := IPv6PrefixToReverseDnsPrefixSuffix(netip.PrefixFrom(
		(*prefix).Addr(),
		48,
	))
	if err != nil {
		revPrefix48 = "f.f.f.f.8.b.d.0.1.0.0.2"
	}

	getIPv6SubnetCache := make(map[string]string)
	mixPrefixIPCache := make(map[string]string)
	vars := map[string]any{
		"ut_10":  ut,
		"ipv6_prefix":   ipstr,
		"ipv6_revdns_prefix": revPrefix,
		"ipv6_revdns_prefix_48": revPrefix48,
		"pd_size": fmt.Sprint((*prefix).Bits()),
	}

	vars = *appendVarMap(&vars, &service.Vars)
	vars = *varHostFoundAdd(&vars, &cacheHostFound)

    tpl := template.New("zonefile.tmpl").
        Funcs(template.FuncMap{
			"get_ipv6_subnet": func(vlanStr string) (string) {
				if pref, exists := getIPv6SubnetCache[vlanStr]; exists {
					return pref
				}
				vlan, err := strconv.ParseUint(vlanStr, 16, 64)
				if err != nil {
					// Handle conversion error
					return "2001:db8"
					// return "2001:db8", fmt.Errorf("Error converting VLAN number: %w", err)
				}

				pref := getIpv6Subnet(prefix, vlan)
				getIPv6SubnetCache[vlanStr] = pref

				return pref
			},

			"mix_prefix_ip": func(ipStr string) (string) {
				if pref, exists := mixPrefixIPCache[ipStr]; exists {
					return pref
				}

				ip, err := looseParseSuffix(ipStr)
				if err != nil {
					return "2001:db8::"
				}

				mixed := mixPrefixIP(prefix, &ip)
				mixedStr := (*mixed).Addr().String()
				mixPrefixIPCache[ipStr] = mixedStr

				return mixedStr
			},

			"get_reverse_dns_ip": func(ipStr string) (string) {
				if pref, exists := mixPrefixIPCache[ipStr]; exists {
					return pref
				}

				ip, err := looseParseSuffix(ipStr)
				if err != nil {
					ip = netip.MustParseAddr(ipv6MaxAddr)
				}

				mixed := mixPrefixIP(prefix, &ip)
				_, suffix, err := IPv6PrefixToReverseDnsPrefixSuffix(*mixed)
				if err != nil {
					return ""
				}

				return suffix
			},

			"get_reverse_dns_ip_len": func(ipStr string, bits int) (string) {
				if pref, exists := mixPrefixIPCache[ipStr]; exists {
					return pref
				}

				ip, err := looseParseSuffix(ipStr)
				if err != nil {
					ip = netip.MustParseAddr(ipv6MaxAddr)
				}

				mixed := mixPrefixIP(prefix, &ip)
				_, suffix, err := IPv6PrefixToReverseDnsPrefixSuffix(
					netip.PrefixFrom(
						(*mixed).Addr(),
						bits,
					),
				)
				if err != nil {
					return ""
				}

				return suffix
			},
		},
	)

    tpl, err = tpl.Parse(string(*content))
    if err != nil {
        return "", fmt.Errorf("error parsing template: %v", err)
    }

    var out bytes.Buffer
    if err := tpl.Execute(&out, vars); err != nil {
        return "", fmt.Errorf("template execution failed: %w", err)
    }



	// log.Println("rep vars")
	// replacedContent := replaceIPv6Prefix(string(*content), *prefix)
	// log.Println("repped vars dyn vlan")
	//
	// replacedContent = strings.ReplaceAll(replacedContent, "#@ipv6_prefix@#", ipstr)
	// log.Println("repped vars main")
	// replacedContent = strings.ReplaceAll(replacedContent, "#@ut_10@#", ut)
	// log.Println("repped vars ut10")
	// replacedContent = strings.ReplaceAll(replacedContent, "@::#@ipv6_revdns_prefix@#", rev_dns)
	// log.Println("repped vars reverse")

	return out.String(), nil
}


func restartFreebsdServices(ctx context.Context, config Service) ([]error) {
	var errs []error

	if strings.ToLower(runtime.GOOS) == "freebsd" {
		errs = append(errs, errors.ErrUnsupported)
		return errs
	}


	for _, target := range config.RestartFreebsdServices {
		var outBuf, errBuf bytes.Buffer
		cmd := exec.CommandContext(ctx, "service", target, "restart")
		cmd.Stdout = &outBuf
		cmd.Stderr = &errBuf

		err := cmd.Run()
		_ = outBuf.String()
		errStr := errBuf.String()
		if err != nil {
			if len(strings.TrimSpace(errStr)) >= 1 {
				err = ErrStdErrNotEmpty
			}
		}

		errs = append(errs, err)
	}

	return errs
}

func runRestartCmds(ctx context.Context, config Service) (errs []error) {

	for _, target := range config.RestartCmds {
		var outBuf, errBuf bytes.Buffer

		cmd := exec.CommandContext(
			ctx,
			target[0],
			target[1:]...,
		)
		cmd.Stdout = &outBuf
		cmd.Stderr = &errBuf

		err := cmd.Run()
		_ = outBuf.String()
		errStr := errBuf.String()
		if err != nil {
			if len(strings.TrimSpace(errStr)) >= 1 {
				err = fmt.Errorf("%w, stderr: %v", ErrStdErrNotEmpty, errBuf.String())
			}
		}

		errs = append(errs, err)
	}

	return errs
}

func inferHostIndex() (hostIndex int, err error) {

	hostname, err := os.Hostname()
	if err != nil {
		return -1, err
	}

	spl := strings.Split(hostname, ".")
	dev_name := spl[0]

	numericStr := ""
	for _, char := range dev_name {
		if (char >= '0' && char <= '9') || char == '.' {
			numericStr += string(char)
		}
	}

	// Convert string to float64
	hostIndex, err = strconv.Atoi(numericStr)
	if err != nil {
		return -1, err
	}

	return hostIndex, nil
}


func restartServices(service Service) {
	logTitleln("Restarting services")

	if service.RestartTimeout <= 0 {
		service.RestartTimeout = 10
	}

	waitTime := 0.0
	waitTimeMul := service.RestartTimeHost
	waitTimeDef := rand.Float64() * 15

	if service.HostIndex >= 1 {
		waitTime = (float64(service.HostIndex-1)) * waitTimeMul
	} else {

		hostIndex, err := inferHostIndex()
		if err != nil {
			slog.Warn(fmt.Sprintf(
				"Can't infering host index and none manually specified: %v",
				err,
			))
			waitTime = waitTimeDef
		} else {
			waitTime = (float64(hostIndex-1)) * waitTimeMul
		}

	}


	time.Sleep(time.Duration(waitTime) * time.Second)

	ctx := context.Background()
	if service.SystemdEnable {
		errs := restartSystemdServices(ctx, service)
		for _, err := range errs {
			switch err {
			default:
				slog.Error(fmt.Sprintf("systemd err: %v", err))

			case nil:
			case errors.ErrUnsupported:
			}

		}
	}

	if service.FreebsdServiceEnable {
		errs := restartFreebsdServices(ctx, service)
		for _, err := range errs {
			switch err {
			default:
				slog.Error(fmt.Sprintf("freebsd service err: %v", err))
			case nil:
			case errors.ErrUnsupported:
			}

		}
	}

	cmdsErred := false
	if len(service.RestartCmds) > 0 {
		errs := runRestartCmds(ctx, service)
		for _, err := range errs {
			switch err {
			default:
				slog.Error(fmt.Sprintf("restart cmd err: %v", err, ))
				cmdsErred = true
			case nil:
			// case errors.ErrUnsupported:
			}

		}
	}

	if service.SystemdEnableCmdFallback && cmdsErred {
		errs := restartSystemdServices(ctx, service)
		for _, err := range errs {
			switch err {
			default:
				slog.Error(fmt.Sprintf("systemd err: %v", err))

			case nil:
			case errors.ErrUnsupported:
			}

		}
	}

	if service.FreebsdServiceEnableCmdFallback && cmdsErred {
		errs := restartFreebsdServices(ctx, service)
		for _, err := range errs {
			switch err {
			default:
				slog.Error(fmt.Sprintf("freebsd service err: %v", err))
			case nil:
			case errors.ErrUnsupported:
			}

		}
	}

}

func repSaveFileAndFolder(
	service Service,
	prefix netip.Prefix,
) (changed bool, err error) {
	var allFiles []FileMapping = service.Files

	logTitleln("Reading and saving files")

	for _, folder := range service.Folders {

		entries, err := os.ReadDir(folder.From)
		if err != nil {
			slog.Error(fmt.Sprintf("error replacing vars: %v", err))
			continue
		}
		files := make([]fs.FileInfo, 0, len(entries))
		for _, entry := range entries {
			info, err := entry.Info()
			if err != nil {
				slog.Error(fmt.Sprintf("error replacing vars: %v", err))
				continue
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

			tFile := folder
			tFile.From = filePath
			tFile.To = filePathTo

			allFiles = append(allFiles, tFile)
		}
	}

	for _, file := range allFiles {
		// log.Printf("reading: %v\n", file.From)
		content, err := os.ReadFile(file.From)
		if err != nil {
			slog.Error(fmt.Sprintf("error replacing vars: %v", err))
			continue
		}

		replacedContent, err := replaceVars(&content, &prefix, service)
		if err != nil {
			slog.Error(fmt.Sprintf("error replacing vars: %v", err))
			continue
		}


		bReplacedContent := []byte(replacedContent)

		toContent, err := os.ReadFile(file.To)
		switch {
		// case os.IsNotExist(err):
		case err != nil:
			slog.Error(fmt.Sprintf(
				"error reading final file skipping hash compare: %v",
				err,
			))
			changed = true

		default:
			if !bytes.Equal(toContent, bReplacedContent) {
				changed = true
			}
		}


		err = os.WriteFile(file.To, bReplacedContent, file.Perms.FileMode())
		if err != nil {
			slog.Error(fmt.Sprintf("error replacing vars: %v", err))
		}

		usr, err := user.Lookup(file.Owner)
		if err != nil {
			slog.Error(fmt.Sprintf(
				"[%v] err looking up owner by name trying uid: %v",
				file.Owner,
				err,
			))
			usr, err = user.LookupId(file.Owner)
			if err != nil {
				slog.Error(fmt.Sprintf("err looking up owner: %v", err))
				continue
			}
		}

		grp, err := user.LookupGroup(file.Group)
		if err != nil {
			grp, err = user.LookupGroupId(file.Group)
			if err != nil {
				slog.Error(fmt.Sprintf("err looking up group: %v", err))
				continue
			}
		}

		uid, err := strconv.Atoi(usr.Uid)
		if err != nil { continue }

		gid, err := strconv.Atoi(grp.Gid)
		if err != nil { continue }

		err = os.Chown(file.To, uid, gid)
		if err != nil {
			slog.Error(fmt.Sprintf("erring chowning: %v", err))
		}

		slog.Info(fmt.Sprintf("saving: %v", file.To))
	}

	return changed, nil
}

func get_prefix(config Config, noFile bool) (netip.Prefix, error)  {
	var prefix netip.Prefix
	var found_prefix bool = false

	tsource, err := source.FromString(config.Source)
	if err != nil {
		slog.Error("config source error")
		os.Exit(1)
		return netip.Prefix{}, err
	}


	for range 5 {

		if tsource == source.File {
			var prefix_len int

			addr, err := get_addr_from_if(interfaceName)
			if err == nil {
				found_prefix = true
			}

			err, prefix_len = getPdSizeFile(PdFile)
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
				slog.Error(fmt.Sprint(err))
				continue
			}
			defer resp.Body.Close()

			var pr struct{ Prefix netip.Prefix `json:"prefix"` }
			if err := json.NewDecoder(resp.Body).Decode(&pr); err != nil {
				slog.Error(fmt.Sprint(err))
			} else {
				found_prefix = true
			}

			prefix = pr.Prefix
		}


		if found_prefix {
			slog.Info(fmt.Sprintf("found new prefix: %v", prefix.String()))
			if !noFile {
				updateIPv6Prefix(prefix)
			}
			break
		} else if !noFile {
			slog.Info("did not find new prefix")
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
	outputPrefix := setIpaddrBits(prefix, vlan, Prefix_length, prefix_full_subnet_len)
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
			slog.Error("can't parse addr")
			os.Exit(1)
		}

		if isValidIPprefixAddress(ip) {
			p := netip.PrefixFrom(ip, Prefix_length)
			ipv6Prefix = &p
			slog.Info(fmt.Sprintf("ipnet: %v", ipv6Prefix.Addr().String()))

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
	file, err := os.Open(PrefixStore)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	data, err := os.ReadFile(PrefixStore)
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
	return os.WriteFile(PrefixStore, data, 0644)
}

func updateIPv6Prefix(newPrefix netip.Prefix) error {
	var no_stored bool
	storedPrefix, err := readIPv6PrefixFromFile()
	if err != nil {
		slog.Error(fmt.Sprint("can't read prefix", err))
		return writeIPv6PrefixToFile(jsonIPv6Prefix{Prefix: newPrefix})
	}

	if storedPrefix == nil {
		no_stored = true
		p := netip.PrefixFrom(netip.IPv6Unspecified(), 0)
		storedPrefix = &p
	}


	// If no prefix exists or the prefix is different, write new one
	if (no_stored) || ((*storedPrefix) != newPrefix) {
		slog.Error(fmt.Sprint("Updating IPv6 prefix to:", newPrefix.String()))

		return writeIPv6PrefixToFile(jsonIPv6Prefix{Prefix: newPrefix})
	}

	slog.Info("IPv6 prefix is unchanged.")
	return nil
}



func IPv6PrefixToReverseDNS(addr netip.Addr) string {

	exp := ipaddr.NewIPAddressFromNetNetIPAddr(addr)

	revdns, err := exp.GetSection().ToReverseDNSString()
	if err != nil {
		revdns = "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"
	}

	revdns = strings.TrimSuffix(revdns, ".ip6.arpa")

	return revdns
}


func IPv6PrefixToReverseDnsPrefixSuffix(p netip.Prefix) (
	prefix, suffix string,
	err error,
) {
	const totalNibbles = 128 / 4

	prefLen := p.Bits()

	revdns := IPv6PrefixToReverseDNS(p.Addr())

	numNibbles := prefLen / 4

	parts := strings.Split(revdns, ".")
    if len(parts) != totalNibbles {
        // be tolerant: if function producing revdns gives fewer/more labels, bail with error
        return "", "", fmt.Errorf("unexpected nibble count: got %d labels, want %d", len(parts), totalNibbles)
    }

	split := totalNibbles - numNibbles
	prefixParts := parts[split:]

	prefix = strings.Join(prefixParts, ".")

	suffixParts := parts[:split]

	suffix = strings.Join(suffixParts, ".")

	return prefix, suffix, nil
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


func loadConfigs(ctx context.Context) (error) {
	if ctx.Err() != nil { return ctx.Err() }

	config, err := parseConfigFile(ConfigFile)
	if err != nil {
		return err
	}

	services, err := loadServices(ServiceDir)
	if err != nil {
		return err
	}

	if ctx.Err() != nil { return ctx.Err() }


	if !reflect.DeepEqual(getGlobalConfig(), config) ||
	!reflect.DeepEqual(getGlobalServices(), services) {
		filesInvalidAdd1()
	}

	setGlobalConfig(config)
	setGlobalServices(services)

	return nil
}

func pingHost(
	ctx context.Context,
	host HostCheck,
	retries int,
) (bool, error) {
	result := false
	interval := 1 * time.Second


	for range retries {
		pctx, cancel := context.WithTimeout(
			ctx,
			(interval) + (10 * time.Millisecond),
			)
		defer cancel()

		pinger, err := probing.NewPinger(host.Host)
		if err != nil {
			slog.Error(fmt.Sprintf("err making pinger: %v", err))
			return false, err
		}

		// pinger.Count = 7
		pinger.Interval = interval
		pinger.SetPrivileged(true)
		if strings.ToLower(runtime.GOOS) != "freebsd" {
			pinger.SetDoNotFragment(true)
		}


		err = pinger.RunWithContext(pctx)
		if err != nil {

			for _, e := range []error{err, pctx.Err()} {
				if errors.Is(e, context.DeadlineExceeded) ||
				errors.Is(e, context.Canceled) {
					result = false

				} else {
					slog.Error(fmt.Sprintf("err running pinger: %v", err))
					result = false
				}
			}
			result = false
		}

		stats := pinger.Statistics()
		if stats.PacketsRecv > 0 {
			slog.Info(fmt.Sprintf("pinging: %v, result: true", host.Host))
			result = true
			break
		} else {
			slog.Info(fmt.Sprintf("pinging: %v, result: false", host.Host))
			result = false
		}
	}

	return result, nil
}

func checkHosts(ctx context.Context, conf Config) {
	var wg sync.WaitGroup
	prevHostFound := getHostFound()
	newHostFound := getHostFound()
	logTitleln("pinging hosts")

	for _, host := range conf.Hosts {
		if _, ok := prevHostFound[host]; !ok {
			newHostFound[host] = false
		}

		var checkFunc func(context.Context, HostCheck, int) (bool, error)

		switch host.Type {
		case "icmp":
			if host.Port > 0 {
				slog.Warn("setting host port does nothing using `icmp`")
			}
			checkFunc = pingHost

		}


		wg.Add(1)
		go func(host HostCheck) {
			defer wg.Done()
			result, err := checkFunc(ctx, host, 7)
			if err != nil {
				return
			}

			newHostFound[host] = result
		}(host)
	}
	wg.Wait()
	setHostFound(newHostFound)

	if !maps.Equal(getHostFound(), prevHostFound) {
		filesInvalidAdd(1)
	}
}



func templateLoop(skipIF *bool) {
	var lastIPv6Prefix netip.Prefix = netip.PrefixFrom(netip.IPv6Unspecified(), 0)

	var sleep_sec float64
	var sleep_dur time.Duration
	var sleep_ut int64

	// Start an infinite loop
	for {
		logTitleln("starting loop")
		if !(*skipIF) {
			err := getInterfaceNameFile()
			if err != nil {
				slog.Error(fmt.Sprintf("get IF err: %v", err))
				if interfaceName == "" {
					time.Sleep(2 * time.Second)
					continue
				}
			}
		}

		sleep_sec = ((math.Mod(float64(time.Now().Unix()), checkInterval.Seconds())) - checkInterval.Seconds() ) * -1

		sleep_dur = time.Duration(sleep_sec * float64(time.Second))
		sleep_ut = time.Now().Add(sleep_dur).Unix()


		time.Sleep(sleep_dur)

		config := getGlobalConfig()
		services := getGlobalServices()

		ut = get_dns_ut()

		// Get the current IPv6 prefix
		currentIPv6Prefix, err := get_prefix(config, false)
		if err != nil {
			slog.Error(fmt.Sprintln("Error:", err))
			return
		}

		if currentIPv6Prefix != lastIPv6Prefix { filesInvalidAdd(1) }


		startFilesInvalid := getFilesInvalid()
		if getIsFilesInvalid() {

			slog.Info(fmt.Sprintf("slept until: %v", sleep_ut))
			slog.Info(fmt.Sprintf("prefix: %v", currentIPv6Prefix))


			for _, service := range services {
				changed, err := repSaveFileAndFolder(service, currentIPv6Prefix)
				if err != nil {
					slog.Error(fmt.Sprintln("Error:", err))

					// return
				}

				if changed {
					logTitleln("some files changed")
					restartServices(service)
				}
			}


			lastIPv6Prefix = currentIPv6Prefix
			slog.Info("Files updated successfully.")


		}

		filesInvalidDone(startFilesInvalid)
	}

}

func init() {
	ctx := context.Background()
	setEtcDirs()
	loadConfigs(ctx)
	globalStartTime = time.Now()
}


func main() {

	daemonFlag := flag.Bool("d", false, "run as daemon")
	pidFile := flag.String("pid", fmt.Sprintf("/var/run/%v.pid", progName), "PID file path")
	logFile := flag.String("log", fmt.Sprintf("/var/log/%v.log", progName), "log file path for rotated logs")
	niceness := flag.Int("nice", 5, "the niceness to use for the proc")
	skipIF := flag.Bool("skip_interface", false, "skip getting if not needed")

	flag.Parse()


	if *daemonFlag {
		cntxt := &daemon.Context{
			PidFileName: *pidFile,
			PidFilePerm: 0644,
			LogFileName: *logFile,
			LogFilePerm: 0640,
			WorkDir:     "./",
			Umask:       027,
			Args:        os.Args,
		}
		d, err := cntxt.Reborn()
		if err != nil {
			slog.Error(fmt.Sprintf("unable to daemonize: %v", err))
			os.Exit(1)
		}
		if d != nil {
			return
		}
		defer cntxt.Release()
		logFileWriter = lumberjack.Logger{
			Filename:   *logFile,
			MaxSize:    5,    // megabytes
			MaxBackups: 3,    // keep up to n old log files
			MaxAge:     28,   // days
		}

		// log.SetOutput(&logFile)

		handl := slog.NewTextHandler(&logFileWriter, &slog.HandlerOptions{})
		// if you don't do this it prints to log maybe? what?
		slog.SetDefault(slog.New(handl))
	} else {

		handl := tint.NewHandler(os.Stdout, &tint.Options{
			TimeFormat: "2006年01月02日 15時04分05.000秒",
		})
		slog.SetDefault(slog.New(handl))

	}

	if err := setNiceness(*niceness); err != nil {
		slog.Warn(fmt.Sprintf("warning: failed to set priority: %v", err))
	}


	slog.Info("starting program")
	// log.Println("starting program")
	// log.Println("using if:", interfaceName)


	var wg sync.WaitGroup

	wg.Go(func() {
		templateLoop(skipIF)
	})

	wg.Go(func() {
		ctx := context.Background()

		for {
			st := time.Now()
			conf := getGlobalConfig()
			checkHosts(ctx, conf)

			sleepTime := time.Duration(conf.HostsCheckTime * float64(time.Second)) - time.Since(st)
			slog.Info(fmt.Sprintf("ping sleeping for %v", sleepTime))
			time.Sleep(sleepTime)
		}
	})

	wg.Go(func() {
		ctx := context.Background()

		for {
			st := time.Now()
			loadConfigs(ctx)
			time.Sleep((25 * time.Second) - time.Since(st))
		}
	})

	wg.Go(func() {
		st := time.Now()
		// shortSleepTime := (25 * time.Second) - time.Since(st)
		longSleepTime := (100 * time.Second) - time.Since(st)
		for {
			st := time.Now()
			filesInvalidAdd(1)

			// shortSleepTime = (25 * time.Second) - time.Since(st)
			longSleepTime = (100 * time.Second) - time.Since(st)
			time.Sleep(min(
				// shortSleepTime,
				longSleepTime,
			))

		}
	})

	wg.Wait()

}
