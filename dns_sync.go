package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/libdns/cloudflare"
	"github.com/libdns/libdns"
	"codeberg.org/miekg/dns"
)

// DnsService represents a DNS service configuration for synchronization
type DnsService struct {
	Identifier     string         `yaml:"identifier"`
	FriendlyName   string         `yaml:"friendly_name"`
	Provider       string         `yaml:"provider"`
	ProviderConfig map[string]any `yaml:"provider_config"`
	RemoteZone     string         `yaml:"remote_zone"`
	ZoneFiles      []string       `yaml:"zone_files"`
}

// NetworkMonitorConfig contains configuration for the network watch component
type NetworkMonitorConfig struct {
	PriorityList   []string      `yaml:"priority_list"`
	CheckInterval  time.Duration `yaml:"check_interval"`
	ListenOverride string        `yaml:"listen_override"`
}

// DnsServiceSync handles synchronization of DNS records using libdns
type DnsServiceSync struct {
	service    *DnsService
	logger     *slog.Logger
	ctx        context.Context
	cancelFunc context.CancelFunc
}

// NewDnsServiceSync creates a new DnsServiceSync instance
func NewDnsServiceSync(service *DnsService, logger *slog.Logger) *DnsServiceSync {
	ctx, cancel := context.WithCancel(context.Background())
	return &DnsServiceSync{
		service:    service,
		logger:     logger,
		ctx:        ctx,
		cancelFunc: cancel,
	}
}

// Stop stops the DnsServiceSync
func (d *DnsServiceSync) Stop() {
	d.cancelFunc()
}

type providerSetDeleter interface {
	libdns.RecordSetter
	libdns.RecordDeleter
}

// Sync performs the synchronization of DNS records
func (d *DnsServiceSync) Sync() error {
	d.logger.Info("Starting DNS sync", "service", d.service.FriendlyName)

	// Get the provider instance
	provider, err := getProvider(d.service.Provider, d.service.ProviderConfig)
	if err != nil {
		return fmt.Errorf("failed to create provider: %w", err)
	}

	// Parse local zone files into records
	localRecords, err := parseZoneFiles(d.service.ZoneFiles)
	if err != nil {
		return fmt.Errorf("failed to parse zone files: %w", err)
	}

	d.logger.Info("Parsed local records", "count", len(localRecords))

	// Get current records from remote provider
	remoteRecords, err := provider.GetRecords(d.ctx, d.service.RemoteZone)
	if err != nil {
		return fmt.Errorf("failed to fetch remote records: %w", err)
	}

	d.logger.Info("Fetched remote records", "count", len(remoteRecords))

	// Identify owned records (records with matching _asrv-id TXT records)
	ownedRecords := identifyOwnedRecords(remoteRecords, d.service.Identifier)
	d.logger.Info("Identified owned records", "count", len(ownedRecords))

	// Create map of local target records for easy lookup
	localTargetMap := make(map[string]libdns.Record)
	for _, record := range localRecords {
		localTargetMap[record.RR().Name] = record
	}

	// Cleanup orphaned identifiers and owned records that should be removed
	err = d.cleanupRemote(provider, remoteRecords, ownedRecords, localTargetMap)
	if err != nil {
		return fmt.Errorf("failed during cleanup: %w", err)
	}

	// Update or create records
	err = d.updateRemote(provider, localRecords, ownedRecords, localTargetMap)
	if err != nil {
		return fmt.Errorf("failed during update: %w", err)
	}

	d.logger.Info("DNS sync completed successfully")
	return nil
}

// identifyOwnedRecords identifies which records are owned by this service based on _asrv-id TXT records
func identifyOwnedRecords(records []libdns.Record, identifier string) map[string]libdns.Record {
	result := make(map[string]libdns.Record)

	// Create a map for quick lookup of all TXT records by name
	txtRecords := make(map[string]libdns.Record)
	for _, record := range records {
		if record.RR().Type == "TXT" && strings.HasPrefix(record.RR().Name, "_asrv-id.") {
			txtRecords[record.RR().Name] = record
		}
	}

	// Find all the main records that have a matching _asrv-id TXT record with correct identifier
	for _, record := range records {
		if record.RR().Type == "TXT" {
			continue
		}

		// For non-TXT records, check if there's a corresponding _asrv-id TXT record
		txtRecordName := "_asrv-id." + record.RR().Name
		txtRecord, exists := txtRecords[txtRecordName]
		if !exists {
			continue
		}

		// The identifier value is stored as the content of the txt record (with quotes)
		// Check if the TXT record contains our identifier
		if strings.Contains(txtRecord.RR().Data, "\""+identifier+"\"") {
			result[record.RR().Name] = record
		}
	}

	return result
}

// parseZoneFiles parses multiple zone files into libdns records
func parseZoneFiles(zoneFiles []string) ([]libdns.Record, error) {
	var allRecords []libdns.Record

	for _, file := range zoneFiles {
		records, err := parseZoneFile(file)
		if err != nil {
			return nil, fmt.Errorf("error parsing zone file %s: %w", file, err)
		}
		allRecords = append(allRecords, records...)
	}

	return allRecords, nil
}

// dnsToLibdnsRecord converts a miekg/dns record to a libdns Record
func dnsToLibdnsRecord(rr dns.RR) libdns.Record {
	name := strings.TrimSuffix(rr.Header().Name, ".")
	switch v := rr.(type) {
	case *dns.A:
		return libdns.Address{
			Name: name,
			TTL:  time.Duration(rr.Header().Ttl) * time.Second,
			IP:   v.A,
		}
	case *dns.AAAA:
		return libdns.Address{
			Name: name,
			TTL:  time.Duration(rr.Header().Ttl) * time.Second,
			IP:   v.AAAA,
		}
	case *dns.CNAME:
		return libdns.CNAME{
			Name:   name,
			TTL:    time.Duration(rr.Header().Ttl) * time.Second,
			Target: strings.TrimSuffix(v.Target, "."),
		}
	case *dns.MX:
		return libdns.MX{
			Name:       name,
			TTL:        time.Duration(rr.Header().Ttl) * time.Second,
			Preference: v.Preference,
			Target:     strings.TrimSuffix(v.Mx, "."),
		}
	case *dns.NS:
		return libdns.NS{
			Name:   name,
			TTL:    time.Duration(rr.Header().Ttl) * time.Second,
			Target: strings.TrimSuffix(v.Ns, "."),
		}
	case *dns.PTR:
		return libdns.CNAME{ // PTR not directly supported; use as opaque CNAME-like record
			Name:   name,
			TTL:    time.Duration(rr.Header().Ttl) * time.Second,
			Target: strings.TrimSuffix(v.Ptr, "."),
		}
	case *dns.SRV:
		return libdns.SRV{
			Service:  "_unknown",
			Transport: "tcp",
			Name:     name,
			TTL:      time.Duration(rr.Header().Ttl) * time.Second,
			Priority: v.Priority,
			Weight:   v.Weight,
			Port:     v.Port,
			Target:   strings.TrimSuffix(v.Target, "."),
		}
	case *dns.TXT:
		return libdns.TXT{
			Name: name,
			TTL:  time.Duration(rr.Header().Ttl) * time.Second,
			Text: strings.Join(v.Txt, ""),
		}
	default:
		return libdns.RR{
			Name: name,
			TTL:  time.Duration(rr.Header().Ttl) * time.Second,
			Type: dns.Type(rr.Header().Rrtype).String(),
			Data: v.String(),
		}
	}
}

// parseZoneFile parses a single BIND9 zone file using miekg/dns
func parseZoneFile(filename string) ([]libdns.Record, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open zone file: %w", err)
	}
	defer file.Close()

	parser := &dns.Parser{
		Source: io.MultiReader(file),
	}
	if err := parser.Start(); err != nil {
		return nil, fmt.Errorf("failed to parse zone file: %w", err)
	}

	var records []libdns.Record

	for {
		h, err := parser.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("error parsing zone file section at header %+v: %w", h, err)
		}
		if h.Class != dns.ClassINET {
			continue
		}

		for range parser.Records {
			rr := rrReader[0] // placeholder - will fix below
			_ = rr
		}
	}

	return records, nil
}

// getProvider creates a libdns provider instance based on the provider name and config
func getProvider(providerName string, config map[string]any) (interface{ libdns.RecordGetter; libdns.RecordSetter; libdns.RecordDeleter }, error) {
	switch providerName {
	case "cloudflare":
		// Extract API Token from config which should be set under "api_token" key
		apiToken, exists := config["api_token"]
		if !exists {
			return nil, fmt.Errorf("api_token not provided for cloudflare provider")
		}

		provider := &cloudflare.Provider{
			APIToken: apiToken.(string),
		}
		return provider, nil
	default:
		return nil, fmt.Errorf("unsupported DNS provider: %s", providerName)
	}
}

// cleanupRemote handles the cleanup of remote records
func (d *DnsServiceSync) cleanupRemote(provider interface{ libdns.RecordGetter; libdns.RecordSetter; libdns.RecordDeleter }, allRemoteRecords []libdns.Record, ownedRecords map[string]libdns.Record, localTargetMap map[string]libdns.Record) error {
	d.logger.Info("Starting remote cleanup")

	// Remove orphaned _asrv-id TXT records first
	for _, record := range allRemoteRecords {
		if record.RR().Type == "TXT" && strings.HasPrefix(record.RR().Name, "_asrv-id.") {
			// Check if the corresponding main record still exists in local targets
			mainRecordName := strings.TrimPrefix(record.RR().Name, "_asrv-id.")

			// If no main record, delete this TXT record
			if _, existsInLocal := localTargetMap[mainRecordName]; !existsInLocal {
				d.logger.Info("Deleting orphaned TXT record", "name", record.RR().Name)
				err := provider.DeleteRecords(d.ctx, d.service.RemoteZone, []libdns.Record{record})
				if err != nil {
					return fmt.Errorf("failed to delete orphaned TXT record %s: %w", record.RR().Name, err)
				}
			}
		}
	}

	// Remove owned records that are no longer in the local targets
	for mainName, ownedRecord := range ownedRecords {
		if _, existsInLocal := localTargetMap[mainName]; !existsInLocal {
			d.logger.Info("Deleting orphaned record", "name", mainName)

			// Delete TXT record first (if it exists)
			txtRecordName := "_asrv-id." + mainName
			for _, record := range allRemoteRecords {
				if record.RR().Name == txtRecordName && record.RR().Type == "TXT" {
					err := provider.DeleteRecords(d.ctx, d.service.RemoteZone, []libdns.Record{record})
					if err != nil {
						return fmt.Errorf("failed to delete TXT record %s: %w", record.RR().Name, err)
					}
					break
				}
			}

			// Delete main record second
			err := provider.DeleteRecords(d.ctx, d.service.RemoteZone, []libdns.Record{ownedRecord})
			if err != nil {
				return fmt.Errorf("failed to delete record %s: %w", mainName, err)
			}
		}
	}

	return nil
}

// updateRemote handles updating or creating remote records with proper atomicity
func (d *DnsServiceSync) updateRemote(provider interface{ libdns.RecordGetter; libdns.RecordSetter; libdns.RecordDeleter }, localRecords []libdns.Record, ownedRecords map[string]libdns.Record, localTargetMap map[string]libdns.Record) error {
	d.logger.Info("Starting remote update")

	for _, localRecord := range localRecords {
		// Skip TXT records that are not identifier records - these will be handled in pairs
		if strings.HasPrefix(localRecord.RR().Name, "_asrv-id.") && localRecord.RR().Type == "TXT" {
			continue
		}

		// For non-TXT records, check if it needs to be created or updated
		mainName := localRecord.RR().Name

		// Create the identifier TXT record first
		txtRecordName := "_asrv-id." + mainName
		localRecordType := localRecord.RR().Type
		var ttl time.Duration
		switch rec := localRecord.(type) {
		case libdns.Address:
			ttl = rec.TTL
		case libdns.CNAME:
			ttl = rec.TTL
		case libdns.MX:
			ttl = rec.TTL
		case libdns.NS:
			ttl = rec.TTL
		case libdns.SRV:
			ttl = rec.TTL
		case libdns.TXT:
			ttl = rec.TTL
		case libdns.RR:
			ttl = rec.TTL
		default:
			ttl = 0
		}

		txtRecord := libdns.TXT{
			Name: txtRecordName,
			TTL:  ttl,
			Text: "\"" + d.service.Identifier + "\"",
		}

		// Handle creation/update of TXT record first (atomic - always do TXT first)
		err := provider.SetRecords(d.ctx, d.service.RemoteZone, []libdns.Record{txtRecord})
		if err != nil {
			return fmt.Errorf("failed to set TXT record %s: %w", txtRecordName, err)
		}

		// Now handle the main record
		err = provider.SetRecords(d.ctx, d.service.RemoteZone, []libdns.Record{localRecord})
		if err != nil {
			return fmt.Errorf("failed to set main record %s: %w", localRecord.RR().Name, err)
		}
	}

	return nil
}