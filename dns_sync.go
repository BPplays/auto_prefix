package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/libdns/libdns"
	"github.com/libdns/cloudflare"
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
		localTargetMap[record.Name] = record
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
		if record.Type == "TXT" && strings.HasPrefix(record.Name, "_asrv-id.") {
			txtRecords[record.Name] = record
		}
	}

	// Find all the main records that have a matching _asrv-id TXT record with correct identifier
	for _, record := range records {
		if record.Type == "TXT" {
			continue
		}

		// For non-TXT records, check if there's a corresponding _asrv-id TXT record
		txtRecordName := "_asrv-id." + record.Name
		txtRecord, exists := txtRecords[txtRecordName]
		if !exists {
			continue
		}
		
		// The identifier value is stored as the content of the txt record (with quotes)
		// Check if the TXT record contains our identifier 
		if strings.Contains(txtRecord.Value, "\""+identifier+"\"") {
			result[record.Name] = record
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

// parseZoneFile parses a single BIND9 zone file using miekg/dns
func parseZoneFile(filename string) ([]libdns.Record, error) {
	file, err := dns.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open zone file: %w", err)
	}
	defer file.Close()

	var records []libdns.Record

	for {
		message, err := file.ReadMessage()
		if err != nil {
			// EOF is expected at the end of zone file
			break
		}

		// Process each resource record (RR) in the message
		for _, rr := range message.Answer {
			libdnsRecord := dnsToLibdnsRecord(rr)
			if libdnsRecord.Name != "" {
				records = append(records, libdnsRecord)
			}
		}
	}

	return records, nil
}

// dnsToLibdnsRecord converts a miekg/dns record to a libdns Record
func dnsToLibdnsRecord(rr dns.RR) libdns.Record {
	record := libdns.Record{
		Name:  strings.TrimSuffix(rr.Header().Name, "."),
		Type:  rr.Header().Class,
		Value: "",
		TTL:   uint32(rr.Header().Ttl),
	}

	switch v := rr.(type) {
	case *dns.A:
		record.Value = v.A.String()
	case *dns.AAAA:
		record.Value = v.AAAA.String()
	case *dns.CNAME:
		record.Value = v.Target
	case *dns.MX:
		record.Value = fmt.Sprintf("%d %s", v.Preference, v.Mx)
	case *dns.NS:
		record.Value = v.Ns
	case *dns.PTR:
		record.Value = v.Ptr
	case *dns.SRV:
		record.Value = fmt.Sprintf("%d %d %d %s", v.Priority, v.Weight, v.Port, v.Target)
	case *dns.TXT:
		// Handle TXT record value format - preserve content but remove the outer quotes for parsing
		var txtValues []string
		for _, txt := range v.Txt {
			txtValues = append(txtValues, "\""+txt+"\"")
		}
		record.Value = strings.Join(txtValues, " ")
	}

	return record
}

// getProvider creates a libdns provider instance based on the provider name and config
func getProvider(providerName string, config map[string]any) (libdns.RecordSetterDeleter, error) {
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
func (d *DnsServiceSync) cleanupRemote(provider libdns.RecordSetterDeleter, allRemoteRecords []libdns.Record, ownedRecords map[string]libdns.Record, localTargetMap map[string]libdns.Record) error {
	d.logger.Info("Starting remote cleanup")

	// Remove orphaned _asrv-id TXT records first
	for _, record := range allRemoteRecords {
		if record.Type == "TXT" && strings.HasPrefix(record.Name, "_asrv-id.") {
			// Check if the corresponding main record still exists in local targets
			mainRecordName := strings.TrimPrefix(record.Name, "_asrv-id.")
			
			// If no main record, delete this TXT record
			if _, existsInLocal := localTargetMap[mainRecordName]; !existsInLocal {
				d.logger.Info("Deleting orphaned TXT record", "name", record.Name)
				err := provider.DeleteRecords(d.ctx, d.service.RemoteZone, []libdns.Record{record})
				if err != nil {
					return fmt.Errorf("failed to delete orphaned TXT record %s: %w", record.Name, err)
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
				if record.Name == txtRecordName && record.Type == "TXT" {
					err := provider.DeleteRecords(d.ctx, d.service.RemoteZone, []libdns.Record{record})
					if err != nil {
						return fmt.Errorf("failed to delete TXT record %s: %w", record.Name, err)
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
func (d *DnsServiceSync) updateRemote(provider libdns.RecordSetterDeleter, localRecords []libdns.Record, ownedRecords map[string]libdns.Record, localTargetMap map[string]libdns.Record) error {
	d.logger.Info("Starting remote update")

	for _, localRecord := range localRecords {
		// Skip TXT records that are not identifier records - these will be handled in pairs
		if strings.HasPrefix(localRecord.Name, "_asrv-id.") && localRecord.Type == "TXT" {
			continue
		}
		
		// For non-TXT records, check if it needs to be created or updated
		mainName := localRecord.Name
		
		// Create the identifier TXT record first
		txtRecordName := "_asrv-id." + mainName
		txtRecord := libdns.Record{
			Name:  txtRecordName,
			Type:  "TXT",
			Value: "\"" + d.service.Identifier + "\"",
			TTL:   localRecord.TTL,
		}
		
		// Handle creation/update of TXT record first (atomic - always do TXT first)
		err := provider.SetRecords(d.ctx, d.service.RemoteZone, []libdns.Record{txtRecord})
		if err != nil {
			return fmt.Errorf("failed to set TXT record %s: %w", txtRecordName, err)
		}
		
		// Now handle the main record
		err = provider.SetRecords(d.ctx, d.service.RemoteZone, []libdns.Record{localRecord})
		if err != nil {
			return fmt.Errorf("failed to set main record %s: %w", localRecord.Name, err)
		}
	}

	return nil
}