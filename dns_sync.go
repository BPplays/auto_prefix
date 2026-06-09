package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
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

func NewDnsServiceSync(service *DnsService, logger *slog.Logger) *DnsServiceSync {
	ctx, cancel := context.WithCancel(context.Background())
	return &DnsServiceSync{service: service, logger: logger, ctx: ctx, cancelFunc: cancel}
}

func (d *DnsServiceSync) Stop() {
	d.cancelFunc()
}

func (d *DnsServiceSync) Sync() error {
	d.logger.Info("Starting DNS sync", "service", d.service.FriendlyName)

	provider, err := getProvider(d.service.Provider, d.service.ProviderConfig)
	if err != nil {
		return fmt.Errorf("failed to create provider: %w", err)
	}

	localRecords, err := parseZoneFiles(d.service.ZoneFiles)
	if err != nil {
		return fmt.Errorf("failed to parse zone files: %w", err)
	}
	d.logger.Info("Parsed local records", "count", len(localRecords))

	remoteRecords, err := provider.GetRecords(d.ctx, d.service.RemoteZone)
	if err != nil {
		return fmt.Errorf("failed to fetch remote records: %w", err)
	}
	d.logger.Info("Fetched remote records", "count", len(remoteRecords))

	ownedRecords := identifyOwnedRecords(remoteRecords, d.service.Identifier)
	d.logger.Info("Identified owned records", "count", len(ownedRecords))

	localTargetMap := make(map[string]libdns.Record)
	for _, r := range localRecords {
		localTargetMap[r.RR().Name] = r
	}

	err = d.cleanupRemote(provider, remoteRecords, ownedRecords, localTargetMap)
	if err != nil {
		return fmt.Errorf("failed during cleanup: %w", err)
	}

	err = d.updateRemote(provider, localRecords, ownedRecords, localTargetMap)
	if err != nil {
		return fmt.Errorf("failed during update: %w", err)
	}

	d.logger.Info("DNS sync completed successfully")
	return nil
}

func identifyOwnedRecords(records []libdns.Record, identifier string) map[string]libdns.Record {
	result := make(map[string]libdns.Record)

	txtRecords := make(map[string]libdns.Record)
	for _, record := range records {
		r := record.RR()
		if r.Type == "TXT" && strings.HasPrefix(r.Name, "_asrv-id.") {
			txtRecords[r.Name] = record
		}
	}

	for _, record := range records {
		recordRR := record.RR()
		if recordRR.Type == "TXT" {
			continue
		}

		txtRecordName := "_asrv-id." + recordRR.Name
		txtRecord, exists := txtRecords[txtRecordName]
		if !exists {
			continue
		}

		if strings.Contains(txtRecord.RR().Data, "\""+identifier+"\"") {
			result[recordRR.Name] = record
		}
	}

	return result
}

func parseZoneFiles(zoneFiles []string) ([]libdns.Record, error) {
	var allRecords []libdns.Record
	for _, f := range zoneFiles {
		recs, err := parseZoneFile(f)
		if err != nil {
			return nil, fmt.Errorf("error parsing zone file %s: %w", f, err)
		}
		allRecords = append(allRecords, recs...)
	}
	return allRecords, nil
}

func parseZoneFile(filename string) ([]libdns.Record, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open zone file: %w", err)
	}
	defer f.Close()

	zp := dns.NewZoneParser(f, "", filename)

	var records []libdns.Record
	for {
		rec, ok := zp.Next()
		if !ok {
			break
		}
		rr, isRR := rec.(dns.RR)
		if !isRR || rr.Header().Class != dns.ClassINET {
			continue
		}

		libdnsRec := dnsToLibdnsRecord(rr)
		if libdnsRec.RR().Name != "" {
			records = append(records, libdnsRec)
		}
	}

	if err := zp.Err(); err != nil {
		return nil, fmt.Errorf("error parsing zone file: %w", err)
	}

	return records, nil
}

func dnsToLibdnsRecord(rr dns.RR) libdns.Record {
	header := rr.Header()
	name := strings.TrimSuffix(header.Name, ".")
	ttl := time.Duration(header.TTL) * time.Second

	switch rr.(type) {
	case *dns.A:
		ip, _ := netip.ParseAddr(rr.(*dns.A).A.String())
		return &libdns.Address{Name: name, TTL: ttl, IP: ip}
	case *dns.AAAA:
		ip, _ := netip.ParseAddr(rr.(*dns.AAAA).AAAA.String())
		return &libdns.Address{Name: name, TTL: ttl, IP: ip}
	case *dns.CNAME:
		return &libdns.CNAME{Name: name, TTL: ttl, Target: rr.(*dns.CNAME).Target}
	case *dns.MX:
		return &libdns.MX{Name: name, TTL: ttl, Preference: rr.(*dns.MX).Preference, Target: rr.(*dns.MX).Mx}
	case *dns.NS:
		return &libdns.NS{Name: name, TTL: ttl, Target: rr.(*dns.NS).Ns}
	case *dns.PTR:
		r := libdns.RR{
			Name: name,
			Type: "PTR",
			TTL:  ttl,
			Data: rr.(*dns.PTR).Ptr,
		}
		return r
	case *dns.SRV:
		s := rr.(*dns.SRV)

		svc := "_asrv-id"
		tr := "tcp"
		baseName := name
		if idx := strings.Index(baseName, "_"); idx > 0 {
			baseName = baseName[idx+1:]
			if dotIdx := strings.Index(baseName, "."); dotIdx > 0 {
				baseName = baseName[dotIdx+1:]
			}
			tr = svc
			svc = ""
		}

		return libdns.SRV{
			Service:  svc,
			Transport: tr,
			Name:     name,
			TTL:      ttl,
			Priority: s.Priority,
			Weight:   s.Weight,
			Port:     s.Port,
			Target:   s.Target,
		}
	case *dns.TXT:
		return &libdns.TXT{Name: name, TTL: ttl, Text: strings.Join(rr.(*dns.TXT).Txt, "")}
	default:
		r := libdns.RR{
			Name: name,
			TTL:  ttl,
		}
		r.Data = rr.String()
		return r
	}
}

type Provider interface {
	libdns.RecordGetter
	libdns.RecordSetter
	libdns.RecordDeleter
}

func getProvider(providerName string, config map[string]any) (Provider, error) {
	switch providerName {
	case "cloudflare":
		apiToken, exists := config["api_token"]
		if !exists {
			return nil, fmt.Errorf("api_token not provided for cloudflare provider")
		}
		return &cloudflare.Provider{APIToken: apiToken.(string)}, nil
	default:
		return nil, fmt.Errorf("unsupported DNS provider: %s", providerName)
	}
}

func (d *DnsServiceSync) cleanupRemote(provider Provider, all []libdns.Record, owned map[string]libdns.Record, localMap map[string]libdns.Record) error {
	d.logger.Info("Starting remote cleanup")

	for _, record := range all {
		rRec := record.RR()
		if rRec.Type == "TXT" && strings.HasPrefix(rRec.Name, "_asrv-id.") {
			mainName := strings.TrimPrefix(rRec.Name, "_asrv-id.")
			if _, inLocal := localMap[mainName]; !inLocal {
				d.logger.Info("Deleting orphaned TXT record", "name", rRec.Name)
				_, err := provider.DeleteRecords(d.ctx, d.service.RemoteZone, []libdns.Record{record})
				if err != nil {
					return fmt.Errorf("failed to delete orphaned TXT record %s: %w", rRec.Name, err)
				}
			}
		}
	}

	for mainName := range owned {
		if _, inLocal := localMap[mainName]; !inLocal {
			d.logger.Info("Deleting orphaned record", "name", mainName)

			txtName := "_asrv-id." + mainName
			for _, record := range all {
				rRec := record.RR()
				if rRec.Name == txtName && rRec.Type == "TXT" {
					_, err := provider.DeleteRecords(d.ctx, d.service.RemoteZone, []libdns.Record{record})
					if err != nil {
						return fmt.Errorf("failed to delete TXT record %s: %w", rRec.Name, err)
					}
					break
				}
			}

			_, err := provider.DeleteRecords(d.ctx, d.service.RemoteZone, []libdns.Record{owned[mainName]})
			if err != nil {
				return fmt.Errorf("failed to delete record %s: %w", mainName, err)
			}
		}
	}

	return nil
}

func (d *DnsServiceSync) updateRemote(provider Provider, localRecords []libdns.Record, ownedMap map[string]libdns.Record, localMap map[string]libdns.Record) error {
	d.logger.Info("Starting remote update")

	for _, rec := range localRecords {
		r := rec.RR()
		if strings.HasPrefix(r.Name, "_asrv-id.") && r.Type == "TXT" {
			continue
		}

		mainName := r.Name

		txtRec := &libdns.TXT{
			Name: "_asrv-id." + mainName,
			TTL:  rec.RR().TTL,
			Text: d.service.Identifier,
		}
		_, err := provider.SetRecords(d.ctx, d.service.RemoteZone, []libdns.Record{txtRec})
		if err != nil {
			return fmt.Errorf("failed to set TXT record %s: %w", txtRec.Name, err)
		}

		_, err = provider.SetRecords(d.ctx, d.service.RemoteZone, []libdns.Record{rec})
		if err != nil {
			return fmt.Errorf("failed to set main record %s: %w", r.Name, err)
		}
	}

	return nil
}
