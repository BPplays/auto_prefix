package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"strings"

	"codeberg.org/miekg/dns"
)

// DnsRecord represents a generic DNS record that can be synced to a remote
type DnsRecord struct {
	Name    string
	Type    uint16
	Value   string
	TTL     uint32
	Comment string
}

// DnsProvider defines the interface for DNS providers that support comments
type DnsProvider interface {
	GetRecords(ctx context.Context, zone string) ([]DnsRecord, error)
	SetRecord(ctx context.Context, zone string, record DnsRecord) error
	DeleteRecord(ctx context.Context, zone string, record DnsRecord) error
}

// wrapIdentifier wraps the identifier as requested
func wrapIdentifier(id string) string {
	return fmt.Sprintf("#!##& %s &##!#", id)
}

// parseZoneFiles parses BIND9 zone files and returns a list of DnsRecords
func parseZoneFiles(ctx context.Context, files []string, prefix netip.Prefix, service Service, dnsSvc DnsService) ([]DnsRecord, error) {
	var allRecords []DnsRecord

	for _, filePath := range files {
		content, err := os.ReadFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("error reading zone file %s: %w", filePath, err)
		}

		// Apply templating using the existing replaceVars function
		replacedContent, err := replaceVars(&content, &prefix, service)
		if err != nil {
			return nil, fmt.Errorf("error replacing vars in %s: %w", filePath, err)
		}

		// Parse BIND zone file
		z := dns.ParseZone(strings.NewReader(replacedContent), dnsSvc.Remote.Zone)
		if z == nil {
			return nil, fmt.Errorf("failed to parse zone file %s", filePath)
		}

		for _, rr := range z.RRs {
			var val string
			switch r := rr.(type) {
			case *dns.A:
				val = r.A.String()
			case *dns.AAAA:
				val = r.AAAA.String()
			case *dns.CNAME:
				val = r.Target
			case *dns.MX:
				val = fmt.Sprintf("%d %s", r.Preference, r.Mx)
			case *dns.TXT:
				val = strings.Join(r.Txt, " ")
			case *dns.NS:
				val = r.Ns
			case *dns.PTR:
				val = r.Ptr
			default:
				continue
			}

			allRecords = append(allRecords, DnsRecord{
				Name:    rr.Hdr.Name,
				Type:    rr.Hdr.Ks,
				Value:   val,
				TTL:     uint32(rr.Hdr.Ttl),
				Comment: wrapIdentifier(dnsSvc.Identifier),
			})
		}
	}

	return allRecords, nil
}

// SyncDns synchronized the local zone files to the remote provider
func SyncDns(ctx context.Context, prefix netip.Prefix, service Service, dnsSvc DnsService, provider DnsProvider) error {
	slog.Info("Syncing DNS records", "service", service.Name, "remote", dnsSvc.FriendlyName)

	// 1. Parse local files
	localRecords, err := parseZoneFiles(ctx, dnsSvc.Files, prefix, service, dnsSvc)
	if err != nil {
		return fmt.Errorf("local parse error: %w", err)
	}

	// 2. Fetch remote records
	remoteRecords, err := provider.GetRecords(ctx, dnsSvc.Remote.Zone)
	if err != nil {
		return fmt.Errorf("remote fetch error: %w", err)
	}

	// 3. Identify records belonging to this service on remote
	identifier := wrapIdentifier(dnsSvc.Identifier)
	var serviceRemoteRecords []DnsRecord
	for _, rr := range remoteRecords {
		if strings.Contains(rr.Comment, identifier) {
			serviceRemoteRecords = append(serviceRemoteRecords, rr)
		}
	}

	// 4. Remove remote records not present locally
	for _, remoteRr := range serviceRemoteRecords {
		found := false
		for _, localRr := range localRecords {
			if remoteRr.Name == localRr.Name && remoteRr.Type == localRr.Type && remoteRr.Value == localRr.Value {
				found = true
				break
			}
		}
		if !found {
			slog.Info("Removing obsolete DNS record", "name", remoteRr.Name, "type", remoteRr.Type)
			if err := provider.DeleteRecord(ctx, dnsSvc.Remote.Zone, remoteRr); err != nil {
				slog.Error("Failed to delete record", "name", remoteRr.Name, "err", err)
			}
		}
	}

	// 5. Apply local records to remote
	for _, localRr := range localRecords {
		exists := false
		for _, remoteRr := range remoteRecords {
			if localRr.Name == remoteRr.Name && localRr.Type == remoteRr.Type && localRr.Value == remoteRr.Value {
				exists = true
				break
			}
		}
		if !exists {
			slog.Info("Adding DNS record", "name", localRr.Name, "type", localRr.Type)
			if err := provider.SetRecord(ctx, dnsSvc.Remote.Zone, localRr); err != nil {
				slog.Error("Failed to set record", "name", localRr.Name, "err", err)
			}
		}
	}

	return nil
}
