package dnspod

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/libdns/libdns"
	d "github.com/nrdcg/dnspod-go"
)

// RecordWithID implements libdns.Record and stores DNSPod record ID
type RecordWithID struct {
	ResourceRecord libdns.RR
	ID             string
}

func (r *RecordWithID) RR() libdns.RR {
	return r.ResourceRecord
}

func (r *RecordWithID) GetID() string {
	return r.ID
}

// Client ...
type Client struct {
	client     *d.Client
	mutex      sync.Mutex
	domainList []d.Domain
	// api is a test seam; nil means talk to the real DNSPod API.
	api dnsAPI
}

// dnsAPI abstracts the dnspod-go calls used by this provider, so the
// ID-stripping fallback paths can be unit tested without network access.
type dnsAPI interface {
	listDomains() ([]d.Domain, error)
	listRecords(domainID, subDomain string) ([]d.Record, error)
	createRecord(domainID string, rec d.Record) (d.Record, error)
	updateRecord(domainID, recordID string, rec d.Record) error
	deleteRecord(domainID, recordID string) error
}

// apiClient returns the injected test double when present, otherwise the
// real DNSPod client (methods on *Client, promoted through the embedding).
func (p *Provider) apiClient() dnsAPI {
	if p.api != nil {
		return p.api
	}
	return p
}

func (c *Client) listDomains() ([]d.Domain, error) {
	domains, _, err := c.client.Domains.List()
	return domains, err
}

func (c *Client) listRecords(domainID, subDomain string) ([]d.Record, error) {
	records, _, err := c.client.Records.List(domainID, subDomain)
	return records, err
}

func (c *Client) createRecord(domainID string, rec d.Record) (d.Record, error) {
	created, _, err := c.client.Records.Create(domainID, rec)
	return created, err
}

func (c *Client) updateRecord(domainID, recordID string, rec d.Record) error {
	_, _, err := c.client.Records.Update(domainID, recordID, rec)
	return err
}

func (c *Client) deleteRecord(domainID, recordID string) error {
	_, err := c.client.Records.Delete(domainID, recordID)
	return err
}

func (p *Provider) getClient() error {
	if p.client == nil {
		params := d.CommonParams{LoginToken: p.APIToken, Format: "json"}
		p.client = d.NewClient(params)
	}

	return nil
}
func (p *Provider) getDomains() ([]d.Domain, error) {
	if len(p.domainList) > 0 {
		return p.domainList, nil
	}
	domains, err := p.apiClient().listDomains()
	if nil != err {
		return p.domainList, err
	}
	p.domainList = domains
	return p.domainList, nil
}
func (p *Provider) getDomainIDByDomainName(domainName string) (string, error) {
	domains, err := p.getDomains()
	if nil != err {
		return "", err
	}
	domainName = strings.Trim(domainName, ".")
	for _, domain := range domains {
		if domain.Name == domainName {
			return string(domain.ID), nil
		}
	}
	return "", fmt.Errorf("Domain %s not found in your dnspod account", domainName)
}

func (p *Provider) getDNSEntries(ctx context.Context, zone string) ([]libdns.Record, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	p.getClient()

	var records []libdns.Record
	domainID, err := p.getDomainIDByDomainName(zone)
	if nil != err {
		//debug
		// fmt.Printf("%s, %s", zone, err.Error())
		return records, fmt.Errorf("Get records err.Zone:%s, Error:%s", zone, err.Error())
	}
	//todo now can only return 100 records
	reqRecords, err := p.apiClient().listRecords(domainID, "")
	if err != nil {
		// fmt.Printf("%s, %s", zone, err.Error())
		return records, fmt.Errorf("Get records err.Zone:%s, Error:%s", zone, err.Error())
	}

	for _, entry := range reqRecords {
		ttl, _ := strconv.ParseInt(entry.TTL, 10, 64)
		rr := libdns.RR{
			Name: entry.Name + "." + strings.Trim(zone, ".") + ".",
			Data: entry.Value,
			Type: entry.Type,
			TTL:  time.Duration(ttl) * time.Second,
		}
		// Store the DNSPod record ID in a custom implementation
		record := &RecordWithID{ResourceRecord: rr, ID: entry.ID}
		records = append(records, record)
	}

	return records, nil
}

func extractRecordName(name string, zone string) string {
	if idx := strings.Index(name, "."+strings.Trim(zone, ".")); idx != -1 {
		return name[:idx]
	}
	return name
}

// findRecordID locates a DNSPod record for callers that lost the record ID:
// certmagic (>= v0.25) stores the normalized RR returned by Record.RR()
// instead of the ID-carrying record AppendRecords produced, so CleanUp
// passes us a bare RR. Returns "" when nothing matches.
//
// For DeleteRecords the value identifies the record (same-name TXT records
// are distinguished by value), so pass requireValueMatch=true. For
// SetRecords the value is the replacement, so identity is name+type only.
func (p *Provider) findRecordID(domainID string, rr libdns.RR, zone string, requireValueMatch bool) (string, error) {
	name := strings.TrimSuffix(extractRecordName(rr.Name, zone), ".")
	entries, err := p.apiClient().listRecords(domainID, name)
	if err != nil {
		return "", fmt.Errorf("Lookup record err.Zone:%s, Name: %s, Error:%s", zone, name, err.Error())
	}
	for _, entry := range entries {
		if entry.Type != rr.Type || entry.Name != name {
			continue
		}
		if requireValueMatch && entry.Value != rr.Data {
			continue
		}
		return entry.ID, nil
	}
	return "", nil
}

func (p *Provider) addDNSEntry(ctx context.Context, zone string, record libdns.Record) (libdns.Record, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	p.getClient()

	rr := record.RR()
	entry := d.Record{
		Name:  extractRecordName(rr.Name, zone),
		Value: rr.Data,
		Type:  rr.Type,
		Line:  "默认",
		TTL:   strconv.Itoa(int(rr.TTL.Seconds())),
	}
	domainID, err := p.getDomainIDByDomainName(zone)
	if nil != err {
		// fmt.Printf("%s, %s, %s, %s, %v", zone, entry.Name, entry.Value, err.Error(), record)
		return record, fmt.Errorf("Create record err.Zone:%s, Name: %s, Value: %s, Error:%s, %v", zone, entry.Name, entry.Value, err.Error(), record)
	}
	rec, err := p.apiClient().createRecord(domainID, entry)
	if err != nil {
		// fmt.Printf("%s, %s, %s, %s, %v", zone, entry.Name, entry.Value, err.Error(), record)
		return record, fmt.Errorf("Create record err.Zone:%s, Name: %s, Value: %s, Error:%s, %v", zone, entry.Name, entry.Value, err.Error(), record)
	}
	// Create a new record with the DNSPod ID
	newRecord := &RecordWithID{ResourceRecord: rr, ID: rec.ID}

	return newRecord, nil
}

func (p *Provider) removeDNSEntry(ctx context.Context, zone string, record libdns.Record) (libdns.Record, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	p.getClient()

	rr := record.RR()
	domainID, err := p.getDomainIDByDomainName(zone)
	if nil != err {
		// fmt.Printf("%s, %s, %s, %s, %v", zone, rr.Name, rr.Data, err.Error(), record)
		return record, fmt.Errorf("Remove record err.Zone:%s, Name: %s, Value: %s, Error:%s", zone, rr.Name, rr.Data, err.Error())
	}
	// Extract DNSPod ID from our custom record type
	recordID := ""
	if rwid, ok := record.(*RecordWithID); ok {
		recordID = rwid.ID
	}
	if recordID == "" {
		// The ID was stripped (certmagic passes a bare RR on CleanUp);
		// fall back to matching by name+type+value. A missing record counts
		// as already deleted, keeping CleanUp idempotent.
		found, ferr := p.findRecordID(domainID, rr, zone, true)
		if ferr != nil {
			return record, ferr
		}
		if found == "" {
			return record, nil
		}
		recordID = found
	}
	err = p.apiClient().deleteRecord(domainID, recordID)
	if err != nil {
		// fmt.Printf("%s, %s, %s, %s, %v", zone, rr.Name, rr.Data, err.Error(), record)
		return record, fmt.Errorf("Remove record err.Zone:%s, Name: %s, Value: %s, Error:%s", zone, rr.Name, rr.Data, err.Error())
	}

	return record, nil
}

func (p *Provider) updateDNSEntry(ctx context.Context, zone string, record libdns.Record) (libdns.Record, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	p.getClient()

	rr := record.RR()
	entry := d.Record{
		Name:  extractRecordName(rr.Name, zone),
		Value: rr.Data,
		Type:  rr.Type,
		Line:  "默认",
		TTL:   strconv.Itoa(int(rr.TTL.Seconds())),
	}
	domainID, err := p.getDomainIDByDomainName(zone)
	if nil != err {
		// fmt.Printf("%s, %s, %s, %s, %v", zone, entry.Name, entry.Value, err.Error(), record)
		return record, fmt.Errorf("Update record err.Zone:%s, Name: %s, Value: %s, Error:%s, %v", zone, entry.Name, entry.Value, err.Error(), record)
	}
	// Extract DNSPod ID from our custom record type
	recordID := ""
	if rwid, ok := record.(*RecordWithID); ok {
		recordID = rwid.ID
	}
	if recordID == "" {
		// Same ID loss as removeDNSEntry. SetRecords contract is
		// update-existing-or-create, so create when nothing matches.
		found, ferr := p.findRecordID(domainID, rr, zone, false)
		if ferr != nil {
			return record, ferr
		}
		if found == "" {
			rec, cerr := p.apiClient().createRecord(domainID, entry)
			if cerr != nil {
				return record, fmt.Errorf("Create record err.Zone:%s, Name: %s, Value: %s, Error:%s, %v", zone, entry.Name, entry.Value, cerr.Error(), record)
			}
			return &RecordWithID{ResourceRecord: rr, ID: rec.ID}, nil
		}
		recordID = found
	}
	err = p.apiClient().updateRecord(domainID, recordID, entry)
	if err != nil {
		// fmt.Printf("%s, %s, %s, %s, %v", zone, entry.Name, entry.Value, err.Error(), record)
		return record, fmt.Errorf("Update record err.Zone:%s, Name: %s, Value: %s, Error:%s, %v", zone, entry.Name, entry.Value, err.Error(), record)
	}

	return record, nil
}
