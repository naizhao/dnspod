package dnspod

import (
	"context"
	"testing"
	"time"

	"github.com/libdns/libdns"
	d "github.com/nrdcg/dnspod-go"
)

// fakeAPI records every call so tests can assert on provider behavior.
type fakeAPI struct {
	domains    []d.Domain
	records    []d.Record
	listedSubs []string
	created    []d.Record
	updatedIDs []string
	deletedIDs []string
}

func (f *fakeAPI) listDomains() ([]d.Domain, error) {
	return f.domains, nil
}

func (f *fakeAPI) listRecords(domainID, subDomain string) ([]d.Record, error) {
	f.listedSubs = append(f.listedSubs, subDomain)
	return f.records, nil
}

func (f *fakeAPI) createRecord(domainID string, rec d.Record) (d.Record, error) {
	f.created = append(f.created, rec)
	rec.ID = "300"
	return rec, nil
}

func (f *fakeAPI) updateRecord(domainID, recordID string, rec d.Record) error {
	f.updatedIDs = append(f.updatedIDs, recordID)
	return nil
}

func (f *fakeAPI) deleteRecord(domainID, recordID string) error {
	f.deletedIDs = append(f.deletedIDs, recordID)
	return nil
}

func newTestProvider(api *fakeAPI) *Provider {
	p := &Provider{APIToken: "123,fake-token"}
	p.api = api
	p.domainList = []d.Domain{{ID: "88", Name: "servbay.com"}}
	return p
}

// TestDeleteRecordsWithIDDeletesByID documents the existing behavior: when the
// caller passes back the ID-carrying record returned by AppendRecords, the
// delete goes straight through by ID without a lookup.
func TestDeleteRecordsWithIDDeletesByID(t *testing.T) {
	api := &fakeAPI{}
	p := newTestProvider(api)

	rec := &RecordWithID{
		ResourceRecord: libdns.RR{Name: "_acme-challenge", Type: "TXT", Data: "tok"},
		ID:             "201",
	}
	deleted, err := p.DeleteRecords(context.Background(), "servbay.com", []libdns.Record{rec})
	if err != nil {
		t.Fatalf("DeleteRecords returned error: %v", err)
	}
	if len(deleted) != 1 {
		t.Fatalf("expected 1 deleted record, got %d", len(deleted))
	}
	if len(api.deletedIDs) != 1 || api.deletedIDs[0] != "201" {
		t.Fatalf("expected delete by ID 201, got %v", api.deletedIDs)
	}
	if len(api.listedSubs) != 0 {
		t.Fatalf("ID path must not perform a lookup, got lists: %v", api.listedSubs)
	}
}

// TestDeleteRecordsWithoutIDFallsBackToNameTypeValue is the regression test for
// the production bug: certmagic (>= v0.25) normalizes records returned by
// AppendRecords via Record.RR(), so CleanUp passes a bare RR without the ID.
// The provider must fall back to matching by name+type+value instead of
// calling the DNSPod API with an empty record ID.
func TestDeleteRecordsWithoutIDFallsBackToNameTypeValue(t *testing.T) {
	api := &fakeAPI{records: []d.Record{
		{ID: "201", Name: "_acme-challenge", Type: "TXT", Value: "tok-current", TTL: "600"},
		{ID: "202", Name: "_acme-challenge", Type: "TXT", Value: "tok-stale", TTL: "600"},
	}}
	p := newTestProvider(api)

	// Shape of the record certmagic passes to DeleteRecords on CleanUp:
	// relative name, no ID.
	rec := libdns.RR{Name: "_acme-challenge", Type: "TXT", Data: "tok-current"}
	_, err := p.DeleteRecords(context.Background(), "servbay.com", []libdns.Record{rec})
	if err != nil {
		t.Fatalf("DeleteRecords returned error: %v", err)
	}
	if len(api.listedSubs) == 0 {
		t.Fatal("expected a fallback Record.List lookup, none happened")
	}
	if len(api.deletedIDs) != 1 || api.deletedIDs[0] != "201" {
		t.Fatalf("expected exactly one delete by ID 201, got %v", api.deletedIDs)
	}
}

// TestDeleteRecordsWithoutIDNoMatchIsNoop: when nothing matches, cleanup must
// be idempotent (no delete call, no error) so certmagic CleanUp never breaks.
func TestDeleteRecordsWithoutIDNoMatchIsNoop(t *testing.T) {
	api := &fakeAPI{records: []d.Record{
		{ID: "202", Name: "_acme-challenge", Type: "TXT", Value: "unrelated", TTL: "600"},
	}}
	p := newTestProvider(api)

	rec := libdns.RR{Name: "_acme-challenge", Type: "TXT", Data: "tok-gone"}
	_, err := p.DeleteRecords(context.Background(), "servbay.com", []libdns.Record{rec})
	if err != nil {
		t.Fatalf("DeleteRecords returned error: %v", err)
	}
	if len(api.deletedIDs) != 0 {
		t.Fatalf("expected no delete call, got %v", api.deletedIDs)
	}
}

// TestSetRecordsWithoutIDUpdatesExisting: SetRecords with an ID-stripped
// record must find the existing record and update it by ID.
func TestSetRecordsWithoutIDUpdatesExisting(t *testing.T) {
	api := &fakeAPI{records: []d.Record{
		{ID: "201", Name: "_acme-challenge", Type: "TXT", Value: "old", TTL: "600"},
	}}
	p := newTestProvider(api)

	rec := libdns.RR{Name: "_acme-challenge", Type: "TXT", Data: "new", TTL: 600 * time.Second}
	_, err := p.SetRecords(context.Background(), "servbay.com", []libdns.Record{rec})
	if err != nil {
		t.Fatalf("SetRecords returned error: %v", err)
	}
	if len(api.updatedIDs) != 1 || api.updatedIDs[0] != "201" {
		t.Fatalf("expected update by ID 201, got %v", api.updatedIDs)
	}
	if len(api.created) != 0 {
		t.Fatalf("expected no create, got %v", api.created)
	}
}

// TestSetRecordsWithoutIDCreatesWhenMissing: SetRecords contract is
// update-existing-or-create; with no matching record it must create.
func TestSetRecordsWithoutIDCreatesWhenMissing(t *testing.T) {
	api := &fakeAPI{}
	p := newTestProvider(api)

	rec := libdns.RR{Name: "_acme-challenge", Type: "TXT", Data: "brand-new", TTL: 600 * time.Second}
	_, err := p.SetRecords(context.Background(), "servbay.com", []libdns.Record{rec})
	if err != nil {
		t.Fatalf("SetRecords returned error: %v", err)
	}
	if len(api.created) != 1 {
		t.Fatalf("expected 1 create, got %d", len(api.created))
	}
	if len(api.created) == 1 && api.created[0].Name != "_acme-challenge" {
		t.Fatalf("expected create name _acme-challenge, got %q", api.created[0].Name)
	}
	if len(api.updatedIDs) != 0 {
		t.Fatalf("expected no update, got %v", api.updatedIDs)
	}
}
