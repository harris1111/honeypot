package heraldingparser

import (
	"testing"
)

func TestParseHeraldingAuthCSVAndSessionJSON(t *testing.T) {
	p := NewParser("node-heralding-1", 21)

	if ev, err := p.ParseAuthCSVLine("timestamp,auth_id,session_id,source_ip,source_port,destination_ip,destination_port,protocol,username,password,password_hash"); err != nil || ev != nil {
		t.Fatalf("expected CSV header skipped cleanly, got ev=%v err=%v", ev, err)
	}

	ev, err := p.ParseAuthCSVLine(`2026-11-16 16:00:01.123456,a1,s1,198.51.100.77,51234,0.0.0.0,2121,ftp,admin,"p@ss,123",deadbeef`)
	if err != nil || ev == nil {
		t.Fatalf("expected parsed FTP auth event, got ev=%v err=%v", ev, err)
	}
	if ev.DestPort != 21 || ev.Protocol != "ftp" || ev.TrapKind != "heralding" || ev.SourceIp != "198.51.100.77" {
		t.Fatalf("unexpected mapped event: %+v", ev)
	}

	evSMTP, err := p.ParseAuthCSVLine(`2026-11-16 16:00:02.000000,a2,s2,203.0.113.44,44444,0.0.0.0,2525,smtp,mailer,secret,`)
	if err != nil || evSMTP == nil || evSMTP.DestPort != 25 || evSMTP.Protocol != "smtp" {
		t.Fatalf("expected SMTP port map 2525->25, got ev=%+v err=%v", evSMTP, err)
	}

	// Session with 0 auth attempts -> captured as unauthenticated probe on mapped POP3 port 110
	evSess, err := p.ParseSessionJSONLine(`{"timestamp":"2026-11-16 16:01:00.000000","duration":1.2,"session_id":"s3","source_ip":"192.0.2.55","source_port":33333,"destination_port":2110,"protocol":"pop3","num_auth_attempts":0,"session_ended":true}`)
	if err != nil || evSess == nil || evSess.DestPort != 110 || evSess.Protocol != "pop3" {
		t.Fatalf("expected unauth session on mapped port 110, got ev=%+v err=%v", evSess, err)
	}

	// Session with num_auth_attempts > 0 -> skipped to avoid duplicating auth.csv
	evDup, err := p.ParseSessionJSONLine(`{"timestamp":"2026-11-16 16:01:00.000000","duration":1.2,"session_id":"s1","source_ip":"198.51.100.77","source_port":51234,"destination_port":2143,"protocol":"imap","num_auth_attempts":2,"session_ended":true}`)
	if err != nil || evDup != nil {
		t.Fatalf("expected session with auth_attempts>0 skipped cleanly, got ev=%v err=%v", evDup, err)
	}
}
