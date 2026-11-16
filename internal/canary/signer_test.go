package canary

import (
	"strings"
	"testing"
	"time"
)

func TestSignerGenerateVerifyAndEncrypt(t *testing.T) {
	s, err := NewSigner([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	now := time.Unix(1794800000, 0).UTC()
	oai, err := s.GenerateToken("openai", "sgp1", "cw", now)
	if err != nil {
		t.Fatalf("GenerateToken openai: %v", err)
	}
	if !strings.HasPrefix(oai, "sk-proj-") {
		t.Fatalf("unexpected openai key prefix: %s", oai)
	}
	if style, ok := s.VerifyFormat(oai); !ok || style != "openai" {
		t.Fatalf("VerifyFormat openai failed: ok=%v style=%s", ok, style)
	}

	ant, err := s.GenerateToken("anthropic", "nyc2", "nx", now)
	if err != nil {
		t.Fatalf("GenerateToken anthropic: %v", err)
	}
	if !strings.HasPrefix(ant, "sk-ant-api03-") {
		t.Fatalf("unexpected anthropic key prefix: %s", ant)
	}
	if style, ok := s.VerifyFormat(ant); !ok || style != "anthropic" {
		t.Fatalf("VerifyFormat anthropic failed: ok=%v style=%s", ok, style)
	}

	// Tampering must fail
	tampered := oai[:len(oai)-1] + "X"
	if tampered == oai {
		tampered = oai[:len(oai)-1] + "Y"
	}
	if _, ok := s.VerifyFormat(tampered); ok {
		t.Fatal("expected tampered key to fail HMAC verification")
	}

	enc, err := s.EncryptPlaintext(ant)
	if err != nil {
		t.Fatalf("EncryptPlaintext: %v", err)
	}
	dec, err := s.DecryptPlaintext(enc)
	if err != nil || dec != ant {
		t.Fatalf("DecryptPlaintext mismatch: got=%q err=%v", dec, err)
	}
}
