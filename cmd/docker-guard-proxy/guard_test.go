package main

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type stubTransport struct {
	called bool
}

func (s *stubTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	s.called = true
	return &http.Response{
		StatusCode: http.StatusCreated,
		Body:       io.NopCloser(strings.NewReader(`{"Id":"abc"}`)),
		Header:     make(http.Header),
	}, nil
}

func TestDockerGuardProxyRejectsEscapesAndAllowsHardenedTrap(t *testing.T) {
	stub := &stubTransport{}
	h := NewGuardHandler(stub, PolicyConfig{AllowedBindRoot: "/var/lib/honeypot-sensor/traps"})

	validJSON := `{
		"Image": "cowrie/cowrie:sha256-test",
		"User": "1000:1000",
		"Env": ["COWRIE_SSH_PORT=2222", "TZ=UTC"],
		"HostConfig": {
			"Binds": ["/var/lib/honeypot-sensor/traps/dep1/var:/cowrie/cowrie-git/var:rw"],
			"NetworkMode": "trap_isolated_net",
			"Privileged": false,
			"ReadonlyRootfs": true,
			"CapDrop": ["ALL"]
		}
	}`

	// Valid request passes through
	req := httptest.NewRequest(http.MethodPost, "/v1.45/containers/create?name=hp-trap-cowrie-1", bytes.NewBufferString(validJSON))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated || !stub.called {
		t.Fatalf("expected 201 on valid trap, got %d (%s)", rec.Code, rec.Body.String())
	}

	// Hostile cases must all be rejected with 403 and NEVER reach upstream
	attackPayloads := map[string]string{
		"privileged": strings.ReplaceAll(validJSON, `"Privileged": false`, `"Privileged": true`),
		"host_bind":  strings.ReplaceAll(validJSON, `/var/lib/honeypot-sensor/traps/dep1/var`, `/etc`),
		"traversal":  strings.ReplaceAll(validJSON, `/var/lib/honeypot-sensor/traps/dep1/var`, `/var/lib/honeypot-sensor/traps/../../etc`),
		"docker_sock": strings.ReplaceAll(validJSON, `/var/lib/honeypot-sensor/traps/dep1/var`, `/var/run/docker.sock`),
		"ld_preload": strings.ReplaceAll(validJSON, `"COWRIE_SSH_PORT=2222"`, `"LD_PRELOAD=/tmp/evil.so"`),
		"pythonpath": strings.ReplaceAll(validJSON, `"COWRIE_SSH_PORT=2222"`, `"PYTHONPATH=/tmp/evil"`),
		"host_net":   strings.ReplaceAll(validJSON, `"trap_isolated_net"`, `"host"`),
		"root_user":  strings.ReplaceAll(validJSON, `"1000:1000"`, `"0:0"`),
		"bad_image":  strings.ReplaceAll(validJSON, `cowrie/cowrie:sha256-test`, `alpine:latest`),
		"rw_rootfs":  strings.ReplaceAll(validJSON, `"ReadonlyRootfs": true`, `"ReadonlyRootfs": false`),
		"pid_host":   strings.ReplaceAll(validJSON, `"Privileged": false`, `"Privileged": false, "PidMode": "host"`),
	}

	for name, body := range attackPayloads {
		stub.called = false
		r := httptest.NewRequest(http.MethodPost, "/containers/create?name=hp-trap-cowrie-1", bytes.NewBufferString(body))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusForbidden || stub.called {
			t.Fatalf("attack case %s was not blocked! status=%d called=%v body=%s", name, w.Code, stub.called, w.Body.String())
		}
	}

	// Unmanaged container name blocked
	stub.called = false
	r := httptest.NewRequest(http.MethodPost, "/containers/create?name=lasoviet-dev-api-1", bytes.NewBufferString(validJSON))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden || stub.called {
		t.Fatalf("expected 403 for non-hp-trap container name")
	}

	// Path traversal via GET /networks/../info & unknown Devices/seccomp=unconfined blocked
	for _, u := range []string{"/v1.45/networks/../info", "/networks/foo%2f..%2fsecrets"} {
		stub.called = false
		r := httptest.NewRequest(http.MethodGet, u, nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusForbidden || stub.called {
			t.Fatalf("expected 403 for GET traversal %s", u)
		}
	}
	for _, fieldBody := range []string{
		strings.ReplaceAll(validJSON, `"CapDrop": ["ALL"]`, `"CapDrop": ["ALL"], "Devices": [{"PathOnHost":"/dev/mem"}]`),
		strings.ReplaceAll(validJSON, `"CapDrop": ["ALL"]`, `"CapDrop": ["ALL"], "SecurityOpt": ["seccomp=unconfined"]`),
	} {
		stub.called = false
		r := httptest.NewRequest(http.MethodPost, "/containers/create?name=hp-trap-cowrie-1", bytes.NewBufferString(fieldBody))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusForbidden || stub.called {
			t.Fatalf("expected 403 for disallowed field/seccomp bypass, got %d", w.Code)
		}
	}
}
