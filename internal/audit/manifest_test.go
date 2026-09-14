package audit

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadBytes_MultiDoc(t *testing.T) {
	crt := base64.StdEncoding.EncodeToString(validCert(t))
	manifest := `
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: web
  namespace: prod
spec:
  rules:
    - host: a.example.com
    - host: b.example.com
  tls:
    - hosts: [a.example.com]
      secretName: a-tls
---
apiVersion: v1
kind: Secret
metadata:
  name: a-tls
  namespace: prod
type: kubernetes.io/tls
data:
  tls.crt: ` + crt + `
  tls.key: a2V5
`
	ms, err := LoadBytes("test.yaml", []byte(manifest))
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	ings, _ := ms.Ingresses()
	if len(ings) != 1 {
		t.Fatalf("got %d ingresses, want 1", len(ings))
	}
	if len(ings[0].Hosts) != 2 {
		t.Errorf("hosts = %v, want 2", ings[0].Hosts)
	}
	sec, _ := ms.Secret("prod", "a-tls")
	if sec == nil || sec.Type != "kubernetes.io/tls" {
		t.Fatalf("secret not loaded correctly: %+v", sec)
	}
	if _, ok := sec.Data["tls.crt"]; !ok {
		t.Error("tls.crt not decoded")
	}

	// Full audit over the loaded manifest: b.example.com is uncovered.
	fs, _ := New(ms, Options{ExpiryWindow: 30 * 24 * time.Hour, Now: fixedClock(now(t))}).Run()
	if f := findByKind(fs, "missing_tls"); f == nil || f.Host != "b.example.com" {
		t.Fatalf("expected missing_tls for b.example.com, got %+v", fs)
	}
}

func TestLoadBytes_DefaultNamespace(t *testing.T) {
	manifest := `
kind: Ingress
metadata:
  name: web
spec:
  rules:
    - host: a.example.com
`
	ms, err := LoadBytes("t.yaml", []byte(manifest))
	if err != nil {
		t.Fatal(err)
	}
	ings, _ := ms.Ingresses()
	if ings[0].Namespace != "default" {
		t.Errorf("namespace = %q, want default", ings[0].Namespace)
	}
}

func TestLoadBytes_StringData(t *testing.T) {
	manifest := `
kind: Secret
metadata:
  name: s
  namespace: ns
type: kubernetes.io/tls
stringData:
  tls.key: plaintextkey
`
	ms, _ := LoadBytes("t.yaml", []byte(manifest))
	sec, _ := ms.Secret("ns", "s")
	if sec == nil || string(sec.Data["tls.key"]) != "plaintextkey" {
		t.Fatalf("stringData not honored: %+v", sec)
	}
}

func TestLoadBytes_BadBase64(t *testing.T) {
	manifest := `
kind: Secret
metadata:
  name: s
  namespace: ns
data:
  tls.crt: "!!!not base64!!!"
`
	if _, err := LoadBytes("t.yaml", []byte(manifest)); err == nil {
		t.Error("expected error for invalid base64 secret data")
	}
}

func TestLoadDir(t *testing.T) {
	dir := t.TempDir()
	crt := base64.StdEncoding.EncodeToString(validCert(t))
	files := map[string]string{
		"ing.yaml": `kind: Ingress
metadata: {name: web, namespace: prod}
spec:
  rules: [{host: a.example.com}]
  tls: [{hosts: [a.example.com], secretName: a-tls}]`,
		"sec.yml": `kind: Secret
metadata: {name: a-tls, namespace: prod}
type: kubernetes.io/tls
data: {tls.crt: ` + crt + `, tls.key: a2V5}`,
		"ignore.txt": "not yaml",
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	ms, err := LoadDir(dir)
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	ings, _ := ms.Ingresses()
	if len(ings) != 1 {
		t.Fatalf("got %d ingresses, want 1", len(ings))
	}
	fs, _ := New(ms, Options{ExpiryWindow: 30 * 24 * time.Hour, Now: fixedClock(now(t))}).Run()
	if len(fs) != 0 {
		t.Fatalf("expected clean audit, got %+v", fs)
	}
}
