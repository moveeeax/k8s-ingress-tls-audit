package audit

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"sigs.k8s.io/yaml"
)

// ManifestSource is a Source backed by Kubernetes YAML manifests on disk.
type ManifestSource struct {
	ingresses []Ingress
	secrets   map[string]*Secret // key: ns/name
}

// LoadDir walks dir recursively, parses every *.yaml/*.yml file (multi-document
// aware) and indexes the Ingress and Secret objects it finds.
func LoadDir(dir string) (*ManifestSource, error) {
	ms := &ManifestSource{secrets: map[string]*Secret{}}
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return ms.parseFile(path, raw)
	})
	if err != nil {
		return nil, err
	}
	return ms, nil
}

// LoadBytes parses a single (possibly multi-document) manifest blob. Useful for
// tests and stdin.
func LoadBytes(name string, raw []byte) (*ManifestSource, error) {
	ms := &ManifestSource{secrets: map[string]*Secret{}}
	if err := ms.parseFile(name, raw); err != nil {
		return nil, err
	}
	return ms, nil
}

type k8sMeta struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
}

type rawObject struct {
	Kind     string  `json:"kind"`
	Metadata k8sMeta `json:"metadata"`
	// Ingress
	Spec struct {
		Rules []struct {
			Host string `json:"host"`
		} `json:"rules"`
		TLS []struct {
			Hosts      []string `json:"hosts"`
			SecretName string   `json:"secretName"`
		} `json:"tls"`
	} `json:"spec"`
	// Secret
	Type       string            `json:"type"`
	Data       map[string]string `json:"data"`
	StringData map[string]string `json:"stringData"`
}

func (ms *ManifestSource) parseFile(name string, raw []byte) error {
	for i, doc := range splitYAMLDocuments(raw) {
		trimmed := bytes.TrimSpace(doc)
		if len(trimmed) == 0 {
			continue
		}
		var obj rawObject
		if err := yaml.Unmarshal(trimmed, &obj); err != nil {
			return fmt.Errorf("%s (doc %d): %w", name, i, err)
		}
		ns := obj.Metadata.Namespace
		if ns == "" {
			ns = "default"
		}
		switch obj.Kind {
		case "Ingress":
			ing := Ingress{Namespace: ns, Name: obj.Metadata.Name}
			seen := map[string]bool{}
			for _, r := range obj.Spec.Rules {
				if r.Host != "" && !seen[r.Host] {
					ing.Hosts = append(ing.Hosts, r.Host)
					seen[r.Host] = true
				}
			}
			for _, t := range obj.Spec.TLS {
				ing.TLS = append(ing.TLS, IngressTLS{Hosts: t.Hosts, SecretName: t.SecretName})
			}
			ms.ingresses = append(ms.ingresses, ing)
		case "Secret":
			sec := &Secret{Namespace: ns, Name: obj.Metadata.Name, Type: obj.Type, Data: map[string][]byte{}}
			for k, v := range obj.Data {
				dec, err := base64.StdEncoding.DecodeString(v)
				if err != nil {
					return fmt.Errorf("%s: secret %s/%s data[%q] is not valid base64: %w", name, ns, sec.Name, k, err)
				}
				sec.Data[k] = dec
			}
			for k, v := range obj.StringData {
				sec.Data[k] = []byte(v)
			}
			ms.secrets[ns+"/"+sec.Name] = sec
		}
	}
	return nil
}

// splitYAMLDocuments splits a manifest on the standard "---" document separator.
func splitYAMLDocuments(raw []byte) [][]byte {
	parts := bytes.Split(raw, []byte("\n---"))
	out := make([][]byte, 0, len(parts))
	for _, p := range parts {
		out = append(out, bytes.TrimPrefix(p, []byte("---")))
	}
	return out
}

// Ingresses implements Source.
func (ms *ManifestSource) Ingresses() ([]Ingress, error) { return ms.ingresses, nil }

// Secret implements Source; returns (nil, nil) when the Secret is absent.
func (ms *ManifestSource) Secret(ns, name string) (*Secret, error) {
	return ms.secrets[ns+"/"+name], nil
}
