// Package k8s adapts a live cluster (via client-go and the current kubeconfig
// context) into an audit.Source.
package k8s

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/moveeeax/k8s-ingress-tls-audit/internal/audit"
)

// LiveSource reads Ingresses and Secrets from a cluster.
type LiveSource struct {
	client    kubernetes.Interface
	namespace string // "" = all namespaces
}

// NewLiveSource builds a LiveSource from the current kubeconfig context.
// namespace "" audits every namespace.
func NewLiveSource(kubeconfig, namespace string) (*LiveSource, error) {
	loading := clientcmd.NewDefaultClientConfigLoadingRules()
	if kubeconfig != "" {
		loading.ExplicitPath = kubeconfig
	}
	cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		loading, &clientcmd.ConfigOverrides{}).ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("load kubeconfig: %w", err)
	}
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("build client: %w", err)
	}
	return &LiveSource{client: cs, namespace: namespace}, nil
}

// Ingresses implements audit.Source.
func (l *LiveSource) Ingresses() ([]audit.Ingress, error) {
	ctx := context.Background()
	list, err := l.client.NetworkingV1().Ingresses(l.namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list ingresses: %w", err)
	}
	out := make([]audit.Ingress, 0, len(list.Items))
	for _, ing := range list.Items {
		a := audit.Ingress{Namespace: ing.Namespace, Name: ing.Name}
		seen := map[string]bool{}
		for _, r := range ing.Spec.Rules {
			if r.Host != "" && !seen[r.Host] {
				a.Hosts = append(a.Hosts, r.Host)
				seen[r.Host] = true
			}
		}
		for _, t := range ing.Spec.TLS {
			a.TLS = append(a.TLS, audit.IngressTLS{Hosts: t.Hosts, SecretName: t.SecretName})
		}
		out = append(out, a)
	}
	return out, nil
}

// Secret implements audit.Source; returns (nil, nil) when the Secret is absent.
func (l *LiveSource) Secret(ns, name string) (*audit.Secret, error) {
	ctx := context.Background()
	s, err := l.client.CoreV1().Secrets(ns).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		if isNotFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("get secret %s/%s: %w", ns, name, err)
	}
	sec := &audit.Secret{Namespace: ns, Name: name, Type: string(s.Type), Data: map[string][]byte{}}
	for k, v := range s.Data {
		sec.Data[k] = v
	}
	return sec, nil
}
