package k8s

import apierrors "k8s.io/apimachinery/pkg/api/errors"

// isNotFound reports whether err is a Kubernetes "not found" API error.
func isNotFound(err error) bool { return apierrors.IsNotFound(err) }
