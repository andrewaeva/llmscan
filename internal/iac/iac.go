// Package iac detects Infrastructure-as-Code files and assigns a logical
// language tag used by IaC scanners (Dockerfile, k8s, terraform, gh-actions).
//
// Detection is based on filename + minimal content sniffing — false-positive
// safe but conservative.
package iac

import (
	"path/filepath"
	"strings"
)

// Kind is the logical IaC type.
type Kind string

const (
	KindNone       Kind = ""
	KindDockerfile Kind = "dockerfile"
	KindKubernetes Kind = "kubernetes"
	KindTerraform  Kind = "terraform"
	KindGhActions  Kind = "github-actions"
	KindCompose    Kind = "docker-compose"
)

// Detect returns the IaC kind for a path or empty if not IaC.
func Detect(path, content string) Kind {
	base := strings.ToLower(filepath.Base(path))
	ext := strings.ToLower(filepath.Ext(path))

	if base == "dockerfile" || strings.HasPrefix(base, "dockerfile.") || strings.HasSuffix(base, ".dockerfile") {
		return KindDockerfile
	}
	if ext == ".tf" || ext == ".tfvars" {
		return KindTerraform
	}
	if strings.Contains(filepath.ToSlash(path), ".github/workflows/") && (ext == ".yml" || ext == ".yaml") {
		return KindGhActions
	}
	if base == "docker-compose.yml" || base == "docker-compose.yaml" || base == "compose.yml" || base == "compose.yaml" {
		return KindCompose
	}
	if ext == ".yml" || ext == ".yaml" {
		if isK8sManifest(content) {
			return KindKubernetes
		}
	}
	return KindNone
}

func isK8sManifest(content string) bool {
	if !strings.Contains(content, "apiVersion") {
		return false
	}
	if !strings.Contains(content, "kind:") {
		return false
	}
	for _, kw := range []string{
		"kind: Deployment", "kind: Pod", "kind: Service", "kind: Ingress",
		"kind: ConfigMap", "kind: Secret", "kind: StatefulSet", "kind: DaemonSet",
		"kind: Job", "kind: CronJob", "kind: Role", "kind: ClusterRole",
		"kind: ServiceAccount", "kind: NetworkPolicy",
	} {
		if strings.Contains(content, kw) {
			return true
		}
	}
	return false
}

// AgentName maps an IaC kind to the canonical scanner name (used in DAG/SKILL.md).
func AgentName(k Kind) string {
	switch k {
	case KindDockerfile, KindCompose:
		return "iac-docker"
	case KindKubernetes:
		return "iac-k8s"
	case KindTerraform:
		return "iac-terraform"
	case KindGhActions:
		return "iac-ghactions"
	}
	return ""
}
