package iac

import "testing"

func TestDetectDockerfile(t *testing.T) {
	cases := []struct {
		path string
		want Kind
	}{
		{"Dockerfile", KindDockerfile},
		{"path/to/Dockerfile.alpine", KindDockerfile},
		{"app.dockerfile", KindDockerfile},
		{"app/Dockerfile", KindDockerfile},
	}
	for _, tc := range cases {
		if got := Detect(tc.path, ""); got != tc.want {
			t.Errorf("Detect(%q) = %q, want %q", tc.path, got, tc.want)
		}
	}
}

func TestDetectTerraform(t *testing.T) {
	if got := Detect("infra/main.tf", "resource \"aws_s3_bucket\" \"x\" {}"); got != KindTerraform {
		t.Errorf("got %q", got)
	}
	if got := Detect("infra/vars.tfvars", ""); got != KindTerraform {
		t.Errorf("got %q", got)
	}
}

func TestDetectKubernetes(t *testing.T) {
	manifest := "apiVersion: v1\nkind: Deployment\nmetadata:\n  name: x\n"
	if got := Detect("k8s/deploy.yaml", manifest); got != KindKubernetes {
		t.Errorf("got %q", got)
	}
}

func TestDetectKubernetesRejectsNonK8sYaml(t *testing.T) {
	plain := "name: ci\nsteps:\n  - run: echo hi\n"
	if got := Detect("config/app.yaml", plain); got != KindNone {
		t.Errorf("expected None for non-k8s yaml, got %q", got)
	}
}

func TestDetectGitHubActions(t *testing.T) {
	wf := "name: ci\non: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n"
	if got := Detect(".github/workflows/ci.yml", wf); got != KindGhActions {
		t.Errorf("got %q", got)
	}
}

func TestDetectDockerCompose(t *testing.T) {
	if got := Detect("docker-compose.yml", "services: {}"); got != KindCompose {
		t.Errorf("got %q", got)
	}
	if got := Detect("compose.yaml", ""); got != KindCompose {
		t.Errorf("compose.yaml: got %q", got)
	}
}

func TestDetectNone(t *testing.T) {
	if got := Detect("src/main.go", "package main"); got != KindNone {
		t.Errorf("expected None, got %q", got)
	}
}

func TestAgentName(t *testing.T) {
	cases := map[Kind]string{
		KindDockerfile: "iac-docker",
		KindCompose:    "iac-docker",
		KindKubernetes: "iac-k8s",
		KindTerraform:  "iac-terraform",
		KindGhActions:  "iac-ghactions",
		KindNone:       "",
	}
	for k, want := range cases {
		if got := AgentName(k); got != want {
			t.Errorf("AgentName(%q) = %q, want %q", k, got, want)
		}
	}
}

func BenchmarkDetectK8s(b *testing.B) {
	manifest := "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: x\nspec:\n  replicas: 3\n"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Detect("k8s/deploy.yaml", manifest)
	}
}
