package secrets

import (
	"math"
	"strings"
	"testing"
)

func TestShannon(t *testing.T) {
	cases := []struct {
		in   string
		want float64 // approximate
	}{
		{"", 0},
		{"aaaaa", 0},
		{"ab", 1},
		{"abcd", 2},
	}
	for _, tc := range cases {
		got := Shannon(tc.in)
		if math.Abs(got-tc.want) > 0.01 {
			t.Errorf("Shannon(%q) = %v, want ≈ %v", tc.in, got, tc.want)
		}
	}
	// High-entropy random-looking string > 4.0
	if e := Shannon("AKIAJWQXYZ1234567ABC"); e < 3.5 {
		t.Errorf("expected high entropy for AKIA token, got %v", e)
	}
}

func TestScanTextAWSAccessKey(t *testing.T) {
	src := `cfg := map[string]string{
		"key": "AKIAJWQXYZ1234567ABC",
	}`
	got := ScanText("cfg.go", src)
	if len(got) == 0 {
		t.Fatal("expected at least one match for AKIA token")
	}
	found := false
	for _, m := range got {
		if m.RuleID == "aws-access-key" {
			found = true
			if m.File != "cfg.go" {
				t.Errorf("File = %q", m.File)
			}
			if !strings.HasSuffix(m.Snippet, "***") {
				t.Errorf("expected redacted snippet, got %q", m.Snippet)
			}
			if m.Token == "" {
				t.Error("Token must be set for verifier hand-off")
			}
		}
	}
	if !found {
		t.Errorf("aws-access-key rule did not fire: %+v", got)
	}
}

func TestScanTextSkipsExamplePlaceholder(t *testing.T) {
	// AWS canonical EXAMPLE id must be filtered out (contains "example").
	got := ScanText("f.go", `k = "AKIAIOSFODNN7EXAMPLE"`)
	for _, m := range got {
		if m.RuleID == "aws-access-key" {
			t.Errorf("EXAMPLE placeholder leaked: %+v", m)
		}
	}
}

func TestScanTextSkipsPlaceholders(t *testing.T) {
	// These all contain placeholder markers (placeholder/your-/changeme/dummy/sample/todo/xxx).
	src := `password = "PLACEHOLDER1234567890"
password = "your-password-changeme"
api_key = "dummy-key-xxxx-todo"
`
	got := ScanText("test.py", src)
	for _, m := range got {
		t.Errorf("placeholder leaked through filter: %+v", m)
	}
}

func TestScanTextGitHubPAT(t *testing.T) {
	token := "ghp_" + strings.Repeat("A", 36)
	src := "token = \"" + token + "\""
	got := ScanText("x.go", src)
	if len(got) == 0 || got[0].RuleID != "github-pat" {
		t.Fatalf("expected github-pat match, got %+v", got)
	}
}

func TestScanTextPEM(t *testing.T) {
	src := "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----"
	got := ScanText("k.pem", src)
	if len(got) == 0 {
		t.Fatal("expected pem match")
	}
}

func TestScanTextEmpty(t *testing.T) {
	if got := ScanText("x.go", ""); got != nil {
		t.Errorf("expected nil for empty content, got %+v", got)
	}
}

func TestScanTextLineAccuracy(t *testing.T) {
	src := "line1\nline2\nkey := \"AKIAJWQXYZ1234567ABC\"\nline4\n"
	got := ScanText("f.go", src)
	if len(got) == 0 {
		t.Fatal("no match")
	}
	if got[0].Line != 3 {
		t.Errorf("Line = %d, want 3", got[0].Line)
	}
}

func TestHighEntropyAmbiguous(t *testing.T) {
	src := `token = "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGH"`
	got := HighEntropyAmbiguous(src, 4.5, 24)
	if len(got) == 0 {
		t.Fatal("expected high-entropy match")
	}
	if got[0].RuleID != "high-entropy" {
		t.Errorf("RuleID = %q", got[0].RuleID)
	}
	// Low-entropy must not match.
	low := `token = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"`
	if g := HighEntropyAmbiguous(low, 4.5, 24); len(g) != 0 {
		t.Errorf("low-entropy should be filtered, got %+v", g)
	}
}

func TestIsVaultReference(t *testing.T) {
	vaultRefs := []string{
		"sec-01gk9h068sw52v0607q0hzn9cb",
		"sec-abcdefghijklmnopqrstu",
		"e10-AbCdEfGhIjKlMnOpQrSt",
		"arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/db-AbCdEf",
		"arn:aws:ssm:us-east-1:123456789012:parameter/prod/api/key",
		"projects/my-proj/secrets/db-password",
		"projects/my-proj/secrets/db-password/versions/latest",
		"https://my-vault.vault.azure.net/secrets/db-pw",
		"/secret/data/prod/api",
		"vault:prod/db/password",
		`"sec-01gk9h068sw52v0607q0hzn9cb"`, // quoted form
	}
	for _, r := range vaultRefs {
		if !IsVaultReference(r) {
			t.Errorf("expected vault reference: %q", r)
		}
	}
	notRefs := []string{
		"AKIAJWQXYZ1234567ABC",
		"ghp_" + strings.Repeat("A", 36),
		"sk-1234567890abcdef",
		"sec-short", // too short
		"random-string-value",
	}
	for _, r := range notRefs {
		if IsVaultReference(r) {
			t.Errorf("must not be vault reference: %q", r)
		}
	}
}

func TestScanTextSkipsVaultReferences(t *testing.T) {
	// Yandex CI a.yaml-style: secret_spec.uuid is a *reference*, not the secret.
	src := `secret_environment_variables:
  - key: YA_TOKEN
    secret_spec:
      uuid: sec-01gk9h068sw52v0607q0hzn9cb
      key: ya_token
# also: secret: sec-01gk9h068sw52v0607q0hzn9cb  # vault ref
`
	got := ScanText("a.yaml", src)
	for _, m := range got {
		t.Errorf("vault reference leaked through filter: %+v", m)
	}
	// And high-entropy heuristic must not catch it either.
	quoted := `token: "sec-01gk9h068sw52v0607q0hzn9cb"`
	if g := HighEntropyAmbiguous(quoted, 4.0, 20); len(g) != 0 {
		t.Errorf("high-entropy filter leaked vault ref: %+v", g)
	}
}

func BenchmarkScanTextSmall(b *testing.B) {
	src := strings.Repeat("var x = \"AKIAJWQXYZ1234567ABC\"\n", 20)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ScanText("f.go", src)
	}
}

func BenchmarkScanTextLarge(b *testing.B) {
	var sb strings.Builder
	for i := 0; i < 5000; i++ {
		sb.WriteString("func handler() { log.Println(\"hello\") }\n")
	}
	sb.WriteString("ghp_" + strings.Repeat("A", 36))
	src := sb.String()
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = ScanText("big.go", src)
	}
}

func BenchmarkShannon(b *testing.B) {
	s := strings.Repeat("AKIAJWQXYZ1234567ABC", 5)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Shannon(s)
	}
}
