package keymgr

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"golang.org/x/crypto/argon2"
	"io"
	"os"
	"sort"
	"strings"
)

// 一个静态、硬编码的秘密，用作 Argon2id 的“password”参数。
// 这能确保在 Salt 已知的情况下，密钥派生过程是确定性的。
var argon2Password = []byte("gophantom-static-secret-for-derivation")

// Argon2id 参数。这些参数在生成器和加载器中必须保持一致。
const (
	argon2Time    = 1
	argon2Memory  = 64 * 1024 // 64 MB
	argon2Threads = 4
	keyLength     = 32 // AES-256 需要 32 字节密钥
	saltLength    = 16 // 16 字节的 Salt
)

// DeriveKeyAndSalt 处理 Salt 的创建和主加密密钥的派生。
// 它会尝试从 GOPHANTOM_SALT 环境变量中读取 Base64 编码的 Salt。
// 如果变量不存在，则生成一个新的随机 Salt（非确定性构建）。
// 如果变量存在但格式非法（非 base64 或长度不对），直接报错终止。
func DeriveKeyAndSalt() (key []byte, salt []byte, err error) {
	saltB64 := os.Getenv("GOPHANTOM_SALT")
	if saltB64 == "" {
		// 未设置环境变量 → 随机 salt，非确定性构建
		fmt.Println("[*] GOPHANTOM_SALT not set. Using random salt (non-deterministic build).")
		salt = make([]byte, saltLength)
		if _, err := io.ReadFull(rand.Reader, salt); err != nil {
			return nil, nil, fmt.Errorf("failed to generate random salt: %v", err)
		}
	} else {
		// 设置了环境变量 → 必须合法，否则 hard fail
		var decErr error
		salt, decErr = base64.StdEncoding.DecodeString(saltB64)
		if decErr != nil {
			return nil, nil, fmt.Errorf("GOPHANTOM_SALT is not valid base64: %v", decErr)
		}
		if len(salt) != saltLength {
			return nil, nil, fmt.Errorf("GOPHANTOM_SALT must decode to %d bytes, got %d", saltLength, len(salt))
		}
		fmt.Println("[+] Loaded salt from GOPHANTOM_SALT.")
	}

	// 使用 Argon2id 派生密钥
	key = argon2.IDKey(argon2Password, salt, argon2Time, argon2Memory, argon2Threads, keyLength)
	return key, salt, nil
}

// DeriveKeyFromEnvValues 从环境特征值派生加密密钥。
//
// 流程：
//  1. 将 key=value 对排序（确保顺序一致性）
//  2. 拼接为 "key1=value1\nkey2=value2\n..." 格式
//  3. SHA-256 哈希 → 32 字节摘要
//  4. 以 SHA-256 摘要作为 Argon2id 的 "password"，随机 salt 派生最终密钥
//
// envPairs 格式：["hostname=DC01", "domain=CORP.LOCAL"]
// 返回 32 字节密钥 + 16 字节 salt
func DeriveKeyFromEnvValues(envPairs []string) (key []byte, salt []byte, err error) {
	return DeriveKeyFromEnvValuesWithReader(envPairs, rand.Reader)
}

// DeriveKeyFromEnvValuesWithReader 与 DeriveKeyFromEnvValues 相同，
// 但允许调用方提供随机源，便于生成器实现可复现构建和单元测试。
func DeriveKeyFromEnvValuesWithReader(envPairs []string, random io.Reader) (key []byte, salt []byte, err error) {
	if len(envPairs) == 0 {
		return nil, nil, fmt.Errorf("env-bind requires at least one key=value pair")
	}
	if random == nil {
		random = rand.Reader
	}

	// 排序确保顺序一致性（generator 和 loader 必须产生相同的输入）
	sorted := make([]string, len(envPairs))
	copy(sorted, envPairs)
	sort.Strings(sorted)

	// 拼接并 SHA-256 哈希
	combined := strings.Join(sorted, "\n")
	hash := sha256.Sum256([]byte(combined))

	// 生成随机 salt
	salt = make([]byte, saltLength)
	if _, err := io.ReadFull(random, salt); err != nil {
		return nil, nil, fmt.Errorf("failed to generate random salt: %v", err)
	}

	// Argon2id 派生（以 SHA-256 哈希作为 password）
	key = argon2.IDKey(hash[:], salt, argon2Time, argon2Memory, argon2Threads, keyLength)
	return key, salt, nil
}

// ComputeEnvHash 计算环境特征的 SHA-256 哈希（base64 编码）。
// 用于在 loader 中嵌入预期哈希值，运行时比对。
func ComputeEnvHash(envPairs []string) string {
	sorted := make([]string, len(envPairs))
	copy(sorted, envPairs)
	sort.Strings(sorted)
	combined := strings.Join(sorted, "\n")
	hash := sha256.Sum256([]byte(combined))
	return base64.StdEncoding.EncodeToString(hash[:])
}
