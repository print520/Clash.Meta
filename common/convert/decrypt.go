package convert

import (
	"bytes"
)

// 解密配置数据
// 这个函数会尝试多种解密方式，与Speed项目的实现逻辑一致
func DecryptConfig(buf []byte) []byte {
	// 如果数据为空或太小，直接返回
	if len(buf) == 0 {
		return buf
	}

	// 检查是否看起来像YAML配置（未加密）
	if isYAMLConfig(buf) {
		return buf
	}

	// 尝试方式1: AES-128-CBC + Base64 解密（PHP openssl_encrypt方式）
	aesResult := DecodeAESBase64(buf)
	if isValidConfig(aesResult) && !bytes.Equal(aesResult, buf) {
		return aesResult
	}

	// 尝试方式2: 纯Base64解码（旧格式，优先尝试以保持向后兼容）
	base64Result := DecodeBase64(buf)
	if isValidConfig(base64Result) && !bytes.Equal(base64Result, buf) {
		return base64Result
	}

	// 尝试方式3: 混淆的 Base64 解码（新格式）
	// 注意：如果普通 Base64 解码成功，就不会尝试这个
	// 这样可以确保旧格式的配置文件优先被正确识别
	obfuscatedResult := DecodeObfuscatedBase64(buf)
	if isValidConfig(obfuscatedResult) && !bytes.Equal(obfuscatedResult, buf) {
		return obfuscatedResult
	}

	// 如果都失败，返回原始数据
	return buf
}

// 加密配置数据
// 与DecryptConfig对应，用于加密配置文件
// 使用AES-128-CBC + Base64加密方式（与PHP openssl_encrypt兼容）
func EncryptConfig(buf []byte) []byte {
	// 如果数据为空，直接返回
	if len(buf) == 0 {
		return buf
	}

	// 如果已经是加密数据（不包含YAML关键字），直接返回
	if !isYAMLConfig(buf) && !isValidConfig(buf) {
		// 可能是已经加密的数据，直接返回
		return buf
	}

	// 使用AES-128-CBC + Base64加密
	return EncodeAESBase64(buf)
}

// 预编译的关键字字节数组，避免重复分配
var (
	keywordProxies     = []byte("proxies:")
	keywordProxyGroups = []byte("proxy-groups:")
	keywordRules       = []byte("rules:")
	keywordMixedPort   = []byte("mixed-port:")
	keywordPort        = []byte("port:")
	keywordSocksPort   = []byte("socks-port:")
	keywordAllowLan    = []byte("allow-lan:")
	keywordMode        = []byte("mode:")
)

// 检查是否为有效的配置数据
// 优化版本：使用预编译的关键字，减少内存分配
func isValidConfig(data []byte) bool {
	if len(data) == 0 {
		return false
	}

	// 优化：使用预编译的关键字，避免每次调用都创建新的byte slice
	// 按常见性排序，优先检查最常见的字段
	if bytes.Contains(data, keywordProxies) {
		return true
	}
	if bytes.Contains(data, keywordProxyGroups) {
		return true
	}
	if bytes.Contains(data, keywordRules) {
		return true
	}
	if bytes.Contains(data, keywordMixedPort) {
		return true
	}
	if bytes.Contains(data, keywordPort) {
		return true
	}
	if bytes.Contains(data, keywordSocksPort) {
		return true
	}
	if bytes.Contains(data, keywordAllowLan) {
		return true
	}
	if bytes.Contains(data, keywordMode) {
		return true
	}

	// 检查是否为JSON格式（需要先检查长度）
	if len(data) >= 2 {
		if (data[0] == '{' && data[len(data)-1] == '}') ||
			(data[0] == '[' && data[len(data)-1] == ']') {
			return true
		}
	}

	return false
}

// 检查是否看起来像YAML配置
// 优化版本：使用预编译关键字，只检查必要的前缀
func isYAMLConfig(data []byte) bool {
	if len(data) < 10 {
		return false
	}

	// 优化：只检查前512字节（大多数配置文件的前缀都在这里）
	// 这样可以避免对大文件的完整扫描
	checkLen := 512
	if len(data) < checkLen {
		checkLen = len(data)
	}

	sample := data[:checkLen]

	// 优化：使用预编译的关键字，按常见性排序
	if bytes.Contains(sample, keywordProxies) {
		return true
	}
	if bytes.Contains(sample, keywordProxyGroups) {
		return true
	}
	if bytes.Contains(sample, keywordRules) {
		return true
	}
	if bytes.Contains(sample, keywordMixedPort) {
		return true
	}
	if bytes.Contains(sample, keywordPort) {
		return true
	}

	return false
}
