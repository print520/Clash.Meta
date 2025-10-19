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
	if isValidConfig(aesResult) {
		return aesResult
	}
	
	// 尝试方式2: 纯Base64解码
	base64Result := DecodeBase64(buf)
	if isValidConfig(base64Result) && !bytes.Equal(base64Result, buf) {
		return base64Result
	}
	
	// 如果都失败，返回原始数据
	return buf
}

// 检查是否为有效的配置数据
func isValidConfig(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	
	// 检查是否包含YAML配置的关键字
	keywords := []string{
		"proxies:",
		"proxy-groups:",
		"rules:",
		"mixed-port:",
		"port:",
		"socks-port:",
		"allow-lan:",
		"mode:",
	}
	
	for _, keyword := range keywords {
		if bytes.Contains(data, []byte(keyword)) {
			return true
		}
	}
	
	// 检查是否为JSON格式
	if (data[0] == '{' && data[len(data)-1] == '}') ||
		(data[0] == '[' && data[len(data)-1] == ']') {
		return true
	}
	
	return false
}

// 检查是否看起来像YAML配置
func isYAMLConfig(data []byte) bool {
	if len(data) < 10 {
		return false
	}
	
	// 检查前100个字节
	checkLen := 100
	if len(data) < checkLen {
		checkLen = len(data)
	}
	
	sample := data[:checkLen]
	
	// 如果包含YAML的关键标识，认为是未加密的配置
	yamlIndicators := []string{
		"proxies:",
		"proxy-groups:",
		"rules:",
		"mixed-port:",
		"port:",
	}
	
	for _, indicator := range yamlIndicators {
		if bytes.Contains(sample, []byte(indicator)) {
			return true
		}
	}
	
	return false
}

