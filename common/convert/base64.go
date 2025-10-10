package convert

import (
	"encoding/base64"
	"fmt"
	"strings"
)

var (
	encRaw = base64.RawStdEncoding
	enc    = base64.StdEncoding
)

// DecodeBase64 try to decode content from the given bytes,
// which can be in base64.RawStdEncoding, base64.StdEncoding or just plaintext.
func DecodeBase64(buf []byte) []byte {
	result, err := tryDecodeBase64(buf)
	if err != nil {
		return buf
	}
	return result
}

// DecodeConfig try to decode config with multiple methods:
// 1. AES-128-CBC + Base64 (for encrypted configs)
// 2. Base64 only (for base64 encoded configs)  
// 3. Plaintext (for normal configs)
func DecodeConfig(buf []byte) []byte {
	// 首先尝试AES+Base64双重解密
	if aesResult := DecodeAESBase64(buf); len(aesResult) != len(buf) {
		// 如果AES解密成功（长度改变），验证解密结果是否为有效YAML
		if isValidYAML(aesResult) {
			return aesResult
		}
	}
	
	// 如果AES解密失败，尝试纯Base64解密
	if base64Result := DecodeBase64(buf); len(base64Result) != len(buf) {
		// 如果Base64解密成功，验证解密结果是否为有效YAML
		if isValidYAML(base64Result) {
			return base64Result
		}
	}
	
	// 如果都失败，返回原始数据
	return buf
}

// 简单的YAML有效性检查
func isValidYAML(data []byte) bool {
	// 检查是否包含YAML特征
	str := string(data)
	if len(str) == 0 {
		return false
	}
	
	// 检查常见的YAML关键字
	if containsAny(str, []string{"proxies:", "proxy-groups:", "rules:", "port:", "mixed-port:"}) {
		return true
	}
	
	// 检查是否为有效的JSON（也可能是YAML格式的配置）
	if len(str) > 1 && str[0] == '{' && str[len(str)-1] == '}' {
		return true
	}
	
	// 检查是否包含代理配置特征
	if containsAny(str, []string{"server:", "port:", "type:", "name:"}) {
		return true
	}
	
	return false
}

// 检查字符串是否包含任意一个子字符串
func containsAny(s string, substrs []string) bool {
	for _, substr := range substrs {
		if len(s) >= len(substr) {
			for i := 0; i <= len(s)-len(substr); i++ {
				if s[i:i+len(substr)] == substr {
					return true
				}
			}
		}
	}
	return false
}

func tryDecodeBase64(buf []byte) ([]byte, error) {
	dBuf := make([]byte, encRaw.DecodedLen(len(buf)))
	n, err := encRaw.Decode(dBuf, buf)
	if err != nil {
		n, err = enc.Decode(dBuf, buf)
		if err != nil {
			return nil, err
		}
	}
	return dBuf[:n], nil
}

func urlSafe(data string) string {
	return strings.NewReplacer("+", "-", "/", "_").Replace(data)
}

func decodeUrlSafe(data string) string {
	dcBuf, err := base64.RawURLEncoding.DecodeString(data)
	if err != nil {
		return ""
	}
	return string(dcBuf)
}

func TryDecodeBase64(s string) (decoded []byte, err error) {
	if len(s)%4 == 0 {
		if decoded, err = base64.StdEncoding.DecodeString(s); err == nil {
			return
		}
		if decoded, err = base64.URLEncoding.DecodeString(s); err == nil {
			return
		}
	} else {
		if decoded, err = base64.RawStdEncoding.DecodeString(s); err == nil {
			return
		}
		if decoded, err = base64.RawURLEncoding.DecodeString(s); err == nil {
			return
		}
	}
	return nil, fmt.Errorf("invalid base64-encoded string")
}
