package convert

import (
	"encoding/base64"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
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
	// 先移除可能的BOM（特别是Windows系统）
	buf = removeBOM(buf)
	
	// 首先尝试AES+Base64双重解密
	aesResult := DecodeAESBase64(buf)
	if len(aesResult) != len(buf) && len(aesResult) > 0 {
		// AES解密成功且有数据，尝试验证
		if isValidYAML(aesResult) {
			return aesResult
		}
	}
	
	// 如果AES解密失败，尝试纯Base64解密
	base64Result := DecodeBase64(buf)
	if len(base64Result) != len(buf) && len(base64Result) > 0 {
		// Base64解密成功且有数据，尝试验证
		if isValidYAML(base64Result) {
			return base64Result
		}
	}
	
	// 如果都失败，返回原始数据（可能本身就是明文）
	return buf
}

// YAML有效性检查 - 使用实际的YAML解析验证
func isValidYAML(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	
	// 移除可能的BOM标记
	data = removeBOM(data)
	
	// 直接尝试解析YAML，这是最可靠的方法
	var test interface{}
	err := yaml.Unmarshal(data, &test)
	if err == nil && test != nil {
		// 成功解析且不为空，就认为是有效的YAML
		return true
	}
	
	// 如果YAML解析失败，作为后备，检查是否至少看起来像配置文件
	str := string(data)
	// 检查是否包含配置文件的基本特征（冒号键值对格式）
	return strings.Contains(str, ":") && (strings.Contains(str, "\n") || len(str) > 50)
}

// 移除BOM (Byte Order Mark) - 特别是Windows系统可能添加的BOM
func removeBOM(data []byte) []byte {
	// UTF-8 BOM: EF BB BF
	if len(data) >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF {
		return data[3:]
	}
	// UTF-16 LE BOM: FF FE
	if len(data) >= 2 && data[0] == 0xFF && data[1] == 0xFE {
		return data[2:]
	}
	// UTF-16 BE BOM: FE FF
	if len(data) >= 2 && data[0] == 0xFE && data[1] == 0xFF {
		return data[2:]
	}
	return data
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
