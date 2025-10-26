package convert

import (
	"encoding/base64"
	"strings"
)

// Base64 编码器变量（用于 converter.go）
var (
	encRaw = base64.RawStdEncoding
	enc    = base64.StdEncoding
)

// Base64解码函数
// 这个函数与Speed项目的实现完全一致
func DecodeBase64(buf []byte) []byte {
	// 移除可能的空格和换行符
	str := strings.ReplaceAll(string(buf), "\n", "")
	str = strings.ReplaceAll(str, "\r", "")
	str = strings.ReplaceAll(str, " ", "")

	// 尝试标准base64解码
	decoded, err := base64.StdEncoding.DecodeString(str)
	if err == nil && len(decoded) > 0 {
		return decoded
	}

	// 尝试URL安全的base64解码
	decoded, err = base64.URLEncoding.DecodeString(str)
	if err == nil && len(decoded) > 0 {
		return decoded
	}

	// 尝试RawStdEncoding（不带填充）
	decoded, err = base64.RawStdEncoding.DecodeString(str)
	if err == nil && len(decoded) > 0 {
		return decoded
	}

	// 尝试RawURLEncoding（不带填充）
	decoded, err = base64.RawURLEncoding.DecodeString(str)
	if err == nil && len(decoded) > 0 {
		return decoded
	}

	// 如果所有解码都失败，返回原始数据
	return buf
}

// 内部使用的base64解码函数，返回错误
func tryDecodeBase64(data []byte) ([]byte, error) {
	str := strings.ReplaceAll(string(data), "\n", "")
	str = strings.ReplaceAll(str, "\r", "")
	str = strings.ReplaceAll(str, " ", "")

	// 尝试标准base64解码
	if decoded, err := base64.StdEncoding.DecodeString(str); err == nil {
		return decoded, nil
	}

	// 尝试URL安全的base64解码
	if decoded, err := base64.URLEncoding.DecodeString(str); err == nil {
		return decoded, nil
	}

	// 尝试RawStdEncoding
	if decoded, err := base64.RawStdEncoding.DecodeString(str); err == nil {
		return decoded, nil
	}

	// 尝试RawURLEncoding
	if decoded, err := base64.RawURLEncoding.DecodeString(str); err == nil {
		return decoded, nil
	}

	return nil, base64.CorruptInputError(0)
}

// URL 安全的字符串转换
func urlSafe(data string) string {
	return strings.NewReplacer("+", "-", "/", "_").Replace(data)
}

// URL 安全的 Base64 解码
func decodeUrlSafe(data string) string {
	dcBuf, err := base64.RawURLEncoding.DecodeString(data)
	if err != nil {
		return ""
	}
	return string(dcBuf)
}

// 尝试 Base64 解码（用于 SSR）
func TryDecodeBase64(s string) (decoded []byte, err error) {
	if len(s)%4 == 0 {
		if decoded, err = base64.StdEncoding.DecodeString(s); err == nil {
			return
		}
	}
	if decoded, err = base64.RawStdEncoding.DecodeString(s); err == nil {
		return
	}
	if decoded, err = base64.URLEncoding.DecodeString(s); err == nil {
		return
	}
	if decoded, err = base64.RawURLEncoding.DecodeString(s); err == nil {
		return
	}
	// 尝试添加填充
	if len(s)%4 != 0 {
		s += strings.Repeat("=", 4-len(s)%4)
		if decoded, err = base64.StdEncoding.DecodeString(s); err == nil {
			return
		}
	}
	return nil, err
}
