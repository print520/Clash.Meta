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
// 优化版本：减少字符串操作和内存分配，提升性能
func DecodeBase64(buf []byte) []byte {
	if len(buf) == 0 {
		return buf
	}

	// 优化：先检查是否需要清理，避免不必要的内存分配
	needsCleanup := false
	for i := 0; i < len(buf); i++ {
		if buf[i] == '\n' || buf[i] == '\r' || buf[i] == ' ' {
			needsCleanup = true
			break
		}
	}

	var cleanedBuf []byte
	if needsCleanup {
		// 只分配一次内存，手动过滤字符
		cleanedBuf = make([]byte, 0, len(buf))
		for i := 0; i < len(buf); i++ {
			if buf[i] != '\n' && buf[i] != '\r' && buf[i] != ' ' {
				cleanedBuf = append(cleanedBuf, buf[i])
			}
		}
	} else {
		cleanedBuf = buf
	}

	// 尝试标准base64解码
	if decoded, err := base64.StdEncoding.DecodeString(string(cleanedBuf)); err == nil && len(decoded) > 0 {
		return decoded
	}

	// 尝试URL安全的base64解码
	if decoded, err := base64.URLEncoding.DecodeString(string(cleanedBuf)); err == nil && len(decoded) > 0 {
		return decoded
	}

	// 尝试RawStdEncoding（不带填充）
	if decoded, err := base64.RawStdEncoding.DecodeString(string(cleanedBuf)); err == nil && len(decoded) > 0 {
		return decoded
	}

	// 尝试RawURLEncoding（不带填充）
	if decoded, err := base64.RawURLEncoding.DecodeString(string(cleanedBuf)); err == nil && len(decoded) > 0 {
		return decoded
	}

	// 如果所有解码都失败，返回原始数据
	return buf
}

// 内部使用的base64解码函数，返回错误
// 优化版本：减少字符串操作
func tryDecodeBase64(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, base64.CorruptInputError(0)
	}

	// 优化：先检查是否需要清理
	needsCleanup := false
	for i := 0; i < len(data); i++ {
		if data[i] == '\n' || data[i] == '\r' || data[i] == ' ' {
			needsCleanup = true
			break
		}
	}

	var cleanedBuf []byte
	if needsCleanup {
		cleanedBuf = make([]byte, 0, len(data))
		for i := 0; i < len(data); i++ {
			if data[i] != '\n' && data[i] != '\r' && data[i] != ' ' {
				cleanedBuf = append(cleanedBuf, data[i])
			}
		}
	} else {
		cleanedBuf = data
	}

	str := string(cleanedBuf)

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
