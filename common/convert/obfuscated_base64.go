package convert

import (
	"encoding/base64"
)

// Base64 字符集
const base64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

// 混淆后的字符集（与 Dart 端保持一致）
const obfuscatedChars = "ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqponmlkjihgfedcba9876543210/+"

// 构建混淆映射表
// 优化：使用数组代替 Map，直接索引访问，避免 Map 查找开销
// 使用 [256]byte 数组，可以直接用 byte 值作为索引（ASCII 字符范围 0-127）
var obfuscateMap = buildObfuscateMap()
var deobfuscateMap = buildDeobfuscateMap()

func buildObfuscateMap() [256]byte {
	var m [256]byte
	// 初始化：未映射的字符保持为 0，表示不进行替换
	for i := 0; i < len(base64Chars); i++ {
		m[base64Chars[i]] = obfuscatedChars[i]
	}
	return m
}

func buildDeobfuscateMap() [256]byte {
	var m [256]byte
	// 初始化：未映射的字符保持为 0，表示不进行替换
	for i := 0; i < len(obfuscatedChars); i++ {
		m[obfuscatedChars[i]] = base64Chars[i]
	}
	return m
}

// 混淆 Base64 字符串
// 优化：预分配固定大小的 slice，直接索引赋值，避免 append 开销
func obfuscateBase64(s string) string {
	result := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		char := s[i]
		// 如果是 Base64 字符，进行替换；否则保持原样（如填充字符 =）
		if obfuscated := obfuscateMap[char]; obfuscated != 0 {
			result[i] = obfuscated
		} else {
			result[i] = char
		}
	}
	return string(result)
}

// 去混淆 Base64 字符串
// 优化：预分配固定大小的 slice，直接索引赋值，避免 append 开销
func deobfuscateBase64(s string) string {
	result := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		char := s[i]
		// 如果是混淆字符，进行反向替换；否则保持原样（如填充字符 =）
		if original := deobfuscateMap[char]; original != 0 {
			result[i] = original
		} else {
			result[i] = char
		}
	}
	return string(result)
}

// 检查数据是否可能是混淆的 Base64（通过检查字符分布）
// 如果数据中主要是混淆后的字符（ZYX...等），则可能是混淆格式
func isLikelyObfuscated(data []byte) bool {
	if len(data) == 0 {
		return false
	}

	// 统计混淆字符集中的字符数量
	obfuscatedCount := 0
	totalChars := 0

	for i := 0; i < len(data) && i < 100; i++ { // 只检查前100个字符以提升性能
		char := data[i]
		// 跳过填充字符和空白字符
		if char == '=' || char == '\n' || char == '\r' || char == ' ' {
			continue
		}
		totalChars++
		// 检查是否在混淆字符集中（主要是大写字母Z-A和小写字母z-a）
		if (char >= 'Z' && char <= 'A') || (char >= 'z' && char <= 'a') ||
			(char >= '9' && char <= '0') || char == '/' {
			// 检查是否在混淆字符集范围内（使用数组直接索引，比 Map 查找更快）
			if deobfuscateMap[char] != 0 {
				obfuscatedCount++
			}
		}
	}

	// 如果超过70%的字符是混淆字符，可能是混淆格式
	// 注意：这个判断不是绝对准确的，但可以帮助减少误判
	if totalChars > 0 && float64(obfuscatedCount)/float64(totalChars) > 0.7 {
		return true
	}

	return false
}

// 解码混淆的 Base64 配置
// 与 Dart 端的 encryptConfig 函数对应
func DecodeObfuscatedBase64(buf []byte) []byte {
	if len(buf) == 0 {
		return buf
	}

	// 可选：快速检查是否可能是混淆格式（提升性能，避免不必要的处理）
	// 如果明显不是混淆格式，可以提前返回
	// 但为了兼容性，我们还是尝试解码

	// 尝试去混淆并解码
	str := string(buf)
	deobfuscated := deobfuscateBase64(str)

	// 尝试 Base64 解码
	decoded, err := base64.StdEncoding.DecodeString(deobfuscated)
	if err != nil {
		// 如果解码失败，返回原始数据（可能是旧格式的纯 Base64）
		return buf
	}

	// 验证解码结果是否有效
	// 这是关键：只有解码结果是有效配置时，才认为这是混淆格式
	if len(decoded) > 0 && isValidConfig(decoded) {
		return decoded
	}

	// 如果解码结果无效，返回原始数据（让其他解码方式继续尝试）
	return buf
}
