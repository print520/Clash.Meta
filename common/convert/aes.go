package convert

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
)

// AES-128-CBC 解密函数
// 先进行AES-128-CBC解密，然后进行base64解密
// 适配PHP openssl_encrypt的默认输出格式（base64编码的加密数据）
// 优化版本：减少不必要的操作，提升性能和兼容性
func DecodeAESBase64(buf []byte) []byte {
	// 快速失败：空数据或太小的数据不可能 AES-128-CBC 加密
	if len(buf) == 0 {
		return buf
	}
	// AES-128-CBC 最小密文大小是一个块（16字节）
	if len(buf) < aes.BlockSize {
		return buf
	}

	// AES-128-CBC 加密密钥（16字节）
	aesKey := []byte("4422a60e08c97f30")

	// AES-128-CBC 初始化向量（16字节）
	aesIv := []byte("8c97f304422a60e0")

	// PHP openssl_encrypt默认输出base64格式，所以需要先base64解码
	// 处理流程：接收到的数据 -> base64解码 -> AES解密 -> base64解码 -> YAML

	// 第一步：尝试base64解码（因为PHP输出的是base64格式的加密数据）
	base64Decoded, err := tryDecodeBase64(buf)
	if err != nil {
		// 如果base64解码失败，可能是其他格式，尝试十六进制解码
		if hexDecoded, hexErr := hex.DecodeString(string(buf)); hexErr == nil && len(hexDecoded) >= aes.BlockSize {
			base64Decoded = hexDecoded
		} else {
			// 都失败，尝试直接用原始数据（可能本身就是二进制加密数据）
			// 但需要确保长度是块大小的倍数
			if len(buf)%aes.BlockSize == 0 {
				base64Decoded = buf
			} else {
				// 长度不符合要求，直接返回
				return buf
			}
		}
	}

	// 第二步：验证base64解码后的长度符合AES块大小要求
	if len(base64Decoded) < aes.BlockSize || len(base64Decoded)%aes.BlockSize != 0 {
		return buf
	}

	// 第三步：尝试AES解密
	aesDecrypted, err := aesDecryptCBC(base64Decoded, aesKey, aesIv)
	if err != nil {
		// 如果AES解密失败，返回原始数据（不是DecodeBase64的结果）
		// 这样可以让外层DecodeConfig继续尝试其他方法
		return buf
	}

	// 验证AES解密结果
	if len(aesDecrypted) == 0 {
		return buf
	}

	// 第四步：AES解密成功后，再进行base64解密得到最终的YAML内容
	finalResult := DecodeBase64(aesDecrypted)

	// 如果最终结果为空或太小，走兼容回退：
	// 1) 若AES解密结果本身就是有效配置（历史兼容），返回它
	// 2) 否则返回原始输入，让上层继续尝试其他解码方式，避免误判随机字节
	if len(finalResult) < 10 {
		if isValidConfig(aesDecrypted) {
			return aesDecrypted
		}
		return buf
	}

	return finalResult
}

// AES-128-CBC 解密实现
// 优化版本：改进错误处理，支持更多边界情况
func aesDecryptCBC(ciphertext, key, iv []byte) ([]byte, error) {
	// 检查密钥长度
	if len(key) != aes.BlockSize {
		return nil, aes.KeySizeError(len(key))
	}

	// 检查IV长度
	if len(iv) != aes.BlockSize {
		return nil, aes.KeySizeError(len(iv))
	}

	// 检查密文长度是否为块大小的倍数
	if len(ciphertext) == 0 {
		return nil, aes.KeySizeError(0)
	}
	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, aes.KeySizeError(len(ciphertext))
	}

	// 创建AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// 创建CBC模式解密器
	mode := cipher.NewCBCDecrypter(block, iv)

	// 分配解密缓冲区
	plaintext := make([]byte, len(ciphertext))

	// 解密
	mode.CryptBlocks(plaintext, ciphertext)

	// 移除PKCS7填充
	result := pkcs7Unpadding(plaintext)

	// 验证解密结果不为空
	if len(result) == 0 {
		return nil, aes.KeySizeError(0)
	}

	return result, nil
}

// PKCS7 填充移除
// 优化版本：改进边界检查和安全性，提升兼容性
func pkcs7Unpadding(data []byte) []byte {
	length := len(data)
	if length == 0 {
		return data
	}

	// 获取填充字节数（最后一个字节的值）
	unpadding := int(data[length-1])

	// 边界检查：填充字节数必须在有效范围内 [1, 16] 对于AES
	if unpadding == 0 || unpadding > aes.BlockSize || unpadding > length {
		return data
	}

	// 验证所有填充字节是否一致（PKCS7要求）
	for i := length - unpadding; i < length; i++ {
		if data[i] != byte(unpadding) {
			return data // 填充无效，返回原始数据
		}
	}

	return data[:(length - unpadding)]
}

// 检查是否为十六进制字符串（用于判断是否需要AES解密）
func isHexString(data []byte) bool {
	_, err := hex.DecodeString(string(data))
	return err == nil
}

// PKCS7 填充
// 用于AES加密前的数据填充
func pkcs7Padding(data []byte) []byte {
	padding := aes.BlockSize - len(data)%aes.BlockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

// AES-128-CBC 加密实现
// 优化版本：与解密函数对应
func aesEncryptCBC(plaintext, key, iv []byte) ([]byte, error) {
	// 检查密钥长度
	if len(key) != aes.BlockSize {
		return nil, aes.KeySizeError(len(key))
	}

	// 检查IV长度
	if len(iv) != aes.BlockSize {
		return nil, aes.KeySizeError(len(iv))
	}

	// 检查明文是否为空
	if len(plaintext) == 0 {
		return nil, aes.KeySizeError(0)
	}

	// PKCS7填充
	paddedPlaintext := pkcs7Padding(plaintext)

	// 创建AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// 创建CBC模式加密器
	mode := cipher.NewCBCEncrypter(block, iv)

	// 分配加密缓冲区
	ciphertext := make([]byte, len(paddedPlaintext))

	// 加密
	mode.CryptBlocks(ciphertext, paddedPlaintext)

	return ciphertext, nil
}

// AES-128-CBC 加密函数
// 先进行base64编码，然后进行AES-128-CBC加密，最后再base64编码
// 与DecodeAESBase64的流程相反，适配PHP openssl_encrypt的输出格式
func EncodeAESBase64(buf []byte) []byte {
	if len(buf) == 0 {
		return buf
	}

	// AES-128-CBC 加密密钥（16字节）
	aesKey := []byte("4422a60e08c97f30")

	// AES-128-CBC 初始化向量（16字节）
	aesIv := []byte("8c97f304422a60e0")

	// 处理流程：YAML内容 -> base64编码 -> AES加密 -> base64编码 -> 最终密文
	// 第一步：先将YAML内容进行base64编码
	base64Encoded := base64.StdEncoding.EncodeToString(buf)

	// 第二步：对base64编码后的数据进行AES-128-CBC加密
	aesEncrypted, err := aesEncryptCBC([]byte(base64Encoded), aesKey, aesIv)
	if err != nil {
		// 如果加密失败，返回原始数据
		return buf
	}

	// 第三步：将AES加密后的二进制数据进行base64编码（PHP openssl_encrypt默认输出格式）
	finalResult := base64.StdEncoding.EncodeToString(aesEncrypted)

	return []byte(finalResult)
}
