package convert

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
)

// AES-128-CBC 解密函数
// 先进行AES-128-CBC解密，然后进行base64解密
// 适配PHP openssl_encrypt的默认输出格式（base64编码的加密数据）
func DecodeAESBase64(buf []byte) []byte {
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
		if hexDecoded, hexErr := hex.DecodeString(string(buf)); hexErr == nil {
			base64Decoded = hexDecoded
		} else {
			// 都失败，尝试直接用原始数据（可能本身就是二进制加密数据）
			base64Decoded = buf
		}
	}
	
	// 第二步：尝试AES解密
	aesDecrypted, err := aesDecryptCBC(base64Decoded, aesKey, aesIv)
	if err != nil {
		// 如果AES解密失败，返回原始数据（不是DecodeBase64的结果）
		// 这样可以让外层DecodeConfig继续尝试其他方法
		return buf
	}
	
	// 第三步：AES解密成功后，再进行base64解密得到最终的YAML内容
	finalResult := DecodeBase64(aesDecrypted)
	
	// 如果最终结果为空或太小，返回AES解密的直接结果
	if len(finalResult) < 10 {
		return aesDecrypted
	}
	
	return finalResult
}

// AES-128-CBC 解密实现
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
	
	// 解密
	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)
	
	// 移除PKCS7填充
	return pkcs7Unpadding(plaintext), nil
}

// PKCS7 填充移除
func pkcs7Unpadding(data []byte) []byte {
	length := len(data)
	if length == 0 {
		return data
	}
	
	unpadding := int(data[length-1])
	if unpadding > length {
		return data
	}
	
	return data[:(length - unpadding)]
}

// 检查是否为十六进制字符串（用于判断是否需要AES解密）
func isHexString(data []byte) bool {
	_, err := hex.DecodeString(string(data))
	return err == nil
}

