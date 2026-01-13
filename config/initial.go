package config

import (
	"fmt"
	"os"
	"path/filepath"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
)

// Init prepare necessary files
func Init(dir string) error {
	// initial homedir
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		if err := os.MkdirAll(dir, 0o777); err != nil {
			return fmt.Errorf("can't create config directory %s: %s", dir, err.Error())
		}
	}

	// initial config.yaml
	// 使用完整路径，确保在正确的 HomeDir 中查找/创建配置文件
	// C.Path.Config() 可能返回相对路径 "config.yaml"，需要与 HomeDir 拼接
	configPath := C.Path.Config()
	if !filepath.IsAbs(configPath) {
		configPath = filepath.Join(C.Path.HomeDir(), configPath)
	}

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		log.Infoln("Can't find config, create a initial config file")
		f, err := os.OpenFile(configPath, os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			return fmt.Errorf("can't create file %s: %s", configPath, err.Error())
		}
		f.Write([]byte(`mixed-port: 7890`))
		f.Close()
	}

	return nil
}
