package tool

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"reflect"
)

func GetFileFullPath(path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	exPath, _ := os.Getwd()

	return filepath.Join(exPath, path)
}

func GetUrlArg(args string, key string) string {
	values, _ := url.ParseQuery(args)
	return values.Get(key)
}

func SafeAsString(m map[string]interface{}, keys ...string) string {
	var current interface{} = m
	for _, key := range keys {
		if v, ok := current.(map[string]interface{}); ok {
			if val, ok := v[key]; ok {
				switch s := val.(type) {
				case string:
					return strings.TrimSpace(s)
				case float64:
					return fmt.Sprintf("%.0f", s)
				case int:
					return fmt.Sprintf("%d", s)
				}
			}
		}
	}

	return ""
}

func SafeAsBool(m map[string]interface{}, keys ...string) bool {
	var current interface{} = m
	for _, key := range keys {
		if v, ok := current.(map[string]interface{}); ok {
			if val, ok := v[key]; ok {
				if boolVal, ok := val.(bool); ok {
					return boolVal
				}
			}
		}
	}

	return false
}

func Contains(arr []string, key string) bool {
	for _, i := range arr {
		if i == key {
			return true
		}
	}
	return false
}

func IsLocalFile(path string) bool {
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		return false
	}
	return true
}

// 从本地文件或者http链接读取配置文件内容
func ReadFile(path string) ([]byte, error) {
	if !IsLocalFile(path) {
		resp, err := GetHttpClient().Get(path)
		if err != nil {
			return nil, errors.New("config file http get fail")
		}
		defer resp.Body.Close()
		return io.ReadAll(resp.Body)
	} else if filepath.IsAbs(path) {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			return nil, err
		}
		return os.ReadFile(path)
	} else {
		path, err := filepath.Abs(path)
		if err != nil {
			return nil, err
		}
		if _, err := os.Stat(path); os.IsNotExist(err) {
			return nil, err
		}
		return os.ReadFile(path)
	}
}

// getJSONStringPropertyValue 根据 JSON 字符串和属性路径获取对应的字符串属性值
func GetJSONPropertyValue(jsonStr, path string) (string, error) {
	// 解析 JSON 字符串为 map[string]interface{} 类型
	var data map[string]interface{}
	err := json.Unmarshal([]byte(jsonStr), &data)
	if err != nil {
		return "", fmt.Errorf("failed to parse JSON: %v", err)
	}

	// 按点分割属性路径
	parts := strings.Split(path, ".")

	// 从根节点逐级访问属性路径
	var current interface{} = data
	for _, part := range parts {
		switch v := current.(type) {
		case map[string]interface{}:
			value, ok := v[part]
			if !ok {
				return "", fmt.Errorf("field '%s' not found", part)
			}
			current = value
		default:
			return "", fmt.Errorf("invalid operation: %T is not a map", current)
		}
	}

	// 将最终的属性值转换为字符串类型
	if strValue, ok := current.(string); ok {
		return strValue, nil
	}

	// 如果最终值不是字符串类型，则返回错误
	return "", fmt.Errorf("field '%s' is not a string", path)
}
