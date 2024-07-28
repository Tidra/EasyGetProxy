package tool

import (
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

// 通过json路径字符串获取json数据
func getFieldByPath(data interface{}, fieldPath string) (interface{}, error) {
    // 按点分割字段路径字符串
    path := strings.Split(fieldPath, ".")

    // 使用反射动态访问结构体字段
    value := reflect.ValueOf(data)
    for _, fieldName := range path {
        if value.Kind() == reflect.Ptr {
            value = value.Elem()
        }
        fieldValue := value.FieldByName(fieldName)
        if !fieldValue.IsValid() {
            return nil, fmt.Errorf("field '%s' not found", fieldName)
        }
        value = fieldValue
    }

    return value.Interface(), nil
}