package tool

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
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

// getNestedValue 根据提供的键序列在嵌套 map 中查找对应的值
func getNestedValue(m map[string]any, keys ...string) any {
	current := m
	for i, key := range keys {
		val, ok := current[key]
		if !ok {
			return nil
		}
		// 如果不是最后一个键，且值是 map 类型，则继续深入查找
		if i < len(keys)-1 {
			if nextMap, ok := val.(map[string]any); ok {
				current = nextMap
			} else {
				return nil
			}
		} else {
			// 最后一个键，返回对应的值
			return val
		}
	}
	return current
}

func SafeAsString(m map[string]interface{}, keys ...string) string {
	var val = getNestedValue(m, keys...)
	switch s := val.(type) {
	case string:
		return strings.TrimSpace(s)
	case float64:
		return fmt.Sprintf("%.0f", s)
	case int:
		return fmt.Sprintf("%d", s)
	case []string:
		return strings.Join(s, ",")
		// default:
		// 	// 如果不是字符串类型，尝试将其转换为字符串
		// 	return fmt.Sprintf("%v", s)
	}
	return ""
}

func SafeAsBool(m map[string]interface{}, keys ...string) bool {
	var val = getNestedValue(m, keys...)
	switch val := val.(type) {
	case string:
		if boolVal, err := strconv.ParseBool(val); err == nil {
			return boolVal
		}
	case bool:
		return val
	case float64:
		return val > 0
	case int:
		return val > 0
	}

	return false
}

func SafeAsInt(m map[string]interface{}, keys ...string) int {
	var val = getNestedValue(m, keys...)
	switch s := val.(type) {
	case string:
		if intVal, err := strconv.Atoi(s); err == nil {
			return intVal
		}
	case float64:
		return int(s)
	case int:
		return s
	}

	return 0
}

// 转换为字段
func SafeAsMap(m map[string]interface{}, keys ...string) map[string]interface{} {
	var val = getNestedValue(m, keys...)
	if mapVal, ok := val.(map[string]interface{}); ok {
		return mapVal
	}
	return nil
}

// 转换为字符串字典
func SafeAsStringMap(m map[string]interface{}, keys ...string) map[string]string {
	var val = getNestedValue(m, keys...)
	if mapVal, ok := val.(map[string]interface{}); ok {
		result := make(map[string]string)
		for k, v := range mapVal {
			switch v := v.(type) {
			case string:
				result[k] = strings.TrimSpace(v)
			case float64:
				result[k] = fmt.Sprintf("%.0f", v)
			case int:
				result[k] = fmt.Sprintf("%d", v)
			default:
				// 如果不是字符串类型，尝试将其转换为字符串
				result[k] = fmt.Sprintf("%v", v)
			}
		}
		return result
	}

	return nil
}

// 转换为字符串数组
func SafeAsStringArray(m map[string]interface{}, keys ...string) []string {
	var val = getNestedValue(m, keys...)
	switch s := val.(type) {
	case []string:
		return s
	case string:
		return []string{s}
	case []interface{}:
		var arr []string
		for _, i := range s {
			if str, ok := i.(string); ok {
				arr = append(arr, str)
			}
		}
		return arr
	}
	return nil
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
