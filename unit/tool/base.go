package tool

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
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
