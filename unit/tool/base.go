package tool

import (
	"net/url"
	"os"
	"path/filepath"
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

func SafeAsString(m map[string]interface{}, key string) string {
	if val, ok := m[key]; ok {
		if strVal, ok := val.(string); ok {
			return strVal
		}
	}
	return ""
}

func SafeAsBool(m map[string]interface{}, key string) bool {
	if val, ok := m[key]; ok {
		if boolVal, ok := val.(bool); ok {
			return boolVal
		}
	}
	return false
}
