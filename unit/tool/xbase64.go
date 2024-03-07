package tool

import (
	"encoding/base64"
	"strings"
)

func Base64DecodeByte(s string) ([]byte, error) {
	if i := len(s) % 4; i != 0 {
		s += strings.Repeat("=", 4-i)
	}
	s = strings.ReplaceAll(s, " ", "+")
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		decoded, err = base64.URLEncoding.DecodeString(s)
	}
	return decoded, err
}

func Base64DecodeString(s string) (string, error) {
	if i := len(s) % 4; i != 0 {
		s += strings.Repeat("=", 4-i)
	}
	s = strings.ReplaceAll(s, " ", "+")
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		decoded, err = base64.URLEncoding.DecodeString(s)
	}
	return string(decoded), err
}

func Base64EncodeString(str string) string {
	return base64.StdEncoding.EncodeToString([]byte(str))
}
