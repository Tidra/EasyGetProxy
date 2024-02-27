package config

type Source struct {
	Type    string                 `json:"type" yaml:"type"`
	Options map[string]interface{} `json:"options" yaml:"options"`
}
