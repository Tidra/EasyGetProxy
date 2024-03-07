package tool

import (
	"encoding/json"

	"github.com/Tidra/EasyGetProxy/unit/log"
)

type CountryEmoji struct {
	Code  string `json:"code"`
	Emoji string `json:"emoji"`
}

type EmojiMap map[string]string

func InitEmojiData() EmojiMap {
	data, err := ReadFile("assets/flags.json")
	if err != nil {
		log.LogError("读取国家emoji文件失败: %s", err.Error())
		return nil
	}

	var countryEmojiList = make([]CountryEmoji, 0)
	err = json.Unmarshal(data, &countryEmojiList)
	if err != nil {
		log.LogError("读取国家emoji文件失败: %s", err.Error())
		return nil
	}

	emojiMap := make(map[string]string)
	for _, i := range countryEmojiList {
		emojiMap[i.Code] = i.Emoji
	}
	return emojiMap
}

func (e EmojiMap) GetEmoji(country string) string {
	if e != nil {
		if em := e[country]; em != "" {
			return em
		}
	}
	return ""
}
