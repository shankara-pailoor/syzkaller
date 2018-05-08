package utils

import (
	"strings"
	"encoding/hex"
	"fmt"
)

func StripString(s string) (string, int) {
	k, j := 0, 0
	foundQuote := false
	for i := 0; i < len(s); i++ {
		if s[i] == '"' {
			if foundQuote {
				k = i
				break
			}
			j = i
			foundQuote = true
		}
	}
	return s[j+1:k], k-j-1
}

func ParseString(s string) string{
	var decoded []byte
	var err error
	if decoded, err = hex.DecodeString(strings.Replace(s, `\x`, "", -1)); err != nil {
		panic(fmt.Sprintf("Failed to decode string: %s, with error: %s\n", s, err.Error()))
	}
	return string(decoded)
}
