package saml2

import (
	"encoding/base64"
	"fmt"
	"regexp"
)

func xmlBytes(str string) ([]byte, error) {
	if len(str) == 0 {
		return nil, fmt.Errorf("No string to decode")
	}

	re := regexp.MustCompile("[ \t]")
	str = re.ReplaceAllString(str, "")

	if str[0] == '\n' {
		str = str[1:]
	}

	return base64.StdEncoding.DecodeString(str)
}
