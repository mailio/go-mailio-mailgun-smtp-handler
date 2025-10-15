package mailgunsmtphandler

import (
	"strings"

	helpers "github.com/mailio/go-mailio-smtp-helpers"
)

func toMailioVerdict(verdict string) string {
	verdict = strings.ToLower(verdict)
	switch verdict {
	case "pass":
		return "PASS"
	case "fail":
		return "FAIL"
	case "softfail":
		return "FAIL"
	case "neutral":
		return "NOT_AVAILABLE"
	default:
		return "NOT_AVAILABLE"
	}
}

func parseMessageIdFromMime(mime []byte) (string, error) {
	parsed, err := helpers.ParseMime(mime)
	if err != nil {
		return "", err
	}
	return parsed.MessageId, nil
}
