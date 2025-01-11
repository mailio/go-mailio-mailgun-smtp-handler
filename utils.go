package mailgunsmtphandler

import (
	"strings"

	mailioutil "github.com/mailio/go-mailio-server/email/smtp"
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
	parsed, err := mailioutil.ParseMime(mime)
	if err != nil {
		return "", err
	}
	return parsed.MessageId, nil
}
