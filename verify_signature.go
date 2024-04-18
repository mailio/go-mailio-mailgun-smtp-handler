package mailgunsmtphandler

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"io"

	"github.com/mailgun/mailgun-go/v4"
)

// VerifyWebhookSignature is a modified method from mailgun that supports a webhook key, intead of sending api key
func VerifyWebhookSignature(sig mailgun.Signature, webhookApiKey string) (verified bool, err error) {
	h := hmac.New(sha256.New, []byte(webhookApiKey))
	io.WriteString(h, sig.TimeStamp)
	io.WriteString(h, sig.Token)

	calculatedSignature := h.Sum(nil)
	signature, err := hex.DecodeString(sig.Signature)
	if err != nil {
		return false, err
	}
	if len(calculatedSignature) != len(signature) {
		return false, nil
	}

	return subtle.ConstantTimeCompare(signature, calculatedSignature) == 1, nil
}
