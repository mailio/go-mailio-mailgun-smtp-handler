package mailgunsmtphandler

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/mail"
	"strconv"
	"strings"
	"time"

	"github.com/mailgun/mailgun-go/v4"
	mailioutil "github.com/mailio/go-mailio-server/email/smtp"
	mailiotypes "github.com/mailio/go-mailio-server/email/smtp/types"
)

const MaxNumberOfRecipients = 20

type MailgunSmtpHandler struct {
	mg *mailgun.MailgunImpl
}

func NewMailgunSmtpHandler(apiKey string, domain string) *MailgunSmtpHandler {
	mg := mailgun.NewMailgun(domain, apiKey)
	return &MailgunSmtpHandler{mg: mg}
}

// send mail using mailgun
func (m *MailgunSmtpHandler) SendMimeMail(raw []byte, to []mail.Address) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	nr := bytes.NewReader(raw)
	readCloser := io.NopCloser(nr)
	defer readCloser.Close() // no-op closer

	tos := []string{}
	for _, t := range to {
		tos = append(tos, t.String())
	}

	mailgunMsg := m.mg.NewMIMEMessage(readCloser, tos...)

	_, id, err := m.mg.Send(ctx, mailgunMsg)
	if err != nil {
		return "", err
	}
	return id, nil
}

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

/*
* Note: To receive raw MIME messages and perform your own parsing, you must configure a route with a URL ending with "mime". Example: http://myhost/post_mime
 */
func (m *MailgunSmtpHandler) ReceiveMail(request http.Request) (*mailiotypes.Mail, error) {

	err := request.ParseMultipartForm(32 << 20) // max 32 MB
	if err != nil {
		return nil, err
	}

	// PASS FAIL NOT_AVAILABLE
	spam := request.FormValue("X-Mailgun-Sflag") // True/False
	// spamScore := request.FormValue("X-Mailgun-Sscore")                        // spamicity score
	dkim := strings.ToLower(request.FormValue("X-Mailgun-Dkim-Check-Result")) // pass/fail
	spf := strings.ToLower(request.FormValue("X-Mailgun-Spf-Mailgun"))        // Pass/Neutral/Fail/SoftFail
	spamMailio := "PASS"
	if spam != "" {
		sVal, _ := strconv.ParseBool(spam)
		if sVal {
			spamMailio = "FAIL"
		}
	}

	timestamp := request.FormValue("timestamp")
	token := request.FormValue("token")
	signature := request.FormValue("signature")

	mailGunSignature := mailgun.Signature{
		Signature: signature,
		Token:     token,
		TimeStamp: timestamp,
	}

	verified, vErr := m.mg.VerifyWebhookSignature(mailGunSignature)
	if vErr != nil {
		return nil, vErr
	}
	if !verified {
		return nil, fmt.Errorf("failed to veriify webhook signature")
	}

	mime := request.FormValue("Body-mime")

	parsed, err := mailioutil.ParseMime([]byte(mime))
	if err != nil {
		return nil, err
	}
	parsed.DkimVerdict = &mailiotypes.VerdictStatus{
		Status: toMailioVerdict(dkim),
	}
	parsed.SpfVerdict = &mailiotypes.VerdictStatus{
		Status: toMailioVerdict(spf),
	}
	parsed.SpamVerdict = &mailiotypes.VerdictStatus{
		Status: spamMailio,
	}
	return parsed, nil
}
