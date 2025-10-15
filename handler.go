package mailgunsmtphandler

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/mail"
	"net/smtp"
	"strconv"
	"strings"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/mailgun/mailgun-go/v4"
	abi "github.com/mailio/go-mailio-smtp-abi"
	helpers "github.com/mailio/go-mailio-smtp-helpers"
)

const MaxNumberOfRecipients = 20

type MailgunSmtpHandler struct {
	webhookApiKey     string
	developmentApiKey string
	restClient        *resty.Client
	smtpHost          string
	smtpPort          int
	smtpUsername      string
	smtpPassword      string
}

// NewMailgunSmtpHandler creates a new Mailgun SMTP handler with the specified webhook signing key
//
// Parameters:
//   - webhookSigningKey: The signing key used for validating webhook requests for incoming emails.
//   - developmentApiKey: The API key used for sending emails from the development domain.
//   - smtpHost: The SMTP host to use for sending emails.
//   - smtpUsername: The username to use for authenticating with the SMTP server.
//   - smtpPassword: The password to use for authenticating with the SMTP server.
//
// Returns:
//   - A new instance of MailgunSmtpHandler that implements the mailioutil.SmtpHandler interface.
func NewMailgunSmtpHandler(webhookSigningKey string, developmentApiKey string, smtpHost string, smtpPort int, smtpUsername, smtpPassword string) *MailgunSmtpHandler {
	// new SMTP client
	restClient := resty.New()
	return &MailgunSmtpHandler{
		webhookApiKey:     webhookSigningKey,
		developmentApiKey: developmentApiKey,
		restClient:        restClient,
		smtpHost:          smtpHost,
		smtpPort:          smtpPort,
		smtpUsername:      smtpUsername,
		smtpPassword:      smtpPassword,
	}
}

// send mail using mailgun smtp server
func (m *MailgunSmtpHandler) SendMimeMail(from mail.Address, mime []byte, to []mail.Address) (string, error) {
	loginAuth := PlainOrLoginAuth(m.smtpUsername, m.smtpPassword, m.smtpHost)

	msgId, mErr := parseMessageIdFromMime(mime)
	if mErr != nil {
		return "", mErr
	}

	tos := make([]string, 0)
	for i, t := range to {
		tos = append(tos, t.Address)
		if i > MaxNumberOfRecipients {
			break
		}
	}
	smtpHost := fmt.Sprintf("%s:%d", m.smtpHost, m.smtpPort)
	sndErr := smtp.SendMail(smtpHost, loginAuth, from.Address, tos, mime)
	if sndErr != nil {
		return msgId, sndErr
	}
	return msgId, nil
}

/*
* Note: To receive raw MIME messages and perform your own parsing, you must configure a route with a URL ending with "mime". Example: http://myhost/post_mime
 */
func (m *MailgunSmtpHandler) ReceiveMail(request http.Request) (*abi.Mail, error) {
	body, err := io.ReadAll(request.Body)
	if err != nil {
		log.Printf("Error reading body: %v", err)
		return nil, err
	}

	log.Printf("%s", string(body))

	request.Body = io.NopCloser(bytes.NewBuffer(body))

	contentType := request.Header.Get("Content-Type")
	if contentType == "application/x-www-form-urlencoded" {
		err := request.ParseForm()
		if err != nil {
			return nil, err
		}
	} else if contentType == "multipart/form-data" {
		err := request.ParseMultipartForm(32 << 20) // max 32 MB
		if err != nil {
			return nil, err
		}
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

	verified, vErr := VerifyWebhookSignature(mailGunSignature, m.webhookApiKey)
	if vErr != nil {
		return nil, vErr
	}
	if !verified {
		return nil, fmt.Errorf("failed to veriify webhook signature")
	}

	mime := request.FormValue("body-mime")

	parsed, err := helpers.ParseMime([]byte(mime))
	if err != nil {
		return nil, err
	}
	parsed.DkimVerdict = &abi.VerdictStatus{
		Status: toMailioVerdict(dkim),
	}
	parsed.SpfVerdict = &abi.VerdictStatus{
		Status: toMailioVerdict(spf),
	}
	parsed.SpamVerdict = &abi.VerdictStatus{
		Status: spamMailio,
	}
	parsed.RawMime = []byte(mime)
	return parsed, nil
}

// list all supported domains using mailgun api
func (m *MailgunSmtpHandler) ListDomains() ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var domains Domains

	resp, err := m.restClient.R().
		SetBasicAuth("api", m.developmentApiKey).
		SetResult(&domains).
		SetQueryParam("limit", "500").
		SetQueryParam("state", "active").
		SetContext(ctx).Get("https://api.mailgun.net/v4/domains")

	if err != nil {
		log.Printf("Error getting domains: %v", err)
		return nil, err
	}
	if resp.IsError() {
		log.Printf("Error getting domains: %v", resp.Error())
		return nil, fmt.Errorf("error getting domains: %v", resp.Error())
	}

	var domainNames []string
	for _, d := range domains.Items {
		domainNames = append(domainNames, d.Name)
	}

	return domainNames, nil
}
