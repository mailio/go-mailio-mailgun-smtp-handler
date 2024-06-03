package mailgunsmtphandler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/mail"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/mailgun/mailgun-go/v4"
	mailioutil "github.com/mailio/go-mailio-server/email/smtp"
	mailiotypes "github.com/mailio/go-mailio-server/email/smtp/types"
)

const MaxNumberOfRecipients = 20

type MailgunSmtpHandler struct {
	mg                *mailgun.MailgunImpl
	baseURL           string
	webhookApiKey     string
	developmentApiKey string
	client            *resty.Client
	mutex             sync.Mutex
	domainKeyMap      map[string]string
}

// NewMailgunSmtpHandler creates a new Mailgun SMTP handler with the specified webhook signing key and optional base URL.
// If the base URL is not provided, it defaults to "https://api.mailgun.net/v3".
//
// Parameters:
//   - webhookSigningKey: The signing key used for validating webhook requests for incoming emails.
//   - developmentApiKey: The API key used for sending emails from the development domain.
//   - baseURL: A pointer to a string specifying the base URL for the Mailgun API. If nil, the default URL is used.
//
// Returns:
//   - A new instance of MailgunSmtpHandler that implements the mailioutil.SmtpHandler interface.
func NewMailgunSmtpHandler(webhookSigningKey string, developmentApiKey string, baseURL *string) *MailgunSmtpHandler {
	base := "https://api.mailgun.net/v3"
	if baseURL != nil {
		base = *baseURL
	}
	client := resty.New()
	mg := mailgun.NewMailgun("mailgun.net", "api-key")
	return &MailgunSmtpHandler{
		client:            client,
		baseURL:           base,
		mg:                mg,
		webhookApiKey:     webhookSigningKey,
		developmentApiKey: developmentApiKey,
		domainKeyMap:      make(map[string]string)}
}

// associates the domain with the sending api key
func (m *MailgunSmtpHandler) SetDomainAndSendApiKey(key string, domain string) error {
	if key == "" || domain == "" {
		return fmt.Errorf("key and domain cannot be empty")
	}
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.domainKeyMap[domain] = key
	return nil
}

// send mail using mailgun
func (m *MailgunSmtpHandler) SendMimeMail(from mail.Address, raw []byte, to []mail.Address) (string, error) {
	fromDomain := strings.Split(from.Address, "@")[1]
	apiSendKey, ok := m.domainKeyMap[fromDomain]
	if !ok {
		return "", fmt.Errorf("no api key found for domain %s", fromDomain)
	}
	if len(to) > MaxNumberOfRecipients {
		return "", fmt.Errorf("max number of recipients exceeded (20)")
	}

	toCommaSeparated := ""
	for i, t := range to {
		toCommaSeparated += t.String()
		if i < len(to)-1 {
			toCommaSeparated += ","
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := m.client.R().
		SetFileReader("message", "message", bytes.NewReader(raw)).
		SetFormData(map[string]string{
			"to": toCommaSeparated,
		}).SetHeader("Content-Type", "multipart/form-data").
		SetBasicAuth("api", apiSendKey).SetContext(ctx).
		Post(fmt.Sprintf("%s/%s/messages.mime", m.baseURL, fromDomain))

	if err != nil {
		log.Default().Printf("Error creating request: %v", err)
		return err.Error(), err
	}
	if req.IsError() {
		log.Default().Printf("Error sending request: %v, code: %d", req.Error(), req.StatusCode())
		return "", fmt.Errorf("error sending request: %v, code: %d", req.Error(), req.StatusCode())
	}
	var body map[string]interface{}
	mErr := json.Unmarshal(req.Body(), &body)
	if mErr != nil {
		log.Default().Printf("Error unmarshalling response: %v", mErr)
		return "", mErr
	}
	if _, ok := body["id"]; !ok {
		return "", fmt.Errorf("no id found in response")
	}

	return body["id"].(string), nil
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

// list all supported domains
func (m *MailgunSmtpHandler) ListDomains() ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var domains Domains

	resp, err := m.client.R().
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
