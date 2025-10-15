package mailgunsmtphandler

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"net/mail"
	"os"
	"strconv"
	"testing"

	"github.com/jhillyerd/enmime/v2"
	"github.com/joho/godotenv"
	"github.com/stretchr/testify/assert"
)

var (
	apiDevKey         string
	webHookSigningKey string
	smtpHost          string
	smtpUsername      string
	smtpPassword      string
	smtpPort          int
)

func init() {
	err := godotenv.Load()
	if err != nil {
		log.Fatalf("Error loading .env file, %v", err)
	}
	apiDevKey = os.Getenv("api_dev_key")
	webHookSigningKey = os.Getenv("webhook_signing_key")
	smtpHost = os.Getenv("smtp_server")
	smtpUsername = os.Getenv("smtp_username")
	smtpPassword = os.Getenv("smtp_password")
	smtpPort, _ = strconv.Atoi(os.Getenv("smtp_port"))

}

func TestMailgunSignature(t *testing.T) {
	// timestamp := "1713477754"
	// token := "4a280054b2dd2cd53e721e535339aae9be0ecc621970a4c904"
	// signature := "be1e42b5f7d86fb8ea6eb085759361951ba3cabc82559e766e1bee5547e8b85f"
	timestamp := "1717451874"
	token := "84f9394dc35fe0ea72ccc8a68e22d62becca294c26fc550fdf"
	signature := "c520c04aa841120e58d56f9fa78e3c97618512e8c1622507f75b9d0257d7bc61"
	h := hmac.New(sha256.New, []byte(webHookSigningKey))
	io.WriteString(h, timestamp)
	io.WriteString(h, token)

	calculatedSignature := h.Sum(nil)
	sig, err := hex.DecodeString(signature)
	if err != nil {
		t.Fatal(err)
	}
	if len(calculatedSignature) != len(sig) {
		t.Fatal(err)
	}

	isEqual := subtle.ConstantTimeCompare(sig, calculatedSignature) == 1
	assert.True(t, isEqual)
}

func TestMailgunSending(t *testing.T) {
	// Test sending email
	h := NewMailgunSmtpHandler(webHookSigningKey, apiDevKey, smtpHost, smtpPort, smtpUsername, smtpPassword)
	if h == nil {
		t.Fatalf("Error creating a new handler")
	}

	from := mail.Address{
		Name:    "Mg Tester",
		Address: "test@mailiomail.com",
	}

	outgoingMime := enmime.Builder().
		From(from.Name, from.Address).
		Subject("Testing it").
		Text([]byte("Text body")).
		HTML([]byte("<p>HTML body</p>"))

	to := []mail.Address{
		{
			Name:    "Igor Rendulic",
			Address: "rendulic.igor@mailiomail.com",
		},
	}
	bcc := []mail.Address{
		{
			Name:    "Igor Rendulic",
			Address: "igor.abc@mailiomail.com",
		},
	}
	cc := []mail.Address{
		{
			Name:    "Igor Rendulic",
			Address: "igor@mmmm.io",
		},
	}
	outgoingMime = outgoingMime.ToAddrs(to)
	outgoingMime = outgoingMime.CCAddrs(cc)
	// don't add bcc recipients into mime, add them to To field
	// outgoingMime = outgoingMime.BCCAddrs(bcc)

	ep, err := outgoingMime.Build()
	if err != nil {
		t.Fatalf("Error building email: %v", err)
	}
	var buf bytes.Buffer
	err = ep.Encode(&buf)
	if err != nil {
		t.Fatalf("Error encoding email: %v", err)
	}
	fmt.Printf("Email: %s\n", buf.String())

	if len(cc) > 0 {
		to = append(to, cc...)
	}
	if len(bcc) > 0 {
		to = append(to, bcc...)
	}
	id, err := h.SendMimeMail(from, buf.Bytes(), to)
	if err != nil {
		t.Errorf("Error sending email: %v", err)
	}
	fmt.Printf("Email sent with id: %s\n", id)
}

func MyHTTPHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Hello, World!"))
}

func TestMailgunReceive(t *testing.T) {
	content, err := os.ReadFile("test_data/gmail_newsletter_redfin.eml")
	if err != nil {
		t.Fatalf("Error reading test data: %v", err)
	}
	var buffer bytes.Buffer
	multipartWriter := multipart.NewWriter(&buffer)

	// define fields
	timestamp := "1234567"
	token := "token"

	multipartWriter.WriteField("from", "Redfin <listings@redfin.com>")
	multipartWriter.WriteField("recipient", "igor.amplio@gmail.com")
	multipartWriter.WriteField("sender", "sender@test.com")
	multipartWriter.WriteField("subject", "Test subject")
	multipartWriter.WriteField("body-mime", string(content))
	multipartWriter.WriteField("timestamp", "1234567")
	multipartWriter.WriteField("token", "token")
	hm := hmac.New(sha256.New, []byte(webHookSigningKey))
	io.WriteString(hm, timestamp)
	io.WriteString(hm, token)

	calculatedSignature := hm.Sum(nil)
	signature := hex.EncodeToString(calculatedSignature)
	err = multipartWriter.WriteField("signature", signature)
	if err != nil {
		t.Fatal(err)
	}

	req, reqErr := http.NewRequest("POST", "http://localhost:8080", &buffer)
	if reqErr != nil {
		t.Fatal(reqErr)
	}
	req.Header.Set("Content-Type", multipartWriter.FormDataContentType())
	multipartWriter.Close()

	h := NewMailgunSmtpHandler(webHookSigningKey, apiDevKey, smtpHost, smtpPort, smtpUsername, smtpPassword)
	em, err := h.ReceiveMail(*req)
	if err != nil {
		t.Fatalf("Error receiving email: %v", err)
	}
	assert.Equal(t, 1, len(em.ReplyTo))
	assert.Equal(t, "Salt Lake City Tour Insights: 2684 S Melbourne St E and 1 more update", em.Subject)
	assert.Equal(t, "<0101018e5b55e0ef-7a8315df-2fad-40ac-93d4-5c6b27adc02e-000000@us-west-2.amazonses.com>", em.MessageId)
	assert.Equal(t, "listings_support@redfin.com", em.ReplyTo[0].Address)
	assert.Equal(t, "igor.amplio@gmail.com", em.To[0].Address)
	assert.Equal(t, "listings@redfin.com", em.From.Address)
}

func TestMailgunListDomains(t *testing.T) {
	h := NewMailgunSmtpHandler(webHookSigningKey, apiDevKey, smtpHost, smtpPort, smtpUsername, smtpPassword)
	domains, err := h.ListDomains()
	if err != nil {
		t.Fatalf("Error listing domains: %v", err)
	}
	assert.Greater(t, len(domains), 0)
}
