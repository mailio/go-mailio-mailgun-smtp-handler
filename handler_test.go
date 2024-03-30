package mailgunsmtphandler

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"net/mail"
	"os"
	"testing"

	"github.com/jhillyerd/enmime"
	"github.com/joho/godotenv"
	"github.com/stretchr/testify/assert"
)

var (
	domain            string
	apiKey            string
	webHookSigningKey string
)

func init() {
	err := godotenv.Load()
	if err != nil {
		log.Fatalf("Error loading .env file, %v", err)
	}
	domain = os.Getenv("domain")
	apiKey = os.Getenv("apikey")
	webHookSigningKey = os.Getenv("webhook_signing_key")
}

func TestMailgunSending(t *testing.T) {
	// Test sending email
	// to := []string{"igor@mail.io"}
	h := NewMailgunSmtpHandler(apiKey, domain)

	outgoingMime := enmime.Builder().
		From("Mg Tester", "test@mg.mailiomail.com").
		Subject("Testing it").
		Text([]byte("Text body")).
		HTML([]byte("<p>HTML body</p>"))

	to := []mail.Address{
		{
			Name:    "Igor",
			Address: "igor@mail.io",
		},
	}
	outgoingMime = outgoingMime.ToAddrs(to)

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

	id, err := h.SendMimeMail(buf.Bytes(), to)
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
	multipartWriter.WriteField("Body-mime", string(content))
	multipartWriter.WriteField("timestamp", "1234567")
	multipartWriter.WriteField("token", "token")
	hm := hmac.New(sha256.New, []byte(apiKey))
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

	h := NewMailgunSmtpHandler(apiKey, domain)
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
