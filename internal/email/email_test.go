package email_test

import (
	"context"
	"log/slog"
	"testing"

	"github.com/crueber/passage/internal/config"
	"github.com/crueber/passage/internal/email"
)

// testConfig returns a Config with a blank SMTP host so we can test the
// "SMTP not configured" error path without connecting to a real server.
func testConfig(smtpHost string) *config.Config {
	return &config.Config{
		SMTP: config.SMTPConfig{
			Host:     smtpHost,
			Port:     587,
			Username: "user",
			Password: "pass",
			From:     "passage@example.com",
			TLS:      "starttls",
		},
		Server: config.ServerConfig{
			BaseURL: "https://auth.example.com",
		},
	}
}

// TestNewSMTPSender_ParsesTemplates verifies that NewSMTPSender succeeds and
// that the embedded templates parse without error.
func TestNewSMTPSender_ParsesTemplates(t *testing.T) {
	t.Parallel()

	logger := slog.Default()
	_, err := email.NewSMTPSender(testConfig("smtp.example.com"), logger)
	if err != nil {
		t.Fatalf("NewSMTPSender: unexpected error parsing templates: %v", err)
	}
}

// TestSendPasswordReset_SMTPNotConfigured verifies that SendPasswordReset
// returns an error when the SMTP host is empty, rather than panicking or
// silently dropping the email.
func TestSendPasswordReset_SMTPNotConfigured(t *testing.T) {
	t.Parallel()

	logger := slog.Default()
	sender, err := email.NewSMTPSender(testConfig(""), logger)
	if err != nil {
		t.Fatalf("NewSMTPSender: %v", err)
	}

	err = sender.SendPasswordReset(
		context.Background(),
		"user@example.com",
		"Test User",
		"https://auth.example.com/reset/sometoken",
	)
	if err == nil {
		t.Fatal("SendPasswordReset with empty SMTP host: expected error, got nil")
	}
}
