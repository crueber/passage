package email

import (
	"bytes"
	"context"
	"embed"
	"fmt"
	"html/template"
	"log/slog"
	ttext "text/template"

	mail "github.com/wneessen/go-mail"

	"github.com/crueber/passage/internal/config"
)

//go:embed templates/*.html templates/*.txt
var templateFS embed.FS

// Sender is the interface for sending emails. It is defined here at the
// consumer boundary.
type Sender interface {
	SendPasswordReset(ctx context.Context, toEmail, toName, resetURL string) error
}

// resetData holds the data passed to password reset email templates.
type resetData struct {
	Name     string
	ResetURL string
}

// SMTPSender sends emails via SMTP using go-mail.
type SMTPSender struct {
	cfg      *config.Config
	logger   *slog.Logger
	htmlTmpl *template.Template
	textTmpl *ttext.Template
}

// NewSMTPSender creates a new SMTPSender. Templates are parsed at construction time.
func NewSMTPSender(cfg *config.Config, logger *slog.Logger) (*SMTPSender, error) {
	htmlTmpl, err := template.ParseFS(templateFS, "templates/password_reset.html")
	if err != nil {
		return nil, fmt.Errorf("email: parse html template: %w", err)
	}
	textTmpl, err := ttext.ParseFS(templateFS, "templates/password_reset.txt")
	if err != nil {
		return nil, fmt.Errorf("email: parse text template: %w", err)
	}
	return &SMTPSender{
		cfg:      cfg,
		logger:   logger,
		htmlTmpl: htmlTmpl,
		textTmpl: textTmpl,
	}, nil
}

// SendPasswordReset sends a password reset email to the given recipient.
// If SMTP host is not configured, an error is returned.
func (s *SMTPSender) SendPasswordReset(ctx context.Context, toEmail, toName, resetURL string) error {
	if s.cfg.SMTP.Host == "" {
		s.logger.Warn("SMTP not configured: cannot send password reset email", "to", toEmail)
		return fmt.Errorf("email: SMTP host is not configured")
	}

	data := resetData{Name: toName, ResetURL: resetURL}

	var htmlBuf, textBuf bytes.Buffer
	if err := s.htmlTmpl.Execute(&htmlBuf, data); err != nil {
		return fmt.Errorf("email: render html template: %w", err)
	}
	if err := s.textTmpl.Execute(&textBuf, data); err != nil {
		return fmt.Errorf("email: render text template: %w", err)
	}

	// Build the go-mail client options.
	opts := []mail.Option{
		mail.WithPort(s.cfg.SMTP.Port),
		mail.WithSMTPAuth(mail.SMTPAuthPlain),
		mail.WithUsername(s.cfg.SMTP.Username),
		mail.WithPassword(s.cfg.SMTP.Password),
	}
	switch s.cfg.SMTP.TLS {
	case "tls":
		opts = append(opts, mail.WithSSL())
	case "none":
		opts = append(opts, mail.WithTLSPolicy(mail.NoTLS))
	default: // "starttls" and anything else
		opts = append(opts, mail.WithTLSPolicy(mail.TLSMandatory))
	}

	client, err := mail.NewClient(s.cfg.SMTP.Host, opts...)
	if err != nil {
		return fmt.Errorf("email: create smtp client: %w", err)
	}

	msg := mail.NewMsg()
	if err := msg.From(s.cfg.SMTP.From); err != nil {
		return fmt.Errorf("email: set from: %w", err)
	}
	if err := msg.AddToFormat(toName, toEmail); err != nil {
		return fmt.Errorf("email: set to: %w", err)
	}
	msg.Subject("Reset your Passage password")
	msg.SetBodyString(mail.TypeTextPlain, textBuf.String())
	msg.AddAlternativeString(mail.TypeTextHTML, htmlBuf.String())

	if err := client.DialAndSendWithContext(ctx, msg); err != nil {
		return fmt.Errorf("email: send: %w", err)
	}
	return nil
}
