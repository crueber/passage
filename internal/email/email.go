package email

import (
	"bytes"
	"context"
	"embed"
	"fmt"
	"html/template"
	"log/slog"
	ttext "text/template"
	"time"

	mail "github.com/wneessen/go-mail"

	"github.com/crueber/passage/internal/config"
	"github.com/crueber/passage/internal/settings"
)

//go:embed templates/*.html templates/*.txt
var templateFS embed.FS

// Sender is the interface for sending emails. It is defined here at the
// consumer boundary.
type Sender interface {
	SendPasswordReset(ctx context.Context, toEmail, toName, resetURL string) error
	SendMagicLink(ctx context.Context, toEmail, toName, magicURL string) error
	SendVerifyEmail(ctx context.Context, toEmail, toName, verifyURL string) error
	SendInvite(ctx context.Context, toEmail, toName, inviter, inviteURL string, expiresIn time.Duration) error
}

// resetData holds the data passed to password reset email templates.
type resetData struct {
	Name     string
	ResetURL string
}

// magicLinkData holds the data passed to magic link email templates.
type magicLinkData struct {
	Name     string
	MagicURL string
}

// verifyEmailData holds the data passed to email verification templates.
type verifyEmailData struct {
	Name      string
	VerifyURL string
}

// inviteData holds the data passed to invitation email templates.
type inviteData struct {
	Name      string
	Inviter   string
	InviteURL string
	ExpiresIn string
}

// SMTPSender sends emails via SMTP using go-mail.
type SMTPSender struct {
	cfg               *config.Config
	settings          settings.Store // optional; live SMTP settings when wired
	logger            *slog.Logger
	htmlTmpl          *template.Template
	textTmpl          *ttext.Template
	magicLinkHTMLTmpl *template.Template
	magicLinkTextTmpl *ttext.Template
	verifyHTMLTmpl    *template.Template
	verifyTextTmpl    *ttext.Template
	inviteHTMLTmpl    *template.Template
	inviteTextTmpl    *ttext.Template
}

// NewSMTPSender creates a new SMTPSender. Templates are parsed at construction time.
func NewSMTPSender(cfg *config.Config, logger *slog.Logger, stores ...settings.Store) (*SMTPSender, error) {
	var st settings.Store
	if len(stores) > 0 {
		st = stores[0]
	}
	htmlTmpl, err := template.ParseFS(templateFS, "templates/password_reset.html")
	if err != nil {
		return nil, fmt.Errorf("email: parse html template: %w", err)
	}
	textTmpl, err := ttext.ParseFS(templateFS, "templates/password_reset.txt")
	if err != nil {
		return nil, fmt.Errorf("email: parse text template: %w", err)
	}
	magicLinkHTMLTmpl, err := template.ParseFS(templateFS, "templates/magic_link.html")
	if err != nil {
		return nil, fmt.Errorf("email: parse magic link html template: %w", err)
	}
	magicLinkTextTmpl, err := ttext.ParseFS(templateFS, "templates/magic_link.txt")
	if err != nil {
		return nil, fmt.Errorf("email: parse magic link text template: %w", err)
	}
	verifyHTMLTmpl, err := template.ParseFS(templateFS, "templates/verify_email.html")
	if err != nil {
		return nil, fmt.Errorf("email: parse verify email html template: %w", err)
	}
	verifyTextTmpl, err := ttext.ParseFS(templateFS, "templates/verify_email.txt")
	if err != nil {
		return nil, fmt.Errorf("email: parse verify email text template: %w", err)
	}
	inviteHTMLTmpl, err := template.ParseFS(templateFS, "templates/invite.html")
	if err != nil {
		return nil, fmt.Errorf("email: parse invite html template: %w", err)
	}
	inviteTextTmpl, err := ttext.ParseFS(templateFS, "templates/invite.txt")
	if err != nil {
		return nil, fmt.Errorf("email: parse invite text template: %w", err)
	}
	return &SMTPSender{
		cfg:               cfg,
		settings:          st,
		logger:            logger,
		htmlTmpl:          htmlTmpl,
		textTmpl:          textTmpl,
		magicLinkHTMLTmpl: magicLinkHTMLTmpl,
		magicLinkTextTmpl: magicLinkTextTmpl,
		verifyHTMLTmpl:    verifyHTMLTmpl,
		verifyTextTmpl:    verifyTextTmpl,
		inviteHTMLTmpl:    inviteHTMLTmpl,
		inviteTextTmpl:    inviteTextTmpl,
	}, nil
}

// smtpConfig reads the live SMTP settings, falling back to the startup config
// snapshot. A change in the admin UI therefore applies to the next email
// without restarting the process.
func (s *SMTPSender) smtpConfig(ctx context.Context) config.SMTPConfig {
	c := s.cfg.SMTP
	if s.settings == nil {
		return c
	}
	c.Host = settings.String(ctx, s.settings, settings.SMTPHost, c.Host)
	c.Port = settings.Int(ctx, s.settings, settings.SMTPPort, c.Port, 1, 65535)
	c.Username = settings.String(ctx, s.settings, settings.SMTPUsername, c.Username)
	c.Password = settings.String(ctx, s.settings, settings.SMTPPassword, c.Password)
	c.TLS = settings.String(ctx, s.settings, settings.SMTPTLS, c.TLS)
	c.From = settings.String(ctx, s.settings, settings.SMTPFrom, c.From)
	return c
}

// SendPasswordReset sends a password reset email to the given recipient.
// If SMTP host is not configured, an error is returned.
func (s *SMTPSender) SendPasswordReset(ctx context.Context, toEmail, toName, resetURL string) error {
	smtp := s.smtpConfig(ctx)
	if smtp.Host == "" {
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
		mail.WithPort(smtp.Port),
		mail.WithSMTPAuth(mail.SMTPAuthPlain),
		mail.WithUsername(smtp.Username),
		mail.WithPassword(smtp.Password),
	}
	switch smtp.TLS {
	case "tls":
		opts = append(opts, mail.WithSSL())
	case "none":
		opts = append(opts, mail.WithTLSPolicy(mail.NoTLS))
	default: // "starttls" and anything else
		opts = append(opts, mail.WithTLSPolicy(mail.TLSMandatory))
	}

	client, err := mail.NewClient(smtp.Host, opts...)
	if err != nil {
		return fmt.Errorf("email: create smtp client: %w", err)
	}

	msg := mail.NewMsg()
	if err := msg.From(smtp.From); err != nil {
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

// SendMagicLink sends a magic sign-in link email to the given recipient.
// If SMTP host is not configured, an error is returned.
func (s *SMTPSender) SendMagicLink(ctx context.Context, toEmail, toName, magicURL string) error {
	smtp := s.smtpConfig(ctx)
	if smtp.Host == "" {
		s.logger.Warn("SMTP not configured: cannot send magic link email", "to", toEmail)
		return fmt.Errorf("email: SMTP host is not configured")
	}

	data := magicLinkData{Name: toName, MagicURL: magicURL}

	var htmlBuf, textBuf bytes.Buffer
	if err := s.magicLinkHTMLTmpl.Execute(&htmlBuf, data); err != nil {
		return fmt.Errorf("email: render magic link html template: %w", err)
	}
	if err := s.magicLinkTextTmpl.Execute(&textBuf, data); err != nil {
		return fmt.Errorf("email: render magic link text template: %w", err)
	}

	// Build the go-mail client options.
	opts := []mail.Option{
		mail.WithPort(smtp.Port),
		mail.WithSMTPAuth(mail.SMTPAuthPlain),
		mail.WithUsername(smtp.Username),
		mail.WithPassword(smtp.Password),
	}
	switch smtp.TLS {
	case "tls":
		opts = append(opts, mail.WithSSL())
	case "none":
		opts = append(opts, mail.WithTLSPolicy(mail.NoTLS))
	default: // "starttls" and anything else
		opts = append(opts, mail.WithTLSPolicy(mail.TLSMandatory))
	}

	client, err := mail.NewClient(smtp.Host, opts...)
	if err != nil {
		return fmt.Errorf("email: create smtp client: %w", err)
	}

	msg := mail.NewMsg()
	if err := msg.From(smtp.From); err != nil {
		return fmt.Errorf("email: set from: %w", err)
	}
	if err := msg.AddToFormat(toName, toEmail); err != nil {
		return fmt.Errorf("email: set to: %w", err)
	}
	msg.Subject("Your Passage sign-in link")
	msg.SetBodyString(mail.TypeTextPlain, textBuf.String())
	msg.AddAlternativeString(mail.TypeTextHTML, htmlBuf.String())

	if err := client.DialAndSendWithContext(ctx, msg); err != nil {
		return fmt.Errorf("email: send magic link: %w", err)
	}
	return nil
}

// SendVerifyEmail sends an email address verification link to the recipient.
// If SMTP is not usable, an error is returned and the caller must keep the
// account usable (unverified) rather than failing the registration.
func (s *SMTPSender) SendVerifyEmail(ctx context.Context, toEmail, toName, verifyURL string) error {
	smtp := s.smtpConfig(ctx)
	if smtp.Host == "" || smtp.From == "" {
		s.logger.Warn("SMTP not configured: cannot send verification email", "to", toEmail)
		return fmt.Errorf("email: SMTP host or from address is not configured")
	}

	data := verifyEmailData{Name: toName, VerifyURL: verifyURL}

	var htmlBuf, textBuf bytes.Buffer
	if err := s.verifyHTMLTmpl.Execute(&htmlBuf, data); err != nil {
		return fmt.Errorf("email: render verify email html template: %w", err)
	}
	if err := s.verifyTextTmpl.Execute(&textBuf, data); err != nil {
		return fmt.Errorf("email: render verify email text template: %w", err)
	}

	// Build the go-mail client options.
	opts := []mail.Option{
		mail.WithPort(smtp.Port),
		mail.WithSMTPAuth(mail.SMTPAuthPlain),
		mail.WithUsername(smtp.Username),
		mail.WithPassword(smtp.Password),
	}
	switch smtp.TLS {
	case "tls":
		opts = append(opts, mail.WithSSL())
	case "none":
		opts = append(opts, mail.WithTLSPolicy(mail.NoTLS))
	default: // "starttls" and anything else
		opts = append(opts, mail.WithTLSPolicy(mail.TLSMandatory))
	}

	client, err := mail.NewClient(smtp.Host, opts...)
	if err != nil {
		return fmt.Errorf("email: create smtp client: %w", err)
	}

	msg := mail.NewMsg()
	if err := msg.From(smtp.From); err != nil {
		return fmt.Errorf("email: set from: %w", err)
	}
	if err := msg.AddToFormat(toName, toEmail); err != nil {
		return fmt.Errorf("email: set to: %w", err)
	}
	msg.Subject("Verify your Passage email address")
	msg.SetBodyString(mail.TypeTextPlain, textBuf.String())
	msg.AddAlternativeString(mail.TypeTextHTML, htmlBuf.String())

	if err := client.DialAndSendWithContext(ctx, msg); err != nil {
		return fmt.Errorf("email: send verification email: %w", err)
	}
	return nil
}

// SendInvite sends an invitation link to an address that does not yet have an
// account. If SMTP is not usable an error is returned and the caller should not
// leave a dangling invitation behind.
func (s *SMTPSender) SendInvite(ctx context.Context, toEmail, toName, inviter, inviteURL string, expiresIn time.Duration) error {
	smtp := s.smtpConfig(ctx)
	if smtp.Host == "" || smtp.From == "" {
		s.logger.Warn("SMTP not configured: cannot send invitation email", "to", toEmail)
		return fmt.Errorf("email: SMTP host or from address is not configured")
	}

	data := inviteData{
		Name:      toName,
		Inviter:   inviter,
		InviteURL: inviteURL,
		ExpiresIn: humanDuration(expiresIn),
	}

	var htmlBuf, textBuf bytes.Buffer
	if err := s.inviteHTMLTmpl.Execute(&htmlBuf, data); err != nil {
		return fmt.Errorf("email: render invite html template: %w", err)
	}
	if err := s.inviteTextTmpl.Execute(&textBuf, data); err != nil {
		return fmt.Errorf("email: render invite text template: %w", err)
	}

	// Build the go-mail client options.
	opts := []mail.Option{
		mail.WithPort(smtp.Port),
		mail.WithSMTPAuth(mail.SMTPAuthPlain),
		mail.WithUsername(smtp.Username),
		mail.WithPassword(smtp.Password),
	}
	switch smtp.TLS {
	case "tls":
		opts = append(opts, mail.WithSSL())
	case "none":
		opts = append(opts, mail.WithTLSPolicy(mail.NoTLS))
	default: // "starttls" and anything else
		opts = append(opts, mail.WithTLSPolicy(mail.TLSMandatory))
	}

	client, err := mail.NewClient(smtp.Host, opts...)
	if err != nil {
		return fmt.Errorf("email: create smtp client: %w", err)
	}

	msg := mail.NewMsg()
	if err := msg.From(smtp.From); err != nil {
		return fmt.Errorf("email: set from: %w", err)
	}
	if err := msg.AddToFormat(toName, toEmail); err != nil {
		return fmt.Errorf("email: set to: %w", err)
	}
	msg.Subject("You have been invited to Passage")
	msg.SetBodyString(mail.TypeTextPlain, textBuf.String())
	msg.AddAlternativeString(mail.TypeTextHTML, htmlBuf.String())

	if err := client.DialAndSendWithContext(ctx, msg); err != nil {
		return fmt.Errorf("email: send invitation email: %w", err)
	}
	return nil
}

// humanDuration renders a TTL the way an email reads: whole days when it is at
// least one, otherwise hours. A zero or negative value never reaches a
// template (invitations always carry a positive TTL).
func humanDuration(d time.Duration) string {
	if d >= 24*time.Hour {
		days := int(d / (24 * time.Hour))
		if days == 1 {
			return "1 day"
		}
		return fmt.Sprintf("%d days", days)
	}
	hours := int(d / time.Hour)
	if hours <= 1 {
		return "1 hour"
	}
	return fmt.Sprintf("%d hours", hours)
}
