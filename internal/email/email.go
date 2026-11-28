package email

import (
	"bytes"
	"context"
	"embed"
	"fmt"
	"html/template"
	"log/slog"
	netmail "net/mail"
	"strings"
	ttext "text/template"
	"time"

	mail "github.com/wneessen/go-mail"

	"github.com/crueber/passage/internal/config"
	"github.com/crueber/passage/internal/settings"
)

//go:embed templates/*.html templates/*.txt
var templateFS embed.FS

// smtpTimeout bounds an outbound SMTP delivery below http.Server.WriteTimeout
// (10s) so a slow mail relay returns an error cleanly instead of dropping the
// HTTP connection mid-request.
const smtpTimeout = 8 * time.Second

// Sender is the interface for sending emails.
type Sender interface {
	SendPasswordReset(ctx context.Context, toEmail, toName, resetURL string) error
	SendMagicLink(ctx context.Context, toEmail, toName, magicURL string) error
	SendVerifyEmail(ctx context.Context, toEmail, toName, verifyURL string) error
	SendInvite(ctx context.Context, toEmail, toName, inviter, inviteURL string, expiresIn time.Duration) error
}

type resetData struct {
	Name     string
	ResetURL string
}

type magicLinkData struct {
	Name     string
	MagicURL string
}

type verifyEmailData struct {
	Name      string
	VerifyURL string
}

type inviteData struct {
	Name      string
	Inviter   string
	InviteURL string
	ExpiresIn string
}

// SMTPSender sends emails via SMTP using go-mail.
type SMTPSender struct {
	cfg      *config.Config
	settings settings.Store // optional; live SMTP settings when wired
	logger   *slog.Logger
	html     *template.Template
	text     *ttext.Template
}

// NewSMTPSender creates a new SMTPSender. Templates are parsed at construction time.
func NewSMTPSender(cfg *config.Config, logger *slog.Logger, stores ...settings.Store) (*SMTPSender, error) {
	if logger == nil {
		logger = slog.Default()
	}
	var st settings.Store
	if len(stores) > 0 {
		st = stores[0]
	}
	htmlTmpl, err := template.ParseFS(templateFS, "templates/*.html")
	if err != nil {
		return nil, fmt.Errorf("email: parse html templates: %w", err)
	}
	textTmpl, err := ttext.ParseFS(templateFS, "templates/*.txt")
	if err != nil {
		return nil, fmt.Errorf("email: parse text templates: %w", err)
	}
	return &SMTPSender{
		cfg:      cfg,
		settings: st,
		logger:   logger,
		html:     htmlTmpl,
		text:     textTmpl,
	}, nil
}

// smtpConfig reads the live SMTP settings, falling back to the startup config
// snapshot only when a key is absent from the database. Using settings.Raw
// ensures clearing SMTP fields in the admin UI takes effect immediately without
// restarting the process.
func (s *SMTPSender) smtpConfig(ctx context.Context) config.SMTPConfig {
	c := s.cfg.SMTP
	if s.settings == nil {
		return c
	}
	c.Host = strings.TrimSpace(settings.Raw(ctx, s.settings, settings.SMTPHost, c.Host))
	c.Port = settings.Int(ctx, s.settings, settings.SMTPPort, c.Port, 1, 65535)
	c.Username = strings.TrimSpace(settings.Raw(ctx, s.settings, settings.SMTPUsername, c.Username))
	c.Password = settings.Raw(ctx, s.settings, settings.SMTPPassword, c.Password)
	c.TLS = strings.TrimSpace(settings.String(ctx, s.settings, settings.SMTPTLS, c.TLS))
	c.From = strings.TrimSpace(settings.Raw(ctx, s.settings, settings.SMTPFrom, c.From))
	return c
}

// SendPasswordReset sends a password reset email to the given recipient.
func (s *SMTPSender) SendPasswordReset(ctx context.Context, toEmail, toName, resetURL string) error {
	return s.send(ctx, "password_reset", "Reset your Passage password", toEmail, toName, resetData{
		Name:     toName,
		ResetURL: resetURL,
	})
}

// SendMagicLink sends a magic sign-in link email to the given recipient.
func (s *SMTPSender) SendMagicLink(ctx context.Context, toEmail, toName, magicURL string) error {
	return s.send(ctx, "magic_link", "Your Passage sign-in link", toEmail, toName, magicLinkData{
		Name:     toName,
		MagicURL: magicURL,
	})
}

// SendVerifyEmail sends an email address verification link to the recipient.
func (s *SMTPSender) SendVerifyEmail(ctx context.Context, toEmail, toName, verifyURL string) error {
	return s.send(ctx, "verify_email", "Verify your Passage email address", toEmail, toName, verifyEmailData{
		Name:      toName,
		VerifyURL: verifyURL,
	})
}

// SendInvite sends an invitation link to an address that does not yet have an
// account. If SMTP is not usable an error is returned and the caller should not
// leave a dangling invitation behind.
func (s *SMTPSender) SendInvite(ctx context.Context, toEmail, toName, inviter, inviteURL string, expiresIn time.Duration) error {
	return s.send(ctx, "invite", "You have been invited to Passage", toEmail, toName, inviteData{
		Name:      toName,
		Inviter:   inviter,
		InviteURL: inviteURL,
		ExpiresIn: humanDuration(expiresIn),
	})
}

func (s *SMTPSender) send(ctx context.Context, tmplBase, subject, toEmail, toName string, data any) error {
	smtp := s.smtpConfig(ctx)
	if smtp.Host == "" || smtp.From == "" {
		s.logger.Warn("SMTP not configured: cannot send email", "template", tmplBase, "to", toEmail)
		return fmt.Errorf("email: SMTP host or from address is not configured")
	}

	var htmlBuf, textBuf bytes.Buffer
	if err := s.html.ExecuteTemplate(&htmlBuf, tmplBase+".html", data); err != nil {
		return fmt.Errorf("email: render %s html template: %w", tmplBase, err)
	}
	if err := s.text.ExecuteTemplate(&textBuf, tmplBase+".txt", data); err != nil {
		return fmt.Errorf("email: render %s text template: %w", tmplBase, err)
	}

	opts := []mail.Option{
		mail.WithPort(smtp.Port),
		mail.WithTimeout(smtpTimeout),
	}
	if smtp.Username != "" || smtp.Password != "" {
		opts = append(opts,
			mail.WithSMTPAuth(mail.SMTPAuthPlain),
			mail.WithUsername(smtp.Username),
			mail.WithPassword(smtp.Password),
		)
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
	// Format via net/mail.Address so display names containing quotes or special
	// RFC 5322 characters are properly escaped instead of failing ParseAddress.
	recipient := (&netmail.Address{Name: toName, Address: toEmail}).String()
	if err := msg.To(recipient); err != nil {
		return fmt.Errorf("email: set to: %w", err)
	}
	msg.Subject(subject)
	msg.SetBodyString(mail.TypeTextPlain, textBuf.String())
	msg.AddAlternativeString(mail.TypeTextHTML, htmlBuf.String())

	if err := client.DialAndSendWithContext(ctx, msg); err != nil {
		return fmt.Errorf("email: send %s: %w", tmplBase, err)
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
