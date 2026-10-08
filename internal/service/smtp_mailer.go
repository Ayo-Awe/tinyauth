package service

import (
	"context"
	"fmt"
	"time"

	"github.com/tinyauthapp/tinyauth/internal/model"
	"github.com/wneessen/go-mail"
)

const smtpTimeout = 15 * time.Second

type SMTPMailer struct {
	config model.SMTPConfig
}

func NewSMTPMailer(config model.SMTPConfig) *SMTPMailer {
	return &SMTPMailer{config: config}
}

func (m *SMTPMailer) Send(ctx context.Context, to string, subject string, body string) error {
	msg := mail.NewMsg()

	if err := msg.From(m.config.From); err != nil {
		return fmt.Errorf("invalid from address: %w", err)
	}

	if err := msg.To(to); err != nil {
		return fmt.Errorf("invalid recipient address: %w", err)
	}

	msg.Subject(subject)
	msg.SetBodyString(mail.TypeTextPlain, body)

	client, err := mail.NewClient(m.config.Host, m.clientOptions()...)

	if err != nil {
		return fmt.Errorf("failed to create smtp client: %w", err)
	}

	if err := client.DialAndSendWithContext(ctx, msg); err != nil {
		return fmt.Errorf("failed to send email: %w", err)
	}

	return nil
}

func (m *SMTPMailer) clientOptions() []mail.Option {
	opts := []mail.Option{
		mail.WithPort(m.config.Port),
		mail.WithTimeout(smtpTimeout),
	}

	switch {
	case m.config.Port == 465:
		opts = append(opts, mail.WithSSL())
	case m.config.Insecure:
		opts = append(opts, mail.WithTLSPolicy(mail.TLSOpportunistic))
	default:
		opts = append(opts, mail.WithTLSPolicy(mail.TLSMandatory))
	}

	if m.config.Username != "" {
		opts = append(opts,
			mail.WithSMTPAuth(mail.SMTPAuthPlain),
			mail.WithUsername(m.config.Username),
			mail.WithPassword(m.config.Password),
		)
	}

	return opts
}
