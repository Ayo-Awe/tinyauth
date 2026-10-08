package service

import (
	"context"
	"errors"
	"regexp"
	"sync"
	"testing"
	"time"

	"github.com/steveiliop56/ding"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tinyauthapp/tinyauth/internal/model"
	"github.com/tinyauthapp/tinyauth/internal/utils/logger"
	"github.com/tinyauthapp/tinyauth/pkg/cache"
)

// emails are delivered in the background, so the fake is safe for concurrent use
type fakeMailer struct {
	mu   sync.Mutex
	sent []fakeMail
	err  error
}

type fakeMail struct {
	to   string
	body string
}

func (m *fakeMailer) Send(ctx context.Context, to string, subject string, body string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return m.err
	}
	m.sent = append(m.sent, fakeMail{to: to, body: body})
	return nil
}

var emailOTPPattern = regexp.MustCompile(`\b(\d{6})\b`)

func (m *fakeMailer) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.sent)
}

func (m *fakeMailer) setErr(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.err = err
}

func (m *fakeMailer) lastRecipient() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.sent[len(m.sent)-1].to
}

// waitForMail waits until n emails have been delivered
func (m *fakeMailer) waitForMail(t *testing.T, n int) {
	require.Eventually(t, func() bool { return m.count() >= n }, time.Second, 5*time.Millisecond)
}

func (m *fakeMailer) lastCode(t *testing.T) string {
	m.waitForMail(t, 1)

	m.mu.Lock()
	defer m.mu.Unlock()

	match := emailOTPPattern.FindStringSubmatch(m.sent[len(m.sent)-1].body)
	require.Len(t, match, 2)
	return match[1]
}

func newTestEmailOTPService(t *testing.T, whitelist []string) (*EmailOTPService, *fakeMailer) {
	log := logger.NewLogger().WithTestConfig()
	log.Init()

	policyEngine, err := NewPolicyEngine(PolicyEngineInput{
		Log: log,
		Config: &model.Config{
			Auth: model.AuthConfig{
				ACLs: model.ACLsConfig{
					Policy: string(PolicyAllow),
				},
			},
		},
	})
	require.NoError(t, err)

	mailer := &fakeMailer{}

	return &EmailOTPService{
		log:          log,
		config:       &model.Config{UI: model.UIConfig{Title: "Tinyauth"}},
		runtime:      &model.RuntimeConfig{EmailOTPWhitelist: whitelist},
		ding:         ding.New(t.Context()),
		policyEngine: policyEngine,
		mailer:       mailer,
		codes:        cache.NewCacheStore[emailOTPPending](MaxEmailOTPPending),
		cooldowns:    cache.NewCacheStore[struct{}](MaxEmailOTPPending),
	}, mailer
}

func TestNewEmailOTPServiceDisabled(t *testing.T) {
	service, err := NewEmailOTPService(EmailOTPServiceInput{
		Config:  &model.Config{SMTP: model.SMTPConfig{Host: "smtp.example.com", From: "auth@example.com"}},
		Runtime: &model.RuntimeConfig{EmailOTPWhitelist: []string{"jane@example.com"}},
	})

	require.NoError(t, err)
	assert.Nil(t, service)
}

func TestNewEmailOTPServiceRequiresWhitelist(t *testing.T) {
	_, err := NewEmailOTPService(EmailOTPServiceInput{
		Config: &model.Config{
			SMTP:     model.SMTPConfig{Host: "smtp.example.com", From: "auth@example.com"},
			EmailOTP: model.EmailOTPConfig{Enabled: true},
		},
		Runtime: &model.RuntimeConfig{},
	})

	require.Error(t, err)
}

func TestNewEmailOTPServiceRequiresSMTP(t *testing.T) {
	_, err := NewEmailOTPService(EmailOTPServiceInput{
		Config:  &model.Config{EmailOTP: model.EmailOTPConfig{Enabled: true}},
		Runtime: &model.RuntimeConfig{EmailOTPWhitelist: []string{"jane@example.com"}},
	})

	require.Error(t, err)
}

func TestEmailOTPIsEmailWhitelisted(t *testing.T) {
	service, _ := newTestEmailOTPService(t, []string{"Jane@Example.com", "sam@example.com"})

	assert.True(t, service.IsEmailWhitelisted("jane@example.com"))
	assert.True(t, service.IsEmailWhitelisted("  JANE@example.com "))
	assert.True(t, service.IsEmailWhitelisted("sam@example.com"))
	assert.False(t, service.IsEmailWhitelisted("john@example.com"))

	regexService, _ := newTestEmailOTPService(t, []string{`/^.+@example\.com$/`})

	assert.True(t, regexService.IsEmailWhitelisted("anyone@example.com"))
	assert.False(t, regexService.IsEmailWhitelisted("anyone@example.com.evil.io"))
}

func TestEmailOTPSendAndVerify(t *testing.T) {
	service, mailer := newTestEmailOTPService(t, []string{"jane@example.com"})

	require.NoError(t, service.SendCode("Jane@Example.com"))
	code := mailer.lastCode(t)

	assert.Equal(t, "jane@example.com", mailer.lastRecipient())
	require.NoError(t, service.VerifyCode("jane@example.com", code))
}

func TestEmailOTPIsSingleUse(t *testing.T) {
	service, mailer := newTestEmailOTPService(t, []string{"jane@example.com"})

	require.NoError(t, service.SendCode("jane@example.com"))
	code := mailer.lastCode(t)

	require.NoError(t, service.VerifyCode("jane@example.com", code))
	assert.ErrorIs(t, service.VerifyCode("jane@example.com", code), ErrEmailOTPInvalid)
}

func TestEmailOTPWrongCodeKeepsPendingCode(t *testing.T) {
	service, mailer := newTestEmailOTPService(t, []string{"jane@example.com"})

	require.NoError(t, service.SendCode("jane@example.com"))
	code := mailer.lastCode(t)

	wrong := "000000"
	if code == wrong {
		wrong = "111111"
	}

	assert.ErrorIs(t, service.VerifyCode("jane@example.com", wrong), ErrEmailOTPInvalid)
	require.NoError(t, service.VerifyCode("jane@example.com", code))
}

func TestEmailOTPNewCodeReplacesOldCode(t *testing.T) {
	service, mailer := newTestEmailOTPService(t, []string{"jane@example.com"})

	require.NoError(t, service.SendCode("jane@example.com"))
	oldCode := mailer.lastCode(t)

	// skip the resend cooldown
	service.cooldowns.Delete("jane@example.com")

	require.NoError(t, service.SendCode("jane@example.com"))
	mailer.waitForMail(t, 2)
	newCode := mailer.lastCode(t)

	if oldCode != newCode {
		assert.ErrorIs(t, service.VerifyCode("jane@example.com", oldCode), ErrEmailOTPInvalid)
	}
	require.NoError(t, service.VerifyCode("jane@example.com", newCode))
}

func TestEmailOTPExpires(t *testing.T) {
	service, mailer := newTestEmailOTPService(t, []string{"jane@example.com"})

	require.NoError(t, service.SendCode("jane@example.com"))
	code := mailer.lastCode(t)

	pending, ok := service.codes.Get("jane@example.com")
	require.True(t, ok)
	service.codes.Set("jane@example.com", pending, time.Nanosecond)
	time.Sleep(time.Millisecond)

	assert.ErrorIs(t, service.VerifyCode("jane@example.com", code), ErrEmailOTPInvalid)
}

func TestEmailOTPNotSentToUnlistedEmail(t *testing.T) {
	service, mailer := newTestEmailOTPService(t, []string{"jane@example.com"})

	require.NoError(t, service.SendCode("mallory@example.com"))
	assert.Never(t, func() bool { return mailer.count() > 0 }, 50*time.Millisecond, 5*time.Millisecond)
}

func TestEmailOTPResendCooldownAppliesToEveryEmail(t *testing.T) {
	service, _ := newTestEmailOTPService(t, []string{"jane@example.com"})

	require.NoError(t, service.SendCode("jane@example.com"))
	assert.ErrorIs(t, service.SendCode("jane@example.com"), ErrEmailOTPCooldown)

	require.NoError(t, service.SendCode("mallory@example.com"))
	assert.ErrorIs(t, service.SendCode("mallory@example.com"), ErrEmailOTPCooldown)
}

func TestEmailOTPDeliveryFailureDiscardsCode(t *testing.T) {
	service, mailer := newTestEmailOTPService(t, []string{"jane@example.com"})
	mailer.setErr(errors.New("smtp down"))

	require.NoError(t, service.SendCode("jane@example.com"))

	assert.Eventually(t, func() bool {
		_, ok := service.codes.Get("jane@example.com")
		return !ok
	}, time.Second, 5*time.Millisecond)
}
