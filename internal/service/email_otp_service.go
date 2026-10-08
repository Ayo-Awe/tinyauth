package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/steveiliop56/ding"
	"github.com/tinyauthapp/tinyauth/internal/model"
	"github.com/tinyauthapp/tinyauth/internal/utils"
	"github.com/tinyauthapp/tinyauth/internal/utils/logger"
	"github.com/tinyauthapp/tinyauth/pkg/cache"
	"go.uber.org/dig"
)

// hard-defaults, like the other in-memory login state
const EmailOTPTTL = 10 * time.Minute
const EmailOTPResendCooldown = 1 * time.Minute
const EmailOTPMaxAttempts = 5
const EmailOTPMaxSendsPerMinute = 30
const MaxEmailOTPPending = 1024
const EmailOTPSendTimeout = 30 * time.Second

var (
	ErrEmailOTPCooldown = errors.New("email otp requested too recently")
	ErrEmailOTPInvalid  = errors.New("invalid or expired email otp")
)

// Mailer sends a plain text email
type Mailer interface {
	Send(ctx context.Context, to string, subject string, body string) error
}

type emailOTPPending struct {
	Hash     [32]byte
	Attempts int
	SentAt   time.Time
}

type EmailOTPService struct {
	log          *logger.Logger
	config       *model.Config
	runtime      *model.RuntimeConfig
	ding         *ding.Ding
	policyEngine *PolicyEngine
	mailer       Mailer
	// only whitelisted emails, the pending code also holds their resend cooldown
	codes *cache.CacheStore[emailOTPPending]
	// cooldowns for other emails, so they get the same response as whitelisted ones
	cooldowns *cache.CacheStore[struct{}]
	// global limit on sent emails, so a regex whitelist cannot be used to flood a domain
	sendsMu     sync.Mutex
	sendsWindow time.Time
	sendsCount  int
}

type EmailOTPServiceInput struct {
	dig.In

	Log          *logger.Logger
	Config       *model.Config
	Runtime      *model.RuntimeConfig
	Ding         *ding.Ding
	PolicyEngine *PolicyEngine
	Mailer       Mailer `optional:"true"`
}

func NewEmailOTPService(i EmailOTPServiceInput) (*EmailOTPService, error) {
	if !i.Config.EmailOTP.Enabled {
		return nil, nil
	}

	if i.Config.SMTP.Host == "" || i.Config.SMTP.From == "" {
		return nil, errors.New("email otp requires the smtp host and from address")
	}

	// fail closed, an empty whitelist would let anyone with a mailbox log in
	if len(i.Runtime.EmailOTPWhitelist) == 0 {
		return nil, errors.New("email otp requires a whitelist")
	}

	mailer := i.Mailer

	if mailer == nil {
		smtpConfig := i.Config.SMTP
		smtpConfig.Password = utils.GetSecret(smtpConfig.Password, smtpConfig.PasswordFile)
		mailer = NewSMTPMailer(smtpConfig)
	}

	service := &EmailOTPService{
		log:          i.Log,
		config:       i.Config,
		runtime:      i.Runtime,
		ding:         i.Ding,
		policyEngine: i.PolicyEngine,
		mailer:       mailer,
		codes:        cache.NewCacheStore[emailOTPPending](MaxEmailOTPPending),
		cooldowns:    cache.NewCacheStore[struct{}](MaxEmailOTPPending),
	}

	i.Ding.Go(func(ctx context.Context) {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				service.codes.Sweep()
				service.cooldowns.Sweep()
			case <-ctx.Done():
				return
			}
		}
	}, ding.RingMinor)

	return service, nil
}

func NormalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// IsEmailWhitelisted uses the same filter format as the OAuth whitelist.
// The whitelist is required, so an empty or broken filter denies.
func (s *EmailOTPService) IsEmailWhitelisted(email string) bool {
	email = NormalizeEmail(email)

	filter := strings.Join(s.runtime.EmailOTPWhitelist, ",")

	// emails are compared in lower case, regex filters are left as they are
	if !(strings.HasPrefix(filter, "/") && strings.HasSuffix(filter, "/")) {
		filter = strings.ToLower(filter)
	}

	return s.policyEngine.EvaluateFunc(func() Effect {
		match, err := utils.CheckFilter(filter, email)
		if err != nil {
			if !errors.Is(err, utils.ErrFilterEmpty) {
				s.log.App.Error().Err(err).Str("email", email).Msg("Failed to evaluate email otp whitelist filter, defaulting to deny")
			}
			return EffectDeny
		}
		if match {
			return EffectAllow
		}
		return EffectDeny
	})
}

// SendCode emails a code to a whitelisted address. Every address gets the same
// result and timing, so callers cannot learn the whitelist: other addresses get
// the same cooldown, and the email is delivered in the background.
func (s *EmailOTPService) SendCode(email string) error {
	email = NormalizeEmail(email)

	if !s.IsEmailWhitelisted(email) {
		var cooldown bool

		s.cooldowns.WithLock(func(actions cache.CacheStoreActions[struct{}]) {
			if _, ok := actions.Get(email); ok {
				cooldown = true
				return
			}
			actions.Set(email, struct{}{}, EmailOTPResendCooldown)
		})

		if cooldown {
			return ErrEmailOTPCooldown
		}

		s.log.App.Warn().Str("email", email).Msg("Email otp requested for an email that is not whitelisted")
		return nil
	}

	code, err := generateEmailOTP()

	if err != nil {
		return fmt.Errorf("failed to generate email otp: %w", err)
	}

	hash := hashEmailOTP(code)

	var cooldown bool

	s.codes.WithLock(func(actions cache.CacheStoreActions[emailOTPPending]) {
		pending, ok := actions.Get(email)

		if ok && time.Since(pending.SentAt) < EmailOTPResendCooldown {
			cooldown = true
			return
		}

		// a new code replaces any pending one
		actions.Set(email, emailOTPPending{
			Hash:   hash,
			SentAt: time.Now(),
		}, EmailOTPTTL)
	})

	if cooldown {
		return ErrEmailOTPCooldown
	}

	if !s.reserveSend() {
		s.log.App.Warn().Str("email", email).Msg("Email otp send limit reached, not sending")
		s.discardCode(email, hash)
		return nil
	}

	subject := fmt.Sprintf("Your %s login code", s.config.UI.Title)
	body := fmt.Sprintf("Your %s login code is %s\n\nIt expires in %d minutes and works once. If you did not request it, you can ignore this email.\n",
		s.config.UI.Title, code, int(EmailOTPTTL.Minutes()))

	// shutdown cancels delivery together with the http listeners
	s.ding.Go(func(ctx context.Context) {
		ctx, cancel := context.WithTimeout(ctx, EmailOTPSendTimeout)
		defer cancel()

		err := s.mailer.Send(ctx, email, subject, body)

		if err != nil {
			s.log.App.Error().Err(err).Str("email", email).Msg("Failed to send email otp")
			s.discardCode(email, hash)
			return
		}

		s.log.App.Debug().Str("email", email).Msg("Email otp sent")
	}, ding.RingNormal)

	return nil
}

// reserveSend counts a send against the global per-minute limit
func (s *EmailOTPService) reserveSend() bool {
	s.sendsMu.Lock()
	defer s.sendsMu.Unlock()

	if time.Since(s.sendsWindow) >= time.Minute {
		s.sendsWindow = time.Now()
		s.sendsCount = 0
	}

	if s.sendsCount >= EmailOTPMaxSendsPerMinute {
		return false
	}

	s.sendsCount++
	return true
}

// discardCode removes a code that was never delivered, unless a newer code replaced it
func (s *EmailOTPService) discardCode(email string, hash [32]byte) {
	s.codes.WithLock(func(actions cache.CacheStoreActions[emailOTPPending]) {
		pending, ok := actions.Get(email)

		if ok && pending.Hash == hash {
			actions.Delete(email)
		}
	})
}

// VerifyCode consumes a correct code. Wrong codes also count towards the login
// lockout in the controller, but that check is not atomic under concurrent
// requests, so each code is discarded after a few wrong guesses as well.
func (s *EmailOTPService) VerifyCode(email string, code string) error {
	email = NormalizeEmail(email)
	code = strings.TrimSpace(code)

	if !s.IsEmailWhitelisted(email) {
		return ErrEmailOTPInvalid
	}

	valid := false

	s.codes.WithLock(func(actions cache.CacheStoreActions[emailOTPPending]) {
		pending, ok := actions.Get(email)

		if !ok {
			return
		}

		hash := hashEmailOTP(code)

		if subtle.ConstantTimeCompare(pending.Hash[:], hash[:]) == 1 {
			valid = true
			actions.Delete(email)
			return
		}

		pending.Attempts++

		if pending.Attempts >= EmailOTPMaxAttempts {
			actions.Delete(email)
			return
		}

		// keeps the original expiry
		actions.Update(email, pending, 0)
	})

	if !valid {
		return ErrEmailOTPInvalid
	}

	return nil
}

func generateEmailOTP() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1_000_000))

	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%06d", n.Int64()), nil
}

func hashEmailOTP(code string) [32]byte {
	return sha256.Sum256([]byte(code))
}
