package controller

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/steveiliop56/ding"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tinyauthapp/tinyauth/internal/model"
	"github.com/tinyauthapp/tinyauth/internal/repository/memory"
	"github.com/tinyauthapp/tinyauth/internal/service"
	"github.com/tinyauthapp/tinyauth/internal/test"
	"github.com/tinyauthapp/tinyauth/internal/utils/logger"
)

// emails are delivered in the background, so the recorder is safe for concurrent use
type recordingMailer struct {
	mu     sync.Mutex
	bodies []string
}

func (m *recordingMailer) Send(ctx context.Context, to string, subject string, body string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.bodies = append(m.bodies, body)
	return nil
}

func (m *recordingMailer) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.bodies)
}

func (m *recordingMailer) lastCode(t *testing.T) string {
	require.Eventually(t, func() bool { return m.count() > 0 }, time.Second, 10*time.Millisecond)

	m.mu.Lock()
	defer m.mu.Unlock()

	match := regexp.MustCompile(`\b(\d{6})\b`).FindStringSubmatch(m.bodies[len(m.bodies)-1])
	require.Len(t, match, 2)
	return match[1]
}

func TestEmailOTPController(t *testing.T) {
	log := logger.NewLogger().WithTestConfig()
	log.Init()

	cfg, runtime := test.CreateTestConfigs(t)
	cfg.SMTP = model.SMTPConfig{Host: "smtp.example.com", Port: 587, From: "auth@example.com"}
	cfg.EmailOTP = model.EmailOTPConfig{Enabled: true}
	runtime.EmailOTPWhitelist = []string{`/^.+@example\.com$/`}

	ctx := context.TODO()
	dg := ding.New(ctx)

	policyEngine, err := service.NewPolicyEngine(service.PolicyEngineInput{
		Log:    log,
		Config: &cfg,
	})
	require.NoError(t, err)

	broker := service.NewOAuthBrokerService(service.OAuthBrokerServiceInput{
		Log:     log,
		Runtime: &runtime,
		Ctx:     ctx,
	})

	authService, err := service.NewAuthService(service.AuthServiceInput{
		Log:          log,
		Config:       &cfg,
		Runtime:      &runtime,
		Ctx:          ctx,
		Ding:         dg,
		Queries:      memory.New(),
		OAuthBroker:  broker,
		PolicyEngine: policyEngine,
	})
	require.NoError(t, err)

	post := func(router *gin.Engine, path string, body any) *httptest.ResponseRecorder {
		payload, err := json.Marshal(body)
		require.NoError(t, err)

		req := httptest.NewRequest("POST", path, strings.NewReader(string(payload)))
		req.Header.Set("Content-Type", "application/json")

		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, req)
		return recorder
	}

	type testCase struct {
		description string
		run         func(t *testing.T, router *gin.Engine, mailer *recordingMailer)
	}

	tests := []testCase{
		{
			description: "Send then verify should create a session",
			run: func(t *testing.T, router *gin.Engine, mailer *recordingMailer) {
				res := post(router, "/api/user/email-otp/send", EmailOTPSendRequest{Email: "Jane@example.com"})
				require.Equal(t, 200, res.Code)

				res = post(router, "/api/user/email-otp/verify", EmailOTPVerifyRequest{Email: "jane@example.com", Code: mailer.lastCode(t)})
				require.Equal(t, 200, res.Code)

				cookies := res.Result().Cookies()
				require.Len(t, cookies, 1)
				assert.Equal(t, "tinyauth-session", cookies[0].Name)
			},
		},
		{
			description: "Send should respond the same and not email an unlisted email",
			run: func(t *testing.T, router *gin.Engine, mailer *recordingMailer) {
				res := post(router, "/api/user/email-otp/send", EmailOTPSendRequest{Email: "mallory@evil.com"})

				assert.Equal(t, 200, res.Code)
				assert.Never(t, func() bool { return mailer.count() > 0 }, 100*time.Millisecond, 10*time.Millisecond)
			},
		},
		{
			description: "Send should fail gracefully on an invalid email",
			run: func(t *testing.T, router *gin.Engine, mailer *recordingMailer) {
				res := post(router, "/api/user/email-otp/send", EmailOTPSendRequest{Email: "not-an-email"})

				assert.Equal(t, 400, res.Code)
			},
		},
		{
			description: "Send should be rate limited within the cooldown",
			run: func(t *testing.T, router *gin.Engine, mailer *recordingMailer) {
				require.Equal(t, 200, post(router, "/api/user/email-otp/send", EmailOTPSendRequest{Email: "kim@example.com"}).Code)

				res := post(router, "/api/user/email-otp/send", EmailOTPSendRequest{Email: "kim@example.com"})

				assert.Equal(t, 429, res.Code)
			},
		},
		{
			description: "Verify should reject a wrong code without a session",
			run: func(t *testing.T, router *gin.Engine, mailer *recordingMailer) {
				require.Equal(t, 200, post(router, "/api/user/email-otp/send", EmailOTPSendRequest{Email: "sam@example.com"}).Code)

				res := post(router, "/api/user/email-otp/verify", EmailOTPVerifyRequest{Email: "sam@example.com", Code: "000000x"})

				assert.Equal(t, 401, res.Code)
				assert.Empty(t, res.Result().Cookies())
			},
		},
		{
			description: "Verify should lock the email after too many wrong codes",
			run: func(t *testing.T, router *gin.Engine, mailer *recordingMailer) {
				require.Equal(t, 200, post(router, "/api/user/email-otp/send", EmailOTPSendRequest{Email: "lee@example.com"}).Code)
				code := mailer.lastCode(t)

				for range cfg.Auth.LoginMaxRetries {
					post(router, "/api/user/email-otp/verify", EmailOTPVerifyRequest{Email: "lee@example.com", Code: "x"})
				}

				res := post(router, "/api/user/email-otp/verify", EmailOTPVerifyRequest{Email: "lee@example.com", Code: code})

				assert.Equal(t, 429, res.Code)
				assert.Equal(t, "true", res.Header().Get("x-tinyauth-lock-locked"))
			},
		},
	}

	for _, test := range tests {
		authService.ClearLoginAttempts()

		t.Run(test.description, func(t *testing.T) {
			mailer := &recordingMailer{}

			emailOTPService, err := service.NewEmailOTPService(service.EmailOTPServiceInput{
				Log:          log,
				Config:       &cfg,
				Runtime:      &runtime,
				Ding:         dg,
				PolicyEngine: policyEngine,
				Mailer:       mailer,
			})
			require.NoError(t, err)

			gin.SetMode(gin.TestMode)
			router := gin.New()

			NewEmailOTPController(EmailOTPControllerInput{
				Log:             log,
				RuntimeConfig:   &runtime,
				RouterGroup:     router.Group("/api"),
				AuthService:     authService,
				EmailOTPService: emailOTPService,
			})

			test.run(t, router, mailer)
		})
	}
}
