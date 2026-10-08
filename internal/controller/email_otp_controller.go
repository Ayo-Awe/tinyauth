package controller

import (
	"errors"
	"fmt"
	"net/http"
	"net/mail"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/tinyauthapp/tinyauth/internal/model"
	"github.com/tinyauthapp/tinyauth/internal/repository"
	"github.com/tinyauthapp/tinyauth/internal/service"
	"github.com/tinyauthapp/tinyauth/internal/utils"
	"github.com/tinyauthapp/tinyauth/internal/utils/logger"
	"go.uber.org/dig"
)

type EmailOTPSendRequest struct {
	Email string `json:"email"`
}

type EmailOTPVerifyRequest struct {
	Email string `json:"email"`
	Code  string `json:"code"`
}

type EmailOTPController struct {
	log      *logger.Logger
	runtime  *model.RuntimeConfig
	auth     *service.AuthService
	emailOTP *service.EmailOTPService
}

type EmailOTPControllerInput struct {
	dig.In

	Log             *logger.Logger
	RuntimeConfig   *model.RuntimeConfig
	RouterGroup     *gin.RouterGroup `name:"apiRouterGroup"`
	AuthService     *service.AuthService
	EmailOTPService *service.EmailOTPService `optional:"true"`
}

func NewEmailOTPController(i EmailOTPControllerInput) *EmailOTPController {
	controller := &EmailOTPController{
		log:      i.Log,
		runtime:  i.RuntimeConfig,
		auth:     i.AuthService,
		emailOTP: i.EmailOTPService,
	}

	if i.EmailOTPService == nil {
		return controller
	}

	emailOTPGroup := i.RouterGroup.Group("/user/email-otp")
	emailOTPGroup.POST("/send", controller.sendHandler)
	emailOTPGroup.POST("/verify", controller.verifyHandler)

	return controller
}

func (controller *EmailOTPController) sendHandler(c *gin.Context) {
	var req EmailOTPSendRequest

	err := c.ShouldBindJSON(&req)
	if err != nil {
		controller.log.App.Error().Err(err).Msg("Failed to bind JSON for email otp request")
		c.JSON(400, gin.H{
			"status":  400,
			"message": "Bad Request",
		})
		return
	}

	email := service.NormalizeEmail(req.Email)

	// only a bare address, no display name
	address, err := mail.ParseAddress(email)
	if err != nil || address.Address != email {
		controller.log.App.Warn().Str("email", email).Msg("Invalid email in email otp request")
		c.JSON(400, gin.H{
			"status":  400,
			"message": "Bad Request",
		})
		return
	}

	err = controller.emailOTP.SendCode(email)

	if err != nil {
		if errors.Is(err, service.ErrEmailOTPCooldown) {
			controller.log.App.Warn().Str("email", email).Msg("Email otp requested again within the cooldown")
			c.JSON(429, gin.H{
				"status":  429,
				"message": "Too many requests. Wait before requesting another code",
			})
			return
		}
		controller.log.App.Error().Err(err).Str("email", email).Msg("Failed to send email otp")
		c.JSON(500, gin.H{
			"status":  500,
			"message": "Internal Server Error",
		})
		return
	}

	// same response whether or not the email is whitelisted
	c.JSON(200, gin.H{
		"status":  200,
		"message": "If the email is allowed, a code has been sent",
	})
}

func (controller *EmailOTPController) verifyHandler(c *gin.Context) {
	var req EmailOTPVerifyRequest

	err := c.ShouldBindJSON(&req)
	if err != nil {
		controller.log.App.Error().Err(err).Msg("Failed to bind JSON for email otp verification")
		c.JSON(400, gin.H{
			"status":  400,
			"message": "Bad Request",
		})
		return
	}

	email := service.NormalizeEmail(req.Email)

	isLocked, remaining := controller.auth.IsAccountLocked(email)

	if isLocked {
		controller.log.App.Warn().Str("email", email).Msg("Email otp verification locked due to too many failed attempts")
		controller.log.AuditLoginFailure(email, "emailotp", c.ClientIP(), "account locked")
		c.Writer.Header().Add("x-tinyauth-lock-locked", "true")
		c.Writer.Header().Add("x-tinyauth-lock-reset", time.Now().Add(time.Duration(remaining)*time.Second).Format(time.RFC3339))
		c.JSON(429, gin.H{
			"status":  429,
			"message": fmt.Sprintf("Too many failed login attempts. Try again in %d seconds", remaining),
		})
		return
	}

	err = controller.emailOTP.VerifyCode(email, req.Code)

	if err != nil {
		controller.log.App.Warn().Str("email", email).Msg("Invalid email otp during verification attempt")
		controller.auth.RecordLoginAttempt(email, false)
		controller.log.AuditLoginFailure(email, "emailotp", c.ClientIP(), "invalid email otp")
		c.JSON(401, gin.H{
			"status":  401,
			"message": "Unauthorized",
		})
		return
	}

	controller.auth.RecordLoginAttempt(email, true)

	cookie, err := controller.auth.CreateSession(c, repository.Session{
		Username: email,
		Name:     utils.Capitalize(email[:strings.Index(email, "@")]),
		Email:    email,
		Provider: "emailotp",
	})

	if err != nil {
		controller.log.App.Error().Err(err).Str("email", email).Msg("Failed to create session cookie after successful email otp verification")
		c.JSON(500, gin.H{
			"status":  500,
			"message": "Internal Server Error",
		})
		return
	}

	http.SetCookie(c.Writer, cookie)

	controller.log.App.Info().Str("email", email).Msg("Email otp verification successful, login complete")
	controller.log.AuditLoginSuccess(email, "emailotp", c.ClientIP())

	c.JSON(200, gin.H{
		"status":  200,
		"message": "Login successful",
	})
}
