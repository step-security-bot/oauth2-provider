// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package openid

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/errorsx"
	"authelia.com/provider/oauth2/internal/stringslice"
	"authelia.com/provider/oauth2/token/jwt"
)

var defaultPrompts = []string{"login", "none", "consent", "select_account"}

type openIDConnectRequestValidatorConfigProvider interface {
	oauth2.RedirectSecureCheckerProvider
	oauth2.AllowedPromptsProvider
}

type OpenIDConnectRequestValidator struct {
	Strategy jwt.Signer
	Config   openIDConnectRequestValidatorConfigProvider
}

func NewOpenIDConnectRequestValidator(strategy jwt.Signer, config openIDConnectRequestValidatorConfigProvider) *OpenIDConnectRequestValidator {
	return &OpenIDConnectRequestValidator{
		Strategy: strategy,
		Config:   config,
	}
}

func (v *OpenIDConnectRequestValidator) ValidatePrompt(ctx context.Context, req oauth2.AuthorizeRequester) error {
	// prompt is case sensitive!
	requiredPrompt := oauth2.RemoveEmpty(strings.Split(req.GetRequestForm().Get("prompt"), " "))

	if req.GetClient().IsPublic() {
		// Threat: Malicious Client Obtains Existing Authorization by Fraud
		// https://datatracker.ietf.org/doc/html/rfc6819#section-4.2.3
		//
		//  Authorization servers should not automatically process repeat
		//  authorizations to public clients unless the client is validated
		//  using a pre-registered redirect URI

		// Client Impersonation
		// https://datatracker.ietf.org/doc/html/rfc8252#section-8.6#
		//
		//  As stated in Section 10.2 of OAuth 2.0 [RFC6749], the authorization
		//  server SHOULD NOT process authorization requests automatically
		//  without user consent or interaction, except when the identity of the
		//  client can be assured.  This includes the case where the user has
		//  previously approved an authorization request for a given client id --
		//  unless the identity of the client can be proven, the request SHOULD
		//  be processed as if no previous request had been approved.

		checker := v.Config.GetRedirectSecureChecker(ctx)
		if stringslice.Has(requiredPrompt, "none") {
			if !checker(ctx, req.GetRedirectURI()) {
				return errorsx.WithStack(oauth2.ErrConsentRequired.WithHint("OAuth 2.0 Client is marked public and redirect uri is not considered secure (https missing), but \"prompt=none\" was requested."))
			}
		}
	}

	availablePrompts := v.Config.GetAllowedPrompts(ctx)
	if len(availablePrompts) == 0 {
		availablePrompts = defaultPrompts
	}

	if !isWhitelisted(requiredPrompt, availablePrompts) {
		return errorsx.WithStack(oauth2.ErrInvalidRequest.WithHintf("Used unknown value '%s' for prompt parameter", requiredPrompt))
	}

	if stringslice.Has(requiredPrompt, "none") && len(requiredPrompt) > 1 {
		// If this parameter contains none with any other value, an error is returned.
		return errorsx.WithStack(oauth2.ErrInvalidRequest.WithHint("Parameter 'prompt' was set to 'none', but contains other values as well which is not allowed."))
	}

	maxAge, err := strconv.ParseInt(req.GetRequestForm().Get("max_age"), 10, 64)
	if err != nil {
		maxAge = 0
	}

	session, ok := req.GetSession().(Session)
	if !ok {
		return errorsx.WithStack(oauth2.ErrServerError.WithDebug("Failed to validate OpenID Connect request because session is not of type oauth2/handler/openid.Session."))
	}

	claims := session.IDTokenClaims()
	if claims.Subject == "" {
		return errorsx.WithStack(oauth2.ErrServerError.WithDebug("Failed to validate OpenID Connect request because session subject is empty."))
	}

	// Adds a bit of wiggle room for timing issues
	if claims.AuthTime.After(time.Now().UTC().Add(time.Second * 5)) {
		return errorsx.WithStack(oauth2.ErrServerError.WithDebug("Failed to validate OpenID Connect request because authentication time is in the future."))
	}

	if maxAge > 0 {
		if claims.AuthTime.IsZero() {
			return errorsx.WithStack(oauth2.ErrServerError.WithDebug("Failed to validate OpenID Connect request because authentication time claim is required when max_age is set."))
		} else if claims.RequestedAt.IsZero() {
			return errorsx.WithStack(oauth2.ErrServerError.WithDebug("Failed to validate OpenID Connect request because requested at claim is required when max_age is set."))
		} else if claims.AuthTime.Add(time.Second * time.Duration(maxAge)).Before(claims.RequestedAt) {
			return errorsx.WithStack(oauth2.ErrLoginRequired.WithDebug("Failed to validate OpenID Connect request because authentication time does not satisfy max_age time."))
		}
	}

	if stringslice.Has(requiredPrompt, "none") {
		if claims.AuthTime.IsZero() {
			return errorsx.WithStack(oauth2.ErrServerError.WithDebug("Failed to validate OpenID Connect request because because auth_time is missing from session."))
		}
		if !claims.AuthTime.Equal(claims.RequestedAt) && claims.AuthTime.After(claims.RequestedAt) {
			// !claims.AuthTime.Truncate(time.Second).Equal(claims.RequestedAt) && claims.AuthTime.Truncate(time.Second).Before(claims.RequestedAt) {
			return errorsx.WithStack(oauth2.ErrLoginRequired.WithHintf("Failed to validate OpenID Connect request because prompt was set to 'none' but auth_time ('%s') happened after the authorization request ('%s') was registered, indicating that the user was logged in during this request which is not allowed.", claims.AuthTime, claims.RequestedAt))
		}
	}

	if stringslice.Has(requiredPrompt, "login") {
		if claims.AuthTime.Before(claims.RequestedAt) {
			return errorsx.WithStack(oauth2.ErrLoginRequired.WithHintf("Failed to validate OpenID Connect request because prompt was set to 'login' but auth_time ('%s') happened before the authorization request ('%s') was registered, indicating that the user was not re-authenticated which is forbidden.", claims.AuthTime, claims.RequestedAt))
		}
	}

	idTokenHint := req.GetRequestForm().Get("id_token_hint")
	if idTokenHint == "" {
		return nil
	}

	tokenHint, err := v.Strategy.Decode(ctx, idTokenHint)
	var ve *jwt.ValidationError
	if errors.As(err, &ve) && ve.Has(jwt.ValidationErrorExpired) {
		// Expired tokens are ok
	} else if err != nil {
		return errorsx.WithStack(oauth2.ErrInvalidRequest.WithHint("Failed to validate OpenID Connect request as decoding id token from id_token_hint parameter failed.").WithWrap(err).WithDebug(err.Error()))
	}

	if hintSub, _ := tokenHint.Claims["sub"].(string); hintSub == "" {
		return errorsx.WithStack(oauth2.ErrInvalidRequest.WithHint("Failed to validate OpenID Connect request because provided id token from id_token_hint does not have a subject."))
	} else if hintSub != claims.Subject {
		return errorsx.WithStack(oauth2.ErrLoginRequired.WithHint("Failed to validate OpenID Connect request because the subject from provided id token from id_token_hint does not match the current session's subject."))
	}

	return nil
}

func isWhitelisted(items []string, whiteList []string) bool {
	for _, item := range items {
		if !stringslice.Has(whiteList, item) {
			return false
		}
	}
	return true
}
