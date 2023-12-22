// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package openid

import (
	"context"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/errorsx"
)

type OpenIDConnectExplicitHandler struct {
	// OpenIDConnectRequestStorage is the storage for open id connect sessions.
	OpenIDConnectRequestStorage   OpenIDConnectRequestStorage
	OpenIDConnectRequestValidator *OpenIDConnectRequestValidator

	Config interface {
		oauth2.IDTokenLifespanProvider
	}

	*IDTokenHandleHelper
}

var (
	_ oauth2.AuthorizeEndpointHandler = (*OpenIDConnectExplicitHandler)(nil)
	_ oauth2.TokenEndpointHandler     = (*OpenIDConnectExplicitHandler)(nil)
)

var oidcParameters = []string{
	consts.FormParameterGrantType,
	consts.FormParameterMaximumAge,
	consts.FormParameterPrompt,
	consts.FormParameterAuthenticationContextClassReferenceValues,
	consts.FormParameterIDTokenHint,
	consts.FormParameterNonce,
}

func (c *OpenIDConnectExplicitHandler) HandleAuthorizeEndpointRequest(ctx context.Context, requester oauth2.AuthorizeRequester, responder oauth2.AuthorizeResponder) error {
	if !(requester.GetGrantedScopes().Has(consts.ScopeOpenID) && requester.GetResponseTypes().ExactOne(consts.ResponseTypeAuthorizationCodeFlow)) {
		return nil
	}

	//if !requester.GetClient().GetResponseTypes().Has("id_token", "code") {
	//	return errorsx.WithStack(oauth2.ErrInvalidRequest.WithDebug("The client is not allowed to use response type id_token and code"))
	//}

	if len(responder.GetCode()) == 0 {
		return errorsx.WithStack(oauth2.ErrMisconfiguration.WithDebug("The authorization code has not been issued yet, indicating a broken code configuration."))
	}

	if err := c.OpenIDConnectRequestValidator.ValidatePrompt(ctx, requester); err != nil {
		return err
	}

	if err := c.OpenIDConnectRequestStorage.CreateOpenIDConnectSession(ctx, responder.GetCode(), requester.Sanitize(oidcParameters)); err != nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	// there is no need to check for https, because it has already been checked by core.explicit

	return nil
}
