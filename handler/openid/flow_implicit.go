// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package openid

import (
	"context"

	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/errorsx"
	"authelia.com/provider/oauth2/token/jwt"
)

type OpenIDConnectImplicitHandler struct {
	*IDTokenHandleHelper

	AuthorizeImplicitGrantTypeHandler *hoauth2.AuthorizeImplicitGrantTypeHandler
	OpenIDConnectRequestValidator     *OpenIDConnectRequestValidator
	RS256JWTStrategy                  *jwt.DefaultSigner

	Config interface {
		oauth2.IDTokenLifespanProvider
		oauth2.MinParameterEntropyProvider
		oauth2.ScopeStrategyProvider
	}
}

var (
	_ oauth2.AuthorizeEndpointHandler = (*OpenIDConnectImplicitHandler)(nil)
)

func (c *OpenIDConnectImplicitHandler) HandleAuthorizeEndpointRequest(ctx context.Context, requester oauth2.AuthorizeRequester, responder oauth2.AuthorizeResponder) error {
	if !(requester.GetGrantedScopes().Has(consts.ScopeOpenID) && (requester.GetResponseTypes().Has(consts.ResponseTypeImplicitFlowToken, consts.ResponseTypeImplicitFlowIDToken) || requester.GetResponseTypes().ExactOne(consts.ResponseTypeImplicitFlowIDToken))) {
		return nil
	} else if requester.GetResponseTypes().Has(consts.ResponseTypeAuthorizationCodeFlow) {
		// hybrid flow
		return nil
	}

	requester.SetDefaultResponseMode(oauth2.ResponseModeFragment)

	if !requester.GetClient().GetGrantTypes().Has(consts.GrantTypeImplicit) {
		return errorsx.WithStack(oauth2.ErrInvalidGrant.WithHint("The OAuth 2.0 Client is not allowed to use the authorization grant 'implicit'."))
	}

	// Disabled because this is already handled at the authorize_request_handler
	//if requester.GetResponseTypes().ExactOne("id_token") && !requester.GetClient().GetResponseTypes().Has("id_token") {
	//	return errorsx.WithStack(oauth2.ErrInvalidGrant.WithDebug("The client is not allowed to use response type id_token"))
	//} else if requester.GetResponseTypes().Matches("token", "id_token") && !requester.GetClient().GetResponseTypes().Has("token", "id_token") {
	//	return errorsx.WithStack(oauth2.ErrInvalidGrant.WithDebug("The client is not allowed to use response type token and id_token"))
	//}

	if nonce := requester.GetRequestForm().Get(consts.FormParameterNonce); len(nonce) == 0 {
		return errorsx.WithStack(oauth2.ErrInvalidRequest.WithHint("Parameter 'nonce' must be set when using the OpenID Connect Implicit Flow."))
	} else if len(nonce) < c.Config.GetMinParameterEntropy(ctx) {
		return errorsx.WithStack(oauth2.ErrInsufficientEntropy.WithHintf("Parameter 'nonce' is set but does not satisfy the minimum entropy of %d characters.", c.Config.GetMinParameterEntropy(ctx)))
	}

	client := requester.GetClient()
	for _, scope := range requester.GetRequestedScopes() {
		if !c.Config.GetScopeStrategy(ctx)(client.GetScopes(), scope) {
			return errorsx.WithStack(oauth2.ErrInvalidScope.WithHintf("The OAuth 2.0 Client is not allowed to request scope '%s'.", scope))
		}
	}

	sess, ok := requester.GetSession().(Session)
	if !ok {
		return errorsx.WithStack(ErrInvalidSession)
	}

	if err := c.OpenIDConnectRequestValidator.ValidatePrompt(ctx, requester); err != nil {
		return err
	}

	claims := sess.IDTokenClaims()
	if requester.GetResponseTypes().Has(consts.ResponseTypeImplicitFlowToken) {
		if err := c.AuthorizeImplicitGrantTypeHandler.IssueImplicitAccessToken(ctx, requester, responder); err != nil {
			return errorsx.WithStack(err)
		}

		requester.SetResponseTypeHandled(consts.ResponseTypeImplicitFlowToken)
		hash, err := c.ComputeHash(ctx, sess, responder.GetParameters().Get(consts.AccessResponseAccessToken))
		if err != nil {
			return err
		}

		claims.AccessTokenHash = hash
	} else {
		responder.AddParameter(consts.FormParameterState, requester.GetState())
	}

	idTokenLifespan := oauth2.GetEffectiveLifespan(requester.GetClient(), oauth2.GrantTypeImplicit, oauth2.IDToken, c.Config.GetIDTokenLifespan(ctx))
	if err := c.IssueImplicitIDToken(ctx, idTokenLifespan, requester, responder); err != nil {
		return errorsx.WithStack(err)
	}

	// there is no need to check for https, because implicit flow does not require https
	// https://datatracker.ietf.org/doc/html/rfc6819#section-4.4.2

	requester.SetResponseTypeHandled(consts.ResponseTypeImplicitFlowIDToken)

	return nil
}
