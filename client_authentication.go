/*
 * Copyright © 2017-2018 Aeneas Rekkas <aeneas+oss@aeneas.io>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * @author		Aeneas Rekkas <aeneas+oss@aeneas.io>
 * @Copyright 	2017-2018 Aeneas Rekkas <aeneas+oss@aeneas.io>
 * @license 	Apache-2.0
 *
 */

package fosite

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/ory/x/errorsx"

	"github.com/ory/fosite/token/jwt"
	"github.com/pkg/errors"
	jose "gopkg.in/square/go-jose.v2"
)

// ClientAuthenticationStrategy provides a method signature for authenticating a client request
type ClientAuthenticationStrategy func(context.Context, *http.Request, url.Values) (Client, error)

const clientAssertionJWTBearerType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

func (f *Fosite) findClientPublicJWK(oidcClient OpenIDConnectClient, t *jwt.Token, expectsRSAKey bool) (interface{}, error) {
	if set := oidcClient.GetJSONWebKeys(); set != nil {
		return findPublicKey(t, set, expectsRSAKey)
	}

	if location := oidcClient.GetJSONWebKeysURI(); len(location) > 0 {
		keys, err := f.JWKSFetcherStrategy.Resolve(location, false)
		if err != nil {
			return nil, err
		}

		if key, err := findPublicKey(t, keys, expectsRSAKey); err == nil {
			return key, nil
		}

		keys, err = f.JWKSFetcherStrategy.Resolve(location, true)
		if err != nil {
			return nil, err
		}

		return findPublicKey(t, keys, expectsRSAKey)
	}

	return nil, errorsx.WithStack(ErrInvalidClient.WithHint("The OAuth 2.0 Client has no JSON Web Keys set registered, but they are needed to complete the request."))
}

// AuthenticateClient authenticates client requests using the configured strategy
// `Fosite.ClientAuthenticationStrategy`, if nil it uses `Fosite.DefaultClientAuthenticationStrategy`
func (f *Fosite) AuthenticateClient(ctx context.Context, r *http.Request, form url.Values) (Client, error) {
	if f.ClientAuthenticationStrategy == nil {
		return f.DefaultClientAuthenticationStrategy(ctx, r, form)
	}
	return f.ClientAuthenticationStrategy(ctx, r, form)
}

// DefaultClientAuthenticationStrategy provides the fosite's default client authentication strategy,
// HTTP Basic Authentication and JWT Bearer
func (f *Fosite) DefaultClientAuthenticationStrategy(ctx context.Context, r *http.Request, form url.Values) (Client, error) {
	if assertionType := form.Get("client_assertion_type"); assertionType == clientAssertionJWTBearerType {
		assertion := form.Get("client_assertion")
		if len(assertion) == 0 {
			return nil, errorsx.WithStack(ErrInvalidRequest.WithHintf("The client_assertion request parameter must be set when using client_assertion_type of '%s'.", clientAssertionJWTBearerType))
		}

		var clientID string
		var client Client

		token, err := jwt.ParseWithClaims(assertion, jwt.MapClaims{}, func(t *jwt.Token) (interface{}, error) {
			var err error
			clientID, _, err = clientCredentialsFromRequestBody(form, false)
			if err != nil {
				return nil, err
			}

			if clientID == "" {
				claims := t.Claims
				if sub, ok := claims["sub"].(string); !ok {
					return nil, errorsx.WithStack(ErrInvalidClient.WithHint("The claim 'sub' from the client_assertion JSON Web Token is undefined."))
				} else {
					clientID = sub
				}
			}

			client, err = f.Store.GetClient(ctx, clientID)
			if err != nil {
				return nil, errorsx.WithStack(ErrInvalidClient.WithWrap(err).WithDebug(err.Error()))
			}

			oidcClient, ok := client.(OpenIDConnectClient)
			if !ok {
				return nil, errorsx.WithStack(ErrInvalidRequest.WithHint("The server configuration does not support OpenID Connect specific authentication methods."))
			}

			switch oidcClient.GetTokenEndpointAuthMethod() {
			case "private_key_jwt":
				break
			case "none":
				return nil, errorsx.WithStack(ErrInvalidClient.WithHint("This requested OAuth 2.0 client does not support client authentication, however 'client_assertion' was provided in the request."))
			case "client_secret_post":
				fallthrough
			case "client_secret_basic":
				return nil, errorsx.WithStack(ErrInvalidClient.WithHintf("This requested OAuth 2.0 client only supports client authentication method '%s', however 'client_assertion' was provided in the request.", oidcClient.GetTokenEndpointAuthMethod()))
			case "client_secret_jwt":
				fallthrough
			default:
				return nil, errorsx.WithStack(ErrInvalidClient.WithHintf("This requested OAuth 2.0 client only supports client authentication method '%s', however that method is not supported by this server.", oidcClient.GetTokenEndpointAuthMethod()))
			}

			if oidcClient.GetTokenEndpointAuthSigningAlgorithm() != fmt.Sprintf("%s", t.Header["alg"]) {
				return nil, errorsx.WithStack(ErrInvalidClient.WithHintf("The 'client_assertion' uses signing algorithm '%s' but the requested OAuth 2.0 Client enforces signing algorithm '%s'.", t.Header["alg"], oidcClient.GetTokenEndpointAuthSigningAlgorithm()))
			}
			switch t.Method {
			case jose.RS256, jose.RS384, jose.RS512:
				return f.findClientPublicJWK(oidcClient, t, true)
			case jose.ES256, jose.ES384, jose.ES512:
				return f.findClientPublicJWK(oidcClient, t, false)
			case jose.PS256, jose.PS384, jose.PS512:
				return f.findClientPublicJWK(oidcClient, t, true)
			case jose.HS256, jose.HS384, jose.HS512:
				return nil, errorsx.WithStack(ErrInvalidClient.WithHint("This authorization server does not support client authentication method 'client_secret_jwt'."))
			default:
				return nil, errorsx.WithStack(ErrInvalidClient.WithHintf("The 'client_assertion' request parameter uses unsupported signing algorithm '%s'.", t.Header["alg"]))
			}
		})
		if err != nil {
			// Do not re-process already enhanced errors
			var e *jwt.ValidationError
			if errors.As(err, &e) {
				if e.Inner != nil {
					return nil, e.Inner
				}
				return nil, errorsx.WithStack(ErrInvalidClient.WithHint("Unable to verify the integrity of the 'client_assertion' value.").WithWrap(err).WithDebug(err.Error()))
			}
			return nil, err
		} else if err := token.Claims.Valid(); err != nil {
			return nil, errorsx.WithStack(ErrInvalidClient.WithHint("Unable to verify the request object because its claims could not be validated, check if the expiry time is set correctly.").WithWrap(err).WithDebug(err.Error()))
		}

		claims := token.Claims
		var jti string
		if !claims.VerifyIssuer(clientID, true) {
			return nil, errorsx.WithStack(ErrInvalidClient.WithHint("Claim 'iss' from 'client_assertion' must match the 'client_id' of the OAuth 2.0 Client."))
		} else if f.TokenURL == "" {
			return nil, errorsx.WithStack(ErrMisconfiguration.WithHint("The authorization server's token endpoint URL has not been set."))
		} else if sub, ok := claims["sub"].(string); !ok || sub != clientID {
			return nil, errorsx.WithStack(ErrInvalidClient.WithHint("Claim 'sub' from 'client_assertion' must match the 'client_id' of the OAuth 2.0 Client."))
		} else if jti, ok = claims["jti"].(string); !ok || len(jti) == 0 {
			return nil, errorsx.WithStack(ErrInvalidClient.WithHint("Claim 'jti' from 'client_assertion' must be set but is not."))
		} else if f.Store.ClientAssertionJWTValid(ctx, jti) != nil {
			return nil, errorsx.WithStack(ErrJTIKnown.WithHint("Claim 'jti' from 'client_assertion' MUST only be used once."))
		}

		// type conversion according to jwt.MapClaims.VerifyExpiresAt
		var expiry int64
		err = nil
		switch exp := claims["exp"].(type) {
		case float64:
			expiry = int64(exp)
		case int64:
			expiry = exp
		case json.Number:
			expiry, err = exp.Int64()
		default:
			err = ErrInvalidClient.WithHint("Unable to type assert the expiry time from claims. This should not happen as we validate the expiry time already earlier with token.Claims.Valid()")
		}

		if err != nil {
			return nil, errorsx.WithStack(err)
		}
		if err := f.Store.SetClientAssertionJWT(ctx, jti, time.Unix(expiry, 0)); err != nil {
			return nil, err
		}

		if auds, ok := claims["aud"].([]interface{}); !ok {
			if !claims.VerifyAudience(f.TokenURL, true) {
				return nil, errorsx.WithStack(ErrInvalidClient.WithHintf("Claim 'audience' from 'client_assertion' must match the authorization server's token endpoint '%s'.", f.TokenURL))
			}
		} else {
			var found bool
			for _, aud := range auds {
				if a, ok := aud.(string); ok && a == f.TokenURL {
					found = true
					break
				}
			}

			if !found {
				return nil, errorsx.WithStack(ErrInvalidClient.WithHintf("Claim 'audience' from 'client_assertion' must match the authorization server's token endpoint '%s'.", f.TokenURL))
			}
		}

		return client, nil
	} else if len(assertionType) > 0 {
		return nil, errorsx.WithStack(ErrInvalidRequest.WithHintf("Unknown client_assertion_type '%s'.", assertionType))
	}

	clientID, clientSecret, err := clientCredentialsFromRequest(r, form)
	if err != nil {
		return nil, err
	}

	client, err := f.Store.GetClient(ctx, clientID)
	if err != nil {
		return nil, errorsx.WithStack(ErrInvalidClient.WithWrap(err).WithDebug(err.Error()))
	}

	if oidcClient, ok := client.(OpenIDConnectClient); !ok {
		// If this isn't an OpenID Connect client then we actually don't care about any of this, just continue!
	} else if ok && form.Get("client_id") != "" && form.Get("client_secret") != "" && oidcClient.GetTokenEndpointAuthMethod() != "client_secret_post" {
		return nil, errorsx.WithStack(ErrInvalidClient.WithHintf("The OAuth 2.0 Client supports client authentication method '%s', but method 'client_secret_post' was requested. You must configure the OAuth 2.0 client's 'token_endpoint_auth_method' value to accept 'client_secret_post'.", oidcClient.GetTokenEndpointAuthMethod()))
	} else if _, _, basicOk := r.BasicAuth(); basicOk && ok && oidcClient.GetTokenEndpointAuthMethod() != "client_secret_basic" {
		return nil, errorsx.WithStack(ErrInvalidClient.WithHintf("The OAuth 2.0 Client supports client authentication method '%s', but method 'client_secret_basic' was requested. You must configure the OAuth 2.0 client's 'token_endpoint_auth_method' value to accept 'client_secret_basic'.", oidcClient.GetTokenEndpointAuthMethod()))
	} else if ok && oidcClient.GetTokenEndpointAuthMethod() != "none" && client.IsPublic() {
		return nil, errorsx.WithStack(ErrInvalidClient.WithHintf("The OAuth 2.0 Client supports client authentication method '%s', but method 'none' was requested. You must configure the OAuth 2.0 client's 'token_endpoint_auth_method' value to accept 'none'.", oidcClient.GetTokenEndpointAuthMethod()))
	}

	if client.IsPublic() {
		return client, nil
	}

	// Enforce client authentication
	if err := f.checkClientSecret(ctx, client, []byte(clientSecret)); err != nil {
		return nil, errorsx.WithStack(ErrInvalidClient.WithWrap(err).WithDebug(err.Error()))
	}

	return client, nil
}

func (f *Fosite) checkClientSecret(ctx context.Context, client Client, clientSecret []byte) error {
	var err error
	err = f.Hasher.Compare(ctx, client.GetHashedSecret(), clientSecret)
	if err == nil {
		return nil
	}
	cc, ok := client.(ClientWithSecretRotation)
	if !ok {
		return err
	}
	for _, hash := range cc.GetRotatedHashes() {
		err = f.Hasher.Compare(ctx, hash, clientSecret)
		if err == nil {
			return nil
		}
	}

	return err
}

func findPublicKey(t *jwt.Token, set *jose.JSONWebKeySet, expectsRSAKey bool) (interface{}, error) {
	keys := set.Keys
	if len(keys) == 0 {
		return nil, errorsx.WithStack(ErrInvalidRequest.WithHintf("The retrieved JSON Web Key Set does not contain any keys."))
	}

	kid, ok := t.Header["kid"].(string)
	if ok {
		keys = set.Key(kid)
	}

	if len(keys) == 0 {
		return nil, errorsx.WithStack(ErrInvalidRequest.WithHintf("The JSON Web Token uses signing key with kid '%s', which could not be found.", kid))
	}

	for _, key := range keys {
		if key.Use != "sig" {
			continue
		}
		if expectsRSAKey {
			if k, ok := key.Key.(*rsa.PublicKey); ok {
				return k, nil
			}
		} else {
			if k, ok := key.Key.(*ecdsa.PublicKey); ok {
				return k, nil
			}
		}
	}

	if expectsRSAKey {
		return nil, errorsx.WithStack(ErrInvalidRequest.WithHintf("Unable to find RSA public key with use='sig' for kid '%s' in JSON Web Key Set.", kid))
	} else {
		return nil, errorsx.WithStack(ErrInvalidRequest.WithHintf("Unable to find ECDSA public key with use='sig' for kid '%s' in JSON Web Key Set.", kid))
	}
}

func clientCredentialsFromRequest(r *http.Request, form url.Values) (clientID, clientSecret string, err error) {
	if id, secret, ok := r.BasicAuth(); !ok {
		return clientCredentialsFromRequestBody(form, true)
	} else if clientID, err = url.QueryUnescape(id); err != nil {
		return "", "", errorsx.WithStack(ErrInvalidRequest.WithHint("The client id in the HTTP authorization header could not be decoded from 'application/x-www-form-urlencoded'.").WithWrap(err).WithDebug(err.Error()))
	} else if clientSecret, err = url.QueryUnescape(secret); err != nil {
		return "", "", errorsx.WithStack(ErrInvalidRequest.WithHint("The client secret in the HTTP authorization header could not be decoded from 'application/x-www-form-urlencoded'.").WithWrap(err).WithDebug(err.Error()))
	}

	return clientID, clientSecret, nil
}

func clientCredentialsFromRequestBody(form url.Values, forceID bool) (clientID, clientSecret string, err error) {
	clientID = form.Get("client_id")
	clientSecret = form.Get("client_secret")

	if clientID == "" && forceID {
		return "", "", errorsx.WithStack(ErrInvalidRequest.WithHint("Client credentials missing or malformed in both HTTP Authorization header and HTTP POST body."))
	}

	return clientID, clientSecret, nil
}
