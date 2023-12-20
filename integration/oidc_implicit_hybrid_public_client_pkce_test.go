// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package integration_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	xoauth2 "golang.org/x/oauth2"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/compose"
	"authelia.com/provider/oauth2/handler/openid"
	"authelia.com/provider/oauth2/internal/gen"
	"authelia.com/provider/oauth2/token/jwt"
)

func TestOIDCImplicitFlowPublicClientPKCE(t *testing.T) {
	session := &defaultSession{
		DefaultSession: &openid.DefaultSession{
			Claims: &jwt.IDTokenClaims{
				Subject: "peter",
			},
			Headers: &jwt.Headers{},
		},
	}
	f := compose.ComposeAllEnabled(&oauth2.Config{
		GlobalSecret: []byte("some-secret-thats-random-some-secret-thats-random-"),
	}, store, gen.MustRSAKey())
	ts := mockServer(t, f, session)
	defer ts.Close()

	oauthClient := newOAuth2Client(ts)

	oauthClient.ClientSecret = ""
	oauthClient.ClientID = "public-client"
	oauthClient.Scopes = []string{"openid"}

	store.Clients["public-client"].(*oauth2.DefaultClient).RedirectURIs[0] = ts.URL + "/callback"

	var state = "12345678901234567890"
	for k, c := range []struct {
		responseType  string
		description   string
		nonce         string
		setup         func()
		codeVerifier  string
		codeChallenge string
	}{
		{

			responseType:  "id_token%20code",
			nonce:         "1111111111111111",
			description:   "should pass id token (id_token code) with PKCE applied.",
			setup:         func() {},
			codeVerifier:  "e7343b9bee0847e3b589ccb60d124ff81adcba6067b84f79b092f86249111fdc",
			codeChallenge: "J11vOtKUitab04a_N0Ogm0dQBytTgl0fgHzYk4xUryo",
		},
	} {
		t.Run(fmt.Sprintf("case=%d/description=%s", k, c.description), func(t *testing.T) {
			c.setup()

			var callbackURL *url.URL
			authURL := strings.Replace(oauthClient.AuthCodeURL(state), "response_type=code", "response_type="+c.responseType, -1) +
				"&nonce=" + c.nonce + "&code_challenge_method=S256&code_challenge=" + c.codeChallenge
			client := &http.Client{
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					callbackURL = req.URL
					return errors.New("Dont follow redirects")
				},
			}

			resp, err := client.Get(authURL)
			require.Error(t, err)

			t.Logf("Response (%d): %s", k, callbackURL.String())
			fragment, err := url.ParseQuery(callbackURL.Fragment)
			require.NoError(t, err)

			code := fragment.Get("code")
			assert.NotEmpty(t, code)

			assert.NotEmpty(t, fragment.Get("id_token"))

			resp, err = http.PostForm(oauthClient.Endpoint.TokenURL, url.Values{
				"code":          {code},
				"grant_type":    {"authorization_code"},
				"client_id":     {"public-client"},
				"redirect_uri":  {ts.URL + "/callback"},
				"code_verifier": {c.codeVerifier},
			})
			require.NoError(t, err)
			defer resp.Body.Close()

			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)

			assert.Equal(t, resp.StatusCode, http.StatusOK)
			token := xoauth2.Token{}
			require.NoError(t, json.Unmarshal(body, &token))

			require.NotEmpty(t, token.AccessToken, "Got body: %s", string(body))

			t.Logf("Passed test case (%d) %s", k, c.description)
		})
	}
}
