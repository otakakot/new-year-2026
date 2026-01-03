package handler

import (
	"bytes"
	"cmp"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/rueidis"

	"github.com/otakakot/new-year-2026/internal/core"
	"github.com/otakakot/new-year-2026/pkg/api"
	"github.com/otakakot/new-year-2026/pkg/schema"
)

var _ api.StrictServerInterface = (*Handler)(nil)

type Handler struct {
	db     *pgxpool.Pool
	cache  rueidis.Client
	wa     *webauthn.WebAuthn
	origin string
}

// New creates a new API handler instance.
func New(
	db *pgxpool.Pool,
	cache rueidis.Client,
	wa *webauthn.WebAuthn,
	origin string,
) api.ServerInterface {
	hdl := &Handler{
		db:     db,
		cache:  cache,
		wa:     wa,
		origin: origin,
	}

	return api.NewStrictHandler(
		hdl,
		[]api.StrictMiddlewareFunc{
			Middleware(),
			hdl.Bearer(),
		})
}

func Middleware() api.StrictMiddlewareFunc {
	return func(next api.StrictHandlerFunc, operationID string) api.StrictHandlerFunc {
		return func(
			ctx context.Context,
			w http.ResponseWriter,
			r *http.Request,
			request any,
		) (any, error) {
			slog.InfoContext(ctx, r.URL.String()+" - started")
			defer slog.InfoContext(ctx, r.URL.String()+" - completed")
			return next(ctx, w, r, request)
		}
	}
}

type subKey struct{}

func (hdl *Handler) Bearer() api.StrictMiddlewareFunc {
	return func(next api.StrictHandlerFunc, operationID string) api.StrictHandlerFunc {
		return func(
			ctx context.Context,
			w http.ResponseWriter,
			r *http.Request,
			request any,
		) (any, error) {
			if _, ok := ctx.Value(api.BearerScopes).([]string); ok {
				tokens := strings.Split(r.Header.Get("Authorization"), " ")

				if len(tokens) != 2 || tokens[0] != "Bearer" {
					return nil, errors.New("invalid authorization header")
				}

				at, err := core.ParceAccessToken(tokens[1], "secret")
				if err != nil {
					return nil, err
				}

				if at.Exp < (time.Now().Unix()) {
					return nil, errors.New("access token expired")
				}

				slog.InfoContext(ctx, fmt.Sprintf("access token: %+v", at))

				ctx = context.WithValue(ctx, subKey{}, at.Sub)
			}
			return next(ctx, w, r, request)
		}
	}
}

// Health implements api.StrictServerInterface.
func (hdl *Handler) Health(
	ctx context.Context,
	request api.HealthRequestObject,
) (api.HealthResponseObject, error) {
	if err := schema.New(hdl.db).Health(ctx); err != nil {
		return nil, err
	}

	if err := hdl.cache.Do(ctx, hdl.cache.B().Ping().Build()).Error(); err != nil {
		return nil, err
	}

	return api.Health200Response{}, nil
}

// OpenIDConfiguration implements api.StrictServerInterface.
func (hdl *Handler) OpenIDConfiguration(
	ctx context.Context,
	request api.OpenIDConfigurationRequestObject,
) (api.OpenIDConfigurationResponseObject, error) {
	return api.OpenIDConfiguration200JSONResponse{
		Issuer:                           hdl.origin,
		TokenEndpoint:                    hdl.origin + "/token",
		UserinfoEndpoint:                 hdl.origin + "/userinfo",
		AuthorizationEndpoint:            hdl.origin + "/authorize",
		JwksUri:                          hdl.origin + "/certs",
		ResponseTypesSupported:           []string{"code"},
		SubjectTypesSupported:            []string{"public"},
		IdTokenSigningAlgValuesSupported: []string{"RS256"},
	}, nil
}

// Authorize implements api.StrictServerInterface.
func (hdl *Handler) Authorize(
	ctx context.Context,
	request api.AuthorizeRequestObject,
) (api.AuthorizeResponseObject, error) {
	cli, err := schema.New(hdl.db).SelectClientByID(ctx, request.Params.ClientId)
	if err != nil {
		return nil, err
	}

	redirectURI := ""
	if request.Params.RedirectUri != nil {
		redirectURI = *request.Params.RedirectUri
	}

	if redirectURI != cli.RedirectUri {
		return nil, errors.New("invalid redirect_uri")
	}

	scope := api.AuthorizeParamsScope("")
	if request.Params.Scope != nil {
		scope = *request.Params.Scope
	}

	state := ""
	if request.Params.State != nil {
		state = *request.Params.State
	}

	auth := core.Authorize{
		ResponseType: string(request.Params.ResponseType),
		ClientID:     request.Params.ClientId.String(),
		RedirectURI:  redirectURI,
		Scope:        string(scope),
		State:        state,
	}

	key := uuid.NewString()

	val := bytes.Buffer{}

	if err := json.NewEncoder(&val).Encode(auth); err != nil {
		return nil, err
	}

	if err := hdl.cache.Do(
		ctx,
		hdl.cache.B().Set().Key(key).Value(val.String()).Build(),
	).Error(); err != nil {
		return nil, err
	}

	cookie := http.Cookie{
		Name:     "__authorize__",
		Value:    key,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	}

	web := cmp.Or(os.Getenv("WEB_URL"), "http://localhost:5500")

	return api.Authorize302Response{
		Headers: api.Authorize302ResponseHeaders{
			Location:  web,
			SetCookie: cookie.String(),
		},
	}, nil
}

// InitializeAssertion implements api.StrictServerInterface.
func (hdl *Handler) InitializeAssertion(
	ctx context.Context,
	request api.InitializeAssertionRequestObject,
) (api.InitializeAssertionResponseObject, error) {
	assertion, session, err := hdl.wa.BeginDiscoverableLogin()
	if err != nil {
		return nil, err
	}

	key := uuid.NewString()

	val := bytes.Buffer{}

	if err := json.NewEncoder(&val).Encode(session); err != nil {
		return nil, err
	}

	if err := hdl.cache.Do(
		ctx,
		hdl.cache.B().Set().Key(key).Value(val.String()).Build(),
	).Error(); err != nil {
		return nil, err
	}

	cookie := http.Cookie{
		Name:     "__assertion__",
		Value:    key,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   60 * 5, // 5 minutes
	}

	return api.InitializeAssertion200JSONResponse{
		Body: assertion.Response,
		Headers: api.InitializeAssertion200ResponseHeaders{
			SetCookie: cookie.String(),
		},
	}, nil
}

// FinalizeAssertion implements api.StrictServerInterface.
func (hdl *Handler) FinalizeAssertion(
	ctx context.Context,
	request api.FinalizeAssertionRequestObject,
) (api.FinalizeAssertionResponseObject, error) {
	var session webauthn.SessionData

	val, err := hdl.cache.Do(
		ctx,
		hdl.cache.B().Getdel().Key(request.Params.UnderscoreUnderscoreAssertion).Build(),
	).ToString()
	if err != nil {
		return nil, err
	}

	if err := json.NewDecoder(bytes.NewBufferString(val)).Decode(&session); err != nil {
		return nil, err
	}

	slog.InfoContext(ctx, fmt.Sprintf("session: %+v", session))

	sid := uuid.NewString()

	// TODO
	uid := uuid.NewString()

	if err := hdl.cache.Do(
		ctx,
		hdl.cache.B().Set().Key(sid).Value(uid).Build(),
	).Error(); err != nil {
		return nil, err
	}

	cookie := http.Cookie{
		Name:     "__session__",
		Value:    sid,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   60 * 60 * 24 * 7, // 7 days
	}

	return api.FinalizeAssertion200JSONResponse{
		Headers: api.FinalizeAssertion200ResponseHeaders{
			SetCookie: cookie.String(),
		},
	}, nil
}

// Callback implements api.StrictServerInterface.
func (hdl *Handler) Callback(
	ctx context.Context,
	request api.CallbackRequestObject,
) (api.CallbackResponseObject, error) {
	var auth core.Authorize

	val, err := hdl.cache.Do(
		ctx,
		hdl.cache.B().Getdel().Key(request.Params.UnderscoreUnderscoreAuthorize).Build(),
	).ToString()
	if err != nil {
		return nil, err
	}

	if err := json.NewDecoder(bytes.NewBufferString(val)).Decode(&auth); err != nil {
		return nil, err
	}

	slog.InfoContext(ctx, fmt.Sprintf("auth: %+v", auth))

	cookie := http.Cookie{
		Name:     "__authorize__",
		Value:    "",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	}

	uid, err := hdl.cache.Do(
		ctx,
		hdl.cache.B().Get().Key(request.Params.UnderscoreUnderscoreSession).Build(),
	).ToString()
	if err != nil {
		return nil, err
	}

	code := rand.Text()

	if err := hdl.cache.Do(
		ctx,
		hdl.cache.B().Set().Key(code).Value(uid).Build(),
	).Error(); err != nil {
		return nil, err
	}

	locationBuf := bytes.Buffer{}

	locationBuf.WriteString(auth.RedirectURI)

	values := url.Values{
		"code": {code},
	}

	if auth.State != "" {
		values.Set("state", auth.State)
	}

	locationBuf.WriteByte('?')

	locationBuf.WriteString(values.Encode())

	return api.Callback302Response{
		Headers: api.Callback302ResponseHeaders{
			Location:  locationBuf.String(),
			SetCookie: cookie.String(),
		},
	}, nil
}

// Token implements api.StrictServerInterface.
func (hdl *Handler) Token(
	ctx context.Context,
	request api.TokenRequestObject,
) (api.TokenResponseObject, error) {
	switch request.Body.GrantType {
	case api.TokenRequestGrantTypeAuthorizationCode:
		code := ""

		if request.Body.Code != nil {
			code = *request.Body.Code
		} else {
			return api.Token400JSONResponse{
				Error:            api.InvalidRequest,
				ErrorDescription: "code is required",
				ErrorUri:         "",
			}, nil
		}

		uid, err := hdl.cache.Do(
			ctx,
			hdl.cache.B().Get().Key(code).Build(),
		).ToString()
		if err != nil {
			return nil, err
		}

		rt := rand.Text()

		if err := hdl.cache.Do(
			ctx,
			hdl.cache.B().Set().Key(rt).Value(uid).Build(),
		).Error(); err != nil {
			return nil, err
		}

		cid := ""
		if request.Body.ClientId != nil {
			cid = *request.Body.ClientId
		} else {
			return api.Token400JSONResponse{
				Error:            api.InvalidRequest,
				ErrorDescription: "client_id is required",
				ErrorUri:         "",
			}, nil
		}

		cas := ""
		if request.Body.ClientAssertion != nil {
			cas = *request.Body.ClientAssertion
		} else {
			return api.Token400JSONResponse{
				Error:            api.InvalidRequest,
				ErrorDescription: "client_assertion is required",
				ErrorUri:         "",
			}, nil
		}

		cli, err := schema.New(hdl.db).SelectClientByID(ctx, uuid.MustParse(cid))
		if err != nil {
			return nil, err
		}

		pubkey, err := core.ParseDERPublicKey(cli.DerPublicKey)
		if err != nil {
			return nil, err
		}

		if _, err := core.ValidateClientAssertion(cas, pubkey); err != nil {
			return nil, err
		}

		jwks, err := schema.New(hdl.db).SelectJwkSets(ctx)
		if err != nil {
			return nil, err
		}

		key, err := core.ParseDERPrivateKey(jwks[0].DerPrivateKey)
		if err != nil {
			return nil, err
		}

		sign := core.SignKey{
			ID:  jwks[0].ID.String(),
			Key: key,
		}

		at := core.GenerateAccessToken(hdl.origin, uid)

		it := core.GenerateIDToken(hdl.origin, uid, cid, "")

		return api.Token200JSONResponse{
			Body: api.TokenResponse{
				AccessToken:  at.JWT("secret"),
				IdToken:      it.JWT(sign),
				RefreshToken: rt,
				TokenType:    "Bearer",
				ExpiresIn:    3600,
			},
			Headers: api.Token200ResponseHeaders{},
		}, nil
	case api.TokenRequestGrantTypeRefreshToken:
		rt := ""
		if request.Body.RefreshToken != nil {
			rt = *request.Body.RefreshToken
		} else {
			return api.Token400JSONResponse{
				Error:            api.InvalidRequest,
				ErrorDescription: "refresh_token is required",
				ErrorUri:         "",
			}, nil
		}

		uid, err := hdl.cache.Do(
			ctx,
			hdl.cache.B().Getdel().Key(rt).Build(),
		).ToString()
		if err != nil {
			return nil, err
		}

		rt = rand.Text()

		if err := hdl.cache.Do(
			ctx,
			hdl.cache.B().Set().Key(rt).Value(uid).Build(),
		).Error(); err != nil {
			return nil, err
		}

		at := core.GenerateAccessToken(hdl.origin, uid)

		return api.Token200JSONResponse{
			Body: api.TokenResponse{
				AccessToken:  at.JWT("secret"),
				IdToken:      "",
				RefreshToken: rt,
				TokenType:    "Bearer",
				ExpiresIn:    3600,
			},
			Headers: api.Token200ResponseHeaders{},
		}, nil
	default:
		return nil, errors.New("error")
	}
}

// Jwks implements api.StrictServerInterface.
func (hdl *Handler) Jwks(
	ctx context.Context,
	request api.JwksRequestObject,
) (api.JwksResponseObject, error) {
	jwks, err := schema.New(hdl.db).SelectJwkSets(ctx)
	if err != nil {
		return nil, err
	}

	keys := make([]api.JWKSet, len(jwks))

	for i, jwk := range jwks {
		key, err := core.ParseDERPrivateKey(jwk.DerPrivateKey)
		if err != nil {
			return nil, err
		}

		sign := core.SignKey{
			ID:  jwk.ID.String(),
			Key: key,
		}

		keys[i] = api.JWKSet{
			Alg: sign.Cert().Alg,
			E:   sign.Cert().E,
			Kid: sign.Cert().KID,
			Kty: sign.Cert().KTY,
			N:   sign.Cert().N,
			Use: sign.Cert().Use,
		}
	}

	return api.Jwks200JSONResponse{
		Keys: keys,
	}, nil
}

// Userinfo implements api.StrictServerInterface.
func (hdl *Handler) Userinfo(
	ctx context.Context,
	request api.UserinfoRequestObject,
) (api.UserinfoResponseObject, error) {
	sub := ctx.Value(subKey{}).(string)

	return api.Userinfo200JSONResponse{
		Email: "",
		Sub:   sub,
	}, nil
}

// Revoke implements api.StrictServerInterface.
func (hdl *Handler) Revoke(
	ctx context.Context,
	request api.RevokeRequestObject,
) (api.RevokeResponseObject, error) {
	if request.Body.Token == "" {
		return api.Revoke200Response{}, nil
	}

	if err := hdl.cache.Do(
		ctx,
		hdl.cache.B().Del().Key(request.Body.Token).Build(),
	).Error(); err != nil {
		return nil, err
	}

	return api.Revoke200Response{}, nil
}
