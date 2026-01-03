package main

import (
	"bytes"
	"cmp"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/otakakot/new-year-2026/pkg/schema"
)

const uri = "http://localhost:8080"

const redirectURI = "http://localhost:3000/callback"

type Tokens struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

var tokens = map[string]Tokens{}

const cookey = "__key__"

var key *rsa.PrivateKey

var client schema.Client

func main() {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	key = privateKey

	derPublicKey, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		panic(err)
	}

	dsn := cmp.Or(
		os.Getenv("DSN"),
		"postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable",
	)

	conn, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		panic(err)
	}

	pool, err := pgxpool.NewWithConfig(context.Background(), conn)
	if err != nil {
		panic(err)
	}
	defer pool.Close()

	cli, err := schema.New(pool).InsertClient(context.Background(), schema.InsertClientParams{
		DerPublicKey: derPublicKey,
		RedirectUri:  redirectURI,
	})
	if err != nil {
		panic(err)
	}

	client = cli

	port := cmp.Or(os.Getenv("PORT"), "3000")

	hdl := http.NewServeMux()

	hdl.HandleFunc("/", Handler)

	hdl.HandleFunc("/callback", Callback)

	hdl.HandleFunc("/userinfo", UserInfo)

	hdl.HandleFunc("/refresh", Refresh)

	hdl.HandleFunc("/logout", Logout)

	srv := &http.Server{
		Addr:              fmt.Sprintf(":%s", port),
		Handler:           hdl,
		ReadHeaderTimeout: 30 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)

	defer stop()

	go func() {
		slog.Info("start server listen")

		slog.Info("http://localhost:" + port)

		if err := srv.ListenAndServe(); err != nil && errors.Is(err, http.ErrServerClosed) {
			panic(err)
		}
	}()

	<-ctx.Done()

	slog.Info("start server shutdown")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)

	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		panic(err)
	}

	slog.Info("done server shutdown")

}

func Handler(w http.ResponseWriter, r *http.Request) {
	if _, err := r.Cookie(cookey); err != nil {
		buf := bytes.Buffer{}

		buf.WriteString(uri + "/authorize")

		state := rand.Text()

		values := url.Values{
			"response_type": {"code"},
			"client_id":     {client.ID.String()},
			"redirect_uri":  {redirectURI},
			"scope":         {"openid"},
			"state":         {state},
		}

		buf.WriteString("?")

		buf.WriteString(values.Encode())

		http.Redirect(w, r, buf.String(), http.StatusFound)

		return
	}

	w.Write([]byte(view))
}

const view = `<!DOCTYPE html>
<html lang="en">

<head>
	<title>Login</title>
</head>

<body>
	<button id="userinfo">UserInfo</button>
	<button id="refresh">Refresh</button>
	<button id="logout">Logout</button>
	<button id="leave">Leave</button>

	<script>
		document.getElementById("userinfo").
			addEventListener("click", async () => {
				location.href = "/userinfo";
			});
		document.getElementById("refresh").
			addEventListener("click", async () => {
				const res = await fetch("/refresh", {
					method: "GET",
					credentials: "include",
				});
				if (res.ok) {
					location.href = "/";
				}
			});
		document.getElementById("logout").
			addEventListener("click", async () => {
				location.href = "/logout";
			});
		document.getElementById("leave").
			addEventListener("click", async () => {
				location.href = "/";
			});
	</script>
</body>

</html>
`

type TokenResponse struct {
	// AccessToken access_token
	AccessToken string `json:"access_token"`

	// ExpiresIn expires_in
	ExpiresIn int `json:"expires_in"`

	// IdToken id_token
	IdToken string `json:"id_token"`

	// RefreshToken refresh_token
	RefreshToken string `json:"refresh_token"`

	// TokenType token_type
	TokenType string `json:"token_type"`
}

type CertsResponseSchema struct {
	Keys []JWKSet `json:"keys"`
}

type JWKSet struct {
	Alg string `json:"alg"`
	E   string `json:"e"`
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	N   string `json:"n"`
	Use string `json:"use"`
}

type Header struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ"`
}

type Payload struct {
	Aud string `json:"aud"`
	Exp int    `json:"exp"`
	Iat int    `json:"iat"`
	Iss string `json:"iss"`
	Sub string `json:"sub"`
}

func Callback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")

	state := r.URL.Query().Get("state")

	slog.Info("code: " + code)

	slog.Info("state: " + state)

	// TODO: validate state

	bearer, _ := GenerateToken(
		key,
		"http://localhost:3000",
		client.ID.String(),
		uri,
		"jwk_id", // 2回使えないようにするにはサーバー側で nonce とか払い出さないとダメじゃない？
	)

	values := url.Values{
		"grant_type":            {"authorization_code"},
		"code":                  {code},
		"redirect_uri":          {redirectURI},
		"client_id":             {client.ID.String()},
		"client_secret":         {""},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
		"client_assertion":      {bearer},
		"scope":                 {"openid"},
	}

	req, err := http.NewRequest(http.MethodPost, uri+"/token", bytes.NewBufferString(values.Encode()))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)

		return
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		slog.Error("failed to post /token" + err.Error())

		http.Error(w, err.Error(), http.StatusInternalServerError)

		return
	}

	defer res.Body.Close()

	slog.Info("status: " + res.Status)

	var response TokenResponse

	slog.Info("response: " + fmt.Sprintf("%+v", response))

	if err := json.NewDecoder(res.Body).Decode(&response); err != nil {
		slog.Error("failed to decode token. error: " + err.Error())

		http.Error(w, err.Error(), http.StatusInternalServerError)

		return
	}

	session := rand.Text()

	tokens[session] = Tokens{
		AccessToken:  response.AccessToken,
		RefreshToken: response.RefreshToken,
	}

	slog.Info("access_token: " + response.AccessToken)

	slog.Info("id_token: " + response.IdToken)

	idTokens := strings.Split(response.IdToken, ".")

	hbyte, err := base64.RawStdEncoding.DecodeString(idTokens[0])
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)

		return
	}

	header := Header{}

	if err := json.Unmarshal(hbyte, &header); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)

		return
	}

	slog.Info("header: " + fmt.Sprintf("%+v", header))

	pbyte, err := base64.RawStdEncoding.DecodeString(idTokens[1])
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)

		return
	}

	payload := Payload{}

	if err := json.Unmarshal(pbyte, &payload); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)

		return
	}

	slog.Info("payload: " + fmt.Sprintf("%+v", payload))

	slog.Info("refresh_token: " + response.RefreshToken)

	slog.Info("token_type: " + response.TokenType)

	slog.Info("expires_in: " + fmt.Sprint(response.ExpiresIn))

	keyID := header.Kid

	jwkset := JWKSet{}

	{
		req, err := http.NewRequest(http.MethodGet, uri+"/certs", nil)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)

			return
		}

		res, err := http.DefaultClient.Do(req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)

			slog.Error(err.Error())

			return
		}

		defer res.Body.Close()

		var response CertsResponseSchema

		if err := json.NewDecoder(res.Body).Decode(&response); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)

			return
		}

		for _, key := range response.Keys {
			if key.Kid == keyID {
				jwkset = key

				break
			}
		}

		slog.Info("keys: " + fmt.Sprintf("%+v", response.Keys))
	}

	nbytes, err := base64.RawURLEncoding.DecodeString(jwkset.N)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)

		return
	}

	n := new(big.Int).SetBytes(nbytes)

	ebytes, err := base64.RawURLEncoding.DecodeString(jwkset.E)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)

		return
	}

	e := new(big.Int).SetBytes(ebytes)

	pubkey := rsa.PublicKey{
		N: n,
		E: int(e.Int64()),
	}

	slog.Info("public_key: " + fmt.Sprintf("%+v", pubkey))

	tk, err := jwt.Parse(response.IdToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return &pubkey, nil
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)

		return
	}

	claims, ok := tk.Claims.(jwt.MapClaims)
	if !ok || !tk.Valid {
		http.Error(w, "token is invalid", http.StatusInternalServerError)

		return
	}

	slog.Info("claims: " + fmt.Sprintf("%+v", claims))

	cookie := &http.Cookie{
		Name:     cookey,
		Value:    session,
		Secure:   true,
		HttpOnly: true,
		Expires:  time.Now().Add(24 * time.Hour),
	}

	slog.Info("session_id: " + session)

	http.SetCookie(w, cookie)

	http.Redirect(w, r, "/", http.StatusFound)
}

type UserInfoResponseSchema struct {
	Email string `json:"email"`
	Sub   string `json:"sub"`
}

func UserInfo(w http.ResponseWriter, r *http.Request) {
	session, err := r.Cookie(cookey)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)

		return
	}

	slog.Info("session_id: " + session.Value)

	req, err := http.NewRequest(http.MethodGet, uri+"/userinfo", nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)

		return
	}

	token := tokens[session.Value]

	slog.Info("access_token: " + token.AccessToken)

	slog.Info("refresh_token: " + token.RefreshToken)

	req.Header.Set("Authorization", "Bearer "+token.AccessToken)

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)

		return
	}

	defer res.Body.Close()

	var response UserInfoResponseSchema

	if err := json.NewDecoder(res.Body).Decode(&response); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)

		return
	}

	slog.Info("status: " + res.Status)

	slog.Info("response: " + fmt.Sprintf("%+v", response))

	w.Write(fmt.Appendf(nil, "%+v", response))
}

func Refresh(w http.ResponseWriter, r *http.Request) {
	session, err := r.Cookie(cookey)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)

		return
	}

	slog.Info("session_id: " + session.Value)

	token := tokens[session.Value]

	slog.Info("access_token: " + token.AccessToken)

	slog.Info("refresh_token: " + token.RefreshToken)

	values := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {token.RefreshToken},
	}

	req, err := http.NewRequest(http.MethodPost, uri+"/token", strings.NewReader(values.Encode()))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)

		return
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)

		return
	}

	defer res.Body.Close()

	var response TokenResponse

	if err := json.NewDecoder(res.Body).Decode(&response); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)

		return
	}

	slog.Info("status: " + res.Status)

	slog.Info("access_token: " + response.AccessToken)

	slog.Info("id_token: " + response.IdToken)

	slog.Info("refresh_token: " + response.RefreshToken)

	slog.Info("token_type: " + response.TokenType)

	slog.Info("expires_in: " + fmt.Sprint(response.ExpiresIn))

	tokens[session.Value] = Tokens{
		AccessToken:  response.AccessToken,
		RefreshToken: response.RefreshToken,
	}
}

func Logout(w http.ResponseWriter, r *http.Request) {
	session, err := r.Cookie(cookey)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)

		return
	}

	slog.Info(fmt.Sprintf("tokens: %+v", tokens))

	slog.Info("session_id: " + session.Value)

	token := tokens[session.Value]

	slog.Info("access_token: " + token.AccessToken)

	slog.Info("refresh_token: " + token.RefreshToken)

	values := url.Values{
		"token":           {token.RefreshToken},
		"token_type_hint": {"refresh_token"},
	}

	req, err := http.NewRequest(http.MethodPost, uri+"/revoke", strings.NewReader(values.Encode()))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)

		return
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)

		return
	}

	defer res.Body.Close()

	slog.Info("status: " + res.Status)

	delete(tokens, session.Value)

	http.SetCookie(w, &http.Cookie{
		Name:   cookey,
		Value:  "",
		MaxAge: -1,
	})

	http.Redirect(w, r, "/", http.StatusFound)
}

func GenerateToken(
	privateKey *rsa.PrivateKey,
	iss string,
	sub string,
	aud string,
	jti string,
) (string, error) {
	claims := jwt.MapClaims{
		"iss": iss,
		"sub": sub,
		"aud": aud,
		"jti": jti,
		"exp": time.Now().Add(time.Hour).Unix(), // 1時間有効
		"iat": time.Now().Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}
