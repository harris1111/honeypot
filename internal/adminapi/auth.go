package adminapi

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/argon2"

	"github.com/harris/honeypot/internal/store"
)

const (
	sessionCookieName = "hp_admin_session"
	sessionTTL        = 12 * time.Hour
)

// AuthManager provides Argon2id password verification, TOTP 2FA, HttpOnly SameSite=Strict
// session cookies, and CSRF validation bound to each session.
type AuthManager struct {
	pg       *store.Postgres
	hmacKey  []byte
	aesKey   []byte
	isHTTPS  bool
}

type sessionClaims struct {
	UserID   string `json:"uid"`
	Username string `json:"usr"`
	CSRF     string `json:"csrf"`
	ExpUnix  int64  `json:"exp"`
}

func NewAuthManager(pg *store.Postgres, masterSecret []byte, isHTTPS bool) *AuthManager {
	hMac := sha256.Sum256(append([]byte("admin-sess-hmac:"), masterSecret...))
	hAES := sha256.Sum256(append([]byte("admin-totp-aes:"), masterSecret...))
	return &AuthManager{
		pg:      pg,
		hmacKey: hMac[:],
		aesKey:  hAES[:],
		isHTTPS: isHTTPS,
	}
}

func HashArgon2id(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	hash := argon2.IDKey([]byte(password), salt, 2, 64*1024, 2, 32)
	return fmt.Sprintf("$argon2id$%s$%s", base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(hash)), nil
}

func VerifyArgon2id(encoded, password string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 4 || parts[1] != "argon2id" {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[2])
	if err != nil {
		return false
	}
	expected, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, 2, 64*1024, 2, uint32(len(expected)))
	return subtle.ConstantTimeCompare(got, expected) == 1
}

// SetupInitialAdmin creates the sole initial operator account with Argon2id + TOTP when admin_users is empty.
func (a *AuthManager) SetupInitialAdmin(ctx context.Context, username, password string) (totpURI, secret string, err error) {
	username = strings.TrimSpace(username)
	if len(username) < 3 || len(password) < 8 || strings.ContainsAny(username, "|:\r\n") {
		return "", "", errors.New("valid username (>=3 chars, no |:) and password (>=8 chars) required")
	}

	tx, err := a.pg.Pool.Begin(ctx)
	if err != nil {
		return "", "", err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(73918275)`); err != nil {
		return "", "", err
	}
	var existingCount int
	if err := tx.QueryRow(ctx, `SELECT COUNT(*) FROM admin_users`).Scan(&existingCount); err != nil {
		return "", "", err
	}
	if existingCount > 0 {
		return "", "", errors.New("admin user already initialized")
	}

	pwHash, err := HashArgon2id(password)
	if err != nil {
		return "", "", err
	}
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "HoneypotHive",
		AccountName: username,
	})
	if err != nil {
		return "", "", err
	}
	encSecret, err := a.encryptBytes([]byte(key.Secret()))
	if err != nil {
		return "", "", err
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO admin_users (username, password_argon2, totp_secret_enc, totp_verified_at)
		VALUES ($1, $2, $3, NOW())
	`, username, pwHash, encSecret)
	if err != nil {
		return "", "", err
	}
	if err := tx.Commit(ctx); err != nil {
		return "", "", err
	}
	return key.URL(), key.Secret(), nil
}

// Authenticate verifies Argon2id password + RFC 6238 TOTP code and mints a signed session token.
func (a *AuthManager) Authenticate(ctx context.Context, username, password, totpCode string) (cookieVal, csrfToken string, err error) {
	var uid, pwHash string
	var encTOTP []byte
	err = a.pg.Pool.QueryRow(ctx, `
		SELECT id::text, password_argon2, totp_secret_enc
		FROM admin_users WHERE username = $1
	`, username).Scan(&uid, &pwHash, &encTOTP)
	if err != nil {
		return "", "", errors.New("invalid credentials")
	}
	if !VerifyArgon2id(pwHash, password) {
		return "", "", errors.New("invalid credentials")
	}
	secBytes, err := a.decryptBytes(encTOTP)
	if err != nil {
		return "", "", errors.New("totp state corrupt")
	}
	if !totp.Validate(strings.TrimSpace(totpCode), string(secBytes)) {
		return "", "", errors.New("invalid TOTP code")
	}

	csrfToken = randomHex(16)
	claims := sessionClaims{
		UserID:   uid,
		Username: username,
		CSRF:     csrfToken,
		ExpUnix:  time.Now().UTC().Add(sessionTTL).Unix(),
	}
	cookieVal = a.signClaims(claims)
	return cookieVal, csrfToken, nil
}

func (a *AuthManager) SetSessionCookie(w http.ResponseWriter, cookieVal string) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    cookieVal,
		Path:     "/",
		HttpOnly: true,
		Secure:   a.isHTTPS,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(sessionTTL.Seconds()),
	})
}

func (a *AuthManager) ClearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
}

func (a *AuthManager) VerifyRequestSession(r *http.Request) (sessionClaims, bool) {
	c, err := r.Cookie(sessionCookieName)
	if err != nil || c.Value == "" {
		return sessionClaims{}, false
	}
	return a.verifyClaims(c.Value)
}

func (a *AuthManager) signClaims(c sessionClaims) string {
	raw := fmt.Sprintf("%s|%s|%s|%d", c.UserID, c.Username, c.CSRF, c.ExpUnix)
	payload := base64.RawURLEncoding.EncodeToString([]byte(raw))
	mac := hmac.New(sha256.New, a.hmacKey)
	_, _ = mac.Write([]byte(payload))
	sig := hex.EncodeToString(mac.Sum(nil))
	return payload + "." + sig
}

func (a *AuthManager) verifyClaims(tok string) (sessionClaims, bool) {
	payload, sigHex, ok := strings.Cut(tok, ".")
	if !ok {
		return sessionClaims{}, false
	}
	mac := hmac.New(sha256.New, a.hmacKey)
	_, _ = mac.Write([]byte(payload))
	wantHex := hex.EncodeToString(mac.Sum(nil))
	if subtle.ConstantTimeCompare([]byte(sigHex), []byte(wantHex)) != 1 {
		return sessionClaims{}, false
	}
	rawBytes, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return sessionClaims{}, false
	}
	parts := strings.Split(string(rawBytes), "|")
	if len(parts) != 4 {
		return sessionClaims{}, false
	}
	var exp int64
	_, _ = fmt.Sscanf(parts[3], "%d", &exp)
	if time.Now().UTC().Unix() > exp {
		return sessionClaims{}, false
	}
	return sessionClaims{
		UserID:   parts[0],
		Username: parts[1],
		CSRF:     parts[2],
		ExpUnix:  exp,
	}, true
}

func (a *AuthManager) encryptBytes(plain []byte) ([]byte, error) {
	blk, err := aes.NewCipher(a.aesKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plain, nil), nil
}

func (a *AuthManager) decryptBytes(ciphertext []byte) ([]byte, error) {
	blk, err := aes.NewCipher(a.aesKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, err
	}
	ns := gcm.NonceSize()
	if len(ciphertext) < ns {
		return nil, errors.New("short ciphertext")
	}
	return gcm.Open(nil, ciphertext[:ns], ciphertext[ns:], nil)
}

func randomHex(nBytes int) string {
	b := make([]byte, nBytes)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
