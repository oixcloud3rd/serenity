package subscription

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/serenity/common/cachefile"
	C "github.com/sagernet/serenity/constant"
	serenityOption "github.com/sagernet/serenity/option"
	"github.com/sagernet/sing-box/include"

	"github.com/metacubex/age"
	"github.com/metacubex/age/armor"
)

func TestFetchOIXCloudConfig(t *testing.T) {
	const (
		key   = "test-hmac-key"
		token = "secret-subscription-token"
	)
	now := time.Unix(1784900000, 0)
	plaintext := []byte("proxies:\n  - name: direct\n    type: direct\n")
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.RawQuery != "z=last&a=%2F+value&a=second" {
			t.Errorf("unexpected query: %q", request.URL.RawQuery)
		}
		if request.Header.Get("Authorization") != "Bearer "+token {
			t.Error("missing bearer token")
		}
		if request.Header.Get("User-Agent") != oixCloudUserAgent {
			t.Errorf("unexpected user-agent: %q", request.Header.Get("User-Agent"))
		}
		timestamp := request.Header.Get("X-Flclash-Timestamp")
		publicKey := request.Header.Get("X-Flclash-Age-Pubkey")
		if timestamp != "1784900000" {
			t.Errorf("unexpected timestamp: %q", timestamp)
		}
		if !strings.HasPrefix(publicKey, "age1") {
			t.Errorf("unexpected age public key: %q", publicKey)
		}
		if request.Header.Get("X-Flclash-Signature") != oixCloudHMAC(key, timestamp+"."+publicKey) {
			t.Error("invalid request signature")
		}
		recipient, err := age.ParseX25519Recipient(publicKey)
		if err != nil {
			t.Fatalf("parse recipient: %v", err)
		}
		ciphertext := encryptOIXCloudTestConfig(t, recipient, plaintext)
		encoded := base64.StdEncoding.EncodeToString(ciphertext)
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("X-Flclash-Response-Signature", oixCloudHMAC(key, timestamp+"."+encoded))
		_ = json.NewEncoder(writer).Encode(oixCloudAPIResponse{Config: encoded})
	}))
	defer server.Close()

	content, err := fetchOIXCloudConfig(context.Background(), server.Client(), server.URL, token, "z=last&a=%2F+value&a=second", key, now)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(content, plaintext) {
		t.Fatalf("unexpected plaintext: %q", content)
	}
}

func TestFetchOIXCloudConfigRejectsUnsignedAndPlaintextResponses(t *testing.T) {
	const key = "test-hmac-key"
	tests := []struct {
		name      string
		sign      bool
		plaintext bool
		want      string
	}{
		{name: "missing signature", plaintext: false, want: "missing its signature"},
		{name: "plaintext", sign: true, plaintext: true, want: "not age armored"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				config := []byte("proxies: []")
				if !test.plaintext {
					recipient, err := age.ParseX25519Recipient(request.Header.Get("X-Flclash-Age-Pubkey"))
					if err != nil {
						t.Fatal(err)
					}
					config = encryptOIXCloudTestConfig(t, recipient, config)
				}
				encoded := base64.StdEncoding.EncodeToString(config)
				if test.sign {
					timestamp := request.Header.Get("X-Flclash-Timestamp")
					writer.Header().Set("X-Flclash-Response-Signature", oixCloudHMAC(key, timestamp+"."+encoded))
				}
				_ = json.NewEncoder(writer).Encode(oixCloudAPIResponse{Config: encoded})
			}))
			defer server.Close()
			_, err := fetchOIXCloudConfig(context.Background(), server.Client(), server.URL, "token", "", key, time.Now())
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("expected %q error, got %v", test.want, err)
			}
		})
	}
}

func TestFetchOIXCloudConfigRejectsInvalidResponses(t *testing.T) {
	const key = "test-hmac-key"
	tests := []struct {
		name   string
		status int
		mode   string
		want   string
	}{
		{name: "non 2xx", status: http.StatusBadGateway, want: "HTTP 502"},
		{name: "invalid JSON", mode: "json", want: "parse oixCloud response"},
		{name: "invalid Base64", mode: "base64", want: "decode oixCloud configuration"},
		{name: "wrong signature", mode: "signature", want: "invalid oixCloud response signature"},
		{name: "invalid age", mode: "age", want: "decrypt oixCloud configuration"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				if test.status != 0 {
					writer.WriteHeader(test.status)
					return
				}
				if test.mode == "json" {
					_, _ = writer.Write([]byte("{"))
					return
				}
				config := "%%%"
				if test.mode == "age" || test.mode == "signature" {
					config = base64.StdEncoding.EncodeToString([]byte("-----BEGIN AGE ENCRYPTED FILE-----\ninvalid\n-----END AGE ENCRYPTED FILE-----"))
				}
				timestamp := request.Header.Get("X-Flclash-Timestamp")
				signature := oixCloudHMAC(key, timestamp+"."+config)
				if test.mode == "signature" {
					signature = strings.Repeat("0", len(signature))
				}
				writer.Header().Set("X-Flclash-Response-Signature", signature)
				_ = json.NewEncoder(writer).Encode(oixCloudAPIResponse{Config: config})
			}))
			defer server.Close()
			_, err := fetchOIXCloudConfig(context.Background(), server.Client(), server.URL, "token", "", key, time.Now())
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("expected %q error, got %v", test.want, err)
			}
		})
	}
}

func TestReadOIXCloudLimited(t *testing.T) {
	_, err := readOIXCloudLimited(strings.NewReader("12345"), 4)
	if err == nil || !strings.Contains(err.Error(), "size limit") {
		t.Fatalf("expected size-limit error, got %v", err)
	}
}

func TestOIXCloudPrimaryFallbackAndFailedRefreshKeepsCache(t *testing.T) {
	const key = "test-hmac-key"
	primaryCalls := 0
	fallbackCalls := 0
	failFallback := false
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/primary" {
			primaryCalls++
			writer.WriteHeader(http.StatusBadGateway)
			return
		}
		fallbackCalls++
		if failFallback {
			writer.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		recipient, err := age.ParseX25519Recipient(request.Header.Get("X-Flclash-Age-Pubkey"))
		if err != nil {
			t.Fatal(err)
		}
		ciphertext := encryptOIXCloudTestConfig(t, recipient, []byte("proxies:\n  - {name: direct, type: direct}\n"))
		config := base64.StdEncoding.EncodeToString(ciphertext)
		timestamp := request.Header.Get("X-Flclash-Timestamp")
		writer.Header().Set("X-Flclash-Response-Signature", oixCloudHMAC(key, timestamp+"."+config))
		_ = json.NewEncoder(writer).Encode(oixCloudAPIResponse{Config: config})
	}))
	defer server.Close()

	originalEndpoints := oixCloudEndpoints
	originalKey := C.OIXCloudSubscriptionHMACKey
	oixCloudEndpoints = []string{server.URL + "/primary", server.URL + "/fallback"}
	C.OIXCloudSubscriptionHMACKey = key
	defer func() {
		oixCloudEndpoints = originalEndpoints
		C.OIXCloudSubscriptionHMACKey = originalKey
	}()

	cache := cachefile.New(t.TempDir() + "/cache.db")
	if err := cache.Start(); err != nil {
		t.Fatal(err)
	}
	defer cache.Close()
	ctx := include.Context(context.Background())
	manager := &Manager{ctx: ctx, logger: noopSubscriptionLogger{}, cacheFile: cache, httpClient: *server.Client()}
	subscription := &Subscription{Subscription: serenityOption.Subscription{Name: "managed", URL: "oixcloud://secret-token?feature=all"}}
	if err := manager.update(subscription); err != nil {
		t.Fatal(err)
	}
	if primaryCalls != 1 || fallbackCalls != 1 || len(subscription.Servers) != 1 {
		t.Fatalf("fallback was not used: primary=%d fallback=%d servers=%d", primaryCalls, fallbackCalls, len(subscription.Servers))
	}
	lastUpdated := subscription.LastUpdated
	if saved := cache.LoadSubscription(ctx, subscription.Name); saved == nil {
		t.Fatal("successful refresh did not write the persistent cache")
	}
	failFallback = true
	if err := manager.update(subscription); err == nil {
		t.Fatal("expected failed refresh")
	}
	if !subscription.LastUpdated.Equal(lastUpdated) || len(subscription.Servers) != 1 {
		t.Fatalf("failed refresh replaced valid state: updated=%v servers=%d", subscription.LastUpdated, len(subscription.Servers))
	}
	saved := cache.LoadSubscription(ctx, subscription.Name)
	if saved == nil || saved.LastUpdated.Unix() != lastUpdated.Unix() || len(saved.Content) != 1 {
		t.Fatalf("failed refresh replaced persistent cache: %#v", saved)
	}
}

type noopSubscriptionLogger struct{}

func (noopSubscriptionLogger) Trace(...any) {}
func (noopSubscriptionLogger) Debug(...any) {}
func (noopSubscriptionLogger) Info(...any)  {}
func (noopSubscriptionLogger) Warn(...any)  {}
func (noopSubscriptionLogger) Error(...any) {}
func (noopSubscriptionLogger) Fatal(...any) {}
func (noopSubscriptionLogger) Panic(...any) {}

func TestOIXCloudURLValidationAndRequestRedaction(t *testing.T) {
	parsed, isOIXCloud, err := parseOIXCloudURL("oixcloud://token-value?client=test")
	if err != nil || !isOIXCloud || parsed.Host != "token-value" {
		t.Fatalf("unexpected parse result: parsed=%v oixCloud=%v err=%v", parsed, isOIXCloud, err)
	}
	for _, invalid := range []string{"oixcloud://", "oixcloud://user@token", "oixcloud://token/path", "oixcloud://token#fragment", "oixcloud+file://token"} {
		_, recognized, parseErr := parseOIXCloudURL(invalid)
		if strings.HasPrefix(invalid, "oixcloud://") && (!recognized || parseErr == nil) {
			t.Fatalf("expected invalid oixCloud URL %q", invalid)
		}
		if strings.HasPrefix(invalid, "oixcloud+file:") && (recognized || parseErr != nil) {
			t.Fatalf("oixcloud+file must remain unsupported: %v", parseErr)
		}
	}

	secretURL := "https://api.example.test/path?token=secret-query"
	requestErr := &url.Error{Op: "Get", URL: secretURL, Err: errors.New("connection refused")}
	message := sanitizeOIXCloudRequestError(requestErr).Error()
	if strings.Contains(message, "secret-query") || strings.Contains(message, secretURL) {
		t.Fatalf("request error leaked URL: %q", message)
	}
}

func TestOIXCloudWithoutBuildKeyFailsClearly(t *testing.T) {
	originalKey := C.OIXCloudSubscriptionHMACKey
	C.OIXCloudSubscriptionHMACKey = ""
	defer func() { C.OIXCloudSubscriptionHMACKey = originalKey }()
	manager := &Manager{ctx: context.Background(), logger: noopSubscriptionLogger{}}
	subscription := &Subscription{Subscription: serenityOption.Subscription{Name: "managed", URL: "oixcloud://secret-token"}}
	err := manager.update(subscription)
	if err == nil || !strings.Contains(err.Error(), "OIXCLOUD_SUBSCRIPTION_HMAC_KEY") {
		t.Fatalf("expected explicit missing-key error, got %v", err)
	}
	if strings.Contains(err.Error(), "secret-token") {
		t.Fatalf("missing-key error leaked token: %v", err)
	}
}

func encryptOIXCloudTestConfig(t *testing.T, recipient age.Recipient, plaintext []byte) []byte {
	t.Helper()
	var buffer bytes.Buffer
	armorWriter := armor.NewWriter(&buffer)
	writer, err := age.Encrypt(armorWriter, recipient)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = writer.Write(plaintext); err != nil {
		t.Fatal(err)
	}
	if err = writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err = armorWriter.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}
