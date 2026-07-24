package subscription

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/sagernet/serenity/common/cachefile"
	C "github.com/sagernet/serenity/constant"
	"github.com/sagernet/serenity/subscription/parser"
	E "github.com/sagernet/sing/common/exceptions"

	"github.com/metacubex/age"
	"github.com/metacubex/age/armor"
)

const (
	oixCloudUserAgent     = "FlClash for oixCloud"
	oixCloudResponseLimit = 16 * 1024 * 1024
	oixCloudConfigLimit   = 10 * 1024 * 1024
)

var (
	oixCloudAgeArmorPrefix = []byte("-----BEGIN AGE ENCRYPTED FILE-----")
	oixCloudEndpoints      = []string{
		"https://oics.net/api/v1/managed/flclash/direct",
		"https://oix-api.dler.io/api/v1/managed/flclash/direct",
	}
)

type oixCloudAPIResponse struct {
	Config string `json:"config"`
}

func parseOIXCloudURL(rawURL string) (*url.URL, bool, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, false, E.New("invalid oixCloud subscription URL")
	}
	if !strings.EqualFold(parsed.Scheme, "oixcloud") {
		return nil, false, nil
	}
	if parsed.User != nil || parsed.Host == "" || parsed.Hostname() != parsed.Host || (parsed.Path != "" && parsed.Path != "/") || parsed.Fragment != "" {
		return nil, true, E.New("invalid oixCloud subscription URL")
	}
	return parsed, true, nil
}

func (m *Manager) updateOIXCloud(subscription *Subscription, managedURL *url.URL) error {
	if strings.TrimSpace(C.OIXCloudSubscriptionHMACKey) == "" {
		return E.New("oixCloud subscription support requires OIXCLOUD_SUBSCRIPTION_HMAC_KEY at build time")
	}
	var refreshErr error
	for index, endpoint := range oixCloudEndpoints {
		content, err := fetchOIXCloudConfig(m.ctx, &m.httpClient, endpoint, managedURL.Host, managedURL.RawQuery, C.OIXCloudSubscriptionHMACKey, time.Now())
		if err != nil {
			refreshErr = E.Errors(refreshErr, err)
			if index+1 < len(oixCloudEndpoints) {
				m.logger.Warn("oixCloud primary API failed; trying fallback API")
			}
			continue
		}
		result, parseErr := parser.ParseSubscription(m.ctx, string(content))
		if len(result.Outbounds)+len(result.Endpoints) == 0 {
			refreshErr = E.Errors(refreshErr, E.Cause(parseErr, "parse oixCloud configuration"))
			if index+1 < len(oixCloudEndpoints) {
				m.logger.Warn("oixCloud primary API returned an invalid configuration; trying fallback API")
			}
			continue
		}
		if parseErr != nil {
			m.logger.Warn("oixCloud subscription ", subscription.Name, " contains skipped proxies: ", parseErr)
		}

		// Do not mutate the in-memory or persistent cache until every remote
		// integrity/decryption check and the shared parser have succeeded.
		now := time.Now()
		err = m.cacheFile.StoreSubscription(m.ctx, subscription.Name, &cachefile.Subscription{
			Content: result.Outbounds, Endpoints: result.Endpoints, LastUpdated: now,
		})
		if err != nil {
			return err
		}
		subscription.rawServers = result.Outbounds
		subscription.rawEndpoints = result.Endpoints
		subscription.LastUpdated = now
		subscription.LastEtag = ""
		m.processSubscription(subscription, true)
		m.logger.Info("updated oixCloud subscription ", subscription.Name, ": ", len(result.Outbounds), " outbounds, ", len(result.Endpoints), " endpoints")
		return nil
	}
	return E.Cause(refreshErr, "refresh oixCloud subscription")
}

func fetchOIXCloudConfig(ctx context.Context, client *http.Client, endpoint string, token string, rawQuery string, key string, now time.Time) ([]byte, error) {
	if client == nil {
		return nil, E.New("oixCloud HTTP client is unavailable")
	}
	if strings.TrimSpace(token) == "" {
		return nil, E.New("empty oixCloud token")
	}
	if strings.TrimSpace(key) == "" {
		return nil, E.New("empty oixCloud subscription HMAC key")
	}
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		return nil, E.New("generate oixCloud age identity")
	}
	publicKey := identity.Recipient().String()
	timestamp := strconv.FormatInt(now.Unix(), 10)
	target, err := url.Parse(endpoint)
	if err != nil || target.Scheme != "https" || target.Host == "" {
		return nil, E.New("invalid oixCloud managed configuration endpoint")
	}
	target.RawQuery = rawQuery
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return nil, E.New("create oixCloud request")
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", oixCloudUserAgent)
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("X-Flclash-Timestamp", timestamp)
	request.Header.Set("X-Flclash-Age-Pubkey", publicKey)
	request.Header.Set("X-Flclash-Signature", oixCloudHMAC(key, timestamp+"."+publicKey))

	response, err := client.Do(request)
	if err != nil {
		return nil, sanitizeOIXCloudRequestError(err)
	}
	defer response.Body.Close()
	body, err := readOIXCloudLimited(response.Body, oixCloudResponseLimit)
	if err != nil {
		return nil, E.Cause(err, "read oixCloud response")
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return nil, E.New("oixCloud managed configuration returned HTTP ", response.StatusCode)
	}
	var payload oixCloudAPIResponse
	if err = json.Unmarshal(body, &payload); err != nil {
		return nil, E.New("parse oixCloud response")
	}
	if payload.Config == "" {
		return nil, E.New("oixCloud response has empty configuration")
	}
	responseSignature := strings.TrimSpace(response.Header.Get("X-Flclash-Response-Signature"))
	if responseSignature == "" {
		return nil, E.New("oixCloud response is missing its signature")
	}
	expectedSignature := oixCloudHMAC(key, timestamp+"."+payload.Config)
	if !hmac.Equal([]byte(responseSignature), []byte(expectedSignature)) {
		return nil, E.New("invalid oixCloud response signature")
	}
	ciphertext, err := base64.StdEncoding.DecodeString(payload.Config)
	if err != nil {
		return nil, E.New("decode oixCloud configuration")
	}
	if len(ciphertext) > oixCloudConfigLimit {
		return nil, E.New("oixCloud encrypted configuration exceeds size limit")
	}
	ciphertext = bytes.TrimSpace(ciphertext)
	if !bytes.HasPrefix(ciphertext, oixCloudAgeArmorPrefix) {
		return nil, E.New("oixCloud configuration is not age armored")
	}
	reader, err := age.Decrypt(armor.NewReader(bytes.NewReader(ciphertext)), identity)
	if err != nil {
		return nil, E.New("decrypt oixCloud configuration")
	}
	plaintext, err := readOIXCloudLimited(reader, oixCloudConfigLimit)
	if err != nil {
		return nil, E.Cause(err, "read decrypted oixCloud configuration")
	}
	if len(bytes.TrimSpace(plaintext)) == 0 {
		return nil, E.New("oixCloud configuration is empty")
	}
	return plaintext, nil
}

func sanitizeOIXCloudRequestError(err error) error {
	_ = err
	return E.New("request oixCloud managed configuration failed")
}

func readOIXCloudLimited(reader io.Reader, limit int64) ([]byte, error) {
	content, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(content)) > limit {
		return nil, E.New("content exceeds size limit")
	}
	return content, nil
}

func oixCloudHMAC(key string, message string) string {
	mac := hmac.New(sha256.New, []byte(key))
	_, _ = mac.Write([]byte(message))
	return hex.EncodeToString(mac.Sum(nil))
}
