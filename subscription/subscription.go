package subscription

import (
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sagernet/serenity/common/cachefile"
	C "github.com/sagernet/serenity/constant"
	"github.com/sagernet/serenity/option"
	"github.com/sagernet/serenity/subscription/parser"
	boxOption "github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/logger"
)

type Manager struct {
	ctx            context.Context
	cancel         context.CancelFunc
	logger         logger.Logger
	cacheFile      *cachefile.CacheFile
	subscriptions  []*Subscription
	updateInterval time.Duration
	updateTicker   *time.Ticker
	httpClient     http.Client
	basePath       string
}

type Subscription struct {
	option.Subscription
	rawServers   []boxOption.Outbound
	rawEndpoints []boxOption.Endpoint
	processes    []*ProcessOptions
	Servers      []boxOption.Outbound
	Endpoints    []boxOption.Endpoint
	LastUpdated  time.Time
	LastEtag     string
}

func NewSubscriptionManager(ctx context.Context, logger logger.Logger, cacheFile *cachefile.CacheFile, rawSubscriptions []option.Subscription, basePath string) (*Manager, error) {
	var (
		subscriptions []*Subscription
		interval      time.Duration
	)
	for index, subscription := range rawSubscriptions {
		if subscription.Name == "" {
			return nil, E.New("initialize subscription[", index, "]: missing name")
		}
		var processes []*ProcessOptions
		if interval == 0 || time.Duration(subscription.UpdateInterval) < interval {
			interval = time.Duration(subscription.UpdateInterval)
		}
		for processIndex, process := range subscription.Process {
			processOptions, err := NewProcessOptions(process)
			if err != nil {
				return nil, E.Cause(err, "initialize subscription[", subscription.Name, "]: parse process[", processIndex, "]")
			}
			processes = append(processes, processOptions)
		}
		subscriptions = append(subscriptions, &Subscription{
			Subscription: subscription,
			processes:    processes,
		})
	}
	if interval == 0 {
		interval = option.DefaultSubscriptionUpdateInterval
	}
	ctx, cancel := context.WithCancel(ctx)
	return &Manager{
		ctx:            ctx,
		cancel:         cancel,
		logger:         logger,
		cacheFile:      cacheFile,
		subscriptions:  subscriptions,
		updateInterval: interval,
		basePath:       basePath,
	}, nil
}

func (m *Manager) Start() error {
	for _, subscription := range m.subscriptions {
		savedSubscription := m.cacheFile.LoadSubscription(m.ctx, subscription.Name)
		if savedSubscription != nil {
			subscription.rawServers = savedSubscription.Content
			subscription.rawEndpoints = savedSubscription.Endpoints
			subscription.LastUpdated = savedSubscription.LastUpdated
			subscription.LastEtag = savedSubscription.LastEtag
			m.processSubscription(subscription, false)
		}
	}
	return nil
}

func (m *Manager) processSubscription(s *Subscription, onUpdate bool) {
	servers := s.rawServers
	endpoints := s.rawEndpoints
	for _, process := range s.processes {
		renameMap := process.RenameMap(servers, endpoints)
		servers = process.Process(servers)
		endpoints = process.ProcessEndpoints(endpoints)
		RewriteRenamedDetours(servers, endpoints, renameMap)
	}
	if s.DeDuplication {
		originLen := len(servers)
		servers = Deduplication(m.ctx, servers)
		if onUpdate && originLen != len(servers) {
			m.logger.Info("excluded ", originLen-len(servers), " duplicated servers in ", s.Name)
		}
		originEndpointLen := len(endpoints)
		endpoints = DeduplicateEndpoints(endpoints)
		if onUpdate && originEndpointLen != len(endpoints) {
			m.logger.Info("excluded ", originEndpointLen-len(endpoints), " duplicated endpoints in ", s.Name)
		}
	}
	s.Servers = servers
	s.Endpoints = endpoints
}

func (m *Manager) PostStart(headless bool) error {
	m.updateAll()
	if !headless {
		m.updateTicker = time.NewTicker(m.updateInterval)
		go m.loopUpdate()
	}
	return nil
}

func (m *Manager) Close() error {
	if m.updateTicker != nil {
		m.updateTicker.Stop()
	}
	m.cancel()
	m.httpClient.CloseIdleConnections()
	return nil
}

func (m *Manager) Subscriptions() []*Subscription {
	return m.subscriptions
}

func (m *Manager) loopUpdate() {
	for {
		select {
		case <-m.updateTicker.C:
			m.updateAll()
		case <-m.ctx.Done():
			return
		}
	}
}

func (m *Manager) updateAll() {
	for _, subscription := range m.subscriptions {
		if time.Since(subscription.LastUpdated) < m.updateInterval {
			continue
		}
		err := m.update(subscription)
		if err != nil {
			m.logger.Error(E.Cause(err, "update subscription ", subscription.Name))
		}
	}
}

func (m *Manager) update(subscription *Subscription) error {
	managedURL, isOIXCloud, err := parseOIXCloudURL(subscription.URL)
	if err != nil {
		return err
	}
	if isOIXCloud {
		return m.updateOIXCloud(subscription, managedURL)
	}
	// Check if URL is a local file path
	if isLocalFile(subscription.URL) {
		return m.updateFromFile(subscription)
	}

	request, err := http.NewRequest("GET", subscription.URL, nil)
	if err != nil {
		return err
	}
	if subscription.UserAgent != "" {
		request.Header.Set("User-Agent", subscription.UserAgent)
	} else {
		request.Header.Set("User-Agent", F.ToString("serenity/", C.Version, " (sing-box ", C.CoreVersion(), "; Clash compatible)"))
	}
	if subscription.LastEtag != "" {
		request.Header.Set("If-None-Match", subscription.LastEtag)
	}
	response, err := m.httpClient.Do(request.WithContext(m.ctx))
	if err != nil {
		return err
	}
	switch response.StatusCode {
	case http.StatusOK:
	case http.StatusNotModified:
		subscription.LastUpdated = time.Now()
		err = m.cacheFile.StoreSubscription(m.ctx, subscription.Name, &cachefile.Subscription{
			Content:     subscription.rawServers,
			Endpoints:   subscription.rawEndpoints,
			LastUpdated: subscription.LastUpdated,
			LastEtag:    subscription.LastEtag,
		})
		if err != nil {
			return err
		}
		m.logger.Info("updated subscription ", subscription.Name, ": not modified")
		return nil
	default:
		return E.New("unexpected status: ", response.Status)
	}
	content, err := io.ReadAll(response.Body)
	if err != nil {
		response.Body.Close()
		return err
	}
	response.Body.Close()
	result, err := parser.ParseSubscription(m.ctx, string(content))
	if err != nil && len(result.Outbounds)+len(result.Endpoints) == 0 {
		return err
	}
	if err != nil {
		m.logger.Warn("subscription ", subscription.Name, " contains skipped proxies: ", err)
	}
	subscription.rawServers = result.Outbounds
	subscription.rawEndpoints = result.Endpoints
	m.processSubscription(subscription, true)
	eTagHeader := response.Header.Get("Etag")
	if eTagHeader != "" {
		subscription.LastEtag = eTagHeader
	}
	subscription.LastUpdated = time.Now()
	err = m.cacheFile.StoreSubscription(m.ctx, subscription.Name, &cachefile.Subscription{
		Content:     subscription.rawServers,
		Endpoints:   subscription.rawEndpoints,
		LastUpdated: subscription.LastUpdated,
		LastEtag:    subscription.LastEtag,
	})
	if err != nil {
		return err
	}
	m.logger.Info("updated subscription ", subscription.Name, ": ", len(subscription.rawServers), " outbounds, ", len(subscription.rawEndpoints), " endpoints")
	return nil
}

// isLocalFile checks if the URL is a local file path
func isLocalFile(url string) bool {
	return strings.HasPrefix(url, "file://") ||
		(!strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://"))
}

// updateFromFile updates subscription from a local file
func (m *Manager) updateFromFile(subscription *Subscription) error {
	filePath := subscription.URL
	// Remove file:// prefix if present
	filePath = strings.TrimPrefix(filePath, "file://")

	// If it's a relative path, resolve it relative to the config file directory
	if !filepath.IsAbs(filePath) && m.basePath != "" {
		filePath = filepath.Join(m.basePath, filePath)
	}

	// Read file content
	content, err := os.ReadFile(filePath)
	if err != nil {
		return E.Cause(err, "read file")
	}

	// Parse subscription content
	result, err := parser.ParseSubscription(m.ctx, string(content))
	if err != nil && len(result.Outbounds)+len(result.Endpoints) == 0 {
		return E.Cause(err, "parse subscription")
	}
	if err != nil {
		m.logger.Warn("subscription ", subscription.Name, " contains skipped proxies: ", err)
	}

	subscription.rawServers = result.Outbounds
	subscription.rawEndpoints = result.Endpoints
	m.processSubscription(subscription, true)
	subscription.LastUpdated = time.Now()

	// Store to cache
	err = m.cacheFile.StoreSubscription(m.ctx, subscription.Name, &cachefile.Subscription{
		Content:     subscription.rawServers,
		Endpoints:   subscription.rawEndpoints,
		LastUpdated: subscription.LastUpdated,
		LastEtag:    "",
	})
	if err != nil {
		return err
	}

	m.logger.Info("updated subscription ", subscription.Name, " from file: ", len(subscription.rawServers), " outbounds, ", len(subscription.rawEndpoints), " endpoints")
	return nil
}
