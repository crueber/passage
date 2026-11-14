package authlog

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sync"
	"time"
)

const (
	// webhookQueueSize is how many events may wait for delivery before new ones
	// are dropped. It is deliberately small: the webhook is an alerting side
	// channel, and a backlog is a sign the endpoint is unhealthy.
	webhookQueueSize = 256

	// webhookSignatureHeader carries the HMAC of the request body when a
	// secret is configured.
	webhookSignatureHeader = "X-Passage-Signature"

	// webhookUserAgent identifies Passage in the receiver's logs.
	webhookUserAgent = "passage-security-webhook/1"

	// maxWebhookResponseBytes bounds how much of a response body is read and
	// discarded. A receiver that streams an endless body must not be able to
	// pin the worker.
	maxWebhookResponseBytes = 4 << 10
)

// webhookPayload is the complete JSON body sent to the endpoint. Keep it
// small: a receiver sees exactly these fields and nothing else. There is no
// token, password, session identifier, or CSRF value here, and none may be
// added — the webhook crosses a machine boundary.
type webhookPayload struct {
	Event     string `json:"event"`
	Outcome   string `json:"outcome"`
	Username  string `json:"username"`
	UserID    string `json:"user_id"`
	IP        string `json:"ip"`
	UserAgent string `json:"user_agent"`
	Detail    string `json:"detail"`
	CreatedAt string `json:"created_at"`
}

// WebhookConfig is resolved per delivery so a URL, secret or timeout changed in
// the admin UI applies without restarting the process.
type WebhookConfig struct {
	Endpoint string
	Secret   string
	Timeout  time.Duration
}

// WebhookConfigFunc supplies the current webhook configuration. It is called
// on the delivery worker, never on the request path.
type WebhookConfigFunc func(ctx context.Context) WebhookConfig

// WebhookNotifier delivers recorded authentication events to an HTTP endpoint
// as JSON, optionally HMAC-SHA256 signed. It is the optional second sink on the
// Recorder: the SQLite store is authoritative and always written first.
//
// Delivery is asynchronous and at-most-once. Notify never blocks the caller;
// when the queue is full the event is dropped with a warning. There is no
// retry queue and no persistence, so a webhook is an alerting aid, not an
// audit trail — the auth event log remains the source of truth. A dead or
// hanging endpoint can therefore never slow down or fail an authentication.
type WebhookNotifier struct {
	url      string
	secret   string
	timeout  time.Duration
	provider WebhookConfigFunc // optional; takes precedence when set
	client   *http.Client
	logger   *slog.Logger

	events chan Event

	mu      sync.Mutex
	started bool
	cancel  context.CancelFunc
	done    chan struct{}
}

// NewWebhookNotifier validates endpoint and returns a notifier that will POST
// events to it. secret is optional; when non-empty each request body is signed
// with HMAC-SHA256 under it. timeout bounds one delivery attempt.
//
// The returned notifier does nothing until Start is called.
func NewWebhookNotifier(endpoint, secret string, timeout time.Duration, logger *slog.Logger, providers ...WebhookConfigFunc) (*WebhookNotifier, error) {
	var provider WebhookConfigFunc
	if len(providers) > 0 {
		provider = providers[0]
	}
	if provider == nil {
		if err := validateWebhookEndpoint(endpoint); err != nil {
			return nil, err
		}
		if timeout <= 0 {
			return nil, fmt.Errorf("authlog webhook: timeout must be positive, got %s", timeout)
		}
	}
	if logger == nil {
		logger = slog.Default()
	}

	return &WebhookNotifier{
		url:      endpoint,
		secret:   secret,
		timeout:  timeout,
		provider: provider,
		client: &http.Client{
			// A webhook endpoint must answer where the operator pointed it.
			// Following a redirect would send events — and the signature —
			// to a host that was never configured.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		logger: logger,
		events: make(chan Event, webhookQueueSize),
		done:   make(chan struct{}),
	}, nil
}

func validateWebhookEndpoint(endpoint string) error {
	u, err := url.Parse(endpoint)
	if err != nil {
		return fmt.Errorf("authlog webhook: parse endpoint: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("authlog webhook: endpoint scheme must be http or https, got %q", u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("authlog webhook: endpoint %q has no host", endpoint)
	}
	return nil
}

// Start launches the single delivery worker on ctx and returns immediately.
// Cancelling ctx, or calling Close, stops the worker; events still queued at
// that point are discarded. Start must be called at most once, before Close.
func (w *WebhookNotifier) Start(ctx context.Context) {
	w.mu.Lock()
	if w.started {
		w.mu.Unlock()
		return
	}
	w.started = true
	ctx, w.cancel = context.WithCancel(ctx)
	w.mu.Unlock()

	go w.run(ctx)
}

// Close stops the worker and waits for it to return. It is safe to call when
// Start was never called, and safe to call more than once.
func (w *WebhookNotifier) Close() {
	w.mu.Lock()
	started, cancel := w.started, w.cancel
	w.mu.Unlock()

	if !started {
		return
	}
	cancel()
	<-w.done
}

// Notify hands e to the delivery worker without blocking. It never returns an
// error: a full queue drops the event and logs one warning.
func (w *WebhookNotifier) Notify(e Event) {
	select {
	case w.events <- e:
	default:
		w.logger.Warn("authlog webhook: queue full, dropping event",
			"event", e.Event,
			"outcome", e.Outcome,
			"queue_size", webhookQueueSize,
		)
	}
}

// run is the delivery worker. It exits when ctx is cancelled, abandoning any
// events still queued (at-most-once, no persistence).
func (w *WebhookNotifier) run(ctx context.Context) {
	defer close(w.done)

	for {
		if ctx.Err() != nil {
			return
		}
		select {
		case <-ctx.Done():
			return
		case e := <-w.events:
			w.deliver(ctx, e)
		}
	}
}

// deliver makes one POST attempt. Failures are logged, never returned: the
// worker has nowhere to retry to.
func (w *WebhookNotifier) deliver(ctx context.Context, e Event) {
	endpoint, secret, timeout := w.url, w.secret, w.timeout
	if w.provider != nil {
		cfg := w.provider(ctx)
		endpoint, secret, timeout = cfg.Endpoint, cfg.Secret, cfg.Timeout
	}
	if endpoint == "" {
		return
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	if err := validateWebhookEndpoint(endpoint); err != nil {
		w.logger.Warn("authlog webhook: invalid endpoint", "event", e.Event, "error", err)
		return
	}

	body, err := json.Marshal(webhookPayload{
		Event:     e.Event,
		Outcome:   e.Outcome,
		Username:  e.Username,
		UserID:    e.UserID,
		IP:        e.IP,
		UserAgent: e.UserAgent,
		Detail:    e.Detail,
		CreatedAt: e.CreatedAt.UTC().Format(time.RFC3339),
	})
	if err != nil {
		w.logger.Warn("authlog webhook: encode payload", "event", e.Event, "error", err)
		return
	}

	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		w.logger.Warn("authlog webhook: build request", "event", e.Event, "error", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", webhookUserAgent)
	if secret != "" {
		req.Header.Set(webhookSignatureHeader, signBody(secret, body))
	}

	resp, err := w.client.Do(req)
	if err != nil {
		w.logger.Warn("authlog webhook: delivery failed",
			"event", e.Event,
			"outcome", e.Outcome,
			"error", err,
		)
		return
	}
	defer resp.Body.Close()

	// Drain a bounded amount so the connection can be reused, then classify.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxWebhookResponseBytes))
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		w.logger.Warn("authlog webhook: endpoint returned non-2xx",
			"event", e.Event,
			"outcome", e.Outcome,
			"status", resp.StatusCode,
		)
	}
}

// signBody returns "sha256=<hex>" for body under secret.
func signBody(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}
