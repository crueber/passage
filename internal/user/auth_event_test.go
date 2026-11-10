package user_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/crueber/passage/internal/authlog"
)

// listAuthEvents returns every recorded authentication event.
func listAuthEvents(t *testing.T, f *handlerFixture) []*authlog.Event {
	t.Helper()
	events, err := f.authStore.List(context.Background(), authlog.Filter{})
	if err != nil {
		t.Fatalf("list auth events: %v", err)
	}
	return events
}

// postLogin submits the login form with a fixed client address and user agent.
func postLogin(t *testing.T, f *handlerFixture, username, password string) *httptest.ResponseRecorder {
	t.Helper()

	form := url.Values{}
	form.Set("username", username)
	form.Set("password", password)

	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "passage-test-agent")
	req.RemoteAddr = "192.0.2.10:54321"
	rec := httptest.NewRecorder()
	f.handler.PostLogin(rec, req)
	return rec
}

func TestHandler_PostLogin_RecordsAuthEvents(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		setup        func(t *testing.T, f *handlerFixture)
		username     string
		password     string
		wantStatus   int
		wantEvent    string
		wantOutcome  string
		wantUsername string
		wantDetail   string
		wantUserID   bool
	}{
		{
			name: "successful password login",
			setup: func(t *testing.T, f *handlerFixture) {
				t.Helper()
				if _, err := f.userSvc.Register(context.Background(), "alice", "alice@example.com", "password123"); err != nil {
					t.Fatalf("register alice: %v", err)
				}
			},
			username:     "alice",
			password:     "password123",
			wantStatus:   http.StatusFound,
			wantEvent:    authlog.EventLoginSuccess,
			wantOutcome:  authlog.OutcomeSuccess,
			wantUsername: "alice",
			wantDetail:   "password",
			wantUserID:   true,
		},
		{
			name: "wrong password",
			setup: func(t *testing.T, f *handlerFixture) {
				t.Helper()
				if _, err := f.userSvc.Register(context.Background(), "alice", "alice@example.com", "password123"); err != nil {
					t.Fatalf("register alice: %v", err)
				}
			},
			username:     "alice",
			password:     "not-the-password",
			wantStatus:   http.StatusOK,
			wantEvent:    authlog.EventLoginFailure,
			wantOutcome:  authlog.OutcomeFailure,
			wantUsername: "alice",
			wantDetail:   "invalid credentials",
		},
		{
			name:         "unknown username",
			username:     "nobody",
			password:     "password123",
			wantStatus:   http.StatusOK,
			wantEvent:    authlog.EventLoginFailure,
			wantOutcome:  authlog.OutcomeFailure,
			wantUsername: "nobody",
			wantDetail:   "invalid credentials",
		},
		{
			name: "inactive account",
			setup: func(t *testing.T, f *handlerFixture) {
				t.Helper()
				if _, err := f.userSvc.Register(context.Background(), "alice", "alice@example.com", "password123"); err != nil {
					t.Fatalf("register alice: %v", err)
				}
				u, err := f.userStore.GetByUsername(context.Background(), "alice")
				if err != nil {
					t.Fatalf("get alice: %v", err)
				}
				u.IsActive = false
				if err := f.userStore.Update(context.Background(), u); err != nil {
					t.Fatalf("deactivate alice: %v", err)
				}
			},
			username:     "alice",
			password:     "password123",
			wantStatus:   http.StatusOK,
			wantEvent:    authlog.EventLoginFailure,
			wantOutcome:  authlog.OutcomeFailure,
			wantUsername: "alice",
			wantDetail:   "account inactive",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newFullHandlerFixture(t, true)
			if tc.setup != nil {
				tc.setup(t, f)
			}

			rec := postLogin(t, f, tc.username, tc.password)
			if rec.Code != tc.wantStatus {
				t.Fatalf("PostLogin status = %d, want %d", rec.Code, tc.wantStatus)
			}

			events := listAuthEvents(t, f)
			if len(events) != 1 {
				t.Fatalf("got %d auth events, want 1: %+v", len(events), events)
			}
			e := events[0]

			if e.Event != tc.wantEvent {
				t.Errorf("Event = %q, want %q", e.Event, tc.wantEvent)
			}
			if e.Outcome != tc.wantOutcome {
				t.Errorf("Outcome = %q, want %q", e.Outcome, tc.wantOutcome)
			}
			if e.Username != tc.wantUsername {
				t.Errorf("Username = %q, want %q", e.Username, tc.wantUsername)
			}
			if e.Detail != tc.wantDetail {
				t.Errorf("Detail = %q, want %q", e.Detail, tc.wantDetail)
			}
			if tc.wantUserID && e.UserID == "" {
				t.Error("UserID is empty, want the authenticated user's ID")
			}
			if !tc.wantUserID && e.UserID != "" {
				t.Errorf("UserID = %q, want empty", e.UserID)
			}
			if e.IP != "192.0.2.10" {
				t.Errorf("IP = %q, want %q", e.IP, "192.0.2.10")
			}
			if e.UserAgent != "passage-test-agent" {
				t.Errorf("UserAgent = %q, want %q", e.UserAgent, "passage-test-agent")
			}
		})
	}
}

func TestHandler_PostRegister_RecordsRegisterEvent(t *testing.T) {
	t.Parallel()
	f := newFullHandlerFixture(t, true)

	form := url.Values{}
	form.Set("username", "carol")
	form.Set("email", "carol@example.com")
	form.Set("password", "password123")

	req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "192.0.2.11:54321"
	rec := httptest.NewRecorder()
	f.handler.PostRegister(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("PostRegister status = %d, want %d", rec.Code, http.StatusFound)
	}

	events := listAuthEvents(t, f)
	if len(events) != 1 {
		t.Fatalf("got %d auth events, want 1: %+v", len(events), events)
	}
	e := events[0]
	if e.Event != authlog.EventRegisterSuccess || e.Outcome != authlog.OutcomeSuccess {
		t.Errorf("event = %q/%q, want %q/%q", e.Event, e.Outcome, authlog.EventRegisterSuccess, authlog.OutcomeSuccess)
	}
	if e.Username != "carol" {
		t.Errorf("Username = %q, want %q", e.Username, "carol")
	}
	if e.UserID == "" {
		t.Error("UserID is empty, want the new user's ID")
	}
}

func TestHandler_GetLogout_RecordsAuthEvent(t *testing.T) {
	t.Parallel()
	f := newFullHandlerFixture(t, true)

	if _, err := f.userSvc.Register(context.Background(), "dave", "dave@example.com", "password123"); err != nil {
		t.Fatalf("register dave: %v", err)
	}

	loginRec := postLogin(t, f, "dave", "password123")
	if loginRec.Code != http.StatusFound {
		t.Fatalf("login status = %d, want %d", loginRec.Code, http.StatusFound)
	}

	cookies := loginRec.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("login response set no cookies")
	}

	req := httptest.NewRequest(http.MethodGet, "/logout", nil)
	req.AddCookie(cookies[0])
	req.RemoteAddr = "192.0.2.12:54321"
	rec := httptest.NewRecorder()
	f.handler.GetLogout(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("GetLogout status = %d, want %d", rec.Code, http.StatusFound)
	}

	var logout *authlog.Event
	for _, e := range listAuthEvents(t, f) {
		if e.Event == authlog.EventLogout {
			logout = e
		}
	}
	if logout == nil {
		t.Fatal("no logout event recorded")
	}
	if logout.Outcome != authlog.OutcomeSuccess {
		t.Errorf("logout Outcome = %q, want %q", logout.Outcome, authlog.OutcomeSuccess)
	}
}

func TestHandler_GetMagicLinkVerify_RecordsAuthEvents(t *testing.T) {
	t.Parallel()

	t.Run("valid token", func(t *testing.T) {
		t.Parallel()
		h, f := newMagicLinkHandlerFixture(t)

		u, err := f.userSvc.Register(context.Background(), "ml-success", "ml-success@example.com", "password123")
		if err != nil {
			t.Fatalf("register: %v", err)
		}
		tok, err := f.userSvc.CreateMagicLinkToken(context.Background(), u.ID, 15)
		if err != nil {
			t.Fatalf("create token: %v", err)
		}

		req := httptest.NewRequest(http.MethodGet, "/login/magic/verify?token="+tok.Token, nil)
		req.RemoteAddr = "192.0.2.20:54321"
		rec := httptest.NewRecorder()
		h.GetMagicLinkVerify(rec, req)

		if rec.Code != http.StatusFound {
			t.Fatalf("status = %d, want %d", rec.Code, http.StatusFound)
		}

		events := listAuthEvents(t, f)
		if len(events) != 1 {
			t.Fatalf("got %d auth events, want 1", len(events))
		}
		e := events[0]
		if e.Event != authlog.EventMagicLinkLogin || e.Outcome != authlog.OutcomeSuccess {
			t.Errorf("event = %q/%q, want %q/%q", e.Event, e.Outcome, authlog.EventMagicLinkLogin, authlog.OutcomeSuccess)
		}
		if e.Username != "ml-success" {
			t.Errorf("Username = %q, want %q", e.Username, "ml-success")
		}
	})

	t.Run("unknown token", func(t *testing.T) {
		t.Parallel()
		h, f := newMagicLinkHandlerFixture(t)

		req := httptest.NewRequest(http.MethodGet, "/login/magic/verify?token=no-such-token", nil)
		rec := httptest.NewRecorder()
		h.GetMagicLinkVerify(rec, req)

		if rec.Code != http.StatusFound {
			t.Fatalf("status = %d, want %d", rec.Code, http.StatusFound)
		}

		events := listAuthEvents(t, f)
		if len(events) != 1 {
			t.Fatalf("got %d auth events, want 1", len(events))
		}
		e := events[0]
		if e.Event != authlog.EventMagicLinkFailure || e.Outcome != authlog.OutcomeFailure {
			t.Errorf("event = %q/%q, want %q/%q", e.Event, e.Outcome, authlog.EventMagicLinkFailure, authlog.OutcomeFailure)
		}
		if e.Detail != "unknown token" {
			t.Errorf("Detail = %q, want %q", e.Detail, "unknown token")
		}
	})

	t.Run("used token", func(t *testing.T) {
		t.Parallel()
		h, f := newMagicLinkHandlerFixture(t)

		u, err := f.userSvc.Register(context.Background(), "ml-used", "ml-used@example.com", "password123")
		if err != nil {
			t.Fatalf("register: %v", err)
		}
		tok, err := f.userSvc.CreateMagicLinkToken(context.Background(), u.ID, 15)
		if err != nil {
			t.Fatalf("create token: %v", err)
		}

		first := httptest.NewRequest(http.MethodGet, "/login/magic/verify?token="+tok.Token, nil)
		h.GetMagicLinkVerify(httptest.NewRecorder(), first)

		second := httptest.NewRequest(http.MethodGet, "/login/magic/verify?token="+tok.Token, nil)
		h.GetMagicLinkVerify(httptest.NewRecorder(), second)

		var failure *authlog.Event
		for _, e := range listAuthEvents(t, f) {
			if e.Event == authlog.EventMagicLinkFailure {
				failure = e
			}
		}
		if failure == nil {
			t.Fatal("no magic-link failure event recorded")
		}
		if failure.Detail != "token already used" {
			t.Errorf("Detail = %q, want %q", failure.Detail, "token already used")
		}
	})

	t.Run("inactive account", func(t *testing.T) {
		t.Parallel()
		h, f := newMagicLinkHandlerFixture(t)

		u, err := f.userSvc.Register(context.Background(), "ml-inactive", "ml-inactive@example.com", "password123")
		if err != nil {
			t.Fatalf("register: %v", err)
		}
		tok, err := f.userSvc.CreateMagicLinkToken(context.Background(), u.ID, 15)
		if err != nil {
			t.Fatalf("create token: %v", err)
		}

		u.IsActive = false
		if err := f.userStore.Update(context.Background(), u); err != nil {
			t.Fatalf("deactivate: %v", err)
		}

		req := httptest.NewRequest(http.MethodGet, "/login/magic/verify?token="+tok.Token, nil)
		rec := httptest.NewRecorder()
		h.GetMagicLinkVerify(rec, req)

		events := listAuthEvents(t, f)
		if len(events) != 1 {
			t.Fatalf("got %d auth events, want 1", len(events))
		}
		e := events[0]
		if e.Event != authlog.EventMagicLinkFailure || e.Detail != "account inactive" {
			t.Errorf("event = %q/%q, want %q/%q", e.Event, e.Detail, authlog.EventMagicLinkFailure, "account inactive")
		}
		if e.Username != "ml-inactive" {
			t.Errorf("Username = %q, want %q", e.Username, "ml-inactive")
		}
	})
}
