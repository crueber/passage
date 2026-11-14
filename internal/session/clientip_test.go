package session

import "testing"

func TestClientIP(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		want string
	}{
		{"ipv4 with port", "192.168.1.24:54321", "192.168.1.24"},
		{"ipv6 with port", "[2001:db8::1]:443", "2001:db8::1"},
		{"bare ipv4", "192.168.1.24", "192.168.1.24"},
		{"bare ipv6", "2001:db8::1", "2001:db8::1"},
		{"empty", "", ""},
		{"garbage", "not-an-address", "not-an-address"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := clientIP(tt.in); got != tt.want {
				t.Errorf("clientIP(%q) = %q; want %q", tt.in, got, tt.want)
			}
		})
	}
}
