package policy

import (
	"testing"
	"time"
)

// fixedTime returns a time at the given wall clock in UTC, on Monday
// 2026-11-09 (ISO weekday 1) unless dayOffset moves it.
func fixedTime(dayOffset, hour, minute int) time.Time {
	base := time.Date(2026, time.November, 9, hour, minute, 0, 0, time.UTC)
	return base.AddDate(0, 0, dayOffset)
}

func TestEvaluate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		in      Input
		want    bool
		wantWhy string
		wantErr bool
	}{
		{
			name: "empty policy allows",
			in:   Input{Now: fixedTime(0, 12, 0)},
			want: true,
		},
		{
			name: "empty policy allows even with empty client IP",
			in:   Input{ClientIP: "", Now: fixedTime(0, 12, 0)},
			want: true,
		},
		{
			name: "group required and held",
			in: Input{
				Policy:     Policy{RequiredGroup: "platform"},
				UserGroups: []string{"platform", "devs"},
				Now:        fixedTime(0, 12, 0),
			},
			want: true,
		},
		{
			name: "group required and not held",
			in: Input{
				Policy:     Policy{RequiredGroup: "platform"},
				UserGroups: []string{"devs"},
				Now:        fixedTime(0, 12, 0),
			},
			want:    false,
			wantWhy: ReasonGroup,
		},
		{
			name: "group match ignores case and whitespace",
			in: Input{
				Policy:     Policy{RequiredGroup: "  Platform "},
				UserGroups: []string{"platform"},
				Now:        fixedTime(0, 12, 0),
			},
			want: true,
		},
		{
			name: "role required and held",
			in: Input{
				Policy:    Policy{RequiredRole: "ops"},
				UserRoles: []string{"ops"},
				Now:       fixedTime(0, 12, 0),
			},
			want: true,
		},
		{
			name: "role required and not held",
			in: Input{
				Policy:    Policy{RequiredRole: "ops"},
				UserRoles: []string{"viewer"},
				Now:       fixedTime(0, 12, 0),
			},
			want:    false,
			wantWhy: ReasonRole,
		},
		{
			name: "group and role both required both held",
			in: Input{
				Policy:     Policy{RequiredGroup: "platform", RequiredRole: "ops"},
				UserGroups: []string{"platform"},
				UserRoles:  []string{"ops"},
				Now:        fixedTime(0, 12, 0),
			},
			want: true,
		},
		{
			name: "group and role both required role missing",
			in: Input{
				Policy:     Policy{RequiredGroup: "platform", RequiredRole: "ops"},
				UserGroups: []string{"platform"},
				UserRoles:  []string{"viewer"},
				Now:        fixedTime(0, 12, 0),
			},
			want:    false,
			wantWhy: ReasonRole,
		},
		{
			name: "admin groups are not implied",
			in: Input{
				Policy:     Policy{RequiredGroup: "platform"},
				UserGroups: nil,
				IsAdmin:    true,
				Now:        fixedTime(0, 12, 0),
			},
			want:    false,
			wantWhy: ReasonGroup,
		},
		{
			name: "admin only allows admin",
			in: Input{
				Policy:  Policy{AdminOnly: true},
				IsAdmin: true,
				Now:     fixedTime(0, 12, 0),
			},
			want: true,
		},
		{
			name: "admin only denies non-admin",
			in: Input{
				Policy:  Policy{AdminOnly: true},
				IsAdmin: false,
				Now:     fixedTime(0, 12, 0),
			},
			want:    false,
			wantWhy: ReasonAdminOnly,
		},
		{
			name: "admin only still applies other rules to admins",
			in: Input{
				Policy:   Policy{AdminOnly: true, AllowedCIDRs: "10.0.0.0/8"},
				IsAdmin:  true,
				ClientIP: "192.0.2.10",
				Now:      fixedTime(0, 12, 0),
			},
			want:    false,
			wantWhy: ReasonClientIP,
		},
		{
			name: "cidr v4 allowed",
			in: Input{
				Policy:   Policy{AllowedCIDRs: "192.0.2.0/24"},
				ClientIP: "192.0.2.42",
				Now:      fixedTime(0, 12, 0),
			},
			want: true,
		},
		{
			name: "cidr v4 outside",
			in: Input{
				Policy:   Policy{AllowedCIDRs: "192.0.2.0/24"},
				ClientIP: "198.51.100.7",
				Now:      fixedTime(0, 12, 0),
			},
			want:    false,
			wantWhy: ReasonClientIP,
		},
		{
			name: "cidr list with spaces and commas",
			in: Input{
				Policy:   Policy{AllowedCIDRs: " 10.0.0.0/8, 192.168.0.0/16  172.16.0.0/12 "},
				ClientIP: "172.20.1.1",
				Now:      fixedTime(0, 12, 0),
			},
			want: true,
		},
		{
			name: "cidr v6 allowed",
			in: Input{
				Policy:   Policy{AllowedCIDRs: "2001:db8::/32"},
				ClientIP: "2001:db8:1::5",
				Now:      fixedTime(0, 12, 0),
			},
			want: true,
		},
		{
			name: "cidr v6 outside",
			in: Input{
				Policy:   Policy{AllowedCIDRs: "2001:db8::/32"},
				ClientIP: "2001:db9::5",
				Now:      fixedTime(0, 12, 0),
			},
			want:    false,
			wantWhy: ReasonClientIP,
		},
		{
			name: "cidr accepts a client address with port",
			in: Input{
				Policy:   Policy{AllowedCIDRs: "192.0.2.0/24"},
				ClientIP: "192.0.2.42:53122",
				Now:      fixedTime(0, 12, 0),
			},
			want: true,
		},
		{
			name: "cidr with unparseable client address fails closed",
			in: Input{
				Policy:   Policy{AllowedCIDRs: "192.0.2.0/24"},
				ClientIP: "not-an-ip",
				Now:      fixedTime(0, 12, 0),
			},
			wantErr: true,
		},
		{
			name: "cidr with empty client address fails closed",
			in: Input{
				Policy:   Policy{AllowedCIDRs: "192.0.2.0/24"},
				ClientIP: "",
				Now:      fixedTime(0, 12, 0),
			},
			wantErr: true,
		},
		{
			name: "garbage cidr is rejected",
			in: Input{
				Policy:   Policy{AllowedCIDRs: "10.0.0.0/33"},
				ClientIP: "10.0.0.1",
				Now:      fixedTime(0, 12, 0),
			},
			wantErr: true,
		},
		{
			name: "hours inside window",
			in: Input{
				Policy: Policy{AllowedHours: "09:00-17:00"},
				Now:    fixedTime(0, 12, 30),
			},
			want: true,
		},
		{
			name: "hours at start boundary inclusive",
			in: Input{
				Policy: Policy{AllowedHours: "09:00-17:00"},
				Now:    fixedTime(0, 9, 0),
			},
			want: true,
		},
		{
			name: "hours at end boundary inclusive",
			in: Input{
				Policy: Policy{AllowedHours: "09:00-17:00"},
				Now:    fixedTime(0, 17, 0),
			},
			want: true,
		},
		{
			name: "hours before window",
			in: Input{
				Policy: Policy{AllowedHours: "09:00-17:00"},
				Now:    fixedTime(0, 8, 59),
			},
			want:    false,
			wantWhy: ReasonHours,
		},
		{
			name: "hours after window",
			in: Input{
				Policy: Policy{AllowedHours: "09:00-17:00"},
				Now:    fixedTime(0, 17, 1),
			},
			want:    false,
			wantWhy: ReasonHours,
		},
		{
			name: "overnight window late evening",
			in: Input{
				Policy: Policy{AllowedHours: "22:00-06:00"},
				Now:    fixedTime(0, 23, 30),
			},
			want: true,
		},
		{
			name: "overnight window early morning",
			in: Input{
				Policy: Policy{AllowedHours: "22:00-06:00"},
				Now:    fixedTime(0, 5, 59),
			},
			want: true,
		},
		{
			name: "overnight window midday denied",
			in: Input{
				Policy: Policy{AllowedHours: "22:00-06:00"},
				Now:    fixedTime(0, 12, 0),
			},
			want:    false,
			wantWhy: ReasonHours,
		},
		{
			name: "equal hour endpoints mean all day",
			in: Input{
				Policy: Policy{AllowedHours: "00:00-00:00"},
				Now:    fixedTime(0, 13, 37),
			},
			want: true,
		},
		{
			name: "hours evaluated in the supplied location",
			in: Input{
				Policy:   Policy{AllowedHours: "09:00-17:00"},
				Now:      fixedTime(0, 12, 0), // 12:00 UTC
				Location: time.FixedZone("UTC-8", -8*60*60),
			},
			want:    false, // 04:00 local
			wantWhy: ReasonHours,
		},
		{
			name: "day allowed single",
			in: Input{
				Policy: Policy{AllowedDays: "1"},
				Now:    fixedTime(0, 12, 0), // Monday
			},
			want: true,
		},
		{
			name: "day denied single",
			in: Input{
				Policy: Policy{AllowedDays: "2"},
				Now:    fixedTime(0, 12, 0), // Monday
			},
			want:    false,
			wantWhy: ReasonDays,
		},
		{
			name: "day range allows weekday",
			in: Input{
				Policy: Policy{AllowedDays: "1-5"},
				Now:    fixedTime(2, 12, 0), // Wednesday
			},
			want: true,
		},
		{
			name: "day range denies weekend",
			in: Input{
				Policy: Policy{AllowedDays: "1-5"},
				Now:    fixedTime(5, 12, 0), // Saturday
			},
			want:    false,
			wantWhy: ReasonDays,
		},
		{
			name: "sunday is 7",
			in: Input{
				Policy: Policy{AllowedDays: "6,7"},
				Now:    fixedTime(6, 12, 0), // Sunday
			},
			want: true,
		},
		{
			name: "combined rules all pass",
			in: Input{
				Policy: Policy{
					RequiredGroup: "platform",
					RequiredRole:  "ops",
					AllowedCIDRs:  "10.0.0.0/8",
					AllowedHours:  "09:00-17:00",
					AllowedDays:   "1-5",
				},
				UserGroups: []string{"platform"},
				UserRoles:  []string{"ops"},
				ClientIP:   "10.1.2.3",
				Now:        fixedTime(2, 10, 0), // Wednesday 10:00
			},
			want: true,
		},
		{
			name: "combined rules fail on day",
			in: Input{
				Policy: Policy{
					RequiredGroup: "platform",
					AllowedDays:   "1-5",
				},
				UserGroups: []string{"platform"},
				Now:        fixedTime(5, 10, 0), // Saturday
			},
			want:    false,
			wantWhy: ReasonDays,
		},
		{
			name: "garbage hours is rejected",
			in: Input{
				Policy: Policy{AllowedHours: "9am-5pm"},
				Now:    fixedTime(0, 12, 0),
			},
			wantErr: true,
		},
		{
			name: "hours with out-of-range clock is rejected",
			in: Input{
				Policy: Policy{AllowedHours: "24:00-25:00"},
				Now:    fixedTime(0, 12, 0),
			},
			wantErr: true,
		},
		{
			name: "garbage days is rejected",
			in: Input{
				Policy: Policy{AllowedDays: "mon-fri"},
				Now:    fixedTime(0, 12, 0),
			},
			wantErr: true,
		},
		{
			name: "descending day range is rejected",
			in: Input{
				Policy: Policy{AllowedDays: "5-1"},
				Now:    fixedTime(0, 12, 0),
			},
			wantErr: true,
		},
		{
			name: "weekday zero is rejected",
			in: Input{
				Policy: Policy{AllowedDays: "0"},
				Now:    fixedTime(0, 12, 0),
			},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := Evaluate(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("Evaluate() error = nil, want an error (decision %+v)", got)
				}
				if got.Allowed {
					t.Errorf("Evaluate() allowed on error = true, want fail closed")
				}
				return
			}
			if err != nil {
				t.Fatalf("Evaluate() unexpected error: %v", err)
			}
			if got.Allowed != tc.want {
				t.Errorf("Evaluate() allowed = %v, want %v (reason %q)", got.Allowed, tc.want, got.Reason)
			}
			if !tc.want && got.Reason != tc.wantWhy {
				t.Errorf("Evaluate() reason = %q, want %q", got.Reason, tc.wantWhy)
			}
			if tc.want && got.Reason != "" {
				t.Errorf("Evaluate() reason on allow = %q, want empty", got.Reason)
			}
		})
	}
}

func TestIsEmpty(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		p    Policy
		want bool
	}{
		{name: "zero value", p: Policy{}, want: true},
		{name: "whitespace only", p: Policy{RequiredGroup: "  ", AllowedCIDRs: "\t", AllowedDays: "\n"}, want: true},
		{name: "group", p: Policy{RequiredGroup: "platform"}, want: false},
		{name: "role", p: Policy{RequiredRole: "ops"}, want: false},
		{name: "cidrs", p: Policy{AllowedCIDRs: "10.0.0.0/8"}, want: false},
		{name: "admin only", p: Policy{AdminOnly: true}, want: false},
		{name: "hours", p: Policy{AllowedHours: "09:00-17:00"}, want: false},
		{name: "days", p: Policy{AllowedDays: "1-5"}, want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := tc.p.IsEmpty(); got != tc.want {
				t.Errorf("IsEmpty() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestValidate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		p       Policy
		wantErr bool
	}{
		{name: "empty policy is valid", p: Policy{}},
		{name: "group and role are free text", p: Policy{RequiredGroup: "Platform Team", RequiredRole: "ops-admin"}},
		{name: "valid ipv4 cidrs", p: Policy{AllowedCIDRs: "192.0.2.0/24, 10.0.0.0/8"}},
		{name: "valid ipv6 cidr", p: Policy{AllowedCIDRs: "2001:db8::/32"}},
		{name: "invalid cidr", p: Policy{AllowedCIDRs: "192.0.2.1"}, wantErr: true},
		{name: "invalid cidr prefix length", p: Policy{AllowedCIDRs: "10.0.0.0/33"}, wantErr: true},
		{name: "valid hours", p: Policy{AllowedHours: "09:00-17:00"}},
		{name: "valid overnight hours", p: Policy{AllowedHours: "22:30-06:15"}},
		{name: "invalid hours missing dash", p: Policy{AllowedHours: "09:00"}, wantErr: true},
		{name: "invalid hours non-numeric", p: Policy{AllowedHours: "nine-five"}, wantErr: true},
		{name: "invalid hours minute range", p: Policy{AllowedHours: "09:60-17:00"}, wantErr: true},
		{name: "valid days", p: Policy{AllowedDays: "1-5"}},
		{name: "valid days list", p: Policy{AllowedDays: "1,3,5-7"}},
		{name: "invalid day name", p: Policy{AllowedDays: "monday"}, wantErr: true},
		{name: "invalid day number", p: Policy{AllowedDays: "8"}, wantErr: true},
		{name: "multiple invalid fields join", p: Policy{AllowedCIDRs: "x", AllowedDays: "9"}, wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := Validate(tc.p)
			if tc.wantErr && err == nil {
				t.Fatal("Validate() = nil, want an error")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("Validate() = %v, want nil", err)
			}
		})
	}
}
