package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name       string
		headers    http.Header
		wantKey    string
		wantErr    bool
		wantErrMsg string
	}{
		{
			name:       "no authorization header",
			headers:    http.Header{},
			wantKey:    "",
			wantErr:    true,
			wantErrMsg: "no authorization header included",
		},
		{
			name:       "empty authorization header",
			headers:    http.Header{"Authorization": {""}},
			wantKey:    "",
			wantErr:    true,
			wantErrMsg: "no authorization header included",
		},
		{
			name:       "malformed header - missing scheme",
			headers:    http.Header{"Authorization": {"just-a-token"}},
			wantKey:    "",
			wantErr:    true,
			wantErrMsg: "malformed authorization header",
		},
		{
			name:       "malformed header - wrong scheme",
			headers:    http.Header{"Authorization": {"Bearer my-token"}},
			wantKey:    "",
			wantErr:    true,
			wantErrMsg: "malformed authorization header",
		},
		{
			name:    "valid ApiKey header",
			headers: http.Header{"Authorization": {"ApiKey my-secret-key"}},
			wantKey: "my-secret-key",
			wantErr: false,
		},
		{
			name:    "valid ApiKey with extra spaces in value",
			headers: http.Header{"Authorization": {"ApiKey key part2"}},
			wantKey: "key",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotKey, err := GetAPIKey(tt.headers)

			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error but got none")
				}
				if err.Error() != tt.wantErrMsg {
					t.Fatalf("expected error %q, got %q", tt.wantErrMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			}

			if gotKey != tt.wantKey {
				t.Fatalf("expected key %q, got %q", tt.wantKey, gotKey)
			}
		})
	}
}
