package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name      string
		headers   http.Header
		wantKey   string
		wantErr   error
		expectErr bool
	}{
		{
			name:    "valid api key",
			headers: http.Header{"Authorization": []string{"ApiKey my-secret-key"}},
			wantKey: "my-secret-key",
		},
		{
			name:      "no authorization header",
			headers:   http.Header{},
			expectErr: true,
			wantErr:   ErrNoAuthHeaderIncluded,
		},
		{
			name:      "empty authorization value",
			headers:   http.Header{"Authorization": []string{""}},
			expectErr: true,
			wantErr:   ErrNoAuthHeaderIncluded,
		},
		{
			name:      "malformed - only one part",
			headers:   http.Header{"Authorization": []string{"ApiKey"}},
			expectErr: true,
		},
		{
			name:      "malformed - wrong prefix",
			headers:   http.Header{"Authorization": []string{"Bearer my-secret-key"}},
			expectErr: true,
		},
		{
			name:    "extra parts returns first token after prefix",
			headers: http.Header{"Authorization": []string{"ApiKey key with spaces"}},
			wantKey: "key",
		},
	}

	for _, tt := range tests {
		t.Run(t.name, func(t *testing.T) {
			got, err := GetAPIKey(tt.headers)

			if tt.expectErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
					t.Errorf("got error %v, want %v", err, tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.wantKey {
				t.Errorf("got key %q, want %q", got, tt.wantKey)
			}
		})
	}
}
