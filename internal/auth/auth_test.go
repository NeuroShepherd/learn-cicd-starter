package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	cases := []struct {
		headers       http.Header
		expectedKey   string
		expectedError error
	}{
		{
			headers:       http.Header{},
			expectedKey:   "",
			expectedError: ErrNoAuthHeaderIncluded,
		},
		{
			headers:       http.Header{"Authorization": []string{"Bearer sometoken"}},
			expectedKey:   "",
			expectedError: errors.New("malformed authorization header"),
		},
		{
			headers:       http.Header{"Authorization": []string{"ApiKey"}},
			expectedKey:   "",
			expectedError: errors.New("malformed authorization header"),
		},
		{
			headers:       http.Header{"Authorization": []string{"ApiKey mysecretkey"}},
			expectedKey:   "mysecretkey",
			expectedError: nil,
		},
	}

	for _, c := range cases {
		actualKey, actualError := GetAPIKey(c.headers)
		if actualKey != c.expectedKey {
			t.Errorf("GetAPIKey(%v) returned key '%v', expected '%v'", c.headers, actualKey, c.expectedKey)
		}
		if (actualError == nil) != (c.expectedError == nil) || (actualError != nil && actualError.Error() != c.expectedError.Error()) {
			t.Errorf("GetAPIKey(%v) returned error '%v', expected '%v'", c.headers, actualError, c.expectedError)
		}
	}
}
