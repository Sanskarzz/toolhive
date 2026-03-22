// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package validating

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stacklok/toolhive/pkg/auth"
	"github.com/stacklok/toolhive/pkg/mcp"
	"github.com/stacklok/toolhive/pkg/transport/types"
	"github.com/stacklok/toolhive/pkg/webhook"
)

//nolint:paralleltest // Shares a mock HTTP server and lastRequest state
func TestValidatingMiddleware(t *testing.T) {
	// Setup a mock webhook server
	var lastRequest webhook.Request
	mockResponse := webhook.Response{
		Version: webhook.APIVersion,
		UID:     "resp-uid",
		Allowed: true,
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "application/json", r.Header.Get("Content-Type"))

		err := json.NewDecoder(r.Body).Decode(&lastRequest)
		require.NoError(t, err)

		w.Header().Set("Content-Type", "application/json")
		err = json.NewEncoder(w).Encode(mockResponse)
		require.NoError(t, err)
	}))
	defer server.Close()

	// Create middleware handler
	config := []webhook.Config{
		{
			Name:          "test-webhook",
			URL:           server.URL,
			Timeout:       webhook.DefaultTimeout,
			FailurePolicy: webhook.FailurePolicyFail,
			TLSConfig: &webhook.TLSConfig{
				InsecureSkipVerify: true, // Need this for httptest server
			},
		},
	}

	var executors []clientExecutor
	for _, cfg := range config {
		client, err := webhook.NewClient(cfg, webhook.TypeValidating, nil)
		require.NoError(t, err)
		executors = append(executors, clientExecutor{client: client, config: cfg})
	}

	mw := createValidatingHandler(executors, "test-server", "stdio")

	t.Run("Allowed Request", func(t *testing.T) {
		mockResponse.Allowed = true // Server will return allowed

		reqBody := []byte(`{"jsonrpc":"2.0","method":"tools/call","id":1}`)
		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(reqBody))

		// Add parsed MCP request and auth identity to context
		parsedMCP := &mcp.ParsedMCPRequest{
			Method: "tools/call",
			ID:     1,
		}
		ctx := context.WithValue(req.Context(), mcp.MCPRequestContextKey, parsedMCP)

		identity := &auth.Identity{
			Subject: "user-1",
			Email:   "user@example.com",
			Groups:  []string{"admin"},
		}
		ctx = auth.WithIdentity(ctx, identity)

		req = req.WithContext(ctx)
		req.RemoteAddr = "192.168.1.1:1234"

		var nextCalled bool
		nextHandler := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
			nextCalled = true
		})

		rr := httptest.NewRecorder()
		mw(nextHandler).ServeHTTP(rr, req)

		assert.True(t, nextCalled, "Next handler should be called for allowed request")
		assert.Equal(t, http.StatusOK, rr.Code)

		// Verify the payload sent to webhook
		assert.Equal(t, webhook.APIVersion, lastRequest.Version)
		assert.NotEmpty(t, lastRequest.UID)
		assert.NotZero(t, lastRequest.Timestamp)
		assert.JSONEq(t, string(reqBody), string(lastRequest.MCPRequest))

		require.NotNil(t, lastRequest.Context)
		assert.Equal(t, "test-server", lastRequest.Context.ServerName)
		assert.Equal(t, "stdio", lastRequest.Context.Transport)
		assert.Equal(t, "192.168.1.1:1234", lastRequest.Context.SourceIP)

		require.NotNil(t, lastRequest.Principal)
		assert.Equal(t, "user-1", lastRequest.Principal.Sub)
		assert.Equal(t, "user@example.com", lastRequest.Principal.Email)
		assert.Equal(t, []string{"admin"}, lastRequest.Principal.Groups)
	})

	t.Run("Denied Request", func(t *testing.T) {
		mockResponse.Allowed = false
		mockResponse.Message = "Custom deny message"
		mockResponse.Code = http.StatusForbidden

		reqBody := []byte(`{"jsonrpc":"2.0","method":"tools/call","id":1}`)
		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(reqBody))

		ctx := context.WithValue(req.Context(), mcp.MCPRequestContextKey, &mcp.ParsedMCPRequest{})
		req = req.WithContext(ctx)

		var nextCalled bool
		nextHandler := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
			nextCalled = true
		})

		rr := httptest.NewRecorder()
		mw(nextHandler).ServeHTTP(rr, req)

		assert.False(t, nextCalled, "Next handler should not be called for denied request")
		assert.Equal(t, http.StatusForbidden, rr.Code)

		// The error response is a JSON-RPC format
		var errResp map[string]interface{}
		err := json.Unmarshal(rr.Body.Bytes(), &errResp)
		require.NoError(t, err)
		assert.Equal(t, "2.0", errResp["jsonrpc"])
		assert.Nil(t, errResp["id"])

		errObj, ok := errResp["error"].(map[string]interface{})
		require.True(t, ok)
		assert.Equal(t, float64(http.StatusForbidden), errObj["code"])
		assert.Equal(t, "Custom deny message", errObj["message"])
	})

	t.Run("Webhook Error - Fail Policy", func(t *testing.T) {
		// Create a client pointing to a closed port to generate connection error
		cfg := config[0]
		cfg.URL = "http://127.0.0.1:0"
		cfg.FailurePolicy = webhook.FailurePolicyFail

		failClient, err := webhook.NewClient(cfg, webhook.TypeValidating, nil)
		require.NoError(t, err)

		failMw := createValidatingHandler([]clientExecutor{{client: failClient, config: cfg}}, "test", "stdio")

		reqBody := []byte(`{"jsonrpc":"2.0","method":"tools/call","id":1}`)
		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(reqBody))
		ctx := context.WithValue(req.Context(), mcp.MCPRequestContextKey, &mcp.ParsedMCPRequest{})
		req = req.WithContext(ctx)

		var nextCalled bool
		nextHandler := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
			nextCalled = true
		})

		rr := httptest.NewRecorder()
		failMw(nextHandler).ServeHTTP(rr, req)

		assert.False(t, nextCalled, "Next handler should not be called on evaluation error with fail policy")
		assert.Equal(t, http.StatusForbidden, rr.Code)
	})

	t.Run("Webhook Error - Ignore Policy", func(t *testing.T) {
		// Create a client pointing to a closed port to generate connection error
		cfg := config[0]
		cfg.URL = "http://127.0.0.1:0"
		cfg.FailurePolicy = webhook.FailurePolicyIgnore

		ignoreClient, err := webhook.NewClient(cfg, webhook.TypeValidating, nil)
		require.NoError(t, err)

		ignoreMw := createValidatingHandler([]clientExecutor{{client: ignoreClient, config: cfg}}, "test", "stdio")

		reqBody := []byte(`{"jsonrpc":"2.0","method":"tools/call","id":1}`)
		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(reqBody))
		ctx := context.WithValue(req.Context(), mcp.MCPRequestContextKey, &mcp.ParsedMCPRequest{})
		req = req.WithContext(ctx)

		var nextCalled bool
		nextHandler := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
			nextCalled = true
		})

		rr := httptest.NewRecorder()
		ignoreMw(nextHandler).ServeHTTP(rr, req)

		assert.True(t, nextCalled, "Next handler should be called on evaluation error with ignore policy")
		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Skip Non-MCP Requests", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/health", nil)
		// Missing parsed MCP request in context

		var nextCalled bool
		nextHandler := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
			nextCalled = true
		})

		rr := httptest.NewRecorder()
		mw(nextHandler).ServeHTTP(rr, req)

		assert.True(t, nextCalled, "Next handler should be called for non-MCP requests")
		assert.Equal(t, http.StatusOK, rr.Code)
	})
}

func TestMiddlewareParams_Validate(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		params  MiddlewareParams
		wantErr bool
	}{
		{
			name:    "valid",
			params:  MiddlewareParams{Webhooks: []webhook.Config{{Name: "a", URL: "https://a", Timeout: webhook.DefaultTimeout, FailurePolicy: webhook.FailurePolicyFail}}},
			wantErr: false,
		},
		{
			name:    "empty webhooks",
			params:  MiddlewareParams{},
			wantErr: true,
		},
		{
			name:    "invalid webhook config",
			params:  MiddlewareParams{Webhooks: []webhook.Config{{Name: ""}}}, // Missing name
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.params.Validate()
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

type mockRunner struct {
	types.MiddlewareRunner
	middlewares map[string]types.Middleware
}

func (m *mockRunner) AddMiddleware(name string, mw types.Middleware) {
	if m.middlewares == nil {
		m.middlewares = make(map[string]types.Middleware)
	}
	m.middlewares[name] = mw
}

func TestCreateMiddleware(t *testing.T) {
	t.Parallel()
	runner := &mockRunner{}

	// Create valid config JSON
	params := FactoryMiddlewareParams{
		MiddlewareParams: MiddlewareParams{
			Webhooks: []webhook.Config{
				{
					Name:          "test",
					URL:           "https://test.com/hook",
					Timeout:       webhook.DefaultTimeout,
					FailurePolicy: webhook.FailurePolicyIgnore,
				},
			},
		},
		ServerName: "test-server",
		Transport:  "stdio",
	}
	paramsJSON, err := json.Marshal(params)
	require.NoError(t, err)

	mwConfig := &types.MiddlewareConfig{
		Type:       MiddlewareType,
		Parameters: paramsJSON,
	}

	err = CreateMiddleware(mwConfig, runner)
	require.NoError(t, err)

	require.Contains(t, runner.middlewares, MiddlewareType)
	mw := runner.middlewares[MiddlewareType]

	// Test Handler/Close methods to get 100% coverage
	require.NotNil(t, mw.Handler())
	require.NoError(t, mw.Close())
}
