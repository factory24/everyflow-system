package auth

import (
	"context"

	"connectrpc.com/connect"
)

// ClientInterceptor attaches credentials to OUTBOUND Connect calls.
//
// Order matters and is deliberate:
//
//  1. If the caller's context carries a user's token (propagated from an inbound
//     request), forward THAT — the downstream then authorizes as the human, which
//     is what per-user rules like "sponsor sees only their own pools" need.
//  2. Otherwise fall back to this service's own identity token, for calls with no
//     user behind them (cron, startup reconciliation, fan-out).
//
// Getting this backwards is the classic confused-deputy bug: a service that always
// presents its own powerful identity will happily perform an action the requesting
// user was never allowed to perform.
func ClientInterceptor() connect.UnaryInterceptorFunc {
	return connect.UnaryInterceptorFunc(func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			// Never overwrite a header the caller set explicitly.
			if req.Header().Get("Authorization") == "" {
				if tok, ok := TokenFromContext(ctx); ok && tok != "" {
					req.Header().Set("Authorization", "Bearer "+tok)
				} else if tok, err := ServiceToken(); err == nil && tok != "" {
					req.Header().Set("Authorization", "Bearer "+tok)
				}
				// If neither is available we send nothing rather than failing here:
				// the downstream decides, via AUTH_REQUIRE_TOKEN, whether an
				// anonymous call is acceptable. That keeps demo mode working.
			}
			return next(ctx, req)
		}
	})
}

type rawTokenKey struct{}

// NewTokenContext stores the raw inbound bearer token so outbound calls made while
// handling this request can forward the user's identity downstream.
func NewTokenContext(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, rawTokenKey{}, token)
}

// TokenFromContext returns the raw inbound token, if one was propagated.
func TokenFromContext(ctx context.Context) (string, bool) {
	t, ok := ctx.Value(rawTokenKey{}).(string)
	return t, ok
}
