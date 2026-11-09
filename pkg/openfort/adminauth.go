// AdminGateInterceptor — a reusable Connect interceptor that requires an
// ADMIN_EMAILS-listed caller for a given set of procedures, leaving everything
// else to pass through. Shared by every backend that exposes admin-only
// mutations to the browser (iam-service's Role/Permission gateway,
// asset-management-service's Zone CRUD, and any future one) so the
// caller-identity logic below is written once.
package openfort

import (
	"context"
	"errors"
	"net/http"

	"connectrpc.com/connect"

	"github.com/factory24/everyflow-system/pkg/auth"
)

// AdminGateInterceptor requires an ADMIN_EMAILS-listed caller for any
// procedure in `protected` (keyed by its fully-qualified Connect procedure
// name, e.g. iamv1connect.IamServiceCreateRoleProcedure); everything else
// passes through unauthenticated, matching how reads are already used
// elsewhere (e.g. session resolution). cfg resolves the caller's email when
// their token isn't a JWT this process can decode itself (see
// resolveCallerEmail).
func AdminGateInterceptor(cfg UsersConfig, protected map[string]bool) connect.UnaryInterceptorFunc {
	return connect.UnaryInterceptorFunc(func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			if !protected[req.Spec().Procedure] {
				return next(ctx, req)
			}
			token := auth.BearerToken(req.Header())
			if token == "" {
				return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("missing bearer token"))
			}
			email, err := resolveCallerEmail(ctx, cfg, token)
			if err != nil {
				return nil, connect.NewError(connect.CodeUnauthenticated, err)
			}
			if !auth.IsAdminEmail(email) {
				return nil, connect.NewError(connect.CodePermissionDenied, errors.New("admin only"))
			}
			return next(ctx, req)
		}
	})
}

// resolveCallerEmail tries a local JWT check first — which starts working on
// its own once OPENFORT_JWKS_URL is configured for real verification — and
// falls back to asking Openfort directly who the token belongs to. The
// fallback is what actually fires today: the browser's Openfort access token
// (from the SDK's getAccessToken()) is an opaque session credential, not a
// JWT, so the local check always fails first.
//
// The locally-read email is trusted ONLY when the signature was verified
// (Claims.Verified). Without OPENFORT_JWKS_URL, VerifyOrDecode merely decodes
// the payload, so anyone can mint an unsigned JWT naming an ADMIN_EMAILS
// address; accepting that would let a caller pick the weak path just by
// sending a JWT-shaped token. An unverified token is therefore treated like an
// opaque one and sent to Openfort, which actually authenticates it.
func resolveCallerEmail(ctx context.Context, cfg UsersConfig, token string) (string, error) {
	if claims, err := auth.VerifyOrDecode(ctx, token); err == nil && claims.Verified {
		return claims.Email, nil
	}
	me, err := cfg.WhoAmI(ctx, token)
	if err != nil {
		return "", err
	}
	if me.Email == nil || *me.Email == "" {
		return "", errors.New("openfort: caller has no email on file")
	}
	return *me.Email, nil
}

func AdminGateMiddleware(cfg UsersConfig, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}
		token := auth.BearerToken(r.Header)
		if token == "" {
			http.Error(w, "missing bearer token", http.StatusUnauthorized)
			return
		}
		email, err := resolveCallerEmail(r.Context(), cfg, token)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if !auth.IsAdminEmail(email) {
			http.Error(w, "admin only", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}
