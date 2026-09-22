package requestid

import "context"

type key struct{}

func With(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, key{}, id)
}

func From(ctx context.Context) string {
	value, _ := ctx.Value(key{}).(string)
	return value
}

type clientIPKey struct{}

func WithClientIP(ctx context.Context, ip string) context.Context {
	return context.WithValue(ctx, clientIPKey{}, ip)
}
func ClientIP(ctx context.Context) string { v, _ := ctx.Value(clientIPKey{}).(string); return v }

// ClientIPValue distinguishes an intentionally unknown address from middleware
// not having run. An empty Unix peer address must not trigger a TCP fallback.
func ClientIPValue(ctx context.Context) (string, bool) {
	v, ok := ctx.Value(clientIPKey{}).(string)
	return v, ok
}
