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
