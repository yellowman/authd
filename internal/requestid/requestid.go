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
