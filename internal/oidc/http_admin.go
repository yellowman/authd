package oidc

import (
	"context"

	"github.com/yellowman/authd/internal/identity"
)

func (h *HTTP) AdminClients(ctx context.Context, actorRaw string) ([]Client, error) {
	if h == nil || h.service == nil {
		return nil, identity.ErrUnavailable
	}
	return h.service.AdminClients(ctx, actorRaw)
}
func (h *HTTP) CreateClient(ctx context.Context, actorRaw string, edit ClientEdit, a identity.Audit) (Client, string, error) {
	if h == nil || h.service == nil {
		return Client{}, "", identity.ErrUnavailable
	}
	return h.service.CreateClient(ctx, actorRaw, edit, a)
}
func (h *HTTP) UpdateClient(ctx context.Context, actorRaw string, edit ClientEdit, a identity.Audit) error {
	if h == nil || h.service == nil {
		return identity.ErrUnavailable
	}
	return h.service.UpdateClient(ctx, actorRaw, edit, a)
}
func (h *HTTP) RotateClientSecret(ctx context.Context, actorRaw, id string, a identity.Audit) (string, error) {
	if h == nil || h.service == nil {
		return "", identity.ErrUnavailable
	}
	return h.service.RotateClientSecret(ctx, actorRaw, id, a)
}
