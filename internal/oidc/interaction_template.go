package oidc

import "html/template"

var interactionTemplate = template.Must(template.New("interaction").Parse(`
{{define "scope-node"}}
  {{range .}}
    {{if .Children}}
      <details class="permission-branch">
        <summary><code>{{.Label}}</code> <span class="muted small">{{.Count}} scopes</span></summary>
        <div class="permission-children">
          {{if .Scope}}{{template "scope-leaf" .}}{{end}}
          {{template "scope-node" .Children}}
        </div>
      </details>
    {{else if .Scope}}{{template "scope-leaf" .}}{{end}}
  {{end}}
{{end}}
{{define "scope-leaf"}}<div class="permission-leaf consent-scope-row"><code>{{.Scope}}</code>{{if .Description}}<span class="muted">{{.Description}}</span>{{end}}</div>{{end}}
{{define "claim-list"}}<div class="consent-claims"><h4>Additional identity fields</h4>{{range .}}<div class="permission-leaf consent-scope-row"><code>{{.}}</code></div>{{end}}</div>{{end}}
<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{{.Title}} · authd</title><link rel="stylesheet" href="/static/app.css"></head>
<body class="auth-page">
<main class="{{if .Consent}}consent-frame{{else}}auth-frame{{end}}">
  <section class="auth-brand"><div class="mark" aria-hidden="true">A</div><div><h1>authd</h1></div></section>
  <section class="{{if .Consent}}consent-panel{{else}}auth-panel{{end}}">
    <div class="section-rule"></div><h2>{{.Title}}</h2>
    <p>{{.Description}}</p><p class="consent-application"><strong>{{.ClientName}}</strong>{{if .Username}} · {{.Username}}{{end}}</p>
    {{if .Consent}}
      <p class="field-help">Application permissions are limited by your roles. Approving this request does not grant you new roles.</p>
      {{if .Consent.HasPrior}}
        {{if not .Consent.HasChanges}}<p class="message" role="status">No access changes. This request matches your previous approval.</p>{{end}}
      {{else}}<p class="field-help">No previous approval is recorded for this application. Review this first request.</p>{{end}}

      <section class="consent-section" aria-labelledby="new-access">
        <div class="section-heading"><h3 id="new-access">New access</h3><span class="muted small">{{.Consent.NewCount}} items</span></div>
        {{if .Consent.NewCount}}
          <div class="permission-tree">{{template "scope-node" .Consent.NewScopes}}{{if .Consent.NewClaims}}{{template "claim-list" .Consent.NewClaims}}{{end}}</div>
        {{else}}<p class="field-help">No additional access requested.</p>{{end}}
      </section>

      {{if .Consent.HasPrior}}
        <details class="consent-section consent-history">
          <summary>Previously approved <span class="muted small">{{.Consent.ApprovedCount}} items requested again</span></summary>
          <p class="field-help">Last approved {{.Consent.ApprovedAt}}. Your current roles and the application's settings still limit access.</p>
          <div class="permission-tree">{{template "scope-node" .Consent.ApprovedScopes}}{{if .Consent.ApprovedClaims}}{{template "claim-list" .Consent.ApprovedClaims}}{{end}}</div>
          {{if not .Consent.ApprovedCount}}<p class="field-help">None of the previously approved access is requested this time.</p>{{end}}
        </details>
      {{end}}

      {{if .Consent.NotRequestedCount}}
        <details class="consent-section consent-history">
          <summary>Not requested this time <span class="muted small">{{.Consent.NotRequestedCount}} items</span></summary>
          <p class="field-help">This request omits these previously approved items. Existing tokens are not revoked by this change.</p>
          <div class="permission-tree">{{template "scope-node" .Consent.NotRequestedScopes}}{{if .Consent.NotRequestedClaims}}{{template "claim-list" .Consent.NotRequestedClaims}}{{end}}</div>
        </details>
      {{end}}
    {{end}}
    {{if .Offline}}<p class="message">Offline access allows this application to renew access while you are not present, until expiry or revocation. Revoking the associated provider session also revokes its refresh grants.</p>{{end}}
    <form method="post" action="{{.Action}}" class="{{if .Consent}}consent-actions{{else}}stack-lg{{end}}">
      <input type="hidden" name="csrf_token" value="{{.CSRF}}">
      {{if .Flow}}<input type="hidden" name="flow" value="{{.Flow}}">{{end}}
      {{range $name,$value := .Fields}}<input type="hidden" name="{{$name}}" value="{{$value}}">{{end}}
      <button name="decision" value="allow" class="button button-primary">{{if .Consent}}Allow and continue{{else}}Sign out of authd{{end}}</button>
      <button name="decision" value="deny" class="button">Cancel</button>
    </form>
  </section>
</main>
</body></html>`))
