# First complete application integration: bdcmaps

**Result: PASS — full end-to-end login through the actual BDC Maps application.**
Reported by the operator on 2026-09-22, after the v0.9.3 delivery.

The operator reported:

> well we verified full bdcmaps login. worky worky.

This establishes that one real relying application completed its OIDC login with
authd. It is not merely a provider-side token test or an in-memory BDC-shaped
fixture. The actual application callback/login is no longer an outstanding
unexercised first-app gate.

No raw test log or exact deployed commit was supplied with this confirmation.
The report does not enumerate every role, MFA path, refresh failure, logout,
proxy-hardening setting or deployment recovery scenario. Those checks are not
inferred from a successful application login. The named `maps.ykwc.com`
deployment was discussed earlier, but this confirmation does not independently
repeat the hostname or certify its entire infrastructure configuration.

This is application-integration evidence, not OpenID certification, a complete
protocol conformance result, or a test of every future client. It is recorded in
the v0.9.4 validation summary without claiming the new documentation UI was on the
host during that test.
