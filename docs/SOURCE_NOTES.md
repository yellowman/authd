# Source notes for the initial scaffold

These notes record the concrete repositories used to shape the starter rather
than leaving important compatibility choices as oral history.

This is a **2026-09-21 source snapshot**, not current deployment guidance.
Application-specific registration and deployment instructions belong in each
application's repository; the current reusable authd contract is in
`docs/APPLICATION_INTEGRATION.md`.

The first relying-party source inspection was BDC Maps on 2026-09-21. Its
application-specific setup and later authorization migration are documented in
the BDC repository. The dated real-app result remains in `VALIDATION.md`.

## yellowman/liminal

The requested top-level `DESIGN_LANGUAGE.md` was not present on the private
`main` branch when inspected on 2026-09-21. The current sources used for the
adaptation were:

```text
docs/LIMINAL_UX_SPEC.md
frontend/src/index.css
```

The initial authd UI does not copy Liminal's application layout literally. It
carries forward the useful family traits—orientation, continuity, thin visual
hierarchy, strong focus treatment, restrained semantic color—and adapts them to
a quieter identity/admin console. `DESIGN_LANGUAGE.md` is the binding authd
version.
