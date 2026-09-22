# authd design language

This UI derives from the Liminal family but is adapted for an identity provider: quieter, denser, more administrative, and less conversational. Authentication screens should feel trustworthy and immediate; administration screens should feel like an operational console rather than a dashboard template.

## Character

The interface is thin, modern, restrained, and legible. Structure comes from alignment, typography, hairlines, section bands, and whitespace—not piles of floating cards.

The user should always be able to answer:

- where they are;
- what object they are editing;
- what security effect an action will have;
- whether a change is saved;
- how to leave or reverse the operation.

## Layout grammar

### Login and account surfaces

Use a narrow centered content column with a small product mark, one strong heading, one short explanatory line, and the form. Do not wrap every field in separate cards.

```text
                 AUTHD

            Sign in
     Continue to BDC Maps

     Username
     ┌───────────────────────┐
     │                       │
     └───────────────────────┘

     Password
     ┌───────────────────────┐
     │                       │
     └───────────────────────┘

     [ Sign in ]
```

When an OIDC request is active, show the client name so the user knows what they are signing into.

### Administration

Desktop administration uses a slim left icon/text rail and one primary work surface.

```text
┌──────────────┬──────────────────────────────────────────────┐
│ authd        │ Users                         + Create user │
│              ├──────────────────────────────────────────────┤
│ Users        │ search / filter                              │
│ Roles        ├──────────────────────────────────────────────┤
│ Permissions  │ alice     enabled    operator   MFA          │
│ Clients      │ bob       enabled    viewer     —            │
│ Sessions     │ ...                                          │
│ Audit        │                                              │
│ Keys         │                                              │
└──────────────┴──────────────────────────────────────────────┘
```

Avoid a dashboard home full of metric cards. The admin landing page should be a compact operational summary and direct links to the objects that need attention.

On small screens the rail becomes a top bar plus a simple navigation drawer.

## Rows before cards

Collections are rows or tables. An object editor is a continuous form divided by section bands. Cards are reserved for objects that truly need independent containment, such as a one-time secret reveal or a destructive confirmation.

Good:

```text
Security
────────────────────────────────────────────────────────────
Enabled                    [ yes ]
Require MFA                [ no  ]
Refresh tokens             [ yes ]
```

Avoid:

```text
[ Enabled card ] [ MFA card ] [ Refresh-token card ]
```

## Typography

Use a modern sans stack without requiring downloaded fonts:

```css
font-family: Inter, ui-sans-serif, system-ui, -apple-system,
             BlinkMacSystemFont, "Segoe UI", sans-serif;
```

Monospace values use:

```css
ui-monospace, "SFMono-Regular", Menlo, Monaco, Consolas, monospace
```

Typical scale:

```text
page title       24px / 600
section title    13px / 650 / slight tracking
body             14px / 400
control           14px / 500
metadata          12px / 450
code/token        12–13px monospace
```

Use weight and spacing before increasing size.

## Surfaces

Light mode defaults:

```text
canvas             #f7f8fa
surface             #ffffff
surface-subtle      #f1f3f5
text                #181b20
text-muted          #66707c
border              #dfe3e8
border-strong       #c8ced6
accent              #1473e6
accent-hover        #0f61c4
success             #16835d
warning             #a76608
danger              #c53b3b
```

Dark mode may be added from the same semantic tokens, but v1 does not need two separate design implementations. If dark mode is implemented, it must preserve the same hierarchy and contrast rather than adding glow effects.

## Borders and radius

Hairlines do most of the separation work.

```text
normal border       1px
focus outline       2px
input radius        6px
button radius       6px
panel radius        8px maximum
```

Do not use giant 16–24px rounded rectangles everywhere.

## Shadows

Default surfaces have no shadow. Use a restrained shadow only for overlays, menus, and modal dialogs that genuinely sit above the page.

No glassmorphism, gradients, neon glow, or decorative blur.

## Color behavior

Color communicates action or state, not decoration.

- blue: primary action, selection, focus, links;
- green: verified/success/enabled where useful;
- amber: attention, expiring key, recovery-code warning;
- red: destructive action, failure, disabled due to error;
- gray: neutral metadata and inactive states.

Never communicate an authorization/security state by color alone. Pair it with text or an icon.

## Controls

Buttons are compact and visually hierarchical.

```text
Primary      filled accent, one per local action group
Secondary    white/subtle surface + border
Ghost        text/transparent for low-priority navigation
Danger       red only for genuinely destructive actions
```

Avoid button-shaped navigation when a text row/tab is clearer.

Inputs use visible labels above controls. Placeholder text is an example, never the label.

Every focusable control uses one global `:focus-visible` outline; individual components do not invent competing focus styles.

## Tables and lists

Admin collections prefer flat rows with:

- a strong primary identifier;
- one short secondary line if needed;
- compact status text;
- right-aligned row actions or an overflow menu.

Table headers are quiet. Zebra striping is unnecessary when hairlines and spacing already separate rows.

## Section bands

Long editors are divided with a thin tinted band or heading line:

```text
Identity
────────────────────────────────────────────────────────────

Access
────────────────────────────────────────────────────────────

Security
────────────────────────────────────────────────────────────
```

A section band means a conceptual boundary, not a container for every handful of fields.

## Security-specific interaction rules

### One-time secrets

Client secrets, recovery codes, bootstrap tokens, and similar values use a distinct one-time reveal surface with explicit copy action and text explaining that the value will not be shown again.

### Destructive actions

Do not use generic "Are you sure?" copy.

Name the consequence:

```text
Disable alice?
This immediately revokes provider sessions and refresh tokens.
Existing access tokens can remain valid until their short expiry.
```

### Permission changes

When editing roles or clients, show permissions as searchable rows/checklists. Do not use a giant multi-select pill cloud.

### Unsaved state

Saved state is explicit. Do not let security-critical forms look saved when they are not.

## Motion

Motion is short and functional:

```text
hover/focus       100–150ms
panel/modal       150–200ms
success state     <= 200ms
```

No bouncing, rotating decoration, or perpetual pulsing on ordinary admin screens. Respect `prefers-reduced-motion`.

## Accessibility

- visible labels for every input;
- keyboard-complete navigation;
- global focus-visible state;
- minimum 3:1 contrast for focus indicators against adjacent surfaces;
- semantic headings and landmarks;
- error text associated with fields;
- status never color-only;
- modals trap focus and restore it to the invoking control;
- destructive actions remain understandable to screen readers without surrounding visual context.

## Implementation rule

The CSS in `internal/web/static/app.css` is the executable source of the starter UI. This document is the behavioral/design contract. New components should first be expressible using existing semantic tokens and row/section grammar; add a new visual primitive only when the old grammar cannot represent the required interaction cleanly.
