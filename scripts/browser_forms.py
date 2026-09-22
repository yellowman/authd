#!/usr/bin/env python3
"""Native form/guide witnesses using actual Go handlers and synthetic stores.

Invoked by the Go browser-tag tests with a private test-only JSON manifest. No
production endpoint, credential, database or third-party IdP is accepted here.
"""
import json
import os
from pathlib import Path
import shutil
import sys
import ssl
import urllib.request
from urllib.parse import urlsplit

from playwright.sync_api import sync_playwright


def run(manifest: dict[str, str]) -> None:
    origin = manifest["origin"]
    if urlsplit(origin).scheme != "https" or urlsplit(origin).hostname != "127.0.0.1":
        raise ValueError("browser fixture must be a loopback HTTPS test server")
    records = []
    output = Path(manifest["output"]) if manifest.get("output") else None
    if output:
        output.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as p:
        executable = os.environ.get("AUTHD_CHROMIUM_PATH") or shutil.which("chromium") or shutil.which("chromium-browser")
        kwargs = {"headless": True}
        if executable:
            kwargs["executable_path"] = executable
        with p.chromium.launch(**kwargs) as browser:
            context = browser.new_context(ignore_https_errors=True, viewport={"width": 1440, "height": 1000})
            page = context.new_page()
            page.set_default_timeout(10000)

            def submit(path: str, selector: str, status: int, expected_origin: str | None = None) -> None:
                with page.expect_response(lambda r: r.request.method == "POST" and urlsplit(r.url).path == path) as event:
                    page.locator(selector).click()
                response = event.value
                headers = response.request.all_headers()
                actual = {"path": path, "status": response.status, "origin": headers.get("origin"), "referer": headers.get("referer")}
                records.append(actual)
                print(json.dumps(actual), flush=True)
                assert response.status == status, f"native POST {path}: expected {status}, got {response.status} (Origin={headers.get('origin')!r})"
                assert headers.get("origin") == (expected_origin or origin), "browser did not preserve the expected Origin"
                if expected_origin is None:
                    assert headers.get("referer") == origin + "/", "Referer disclosed a path/query or was not origin-only"
                page.wait_for_load_state("domcontentloaded")

            def viewport_check(name: str, full_page: bool = True) -> None:
                page.evaluate("document.fonts.ready")
                assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth"), f"document overflow: {name}"
                if output:
                    page.screenshot(path=str(output / f"{name}.png"), full_page=full_page)

            def use_admin_session() -> None:
                context.add_cookies([{"name": "__Host-authd_session", "value": manifest["session"], "url": origin, "httpOnly": True, "secure": True, "sameSite": "Lax"}])

            if manifest["scenario"] == "layout":
                # Layout-only witness: fetch loopback fixture HTML in Python,
                # render it in memory, and inject its actual CSS. No browser
                # navigation or browser-authentication claim is made in this mode.
                tls = ssl._create_unverified_context()
                def source(path: str) -> str:
                    req = urllib.request.Request(origin + path, headers={"Cookie": "__Host-authd_session=" + manifest["session"]})
                    with urllib.request.urlopen(req, context=tls, timeout=10) as response:
                        return response.read().decode("utf-8")
                css = source("/static/app.css")
                pages = 0
                def assert_rail() -> None:
                    assert page.locator(".rail-nav a[aria-current='page']").count() == 1
                    links = page.locator(".rail a")
                    assert links.count() == 11
                    for i in range(links.count()):
                        link = links.nth(i)
                        assert link.locator("svg[aria-hidden='true'][focusable='false']").count() == 1
                        assert link.get_attribute("aria-label")
                        assert link.inner_text().strip() == "", "letter icon remains"
                        styles = link.evaluate("e => { const s=getComputedStyle(e); return [s.backgroundColor,s.backgroundImage,s.boxShadow] }")
                        assert styles == ["rgba(0, 0, 0, 0)", "none", "none"], styles
                    active = page.locator(".rail-nav a[aria-current='page']")
                    active.hover()
                    assert active.evaluate("e => getComputedStyle(e).backgroundColor") == "rgba(0, 0, 0, 0)"
                    active.focus()
                    assert active.evaluate("e => getComputedStyle(e).outlineStyle") != "none"
                    # Show the ordinary selection state in the screenshot after
                    # separately proving keyboard focus remains visible.
                    active.evaluate("e => e.blur()")
                    page.mouse.move(800 if page.viewport_size["width"] > 800 else 350, 15)
                for width in (1440, 390):
                    page.set_viewport_size({"width": width, "height": 1000 if width == 1440 else 844})
                    for view in ("guide", "users", "roles", "permissions", "clients", "sessions", "keys", "audit"):
                        page.set_content(source("/admin/?view=" + view), wait_until="domcontentloaded")
                        page.add_style_tag(content=css)
                        assert_rail()
                        if view == "guide":
                            article = page.locator(".markdown-body").inner_text()
                            assert "Adding an app to authd" in article
                            assert "BDC" not in article and "bdcmaps" not in article
                        viewport_check(f"{view}-{width}", full_page=view != "guide")
                        pages += 1
                    for label, path in (("documentation", "/admin/docs"), ("field-reference", "/admin/docs?doc=docs%2FFIELD_REFERENCE.md"), ("specification", "/admin/docs?doc=SPEC.md"), ("validation", "/admin/docs?doc=VALIDATION.md")):
                        page.set_content(source(path), wait_until="domcontentloaded")
                        page.add_style_tag(content=css)
                        assert_rail()
                        assert page.locator("h1").count() == 1
                        if label != "documentation":
                            for link in page.locator(".doc-toc a").all():
                                fragment = link.get_attribute("href")[1:]
                                assert page.evaluate("id => !!document.getElementById(id)", fragment), fragment
                        viewport_check(f"{label}-{width}", full_page=False)
                        pages += 1
                    for label, path in (("client-connection", "/admin/?client=00000000-0000-4000-8000-000000000001"), ("account", "/account"), ("setup", "/setup"), ("login", "/login")):
                        page.set_content(source(path), wait_until="domcontentloaded")
                        page.add_style_tag(content=css)
                        viewport_check(f"{label}-{width}")
                        pages += 1
                # Every destination stays reachable on a short viewport. No
                # browser navigation or live identity claims are made here.
                for width in (1440, 390):
                    page.set_viewport_size({"width": width, "height": 360})
                    page.set_content(source("/admin/docs"), wait_until="domcontentloaded")
                    page.add_style_tag(content=css)
                    for link in page.locator(".rail a").all():
                        link.scroll_into_view_if_needed()
                        box = link.bounding_box()
                        assert box and box["y"] >= 0 and box["y"] + box["height"] <= 360
                    viewport_check(f"short-rail-{width}", full_page=False)
                    pages += 1
                records.append({"mode": "layout-only", "pages": pages, "svg_count_per_rail": 11, "shading": "none in default/selected/hover", "native_forms_exercised": False})
            elif manifest["scenario"] == "web":
                page.goto(origin + "/setup?test_private=must-not-leak")
                page.locator('[name="bootstrap_token"]').fill("A" * 43)
                page.locator('[name="username"]').fill("setup-admin")
                page.locator('[name="password"]').fill("a synthetic setup password")
                submit("/setup", 'button[type="submit"], button.button-primary', 303)
                page.goto(origin + "/login?test_private=must-not-leak")
                page.locator('[name="username"]').fill(manifest["username"])
                page.locator('[name="password"]').fill(manifest["password"])
                submit("/login", "button.button-primary", 303)
                assert urlsplit(page.url).path == "/account"
                # Browser state is explicitly seeded for an administrator, not
                # misrepresented as a database-backed admin login.
                use_admin_session()
                for width in (1440, 390):
                    page.set_viewport_size({"width": width, "height": 1000 if width == 1440 else 844})
                    for view in ("guide", "users", "roles", "permissions", "clients", "sessions", "keys", "audit"):
                        response = page.goto(origin + "/admin/?view=" + view)
                        assert response.status == 200, f"cannot render {view}"
                        if view == "guide":
                            assert page.get_by_role("heading", name="Adding an app to authd").count() == 1
                        viewport_check(f"{view}-{width}")
                page.set_viewport_size({"width": 1440, "height": 1000})
                page.goto(origin + "/admin/?view=permissions&test_private=must-not-leak")
                page.locator('form[action="/admin/permissions/create"] input[name="name"]').fill("example.reports.read")
                submit("/admin/permissions/create", 'form[action="/admin/permissions/create"] button', 303)
                page.goto(origin + "/admin/?view=clients")
                form = page.locator('form[action="/admin/clients/create"]')
                form.locator('[name="client_id"]').fill("bdcmaps")
                form.locator('[name="name"]').fill("BDC Maps")
                form.locator('[name="redirect_uris"]').fill("https://maps.example.test/auth/callback")
                form.locator('[name="identity_scopes"][value="groups"]').check()
                submit("/admin/clients/create", 'form[action="/admin/clients/create"] button.button-primary', 200)
                assert "OIDC_CLIENT_SECRET" in page.locator("body").inner_text()
                assert origin in page.locator("#connection-details").inner_text()
                # Never capture the one-time secret screen, even with fixture data.
                page.goto(origin + "/admin/?client=00000000-0000-4000-8000-000000000001")
                viewport_check("client-connection-1440")
                page.set_viewport_size({"width": 390, "height": 844})
                viewport_check("client-connection-390")
                # Negative browser witness: no-referrer still yields an opaque
                # Origin and is refused even with the real valid form CSRF token.
                page.goto(origin + "/login")
                page.evaluate("""() => {const m=document.createElement('meta');m.name='referrer';m.content='no-referrer';document.head.append(m)}""")
                page.locator('[name="username"]').fill(manifest["username"])
                page.locator('[name="password"]').fill(manifest["password"])
                submit("/login", "button.button-primary", 403, expected_origin="null")
                # Removing CSRF does not become acceptable after the header fix.
                page.goto(origin + "/login")
                page.locator('[name="username"]').fill(manifest["username"])
                page.locator('[name="password"]').fill(manifest["password"])
                page.locator('[name="csrf_token"]').evaluate("e => e.value = ''")
                submit("/login", "button.button-primary", 403)
            elif manifest["scenario"] == "oidc":
                use_admin_session()
                page.goto(manifest["authorize"])
                assert page.get_by_role("heading", name="Authorize application").count() == 1
                assert "Share your assigned authd role names." in page.locator("body").inner_text()
                viewport_check("consent-1440")
                submit("/authorize/consent", 'button[name="decision"][value="allow"]', 303)
                page.wait_for_url(origin + "/auth/callback?*")
                assert page.get_by_role("heading", name="Callback received").count() == 1
                page.goto(origin + "/logout")
                viewport_check("logout-1440")
                submit("/logout", 'button[name="decision"][value="allow"]', 302)
                page.wait_for_url(origin + "/login")
            else:
                raise ValueError("unknown fixture scenario")
            context.close()
    if output:
        (output / (manifest["scenario"] + "-browser.json")).write_text(json.dumps(records, indent=2) + "\n")
    if manifest["scenario"] == "layout":
        print("PASS rendered layout only: actual templates/CSS; no native form or browser network qualification", flush=True)
    else:
        print("PASS native " + manifest["scenario"] + " forms; TLS + real handlers, synthetic persistence/credentials", flush=True)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: browser_forms.py PRIVATE_TEST_MANIFEST.json (normally run via make browser-check)")
    run(json.loads(Path(sys.argv[1]).read_text()))
