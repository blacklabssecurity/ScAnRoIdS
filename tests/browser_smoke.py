#!/usr/bin/env python3
"""
Project: ScAnRoIdS Red Team Orchestrator
Module: tests/browser_smoke.py
Purpose: Opt-in browser acceptance checks against a synthetic viewing session.

Start the README synthetic demo, then set SCANROIDS_TEST_URL and
SCANROIDS_TEST_PASSWORD. Install requirements-browser.txt and Chromium first.
"""

import os
from playwright.sync_api import expect, sync_playwright


def main():
    url = os.environ.get("SCANROIDS_TEST_URL", "http://127.0.0.1:8888")
    password = os.environ["SCANROIDS_TEST_PASSWORD"]
    executable = os.environ.get("SCANROIDS_CHROMIUM", "/usr/bin/chromium")
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(executable_path=executable, headless=True)
        page = browser.new_page(viewport={"width": 1512, "height": 1100})
        errors = []
        page.on("pageerror", lambda error: errors.append(str(error)))
        page.goto(url)
        page.get_by_label("Session password").fill(password)
        page.get_by_role("button", name="Open workspace").click()
        expect(page.locator("#service-count")).to_have_text("4")
        expect(page.locator("#host-count")).to_have_text("3")
        expect(page.locator("#uncertain-count")).to_have_text("1")
        page.get_by_label("Port state", exact=True).select_option("uncertain")
        expect(page.locator("#service-rows tr")).to_have_count(1)
        expect(page.locator("#service-rows")).to_contain_text("open|filtered")
        expect(page.locator("#service-rows")).to_contain_text("no-response")
        page.reload()
        expect(page.locator("#port-state")).to_have_value("uncertain")
        expect(page.locator("#service-count")).to_have_text("4")
        page.get_by_label("Port state", exact=True).select_option("")
        page.locator("#search").fill("ssh")
        expect(page.locator("#service-rows tr")).to_have_count(2)
        page.locator("[data-sort=port]").click()
        page.reload()
        expect(page.locator("#search")).to_have_value("ssh")
        expect(page.locator("#service-rows tr")).to_have_count(2)
        page.locator("#search").fill("")
        page.locator("#service-rows button").filter(has_text="Inspect").first.click()
        expect(page.locator("#evidence-dialog")).to_be_visible()
        page.locator("#close-evidence").click()
        page.locator("[data-tab=hosts]").click()
        expect(page.locator("#host-rows tr")).to_have_count(3)
        page.locator("[data-tab=topology]").click()
        expect(page.locator("#topology-view svg")).to_have_count(1)
        page.locator("[data-tab=artifacts]").click()
        expect(page.locator("#artifact-list a")).not_to_have_count(0)
        page.locator("[data-tab=results]").click()
        page.set_viewport_size({"width": 390, "height": 844})
        assert page.evaluate("document.documentElement.scrollWidth<=innerWidth")
        assert not errors, errors
        for _ in range(3):
            context = browser.new_context()
            viewer = context.new_page()
            viewer.goto(url)
            viewer.get_by_label("Session password").fill(password)
            viewer.get_by_role("button", name="Open workspace").click()
            expect(viewer.locator("#service-count")).to_have_text("4")
            context.close()
        browser.close()
        print(
            "Browser smoke passed: login, evidence, persistent table state, topology, artifacts, mobile, multiple viewers"
        )


if __name__ == "__main__":
    main()


"""
INPUT: Synthetic demo server URL, password and local browser executable.
OUTPUT: Browser acceptance results; no scan commands or external targets are used.
"""
