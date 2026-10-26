# secure-cookie-viewer

A minimal, read-only cookie viewer for Chrome.

It shows the cookies stored for the current tab's URL, and nothing else. It is meant for people who handle sensitive sessions and would rather not trust a large third-party extension with them: the whole extension is small enough to read in a few minutes and has no dependencies.

## Why it is safe to use with sensitive sessions

"Secure" here means the extension itself does not become the way your cookies leak. It does not protect cookies from other extensions or malware on the same machine.

### Enforced by Chrome

These hold whatever the code does, because Chrome refuses the rest.

- At install time the extension has no host permission. Host access is in `optional_host_permissions`, which the user grants (`activeTab` also grants temporary access to the current tab when the toolbar button is clicked; the popup does not read cookies until the site is granted)
- The popup page cannot fetch or load anything: its Content Security Policy is `default-src 'none'; script-src 'self'; style-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`, which blocks `fetch`, XHR, `sendBeacon` and WebSocket, images and fonts from anywhere, scripts and styles from outside the package, and inline scripts and styles
- No content script, no `scripting` permission, no background script

### Not in the code, pinned by tests

A CSP does not cover everything. Navigation, opening a tab (`window.open`, `chrome.tabs.create`), WebRTC and some `chrome.*` APIs can still send data out of an extension page, and `activeTab` would let the popup capture the visible tab. This extension relies on not containing any of that, and the tests check it:

- An allowlist test parses `popup.js` and fails on anything it does not already use. The globals are exactly `chrome`, `document`, `navigator`, `URL`, `Date` and `Boolean`. The browser objects may only appear as fixed dotted calls: `chrome.cookies.getAll`, `chrome.permissions.contains` / `request` / `remove`, `chrome.tabs.query`, `document.getElementById` / `createElement` and `navigator.clipboard.writeText`; aliasing one, or wrapping it in an expression, fails. Bracket access, which could build a name from strings, is not allowed at all. Every property name, every kind of syntax, the only `setAttribute` names (`aria-label`, and `title` for the SameSite badge) and the only elements `createElement` may make (`button`, and `span` for the attribute badges) are listed, and no local name may hide a browser global. So `window.open`, `open(...)`, `chrome.tabs.create`, `captureVisibleTab`, navigation, `fetch`, WebRTC, `eval`, `import()` and storage APIs all fail the test, however they are written
- The clipboard is the one way out the extension does use. The test allows exactly one call, `navigator.clipboard.writeText(c.value)` for the row clicked, and the browser test checks that listing, revealing and filtering leave the clipboard unchanged
- The package's file list, the whole of `popup.html`, `popup.css` (no `url()` or `@import`) and the whole manifest (keys, permissions, host patterns, CSP) are pinned as well
- A browser test runs a full session (list, reveal, filter, copy) and checks that no request leaves the extension, no tab or window opens, nothing lands in `localStorage`, `sessionStorage`, IndexedDB or the Cache API, and nothing trips the CSP. It then checks that a request is blocked by the CSP
- Cookie values reach the page only through `textContent`; a test feeds a value containing HTML. Names, domains, paths and attributes also go in as text, and the name is also set as plain text in the copy button's `aria-label`
- No third-party code: the package is plain HTML, CSS and JavaScript with no dependencies. `playwright`, `acorn` and `acorn-walk` are used only by the tests and are not in the package

These tests stop a mistake in this repository from shipping. They are not a guarantee about a build you install: a malicious update would ship with its own tests. For that, see the release checks below, or read `popup.js` (about 160 lines) yourself.

### Releases

- `scripts/pack.sh` builds the zip reproducibly (fixed timestamps, modes and order), so a zip rebuilt from a tag has the same sha256 as the release
- Each release is built by GitHub Actions from a tag on `main` after the tests pass, and carries a build provenance attestation (`gh attestation verify secure-cookie-viewer.zip --repo TakashiAihara/secure-cookie-viewer`)
- The Chrome Web Store repackages what is uploaded, so the attestation covers the GitHub release, not the file Chrome installs. To compare, find the installed files (`chrome://extensions` shows the ID; they are in the profile's `Extensions/<ID>/<version>_0` directory) and diff them against the release zip. The store adds a `_metadata/` directory and rewrites `manifest.json` (it adds keys such as `update_url`); every other file should match byte for byte
- The same workflow then sends that zip to the Chrome Web Store as a CRX signed with a key that is not kept in the Google account (Chrome Web Store "Verified CRX uploads"; Google describes this as a way to "prevent malicious updates if your developer account is compromised"), and the store publishes it once review passes
- The signing key is a secret of the `cws-release` environment, which only `v*` tags may use. The workflow reaches the Chrome Web Store API through OIDC (Workload Identity Federation): Google accepts the token only from `release.yml` on a `v*` tag of this repository in that environment, and no Google credential is stored on GitHub
- So a compromised Google account alone cannot ship an update, but a compromised GitHub account can, by pushing a tag. This is a hobby project; the key is kept on GitHub rather than in a KMS for that reason

### Limits

- A user can grant the extension all sites from `chrome://extensions`. The popup then cannot revoke a single site, and says so
- A copied value goes to the OS clipboard, which may keep a history or sync it to other devices. Clearing it automatically would need a background script, which this extension avoids on purpose
- `popup.html` can also be opened as a normal tab, and then it keeps running while the tab is open

## What it does

- Lists name / value / domain + path / attributes (Secure, HttpOnly, SameSite, expiry) of the cookies for the current tab's URL
- Partitioned cookies (CHIPS) are listed too, labeled with the top-level site they belong to. Cookies this site set while embedded in other sites appear here, although this tab does not send them. Those set under a cross-site ancestor are labeled `cross-site`
- In an incognito window (if you allow the extension there) it shows the incognito cookies, not the regular profile's
- Values are masked until you tick "Show values", so they do not leak on a shared screen
- Filter by name, copy a value to the clipboard
- Revoke the current site's permission from the popup

## What it does not do

- Does not edit, delete or export cookies

## Install

From source:

1. Download or clone this repository
2. Open `chrome://extensions` and turn on Developer mode
3. "Load unpacked" and select the `extension/` directory

## Development

```bash
bun install
bunx playwright install chromium
bun test
```

The tests load the extension into Playwright's Chromium, put cookies into its store and check the popup, including that cookie values are never interpreted as HTML. The permission prompt and the toolbar click itself are not covered, since a test cannot answer the prompt or click the toolbar.

```bash
bun run zip   # scripts/pack.sh: builds secure-cookie-viewer.zip reproducibly and prints its sha256
```

## License

MIT
