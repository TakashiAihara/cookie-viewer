# secure-cookie-viewer

A minimal, read-only cookie viewer for Chrome.

It shows the cookies stored for the current tab's URL, and nothing else. It is meant for people who handle sensitive sessions and would rather not trust a large third-party extension with them: the whole extension is small enough to read in a few minutes and has no dependencies.

## Why it is safe to use with sensitive sessions

"Secure" here means the extension itself does not become the way your cookies leak. It does not protect cookies from other extensions or malware on the same machine.

### Enforced by Chrome

These hold whatever the code does, because Chrome refuses the rest.

- At install time the extension can read no site. Read access comes only from `optional_host_permissions`, which the user grants. The popup asks for the current origin only, and can revoke it again
- The popup page cannot make requests: its Content Security Policy is `default-src 'none'; script-src 'self'; style-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`, which blocks `fetch`, XHR, `sendBeacon`, WebSocket, images, styles and scripts from anywhere but the package, and inline scripts and styles
- No content script, no `scripting` permission, no background script

### Not in the code, pinned by tests

A CSP does not cover everything. Navigation, opening a tab (`window.open`, `chrome.tabs.create`), WebRTC and some `chrome.*` APIs can still send data out of an extension page, and `activeTab` would let the popup capture the visible tab. This extension relies on not containing any of that, and the tests check it:

- A static test fails if the popup code uses any of: navigation or `window.open`, `chrome.tabs.create` / `update`, `chrome.windows`, `RTCPeerConnection`, WebSocket, `sendBeacon`, `fetch`, XHR, `eval`, HTML-writing APIs, or any storage API. It also fails if `popup.html` has links, forms, frames, images or inline handlers, and if the manifest gains a key or permission
- A browser test runs a full session (list, reveal, filter, copy) and checks that no request leaves the extension, no tab or window opens, nothing lands in `localStorage`, `sessionStorage`, IndexedDB or the Cache API, and nothing trips the CSP. It then checks that a request is blocked by the CSP
- Cookie values reach the page only through `textContent`; a test feeds a value containing HTML
- `activeTab` is used only to read the tab's URL
- No third-party code: the package is plain HTML, CSS and JavaScript with no dependencies. `playwright` is used only by the tests and is not in the package

### Releases

- `scripts/pack.sh` builds the zip reproducibly (fixed timestamps, modes and order), so a zip rebuilt from a tag has the same sha256 as the release
- Each release is built by GitHub Actions from a tag on `main` after the tests pass, and carries a build provenance attestation (`gh attestation verify secure-cookie-viewer.zip --repo TakashiAihara/secure-cookie-viewer`)
- The Chrome Web Store repackages what is uploaded, so the attestation covers the GitHub release, not the file Chrome installs. To compare, unpack the installed extension (`chrome://extensions` shows its ID; the files are in the profile's `Extensions/<ID>/<version>` directory) and diff it against the release zip; the store adds `_metadata/`
- Updates after the first listing are uploaded as CRX files signed with a key that is not kept in the Google account (Chrome Web Store "Verified CRX uploads"). Google describes this as a way to "prevent malicious updates if your developer account is compromised"

### Limits

- A user can grant the extension all sites from `chrome://extensions`. The popup then cannot revoke a single site, and says so
- A copied value goes to the OS clipboard, which may keep a history or sync it to other devices. Clearing it automatically would need a background script, which this extension avoids on purpose
- `popup.html` can also be opened as a normal tab, and then it keeps running while the tab is open

## What it does

- Lists name / value / domain + path / attributes (Secure, HttpOnly, SameSite, expiry) of the cookies for the current tab's URL
- Partitioned cookies (CHIPS) are listed too, labeled with the top-level site they belong to. Cookies this site set while embedded in other sites appear here, although this tab does not send them. Those set under a cross-site ancestor are labeled `cross-site`
- In an incognito window (if you allow the extension there) it shows the incognito cookies, not the regular profile's
- Values are masked until you tick "値を表示" (show values), so they do not leak on a shared screen
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
