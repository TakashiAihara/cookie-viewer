# secure-cookie-viewer

A minimal, read-only cookie viewer for Chrome.

It shows the cookies stored for the current tab's URL, and nothing else. It is meant for people who handle sensitive sessions and would rather not trust a large third-party extension with them: the whole extension is small enough to read in a few minutes and has no dependencies.

## Why it is safe to use with sensitive sessions

"Secure" here means the extension itself cannot become the way your cookies leak. It does not protect cookies from other extensions or malware.

### Enforced by Chrome

These hold even if the code had a bug, because Chrome refuses anything else.

- No site is readable at install time. Read access is granted from the popup one origin at a time (`optional_host_permissions`), and the popup can revoke it again
- No network access. The extension's Content Security Policy is `default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'`, so the popup cannot send anything anywhere, and cannot load or run code from outside the package
- No access to page contents: no content script, no `scripting` permission
- Runs only while the popup is open: no background script

### Checked in the code and tests

- Cookies are not stored: there is no `storage` permission, and a test checks that `localStorage`, `sessionStorage` and IndexedDB stay empty after the popup has listed, revealed and copied cookies
- Cookie values are never interpreted as HTML: they reach the page only through `textContent`, and a test feeds a value containing HTML
- No third-party code: the package is plain HTML, CSS and JavaScript with no dependencies. `playwright` is used only by the tests and is not in the package
- The tests also check that a request from the popup is blocked by the CSP and that the popup makes no outside requests

### Release integrity

- Each release zip is built by GitHub Actions from a tag and carries a build provenance attestation (`gh attestation verify <zip> --repo TakashiAihara/secure-cookie-viewer`). The release notes give its sha256; that zip is what is uploaded to the Chrome Web Store
- From the first update after the initial listing, uploads to the Chrome Web Store are signed with a key kept outside the store account (Verified CRX uploads), so a compromised store account alone cannot publish a different build

### Limits

- A copied value goes to the OS clipboard, which may keep a history or sync it to other devices. Clearing it automatically would need a background script, which this extension avoids on purpose

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
bun run zip   # builds secure-cookie-viewer.zip from extension/ for the Chrome Web Store
```

## License

MIT
