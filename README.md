# cookie-viewer

A minimal, read-only cookie viewer for Chrome.

It shows the cookies that the current tab's URL would send, and nothing else. It is meant for people who handle sensitive sessions and would rather not trust a large third-party extension with them: the whole extension is about 100 lines you can read in a few minutes.

## What it does

- Lists name / value / domain + path / attributes (Secure, HttpOnly, SameSite, Partitioned, expiry) of the cookies for the current tab's URL
- Values are masked until you tick "値を表示" (show values), so they do not leak on a shared screen
- Filter by name, copy a value to the clipboard

## What it does not do

- No network requests, no storage, no background script, no content script
- Does not edit, delete or export cookies
- Does not read any site until you grant that one origin from the popup (`optional_host_permissions`). Granted origins can be revoked from `chrome://extensions` → Details → Site access

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

The tests load the extension into Playwright's Chromium and check the cookie list against a local server, including that cookie values are never interpreted as HTML.

```bash
bun run zip   # builds cookie-viewer.zip from extension/ for the Chrome Web Store
```

## License

MIT
