# secure-cookie-viewer

A minimal, read-only cookie viewer for Chrome.

It shows the cookies stored for the current tab's URL, and nothing else. It is meant for people who handle sensitive sessions and would rather not trust a large third-party extension with them: the whole extension is small enough to read in a few minutes and has no dependencies.

## What it does

- Lists name / value / domain + path / attributes (Secure, HttpOnly, SameSite, expiry) of the cookies for the current tab's URL
- Partitioned cookies (CHIPS) are listed too, labeled with the top-level site they belong to. Cookies this site set while embedded in other sites appear here, although this tab does not send them
- In an incognito window (if you allow the extension there) it shows the incognito cookies, not the regular profile's
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

The tests load the extension into Playwright's Chromium, put cookies into its store and check the popup, including that cookie values are never interpreted as HTML. The permission prompt and the toolbar click itself are not covered, since a test cannot answer the prompt or click the toolbar.

```bash
bun run zip   # builds secure-cookie-viewer.zip from extension/ for the Chrome Web Store
```

## License

MIT
