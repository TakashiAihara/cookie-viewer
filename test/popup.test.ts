import { afterAll, beforeAll, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { cpSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { chromium, type BrowserContext, type Page } from "playwright";

const XSS = "<img src=x onerror=document.title='pwned'>";
const SITE = "https://example.test";
let ctx: BrowserContext;
let extId: string;
// Chrome hashes the resolved path, so a symlinked TMPDIR (macOS) must be resolved first.
const tmp = realpathSync(mkdtempSync(join(tmpdir(), "secure-cookie-viewer-test-")));

// Unpacked extension id on Linux / macOS: sha256 of the UTF-8 path, hex mapped to a-p.
function unpackedId(path: string) {
  const hex = createHash("sha256").update(path).digest("hex").slice(0, 32);
  return [...hex].map((c) => String.fromCharCode(97 + parseInt(c, 16))).join("");
}

beforeAll(async () => {
  // Host permission is pre-granted for example.test only, so other.test exercises the "not granted" path.
  const ext = join(tmp, "ext");
  cpSync(resolve(import.meta.dir, "../extension"), ext, { recursive: true });
  const manifest = JSON.parse(readFileSync(join(ext, "manifest.json"), "utf8"));
  manifest.host_permissions = [`${SITE}/*`];
  writeFileSync(join(ext, "manifest.json"), JSON.stringify(manifest));
  extId = unpackedId(ext);

  ctx = await chromium.launchPersistentContext(join(tmp, "profile"), {
    channel: "chromium",
    args: [`--disable-extensions-except=${ext}`, `--load-extension=${ext}`],
  });
  await ctx.grantPermissions(["clipboard-read", "clipboard-write"]);
  await ctx.addInitScript(() => {
    if (location.protocol !== "chrome-extension:") return;
    // Recorded from the first script on, so a violation caused by the popup's own code is seen too.
    const w = window as any;
    w.__violations = [];
    document.addEventListener("securitypolicyviolation", (e) => w.__violations.push(e.violatedDirective));
    if (!location.hash) return;

    // A popup opened as a tab would query itself as the active tab, so the target URL comes from the hash.
    const url = decodeURIComponent(location.hash.slice(1));
    // @ts-ignore
    chrome.tabs.query = async () => [{ url }];
    // The permission prompt cannot be answered from a test, and a manifest host permission cannot be
    // removed, so the permission calls are replaced according to the query string on the target URL.
    const q = new URL(url).searchParams;
    if (q.get("fail") === "read") chrome.cookies.getAll = (async () => { throw new Error("boom"); }) as never;
    if (q.get("fail") === "copy") navigator.clipboard.writeText = async () => { throw new Error("denied"); };
    if (q.has("grant")) {
      chrome.permissions.contains = (async () => false) as never;
      chrome.permissions.request = (async (p: unknown) => {
        if (q.get("grant") === "throw") throw new Error("no gesture");
        w.__requested = p;
        return q.get("grant") !== "deny";
      }) as never;
    }
    if (q.has("revoke")) {
      const mode = q.get("revoke");
      let removed = false;
      const contains = chrome.permissions.contains.bind(chrome.permissions);
      chrome.permissions.contains = (async (p: never) => (removed ? mode === "still" : contains(p))) as never;
      chrome.permissions.remove = (async (p: unknown) => {
        if (mode === "throw") throw new Error("not removable");
        w.__removed = p;
        removed = mode !== "fail";
        return mode !== "fail";
      }) as never;
    }
  });

  // Cookies go straight into the store over CDP: a local http server cannot set Secure / Partitioned
  // cookies that Chrome then returns for an https URL. Created out of name order so the popup's sort is tested.
  const base = { domain: "example.test", path: "/", secure: true, sourceScheme: "Secure", sourcePort: 443 };
  const part = (topLevelSite: string, hasCrossSiteAncestor: boolean) => ({ topLevelSite, hasCrossSiteAncestor });
  const cdp = await ctx.newCDPSession(await ctx.newPage());
  await cdp.send("Storage.setCookies", {
    cookies: [
      { ...base, name: "xss", value: XSS, sameSite: "Lax" },
      { ...base, name: "sid", value: "secret123", httpOnly: true, sameSite: "Strict" },
      { ...base, name: "Plain", value: "hello", path: "/app", expires: Date.now() / 1000 + 3600 },
      { ...base, name: "chips", value: "part", sameSite: "None", partitionKey: part(SITE, false) },
      { ...base, name: "chips_cross", value: "x", sameSite: "None", partitionKey: part(SITE, true) },
      { ...base, name: "chips_other", value: "o", sameSite: "None", partitionKey: part("https://other.test", false) },
    ],
  } as never);
}, 60_000);

afterAll(async () => {
  await ctx?.close();
  rmSync(tmp, { recursive: true, force: true });
});

const errors: string[] = [];

async function openPopup(target: string) {
  const p = await ctx.newPage();
  p.on("pageerror", (e) => errors.push(e.message));
  await p.goto(`chrome-extension://${extId}/popup.html#${encodeURIComponent(target)}`);
  return p;
}

const rows = (p: Page) =>
  p.$$eval("tbody tr", (trs) => trs.map((tr) => [...tr.cells].map((td) => td.textContent ?? "")));
const row = async (p: Page, name: string) => (await rows(p)).find((r) => r[0] === name)!;
const msg = (p: Page) => p.locator("#msg").textContent();
const waitMsg = (p: Page, text: string) =>
  p.waitForFunction((t) => document.getElementById("msg")!.textContent === t, text);

// /app makes Plain match too, so every seeded cookie is listed.
async function openGranted(query = "") {
  const p = await openPopup(`${SITE}/app${query}`);
  await waitMsg(p, "6 件");
  return p;
}

test("lists every cookie including partitioned ones, values masked until revealed", async () => {
  const p = await openGranted();

  expect((await rows(p)).map((r) => r[0])).toEqual(["chips", "chips_cross", "chips_other", "Plain", "sid", "xss"]);
  expect((await row(p, "sid"))[1]).toBe("••••••••");
  expect((await row(p, "Plain"))[1]).toBe("••••••••");
  expect((await row(p, "sid"))[2]).toBe("example.test/");
  expect((await row(p, "Plain"))[2]).toBe("example.test/app");
  expect((await row(p, "sid"))[3]).toBe("Secure HttpOnly SameSite=Strict Session");
  expect((await row(p, "xss"))[3]).toBe("Secure SameSite=Lax Session");
  expect((await row(p, "chips"))[3]).toBe(`Secure SameSite=None Partitioned(${SITE}) Session`);
  expect((await row(p, "chips_cross"))[3]).toBe(`Secure SameSite=None Partitioned(${SITE}, cross-site) Session`);
  expect((await row(p, "chips_other"))[3]).toBe("Secure SameSite=None Partitioned(https://other.test) Session");
  expect((await row(p, "Plain"))[3]).toMatch(/^Secure \d/);
  expect(await p.locator("#host").textContent()).toBe(SITE);

  await p.check("#reveal");
  expect((await row(p, "sid"))[1]).toBe("secret123");
  expect((await row(p, "chips"))[1]).toBe("part");
  expect((await row(p, "xss"))[1]).toBe(XSS);
  expect(await p.locator("tbody img").count()).toBe(0);
}, 30_000);

test("filters by name ignoring case and counts the matches", async () => {
  const p = await openGranted();
  await p.fill("#filter", "PLA");
  expect((await rows(p)).map((r) => r[0])).toEqual(["Plain"]);
  expect(await msg(p)).toBe("1 / 6 件");
}, 30_000);

test("copies the value, not the name, even while masked", async () => {
  const p = await openGranted();
  await p.getByRole("button", { name: "copy value of sid" }).click();
  await p.waitForFunction(() => [...document.querySelectorAll("button")].some((b) => b.textContent === "ok"));
  expect(await p.evaluate(() => navigator.clipboard.readText())).toBe("secret123");
}, 30_000);

test("says so when copying fails", async () => {
  const p = await openGranted("?fail=copy");
  await p.getByRole("button", { name: "copy value of sid" }).click();
  await p.waitForFunction(() => [...document.querySelectorAll("button")].some((b) => b.textContent === "failed"));
}, 30_000);

test("says so when reading fails", async () => {
  const p = await openPopup(`${SITE}/?fail=read`);
  await waitMsg(p, "読み込めませんでした: boom");
  expect(await p.locator("#tbl").isHidden()).toBe(true);
}, 30_000);

test("asks for permission instead of reading a site that was not granted", async () => {
  const p = await openPopup("https://other.test/");
  await p.waitForSelector("#grant:not([hidden])");
  await p.fill("#filter", "x");
  await p.check("#reveal");
  expect(await p.locator("#tbl").isHidden()).toBe(true);
  expect(await p.locator("#revoke").isHidden()).toBe(true);
  expect(await msg(p)).toBe("");
}, 30_000);

test("asks for exactly the current origin, then lists it and offers to revoke", async () => {
  const p = await openPopup(`${SITE}/app?grant`);
  await p.click("#grant");
  await waitMsg(p, "6 件");
  expect(await p.evaluate(() => (window as any).__requested)).toEqual({ origins: [`${SITE}/*`] });
  expect(await p.locator("#grant").isHidden()).toBe(true);
  expect(await p.locator("#revoke").isHidden()).toBe(false);
}, 30_000);

test("says so when the permission is denied", async () => {
  const p = await openPopup(`${SITE}/?grant=deny`);
  await p.click("#grant");
  await waitMsg(p, "許可されませんでした");
  expect(await p.locator("#tbl").isHidden()).toBe(true);
}, 30_000);

test("says so when the permission request throws", async () => {
  const p = await openPopup(`${SITE}/?grant=throw`);
  await p.click("#grant");
  await waitMsg(p, "許可を求められませんでした: no gesture");
}, 30_000);

test("revokes the site's permission and clears the list", async () => {
  const p = await openGranted("?revoke");
  expect(await p.locator("#revoke").isHidden()).toBe(false);
  await p.click("#revoke");
  await waitMsg(p, "許可を取り消しました");
  expect(await p.evaluate(() => (window as any).__removed)).toEqual({ origins: [`${SITE}/*`] });
  expect(await p.locator("#tbl").isHidden()).toBe(true);
  expect(await p.locator("tbody tr").count()).toBe(0);
  expect(await p.locator("#revoke").isHidden()).toBe(true);
  await p.check("#reveal");
  expect(await p.locator("#tbl").isHidden()).toBe(true);
}, 30_000);

test("does not claim to have revoked a site that a broader grant still covers", async () => {
  const p = await openGranted("?revoke=still");
  await p.click("#revoke");
  await waitMsg(p, "このサイトは chrome://extensions の「サイトへのアクセス」で許可されているため、ここでは取り消せません");
  expect(await p.locator("#tbl").isHidden()).toBe(false);
}, 30_000);

test("says so when revoking fails or throws, and keeps the list", async () => {
  for (const [mode, text] of [["fail", "取り消せませんでした"], ["throw", "取り消せませんでした: not removable"]]) {
    const p = await openGranted(`?revoke=${mode}`);
    await p.click("#revoke");
    await waitMsg(p, text);
    expect(await p.locator("#tbl").isHidden()).toBe(false);
    expect(await p.locator("#revoke").isHidden()).toBe(false);
    expect(await p.locator("tbody tr").count()).toBe(6);
  }
}, 30_000);

test("refuses non-http pages, and keeps refusing after the controls are touched", async () => {
  const p = await openPopup("chrome://settings/");
  await p.waitForFunction(() => document.getElementById("msg")!.textContent!.includes("http / https"));
  await p.fill("#filter", "x");
  expect(await msg(p)).toBe("http / https のページでだけ使えます");
  expect(await p.locator("#tbl").isHidden()).toBe(true);
}, 30_000);

test("the CSP blocks requests, and a full session sends, opens and stores nothing", async () => {
  const outside: string[] = [];
  const pages: string[] = [];
  const onRequest = (r: { url(): string }) => { if (!r.url().startsWith("chrome-extension://")) outside.push(r.url()); };
  const onPage = (pg: Page) => pages.push(pg.url());
  ctx.on("request", onRequest);

  const p = await openGranted();
  ctx.on("page", onPage);
  await p.check("#reveal");
  await p.fill("#filter", "s");
  await p.getByRole("button", { name: "copy value of sid" }).click();
  await p.waitForFunction(() => [...document.querySelectorAll("button")].some((b) => b.textContent === "ok"));
  // Nothing the popup did on its own tripped the CSP (this would also catch an inline style left in popup.html).
  expect(await p.evaluate(() => (window as any).__violations)).toEqual([]);

  // no-cors would resolve with an opaque response if the request were allowed, so only the CSP can reject it.
  const fetched = await p.evaluate(() => fetch("https://example.com/", { mode: "no-cors" }).then(() => "sent", () => "blocked"));
  await p.waitForTimeout(100);
  expect(fetched).toBe("blocked");
  expect(await p.evaluate(() => (window as any).__violations)).toEqual(["connect-src"]);

  ctx.off("request", onRequest);
  ctx.off("page", onPage);
  expect(outside).toEqual([]);
  expect(pages).toEqual([]);

  const stored = await p.evaluate(async () => [
    localStorage.length,
    sessionStorage.length,
    (await indexedDB.databases()).length,
    (await caches.keys()).length,
    document.cookie,
  ]);
  expect(stored).toEqual([0, 0, 0, 0, ""]);
  // The stylesheet is a separate file because the CSP forbids inline styles; this checks it still applies.
  expect(await p.evaluate(() => getComputedStyle(document.body).width)).toBe("640px");
}, 30_000);

// CSP covers requests a page makes, not navigation, new tabs, WebRTC or chrome.* APIs. Those are kept out
// by not having the code at all, and this pins that.
test("the package contains no way out that the CSP does not cover", () => {
  const dir = resolve(import.meta.dir, "../extension");
  // Comments name some of these APIs to say they are not used, so only code is scanned.
  const js = readFileSync(join(dir, "popup.js"), "utf8").replace(/\/\/.*$/gm, "");
  const html = readFileSync(join(dir, "popup.html"), "utf8");
  const manifest = JSON.parse(readFileSync(join(dir, "manifest.json"), "utf8"));

  for (const re of [/window\.open/, /\blocation\b/, /\.href\b/, /chrome\.tabs\.(create|update)/, /chrome\.windows/,
    /chrome\.runtime\.(setUninstallURL|sendMessage|connect)/, /RTCPeerConnection/, /\bWebSocket\b/, /sendBeacon/,
    /\bfetch\b/, /XMLHttpRequest/, /\beval\b|new Function/, /innerHTML|outerHTML|insertAdjacentHTML|document\.write/,
    /localStorage|sessionStorage|indexedDB|chrome\.storage/]) {
    expect(js).not.toMatch(re);
  }
  expect(html).not.toMatch(/<(a|form|iframe|img|object|embed|meta http-equiv)\b|style=|on[a-z]+=/i);
  expect(Object.keys(manifest).sort()).toEqual(["action", "content_security_policy", "description", "icons",
    "incognito", "manifest_version", "minimum_chrome_version", "name", "optional_host_permissions", "permissions",
    "version"]);
  expect(manifest.permissions).toEqual(["cookies", "activeTab"]);
}, 30_000);

// Last, so it sees the errors of every popup above.
test("no popup threw", () => {
  expect(errors).toEqual([]);
});
