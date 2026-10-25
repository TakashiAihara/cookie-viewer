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
const tmp = realpathSync(mkdtempSync(join(tmpdir(), "cookie-viewer-test-")));

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
  // A popup opened as a tab would query itself as the active tab, so the target URL comes from the hash.
  await ctx.addInitScript(() => {
    if (location.protocol === "chrome-extension:" && location.hash) {
      const url = decodeURIComponent(location.hash.slice(1));
      // @ts-ignore
      chrome.tabs.query = async () => [{ url }];
      // Failure paths are reached by a query string on the target URL.
      if (url.includes("fail=read")) chrome.cookies.getAll = (async () => { throw new Error("boom"); }) as never;
      if (url.includes("fail=copy")) navigator.clipboard.writeText = async () => { throw new Error("denied"); };
      if (url.includes("deny")) chrome.permissions.request = (async () => false) as never;
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

// /app makes Plain match too, so every seeded cookie is listed.
async function openGranted(query = "") {
  const p = await openPopup(`${SITE}/app${query}`);
  await p.waitForFunction(() => document.getElementById("msg")!.textContent === "6 件");
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
  await p.waitForFunction(() => document.getElementById("msg")!.textContent === "読み込めませんでした: boom");
  expect(await p.locator("#tbl").isHidden()).toBe(true);
}, 30_000);

test("asks for permission instead of reading a site that was not granted", async () => {
  const p = await openPopup("https://other.test/");
  await p.waitForSelector("#grant:not([hidden])");
  await p.fill("#filter", "x");
  await p.check("#reveal");
  expect(await p.locator("#tbl").isHidden()).toBe(true);
  expect(await msg(p)).toBe("");
}, 30_000);

test("says so when the permission is denied", async () => {
  const p = await openPopup("https://other.test/?deny");
  await p.click("#grant");
  await p.waitForFunction(() => document.getElementById("msg")!.textContent === "許可されませんでした");
  expect(await p.locator("#tbl").isHidden()).toBe(true);
}, 30_000);

test("refuses non-http pages, and keeps refusing after the controls are touched", async () => {
  const p = await openPopup("chrome://settings/");
  await p.waitForFunction(() => document.getElementById("msg")!.textContent!.includes("http / https"));
  await p.fill("#filter", "x");
  expect(await msg(p)).toBe("http / https のページでだけ使えます");
  expect(await p.locator("#tbl").isHidden()).toBe(true);
}, 30_000);

// Last, so it sees the errors of every popup above.
test("no popup threw", () => {
  expect(errors).toEqual([]);
});
