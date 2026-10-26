import { afterAll, beforeAll, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { cpSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { parse } from "acorn";
import { fullAncestor } from "acorn-walk";
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
    if (q.has("slow")) {
      const getAll = chrome.cookies.getAll.bind(chrome.cookies);
      chrome.cookies.getAll = (async (d: never) => { await new Promise((r) => setTimeout(r, 500)); return getAll(d); }) as never;
    }
    if (q.get("fail") === "copy") navigator.clipboard.writeText = async () => { throw new Error("denied"); };
    if (q.has("grant")) {
      chrome.permissions.contains = (async (p: unknown) => ((w.__containsArgs ??= []).push(p), false)) as never;
      chrome.permissions.request = (async (p: unknown) => {
        if (q.get("grant") === "throw") throw new Error("no gesture");
        w.__requestCalls = (w.__requestCalls ?? 0) + 1;
        await new Promise((r) => setTimeout(r, 200));
        w.__requested = p;
        return q.get("grant") !== "deny";
      }) as never;
    }
    if (q.has("revoke")) {
      const mode = q.get("revoke");
      let removed = false;
      const contains = chrome.permissions.contains.bind(chrome.permissions);
      chrome.permissions.contains = (async (p: never) => {
        (w.__containsArgs ??= []).push(p);
        return removed ? mode === "still" : contains(p);
      }) as never;
      chrome.permissions.remove = (async (p: unknown) => {
        if (mode === "throw") throw new Error("not removable");
        w.__removeCalls = (w.__removeCalls ?? 0) + 1;
        await new Promise((r) => setTimeout(r, 200));
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
// The list scrolls inside the popup, so content wider than it would hide the copy column.
const overflows = (p: Page) => p.$eval("#list", (l) => l.scrollWidth > l.clientWidth);
const chipClass = (p: Page, name: string, text: string) =>
  p.$$eval("tbody tr", (trs, [n, t]) => [...trs.find((tr) => tr.cells[0].textContent === n)!.cells[3].children]
    .find((e) => e.textContent === t)?.className, [name, text]);
const row = async (p: Page, name: string) => (await rows(p)).find((r) => r[0] === name)!;
const msg = (p: Page) => p.locator("#msg").textContent();
const waitMsg = (p: Page, text: string) =>
  p.waitForFunction((t) => document.getElementById("msg")!.textContent === t, text);

// /app makes Plain match too, so every seeded cookie is listed.
async function openGranted(query = "") {
  const p = await openPopup(`${SITE}/app${query}`);
  await waitMsg(p, "Cookies: 6");
  return p;
}

test("lists every cookie including partitioned ones, values masked until revealed", async () => {
  const p = await openGranted();

  expect((await rows(p)).map((r) => r[0])).toEqual(["chips", "chips_cross", "chips_other", "Plain", "sid", "xss"]);
  expect((await row(p, "sid"))[1]).toBe("••••••••");
  expect((await row(p, "Plain"))[1]).toBe("••••••••");
  expect((await row(p, "sid"))[2]).toBe("example.test/");
  expect((await row(p, "Plain"))[2]).toBe("example.test/app");
  expect((await row(p, "sid"))[3]).toBe("Secure HttpOnly Strict Session");
  expect((await row(p, "xss"))[3]).toBe("Secure Lax Session");
  expect((await row(p, "chips"))[3]).toBe(`Secure None Partitioned(${SITE}) Session`);
  expect((await row(p, "chips_cross"))[3]).toBe(`Secure None Partitioned(${SITE}, cross-site) Session`);
  expect((await row(p, "chips_other"))[3]).toBe("Secure None Partitioned(https://other.test) Session");
  // Expiry shows the time too: a date alone hides a cookie that expires in minutes.
  expect((await row(p, "Plain"))[3]).toMatch(/^Secure \d\S* \d{1,2}:\d\d/);
  // Only the SameSite value is shortened in the cell; the tooltip names the attribute.
  const titles = (name: string) =>
    p.$$eval("tbody tr", (trs, n) => [...trs.find((tr) => tr.cells[0].textContent === n)!.querySelectorAll("[title]")]
      .map((e) => e.getAttribute("title")), name);
  expect(await titles("sid")).toEqual(["SameSite=Strict"]);
  expect(await titles("chips")).toEqual(["SameSite=None"]);
  expect(await titles("Plain")).toEqual([]);
  expect(await chipClass(p, "sid", "HttpOnly")).toBe("chip httponly");
  expect(await chipClass(p, "sid", "Strict")).toBe("chip");
  expect(await chipClass(p, "chips", "None")).toBe("chip weak");
  expect(await overflows(p)).toBe(false);
  expect(await p.locator("#host").textContent()).toBe(SITE);

  await p.check("#reveal");
  expect((await row(p, "sid"))[1]).toBe("secret123");
  expect((await row(p, "chips"))[1]).toBe("part");
  expect((await row(p, "xss"))[1]).toBe(XSS);
  expect(await p.locator("tbody img").count()).toBe(0);
  expect(await overflows(p)).toBe(false);
}, 30_000);

test("filters by name ignoring case and counts the matches", async () => {
  const p = await openGranted();
  await p.fill("#filter", "PLA");
  expect((await rows(p)).map((r) => r[0])).toEqual(["Plain"]);
  expect(await msg(p)).toBe("Cookies: 1 / 6");
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
  // The longest label the copy button can show must still fit its column.
  expect(await p.getByRole("button", { name: "copy value of sid" }).evaluate((b) => b.getBoundingClientRect().right <= b.parentElement!.getBoundingClientRect().right)).toBe(true);
}, 30_000);

test("says so when reading fails", async () => {
  const p = await openPopup(`${SITE}/?fail=read`);
  await waitMsg(p, "Could not read cookies: boom");
  expect(await p.locator("#tbl").isHidden()).toBe(true);
  // The site is still granted, so it can still be revoked.
  expect(await p.locator("#revoke").isHidden()).toBe(false);
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
  await waitMsg(p, "Cookies: 6");
  expect(await p.evaluate(() => (window as any).__requested)).toEqual({ origins: [`${SITE}/*`] });
  expect(await p.locator("#grant").isHidden()).toBe(true);
  expect(await p.locator("#revoke").isHidden()).toBe(false);
}, 30_000);

test("says so when the permission is denied", async () => {
  const p = await openPopup(`${SITE}/?grant=deny`);
  await p.click("#grant");
  await waitMsg(p, "Access was not granted");
  expect(await p.locator("#tbl").isHidden()).toBe(true);
  expect(await p.locator("#revoke").isHidden()).toBe(true);
  expect(await p.locator("#grant").isHidden()).toBe(false);
  expect(await p.locator("#grant").isEnabled()).toBe(true);
}, 30_000);

test("says so when the permission request throws", async () => {
  const p = await openPopup(`${SITE}/?grant=throw`);
  await p.click("#grant");
  await waitMsg(p, "Could not ask for access: no gesture");
  expect(await p.locator("#tbl").isHidden()).toBe(true);
  expect(await p.locator("#revoke").isHidden()).toBe(true);
  expect(await p.locator("#grant").isEnabled()).toBe(true);
}, 30_000);

test("after granting, revoking works and the grant button comes back", async () => {
  const p = await openPopup(`${SITE}/app?grant&revoke`);
  await p.click("#grant");
  await waitMsg(p, "Cookies: 6");
  await p.click("#revoke");
  await waitMsg(p, "Access revoked");
  expect(await p.evaluate(() => (window as any).__removed)).toEqual({ origins: [`${SITE}/*`] });
  expect(await p.locator("#tbl").isHidden()).toBe(true);
  expect(await p.locator("#grant").isHidden()).toBe(false);
  // The grant button works again: the second request lists the site again.
  await p.click("#grant");
  await waitMsg(p, "Cookies: 6");
  expect(await p.evaluate(() => (window as any).__requestCalls)).toBe(2);
}, 30_000);

test("the revoke button appears only after the list has loaded", async () => {
  const p = await openPopup(`${SITE}/app?slow`);
  await p.waitForTimeout(200);
  expect(await p.locator("#revoke").isHidden()).toBe(true);
  await waitMsg(p, "Cookies: 6");
  expect(await p.locator("#revoke").isHidden()).toBe(false);
}, 30_000);

test("revokes the site's permission and clears the list", async () => {
  const p = await openGranted("?revoke");
  expect(await p.locator("#revoke").isHidden()).toBe(false);
  await p.click("#revoke");
  await waitMsg(p, "Access revoked");
  expect(await p.evaluate(() => (window as any).__removed)).toEqual({ origins: [`${SITE}/*`] });
  expect(await p.locator("#tbl").isHidden()).toBe(true);
  expect(await p.locator("tbody tr").count()).toBe(0);
  expect(await p.locator("#revoke").isHidden()).toBe(true);
  expect(await p.locator("#grant").isHidden()).toBe(false);
  await p.check("#reveal");
  expect(await p.locator("#tbl").isHidden()).toBe(true);
}, 30_000);

test("does not claim to have revoked a site that a broader grant still covers", async () => {
  const p = await openGranted("?revoke=still");
  await p.click("#revoke");
  await waitMsg(p, 'This site is still allowed by "Site access" in chrome://extensions, so it cannot be revoked here');
  expect(await p.locator("#tbl").isHidden()).toBe(false);
  expect(await p.locator("tbody tr").count()).toBe(6);
  expect(await p.locator("#revoke").isHidden()).toBe(false);
  expect(await p.locator("#revoke").isEnabled()).toBe(true);
  expect(await p.locator("#grant").isHidden()).toBe(true);
  // The check after removing asks about this origin, not something broader or empty.
  expect((await p.evaluate(() => (window as any).__containsArgs)).at(-1)).toEqual({ origins: [`${SITE}/*`] });
}, 30_000);

test("says so when revoking fails or throws, and keeps the list", async () => {
  for (const [mode, text] of [["fail", "Could not revoke access"], ["throw", "Could not revoke access: not removable"]]) {
    const p = await openGranted(`?revoke=${mode}`);
    await p.click("#revoke");
    await waitMsg(p, text);
    expect(await p.locator("#tbl").isHidden()).toBe(false);
    expect(await p.locator("#revoke").isHidden()).toBe(false);
    expect(await p.locator("#revoke").isEnabled()).toBe(true);
    expect(await p.locator("tbody tr").count()).toBe(6);
  }
}, 30_000);

test("refuses non-http pages, and keeps refusing after the controls are touched", async () => {
  const p = await openPopup("chrome://settings/");
  await p.waitForFunction(() => document.getElementById("msg")!.textContent!.includes("http / https"));
  await p.fill("#filter", "x");
  expect(await msg(p)).toBe("Works only on http / https pages");
  expect(await p.locator("#tbl").isHidden()).toBe(true);
}, 30_000);

test("the CSP blocks requests, and a full session sends, opens and stores nothing", async () => {
  const outside: string[] = [];
  const pages: Page[] = [];
  const onRequest = (r: { url(): string }) => { if (!r.url().startsWith("chrome-extension://")) outside.push(r.url()); };
  const onPage = (pg: Page) => pages.push(pg);
  ctx.on("request", onRequest);
  ctx.on("page", onPage);

  // The list is slowed down so the clipboard is seeded before it loads; a write while listing would show too.
  const p = await openPopup(`${SITE}/app?slow`);
  await p.evaluate(() => navigator.clipboard.writeText("before"));
  expect(await msg(p)).toBe("");
  await waitMsg(p, "Cookies: 6");
  await p.check("#reveal");
  await p.fill("#filter", "s");
  // Listing, revealing and filtering put nothing on the clipboard; only the copy button does.
  expect(await p.evaluate(() => navigator.clipboard.readText())).toBe("before");
  await p.getByRole("button", { name: "copy value of sid" }).click();
  await p.waitForFunction(() => [...document.querySelectorAll("button")].some((b) => b.textContent === "ok"));
  expect(await p.evaluate(() => navigator.clipboard.readText())).toBe("secret123");
  // Nothing the popup did on its own tripped the CSP (this would also catch an inline style left in popup.html).
  expect(await p.evaluate(() => (window as any).__violations)).toEqual([]);

  // A no-cors fetch is not stopped by CORS, so a rejection with a connect-src violation is the CSP's doing
  // (a network failure would reject without a violation).
  const fetched = await p.evaluate(() => fetch("https://example.com/", { mode: "no-cors" }).then(() => "sent", () => "blocked"));
  await p.waitForFunction(() => (window as any).__violations.length > 0);
  expect(fetched).toBe("blocked");
  expect(await p.evaluate(() => (window as any).__violations)).toEqual(["connect-src"]);

  ctx.off("request", onRequest);
  ctx.off("page", onPage);
  expect(outside).toEqual([]);
  // The only new page is the popup the test itself opened.
  expect(pages).toEqual([p]);

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

// CSP covers requests a page makes, not navigation, new tabs, WebRTC, the clipboard or chrome.* APIs. Those
// are kept out by the code not containing them. This test pins everything popup.js can reach: the browser
// objects (chrome, document, navigator) may only be used as fixed dotted API calls, bracket access is not
// allowed at all, and every property name and kind of syntax is listed. Anything new fails here until it
// is added on purpose.
test("popup.js uses nothing outside the allowlist", async () => {
  const dir = resolve(import.meta.dir, "../extension");
  const src = readFileSync(join(dir, "popup.js"), "utf8");
  const ast = parse(src, { ecmaVersion: "latest", sourceType: "script" }) as any;

  const declared = new Set<string>();
  const declare = (p: any): void => {
    if (!p) return;
    if (p.type === "Identifier") declared.add(p.name);
    else if (p.type === "ArrayPattern") p.elements.forEach(declare);
    else if (p.type === "ObjectPattern") p.properties.forEach((q: any) => declare(q.value ?? q.argument));
    else if (p.type === "AssignmentPattern") declare(p.left);
    else if (p.type === "RestElement") declare(p.argument);
  };
  const types = new Set<string>();
  fullAncestor(ast, (n: any) => {
    types.add(n.type);
    if (n.type === "VariableDeclarator") declare(n.id);
    if (/Function/.test(n.type)) {
      if (n.id) declare(n.id);
      n.params.forEach(declare);
    }
    if (n.type === "CatchClause") declare(n.param);
  });

  const roots = ["chrome", "document", "navigator"];
  const globals = new Set<string>();
  const props = new Set<string>();
  const apis: string[] = [];
  const looseRoots: string[] = [];
  const computed: string[] = [];
  const attrs: string[] = [];
  const clipboard: string[] = [];
  const tags: string[] = [];
  fullAncestor(ast, (n: any, _state: unknown, ancestors: any[]) => {
    const parent = ancestors[ancestors.length - 2];
    if (n.type === "Identifier") {
      if (parent?.type === "MemberExpression" && parent.property === n && !parent.computed) return;
      if (parent?.type === "Property" && parent.key === n && !parent.computed && !parent.shorthand) return;
      if (declared.has(n.name)) return;
      globals.add(n.name);
      if (!roots.includes(n.name)) return;
      // A browser object must be the start of a dotted chain that is called; anything else (aliasing it,
      // wrapping it in an expression, passing it along) would let later code reach APIs not listed here.
      let i = ancestors.length - 2;
      let path = n.name;
      while (ancestors[i]?.type === "MemberExpression" && ancestors[i].object === ancestors[i + 1] && !ancestors[i].computed) {
        path += "." + ancestors[i].property.name;
        i--;
      }
      const top = ancestors[i];
      if (top?.type === "CallExpression" && top.callee === ancestors[i + 1] && path !== n.name) apis.push(path);
      else looseRoots.push(src.slice(n.start, n.end + 20));
    }
    if (n.type === "MemberExpression") {
      if (n.computed) computed.push(src.slice(n.start, n.end));
      else props.add(n.property.name);
    }
    if (n.type === "CallExpression" && n.callee.type === "MemberExpression" && !n.callee.computed) {
      if (n.callee.property.name === "setAttribute") {
        attrs.push(n.arguments[0]?.type === "Literal" ? n.arguments[0].value : "<not a literal>");
      }
      if (n.callee.property.name === "writeText") clipboard.push(src.slice(n.start, n.end));
      if (n.callee.property.name === "createElement") {
        tags.push(n.arguments[0]?.type === "Literal" ? n.arguments[0].value : "<not a literal>");
      }
    }
  });

  expect(computed).toEqual([]);
  expect(looseRoots).toEqual([]);
  expect([...globals].sort()).toEqual(["Boolean", "Date", "URL", "chrome", "document", "navigator"]);
  expect([...new Set(apis)].sort()).toEqual(["chrome.cookies.getAll", "chrome.permissions.contains",
    "chrome.permissions.remove", "chrome.permissions.request", "chrome.tabs.query", "document.createElement",
    "document.getElementById", "navigator.clipboard.writeText"]);
  // The clipboard leaves the browser (history, sync), so it may only ever receive the value of the row clicked.
  expect(clipboard).toEqual(["navigator.clipboard.writeText(c.value)"]);
  expect([...props].sort()).toEqual(["append", "checked", "className", "clipboard", "contains", "cookies",
    "createElement", "disabled", "domain", "expirationDate", "filter", "firstChild", "getAll", "getElementById",
    "hasCrossSiteAncestor", "hidden", "httpOnly", "includes", "insertCell", "insertRow", "join", "length",
    "localeCompare", "message", "name", "onchange", "onclick", "oninput", "origin", "partitionKey", "path",
    "permissions", "query", "remove", "replaceChildren", "request", "sameSite", "secure", "session",
    "setAttribute", "sort", "tabs", "test", "textContent", "then", "toLocaleString", "toLowerCase", "topLevelSite",
    "url", "value", "writeText"]);
  expect(attrs).toEqual(["title", "aria-label"]);
  // A created element is inert only because it is a span or a button; an img, iframe, script or style could load or run.
  expect(tags).toEqual(["span", "button"]);
  const allowedSyntax = ["ArrayExpression", "ArrayPattern", "ArrowFunctionExpression", "AssignmentExpression",
    "AwaitExpression", "BinaryExpression", "BlockStatement", "CallExpression", "CatchClause", "ConditionalExpression",
    "ExpressionStatement", "ForOfStatement", "FunctionDeclaration", "Identifier", "IfStatement", "Literal",
    "LogicalExpression", "MemberExpression", "NewExpression", "ObjectExpression", "Program", "Property",
    "ReturnStatement", "TryStatement", "UnaryExpression", "VariableDeclaration", "VariableDeclarator"];
  expect([...types].filter((t) => !allowedSyntax.includes(t))).toEqual([]);

  // The global check above trusts that a local name is really local. A local named like a browser global
  // (`const fetch = ...` in one function) would hide a real use of that global elsewhere, so none may exist.
  // Taken from an extension page that does not run popup.js (popup.js would add its own top-level functions
  // to window). It has to be the extension's origin: about:blank is not a secure context and lacks globals
  // such as caches and cookieStore.
  const p = await ctx.newPage();
  await p.goto(`chrome-extension://${extId}/popup.css`);
  const windowNames = await p.evaluate(() => {
    const names = new Set<string>();
    for (let o: object | null = window; o; o = Object.getPrototypeOf(o)) Object.getOwnPropertyNames(o).forEach((k) => names.add(k));
    return [...names];
  });
  expect(windowNames).toContain("fetch");
  expect(windowNames).toContain("cookieStore");
  expect([...declared].filter((d) => windowNames.includes(d))).toEqual([]);
  await p.close();
}, 30_000);

// popup.html is pinned whole: any new element, attribute or script must be added here on purpose.
const POPUP_HTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<link rel="stylesheet" href="popup.css">
</head>
<body>
<header id="head">
  <svg class="lock" viewBox="0 0 24 24" aria-hidden="true"><path d="M7.5 10V7.5a4.5 4.5 0 0 1 9 0V10M6 10h12v10H6z"/></svg>
  <h1>Secure Cookie Viewer</h1>
  <div id="host"></div>
</header>
<div id="bar">
  <input id="filter" placeholder="Filter by name">
  <label><input type="checkbox" id="reveal"> Show values</label>
</div>
<div id="msg" class="muted"></div>
<button id="grant" hidden>Allow reading this site's cookies</button>
<div id="list">
<table hidden id="tbl">
  <colgroup><col><col><col><col><col></colgroup>
  <thead><tr><th>Name</th><th>Value</th><th>Domain / Path</th><th>Attributes / SameSite / Expires</th><th>Copy</th></tr></thead>
  <tbody id="rows"></tbody>
</table>
</div>
<footer><button id="revoke" hidden>Revoke access to this site</button></footer>
<script src="popup.js"></script>
</body>
</html>
`;

test("the package files, page and manifest are exactly what is reviewed", () => {
  const dir = resolve(import.meta.dir, "../extension");
  const manifest = JSON.parse(readFileSync(join(dir, "manifest.json"), "utf8"));

  expect(readFileSync(join(dir, "popup.html"), "utf8")).toBe(POPUP_HTML);
  expect(readFileSync(join(dir, "popup.css"), "utf8")).not.toMatch(/url\(|@import/i);
  expect(Object.keys(manifest).sort()).toEqual(["action", "content_security_policy", "description", "icons",
    "incognito", "manifest_version", "minimum_chrome_version", "name", "optional_host_permissions", "permissions",
    "version"]);
  expect(manifest.permissions).toEqual(["cookies", "activeTab"]);
  expect(manifest.optional_host_permissions).toEqual(["http://*/*", "https://*/*"]);
  expect(manifest.content_security_policy).toEqual({
    extension_pages: "default-src 'none'; script-src 'self'; style-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
  });
  // A new file in the package, or a second script, would escape the allowlist above.
  const files = new Bun.Glob("**/*").scanSync({ cwd: dir, dot: true });
  expect([...files].sort()).toEqual(["icons/icon128.png", "icons/icon16.png", "icons/icon32.png", "icons/icon48.png",
    "manifest.json", "popup.css", "popup.html", "popup.js"]);
});

test("a double click asks for the permission once and revokes once", async () => {
  const p = await openPopup(`${SITE}/app?grant&revoke`);
  await p.dblclick("#grant");
  await waitMsg(p, "Cookies: 6");
  expect(await p.evaluate(() => (window as any).__requestCalls)).toBe(1);
  await p.dblclick("#revoke");
  await waitMsg(p, "Access revoked");
  expect(await p.evaluate(() => (window as any).__removeCalls)).toBe(1);
}, 30_000);

// Last, so it sees the errors of every popup above.
test("no popup threw", () => {
  expect(errors).toEqual([]);
});
