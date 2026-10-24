import { afterAll, beforeAll, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { chromium, type BrowserContext } from "playwright";

const XSS = "<img src=x onerror=document.title='pwned'>";
let server: ReturnType<typeof Bun.serve>;
let ctx: BrowserContext;
let extId: string;
const tmp = mkdtempSync(join(tmpdir(), "cookie-viewer-test-"));

// Chrome derives an unpacked extension's id from its absolute path.
function unpackedId(path: string) {
  const hex = createHash("sha256").update(path).digest("hex").slice(0, 32);
  return [...hex].map((c) => String.fromCharCode(97 + parseInt(c, 16))).join("");
}

beforeAll(async () => {
  server = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    fetch: () => {
      const h = new Headers({ "content-type": "text/html" });
      h.append("set-cookie", "plain=hello; Path=/");
      h.append("set-cookie", "sid=secret123; Path=/; HttpOnly; SameSite=Strict");
      h.append("set-cookie", `xss=${XSS}; Path=/`);
      return new Response("ok", { headers: h });
    },
  });

  // Host permission is pre-granted for 127.0.0.1 only, so localhost exercises the "not granted" path.
  const ext = join(tmp, "ext");
  cpSync(resolve(import.meta.dir, "../extension"), ext, { recursive: true });
  const manifest = JSON.parse(readFileSync(join(ext, "manifest.json"), "utf8"));
  manifest.host_permissions = ["http://127.0.0.1/*"];
  writeFileSync(join(ext, "manifest.json"), JSON.stringify(manifest));
  extId = unpackedId(ext);

  ctx = await chromium.launchPersistentContext(join(tmp, "profile"), {
    channel: "chromium",
    args: [`--disable-extensions-except=${ext}`, `--load-extension=${ext}`],
  });
  // A popup opened as a tab would query itself as the active tab, so the target URL comes from the hash.
  await ctx.addInitScript(() => {
    if (location.protocol === "chrome-extension:" && location.hash) {
      const url = decodeURIComponent(location.hash.slice(1));
      chrome.tabs.query = (async () => [{ url }]) as typeof chrome.tabs.query;
    }
  });
  await (await ctx.newPage()).goto(`http://127.0.0.1:${server.port}/`);
}, 60_000);

afterAll(async () => {
  await ctx?.close();
  server?.stop();
  rmSync(tmp, { recursive: true, force: true });
});

async function openPopup(target: string) {
  const p = await ctx.newPage();
  await p.goto(`chrome-extension://${extId}/popup.html#${encodeURIComponent(target)}`);
  return p;
}

test("lists the cookies sent to the page, values masked until revealed", async () => {
  const p = await openPopup(`http://127.0.0.1:${server.port}/`);
  await expect(p.locator("#msg")).toBeDefined();
  await p.waitForFunction(() => document.getElementById("msg")!.textContent === "3 件");

  const rows = () => p.$$eval("tbody tr", (trs) => trs.map((tr) => [...tr.cells].map((td) => td.textContent)));
  const masked = await rows();
  expect(masked.map((r) => r[0])).toEqual(["plain", "sid", "xss"]);
  expect(masked.find((r) => r[0] === "sid")![1]).toBe("•••••••••");
  expect(masked.find((r) => r[0] === "sid")![3]).toContain("HttpOnly");
  expect(masked.find((r) => r[0] === "sid")![3]).toContain("SameSite=strict");

  await p.check("#reveal");
  const shown = await rows();
  expect(shown.find((r) => r[0] === "sid")![1]).toBe("secret123");
  expect(shown.find((r) => r[0] === "xss")![1]).toBe(XSS);
  expect(await p.locator("tbody img").count()).toBe(0);
  expect(await p.title()).not.toBe("pwned");

  await p.fill("#filter", "pla");
  expect((await rows()).map((r) => r[0])).toEqual(["plain"]);
});

test("asks for permission instead of reading a site that was not granted", async () => {
  const p = await openPopup(`http://localhost:${server.port}/`);
  await p.waitForSelector("#grant:not([hidden])");
  expect(await p.locator("#tbl").isHidden()).toBe(true);
});

test("refuses non-http pages", async () => {
  const p = await openPopup("chrome://settings/");
  await p.waitForFunction(() => document.getElementById("msg")!.textContent!.includes("http / https"));
});
