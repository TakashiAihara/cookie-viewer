// Cookie values are untrusted input, so they reach the DOM only through textContent (never innerHTML).
const $ = (id) => document.getElementById(id);
// Turns the chrome.cookies sameSite value into the attribute as written in Set-Cookie.
function sameSiteAttr(v) {
  if (v === "lax") return "Lax";
  if (v === "strict") return "Strict";
  if (v === "no_restriction") return "None";
  return "";
}
let cookies = null;

function chip(el, text, cls, title) {
  const s = document.createElement("span");
  s.textContent = text;
  s.className = cls;
  if (title) s.setAttribute("title", title);
  if (el.firstChild) el.append(" ");
  el.append(s);
}

// Lax and Strict show only the value to keep common rows on one line. None, the weakest setting, is spelled out:
// a bare "None" reads as "no attributes", and a tooltip cannot be reached from the keyboard.
function attrs(td, c) {
  td.className = "at";
  if (c.secure) chip(td, "Secure", "chip secure");
  if (c.httpOnly) chip(td, "HttpOnly", "chip httponly");
  const ss = sameSiteAttr(c.sameSite);
  if (ss === "None") chip(td, "SameSite=None", "chip weak");
  else if (ss) chip(td, ss, "chip", "SameSite=" + ss);
  if (c.partitionKey) {
    const k = [c.partitionKey.topLevelSite, c.partitionKey.hasCrossSiteAncestor && "cross-site"].filter(Boolean);
    chip(td, k.length ? "Partitioned(" + k.join(", ") + ")" : "Partitioned", "chip");
  }
  chip(td, c.session ? "Session" : new Date(c.expirationDate * 1000).toLocaleString([], { dateStyle: "short", timeStyle: "short" }), "exp");
}

function cell(tr, text, cls) {
  const td = tr.insertCell();
  td.textContent = text;
  if (cls) td.className = cls;
  return td;
}

function render() {
  if (!cookies) return;
  const q = $("filter").value.toLowerCase();
  const reveal = $("reveal").checked;
  const shown = cookies.filter((c) => c.name.toLowerCase().includes(q));
  const tbody = $("rows");
  tbody.replaceChildren();
  for (const c of shown) {
    const tr = tbody.insertRow();
    cell(tr, c.name, "v");
    cell(tr, reveal ? c.value : "••••••••", "v");
    cell(tr, c.domain + c.path, "dp");
    attrs(tr.insertCell(), c);
    const btn = document.createElement("button");
    btn.textContent = "copy";
    btn.setAttribute("aria-label", "copy value of " + c.name);
    btn.onclick = () =>
      navigator.clipboard.writeText(c.value).then(
        () => (btn.textContent = "ok"),
        () => (btn.textContent = "failed"),
      );
    tr.insertCell().append(btn);
  }
  $("tbl").hidden = false;
  $("msg").textContent = "Cookies: " + (q ? shown.length + " / " : "") + cookies.length;
}

async function load(url) {
  try {
    // partitionKey: {} returns partitioned cookies (CHIPS) from every partition as well as unpartitioned ones;
    // without it only the latter come back. The API reference does not say so: the basis is Chromium 119's
    // cookies_helpers.cc (no topLevelSite means all partitions) and a measurement.
    cookies = await chrome.cookies.getAll({ url, partitionKey: {} });
  } catch (e) {
    $("msg").textContent = "Could not read cookies: " + e.message;
    return;
  }
  cookies.sort((a, b) => a.name.localeCompare(b.name));
  render();
}

function offerRevoke(url, origins) {
  $("revoke").hidden = false;
  $("revoke").onclick = async () => {
    $("revoke").disabled = true;
    try {
      if (!(await chrome.permissions.remove({ origins }))) {
        $("msg").textContent = "Could not revoke access";
        return;
      }
      // remove only drops the exact pattern, so a broader grant (such as "On all sites") still allows reading.
      if (await chrome.permissions.contains({ origins })) {
        $("msg").textContent = "This site is still allowed by \"Site access\" in chrome://extensions, so it cannot be revoked here";
        return;
      }
    } catch (e) {
      $("msg").textContent = "Could not revoke access: " + e.message;
      return;
    } finally {
      $("revoke").disabled = false;
    }
    cookies = null;
    $("tbl").hidden = true;
    $("rows").replaceChildren();
    $("revoke").hidden = true;
    $("msg").textContent = "Access revoked";
    askGrant(url, origins);
  };
}

function askGrant(url, origins) {
  $("grant").hidden = false;
  $("grant").onclick = async () => {
    $("grant").disabled = true;
    let granted;
    try {
      granted = await chrome.permissions.request({ origins });
    } catch (e) {
      $("msg").textContent = "Could not ask for access: " + e.message;
      return;
    } finally {
      $("grant").disabled = false;
    }
    if (!granted) {
      $("msg").textContent = "Access was not granted";
      return;
    }
    $("grant").hidden = true;
    await showGranted(url, origins);
  };
}

// The revoke button appears only once the list has loaded; shown earlier, a load finishing after a revoke
// would bring the list back. It appears even if loading failed, because the site is still granted.
async function showGranted(url, origins) {
  await load(url);
  offerRevoke(url, origins);
}

(async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const url = tab && tab.url;
  if (!url || !/^https?:/.test(url)) {
    $("msg").textContent = "Works only on http / https pages";
    return;
  }
  const siteOrigin = new URL(url).origin;
  $("host").textContent = siteOrigin;
  const origins = [siteOrigin + "/*"];

  if (await chrome.permissions.contains({ origins })) await showGranted(url, origins);
  else askGrant(url, origins);
})();

$("filter").oninput = render;
$("reveal").onchange = render;
