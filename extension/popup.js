// Cookie の値は信頼できない入力なので、DOM には textContent でだけ入れる (innerHTML は使わない)。
const $ = (id) => document.getElementById(id);
const SAME_SITE = { lax: "Lax", strict: "Strict", no_restriction: "None" };
let cookies = null;

function attrs(c) {
  const a = [];
  if (c.secure) a.push("Secure");
  if (c.httpOnly) a.push("HttpOnly");
  if (SAME_SITE[c.sameSite]) a.push("SameSite=" + SAME_SITE[c.sameSite]);
  if (c.partitionKey) {
    const k = [c.partitionKey.topLevelSite, c.partitionKey.hasCrossSiteAncestor && "cross-site"].filter(Boolean);
    a.push(k.length ? "Partitioned(" + k.join(", ") + ")" : "Partitioned");
  }
  a.push(c.session ? "Session" : new Date(c.expirationDate * 1000).toLocaleString());
  return a.join(" ");
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
  const tbody = $("tbl").tBodies[0];
  tbody.replaceChildren();
  for (const c of shown) {
    const tr = tbody.insertRow();
    cell(tr, c.name, "v");
    cell(tr, reveal ? c.value : "••••••••", "v");
    cell(tr, c.domain + c.path);
    cell(tr, attrs(c));
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
  $("msg").textContent = (q ? shown.length + " / " : "") + cookies.length + " 件";
}

async function load(url) {
  try {
    // partitionKey: {} で、パーティション無しに加えて全パーティションの Cookie (CHIPS) も返る。省くと前者だけになる。
    // API リファレンスには書かれておらず、根拠は Chromium 119 の cookies_helpers.cc (topLevelSite が無ければ全件) と実測。
    cookies = await chrome.cookies.getAll({ url, partitionKey: {} });
  } catch (e) {
    $("msg").textContent = "読み込めませんでした: " + e.message;
    return;
  }
  cookies.sort((a, b) => a.name.localeCompare(b.name));
  render();
}

function offerRevoke(url, origins) {
  $("revoke").hidden = false;
  $("revoke").onclick = async () => {
    try {
      if (!(await chrome.permissions.remove({ origins }))) {
        $("msg").textContent = "取り消せませんでした";
        return;
      }
      // remove は一致するパターンしか外さないので、「すべてのサイト」などで許可されていると読める状態が残る。
      if (await chrome.permissions.contains({ origins })) {
        $("msg").textContent = "このサイトは chrome://extensions の「サイトへのアクセス」で許可されているため、ここでは取り消せません";
        return;
      }
    } catch (e) {
      $("msg").textContent = "取り消せませんでした: " + e.message;
      return;
    }
    cookies = null;
    $("tbl").hidden = true;
    $("tbl").tBodies[0].replaceChildren();
    $("revoke").hidden = true;
    $("msg").textContent = "許可を取り消しました";
    askGrant(url, origins);
  };
}

function askGrant(url, origins) {
  $("grant").hidden = false;
  $("grant").onclick = async () => {
    let granted;
    try {
      granted = await chrome.permissions.request({ origins });
    } catch (e) {
      $("msg").textContent = "許可を求められませんでした: " + e.message;
      return;
    }
    if (!granted) {
      $("msg").textContent = "許可されませんでした";
      return;
    }
    $("grant").hidden = true;
    await showGranted(url, origins);
  };
}

// 取り消しボタンは読み込みが終わってから出す。先に出すと、取り消した後に読み込みが終わって一覧が戻る。
async function showGranted(url, origins) {
  await load(url);
  if (cookies) offerRevoke(url, origins);
}

(async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const url = tab && tab.url;
  if (!url || !/^https?:/.test(url)) {
    $("msg").textContent = "http / https のページでだけ使えます";
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
