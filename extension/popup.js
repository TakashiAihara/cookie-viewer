// Cookie の値は信頼できない入力なので、DOM には textContent でだけ入れる (innerHTML は使わない)。
const $ = (id) => document.getElementById(id);
let cookies = [];

function attrs(c) {
  const a = [];
  if (c.secure) a.push("Secure");
  if (c.httpOnly) a.push("HttpOnly");
  if (c.sameSite && c.sameSite !== "unspecified") a.push("SameSite=" + c.sameSite);
  if (c.partitionKey) a.push("Partitioned");
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
  const q = $("filter").value.toLowerCase();
  const reveal = $("reveal").checked;
  const tbody = $("tbl").tBodies[0];
  tbody.replaceChildren();
  for (const c of cookies.filter((c) => c.name.toLowerCase().includes(q))) {
    const tr = tbody.insertRow();
    cell(tr, c.name, "v");
    cell(tr, reveal ? c.value : "•".repeat(Math.min(c.value.length, 12)), "v");
    cell(tr, c.domain + c.path);
    cell(tr, attrs(c));
    const btn = document.createElement("button");
    btn.textContent = "copy";
    btn.onclick = () => navigator.clipboard.writeText(c.value).then(() => (btn.textContent = "ok"));
    tr.insertCell().append(btn);
  }
  $("tbl").hidden = false;
  $("msg").textContent = cookies.length + " 件";
}

async function load(url) {
  cookies = await chrome.cookies.getAll({ url });
  cookies.sort((a, b) => a.name.localeCompare(b.name));
  render();
}

(async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const url = tab && tab.url;
  if (!url || !/^https?:/.test(url)) {
    $("msg").textContent = "http / https のページでだけ使えます";
    return;
  }
  $("host").textContent = new URL(url).host;
  const origins = [new URL(url).origin + "/*"];

  if (await chrome.permissions.contains({ origins })) return load(url);

  $("grant").hidden = false;
  $("grant").onclick = async () => {
    if (await chrome.permissions.request({ origins })) {
      $("grant").hidden = true;
      load(url);
    }
  };
})();

$("filter").oninput = render;
$("reveal").onchange = render;
