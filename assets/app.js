async function loadFeeds() {
  const res = await fetch("data/feeds.json", { cache: "no-store" });
  if (!res.ok) throw new Error("Failed to load data/feeds.json");
  return res.json();
}

async function loadStatus() {
  try {
    const res = await fetch("data/feed_status.json", { cache: "no-store" });
    if (!res.ok) return null;
    return res.json();
  } catch {
    return null;
  }
}

function esc(s) {
  return String(s ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function badgeHTML(st, err) {
  const status = (st || "unknown").toLowerCase();
  const cls = status === "active" ? "badge badge-active" : status === "down" ? "badge badge-down" : "badge badge-unknown";
  const title = err ? ` title="${esc(err)}"` : "";
  return `<span class="${cls}"${title}>${esc(status)}</span>`;
}

function renderRows(tbody, feeds, statusMap) {
  if (!feeds.length) {
    tbody.innerHTML = `<tr><td colspan="5" class="loading">No results.</td></tr>`;
    return;
  }
  tbody.innerHTML = feeds
    .map((f) => {
      const url = esc(f.url);
      const title = esc(f.title || "");
      const desc = esc(f.description || "");
      const type = esc(f.type || "");
      const st = statusMap?.[f.url]?.status || "unknown";
      const err = statusMap?.[f.url]?.error || "";
      return `
        <tr>
          <td class="col-status">${badgeHTML(st, err)}</td>
          <td class="col-url"><a href="${url}" target="_blank" rel="noreferrer">${url}</a></td>
          <td class="col-title">${title}</td>
          <td class="col-desc">${desc}</td>
          <td class="col-type">${type}</td>
        </tr>
      `.trim();
    })
    .join("");
}

function uniqSorted(arr) {
  return [...new Set(arr.filter(Boolean))].sort((a, b) => a.localeCompare(b));
}

function normalize(s) {
  return String(s ?? "").toLowerCase();
}

function applyFilters(allFeeds, q, type, category, statusFilter, statusMap) {
  const qq = normalize(q).trim();
  const t = normalize(type).trim();
  const c = String(category ?? "").trim();
  return allFeeds.filter((f) => {
  const sf = String(statusFilter || "").toLowerCase();

    if (t && normalize(f.type) !== t) return false;
    if (c && (f.category ?? "") !== c) return false;

    
    if (sf) {
      const st = (statusMap?.[f.url]?.status || "unknown").toLowerCase();
      if (st !== sf) return false;
    }

    if (!qq) return true;
    const hay = `${f.url} ${f.title || ""} ${f.description || ""} ${f.type || ""} ${f.category || ""}`;
    return normalize(hay).includes(qq);
  });
}

(async function main() {
  const tbody = document.getElementById("rows");
  const q = document.getElementById("q");
  const typeFilter = document.getElementById("typeFilter");
  const catFilter = document.getElementById("catFilter");
  const statusFilter = document.getElementById("statusFilter");
  const statusSummary = document.getElementById("statusSummary");
  const meta = document.getElementById("meta");

  try {
    const [data, statusData] = await Promise.all([loadFeeds(), loadStatus()]);
    const all = data.feeds || [];
    const generatedAt = data.generated_at ? new Date(data.generated_at) : null;

    const statusMap = statusData?.results || {};
    const checkedAt = statusData?.checked_at ? new Date(statusData.checked_at) : null;
function computeCounts() {
  let active = 0, down = 0, unknown = 0;
  for (const f of all) {
    const st = (statusMap?.[f.url]?.status || "unknown").toLowerCase();
    if (st === "active") active++;
    else if (st === "down") down++;
    else unknown++;
  }
  return { active, down, unknown, total: all.length };
}

    if (statusFilter && !statusFilter.value) statusFilter.value = "active";

    // categories dropdown
    const cats = uniqSorted(all.map((f) => f.category));
    cats.forEach((c) => {
      const opt = document.createElement("option");
      opt.value = c;
      opt.textContent = `category: ${c}`;
      catFilter.appendChild(opt);
    });

    function update() {
      const filtered = applyFilters(all, q.value, typeFilter.value, catFilter.value, statusFilter?.value, statusMap);
      renderRows(tbody, filtered, statusMap);

      const ga = generatedAt ? generatedAt.toLocaleString() : "unknown";
      const ca = checkedAt ? checkedAt.toLocaleString() : "unknown";
const counts = computeCounts();
if (statusSummary) {
  statusSummary.textContent = `active: ${counts.active} | down: ${counts.down} | unknown: ${counts.unknown} | total: ${counts.total}`;
}
meta.textContent = `showing: ${filtered.length} (feeds.json: ${ga} UTC; status checked: ${ca} UTC)`;
    }

    // live search
    q.addEventListener("input", update);
    typeFilter.addEventListener("change", update);
    catFilter.addEventListener("change", update);
    statusFilter?.addEventListener("change", update);

    update();
  } catch (e) {
    tbody.innerHTML = `<tr><td colspan="5" class="loading">Error: ${esc(e.message)}</td></tr>`;
  }
})();
