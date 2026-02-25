const THEME_KEY = "asf-theme";

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

function normalize(s) {
  return String(s ?? "").toLowerCase();
}

function getSystemTheme() {
  return window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}

function getStoredTheme() {
  try {
    const value = localStorage.getItem(THEME_KEY);
    return value === "dark" || value === "light" ? value : "";
  } catch {
    return "";
  }
}

function setTheme(theme, persist = true) {
  const next = theme === "dark" ? "dark" : "light";
  document.documentElement.dataset.theme = next;
  if (persist) {
    try {
      localStorage.setItem(THEME_KEY, next);
    } catch {
      // no-op
    }
  }
  syncThemeToggle();
}

function syncThemeToggle() {
  const button = document.getElementById("themeToggle");
  const text = document.getElementById("themeToggleText");
  if (!button) return;

  const current = document.documentElement.dataset.theme === "dark" ? "dark" : "light";
  const next = current === "dark" ? "light" : "dark";

  button.setAttribute("aria-pressed", String(current === "dark"));
  button.setAttribute("title", `Switch to ${next} mode`);
  button.setAttribute("aria-label", `Switch to ${next} mode`);
  if (text) text.textContent = current === "dark" ? "Dark" : "Light";
}

function initThemeToggle() {
  const button = document.getElementById("themeToggle");
  if (!button) return;

  syncThemeToggle();
  button.addEventListener("click", () => {
    const current = document.documentElement.dataset.theme === "dark" ? "dark" : "light";
    setTheme(current === "dark" ? "light" : "dark", true);
  });

  const media = window.matchMedia ? window.matchMedia("(prefers-color-scheme: dark)") : null;
  if (media && typeof media.addEventListener === "function") {
    media.addEventListener("change", () => {
      if (!getStoredTheme()) {
        setTheme(getSystemTheme(), false);
      }
    });
  }
}

function badgeHTML(st, err) {
  const status = (st || "unknown").toLowerCase();
  const cls =
    status === "active"
      ? "badge badge-active"
      : status === "down"
        ? "badge badge-down"
        : "badge badge-unknown";
  const title = err ? ` title="${esc(err)}"` : "";
  return `<span class="${cls}"${title}>${esc(status)}</span>`;
}

function displayTitle(feed) {
  return (feed.title || "").trim() || "(untitled)";
}

function renderRows(tbody, feeds, statusMap) {
  if (!feeds.length) {
    tbody.innerHTML = '<tr><td colspan="5" class="loading">No results match the current filters.</td></tr>';
    return;
  }

  tbody.innerHTML = feeds
    .map((f) => {
      const url = esc(f.url);
      const title = esc(displayTitle(f));
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
          <td class="col-type">${type || "-"}</td>
        </tr>
      `.trim();
    })
    .join("");
}

function uniqSorted(arr) {
  return [...new Set(arr.filter(Boolean))].sort((a, b) => a.localeCompare(b));
}

function applyFilters(allFeeds, q, type, category, statusFilter, statusMap) {
  const qq = normalize(q).trim();
  const t = normalize(type).trim();
  const c = String(category ?? "").trim();
  const sf = String(statusFilter || "").toLowerCase();

  return allFeeds.filter((f) => {
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

function computeCounts(allFeeds, statusMap) {
  let active = 0;
  let down = 0;
  let unknown = 0;

  for (const f of allFeeds) {
    const st = (statusMap?.[f.url]?.status || "unknown").toLowerCase();
    if (st === "active") active += 1;
    else if (st === "down") down += 1;
    else unknown += 1;
  }

  return { active, down, unknown, total: allFeeds.length };
}

function formatTimestamp(isoString) {
  if (!isoString) return "unknown";
  const d = new Date(isoString);
  if (Number.isNaN(d.getTime())) return "unknown";
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(d);
}

(function bootTheme() {
  const stored = getStoredTheme();
  if (!document.documentElement.dataset.theme) {
    document.documentElement.dataset.theme = stored || getSystemTheme();
  }
  initThemeToggle();
})();

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
    const all = Array.isArray(data.feeds) ? data.feeds : [];
    const statusMap = statusData?.results || {};

    if (statusFilter && !statusFilter.value) statusFilter.value = "active";

    const cats = uniqSorted(all.map((f) => f.category));
    cats.forEach((c) => {
      const opt = document.createElement("option");
      opt.value = c;
      opt.textContent = `category: ${c}`;
      catFilter.appendChild(opt);
    });

    const counts = computeCounts(all, statusMap);
    const generatedAt = formatTimestamp(data.generated_at);
    const checkedAt = formatTimestamp(statusData?.checked_at);

    function update() {
      const filtered = applyFilters(all, q.value, typeFilter.value, catFilter.value, statusFilter?.value, statusMap);
      renderRows(tbody, filtered, statusMap);

      if (statusSummary) {
        statusSummary.textContent = `active ${counts.active} | down ${counts.down} | unknown ${counts.unknown} | total ${counts.total}`;
      }
      if (meta) {
        meta.textContent = `showing ${filtered.length} | feeds.json ${generatedAt} | status ${checkedAt}`;
      }
    }

    q.addEventListener("input", update);
    typeFilter.addEventListener("change", update);
    catFilter.addEventListener("change", update);
    statusFilter?.addEventListener("change", update);

    update();
  } catch (e) {
    tbody.innerHTML = `<tr><td colspan="5" class="loading">Error: ${esc(e.message)}</td></tr>`;
  }
})();
