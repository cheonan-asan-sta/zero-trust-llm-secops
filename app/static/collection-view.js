/* Read-only navigation of caller-bound unchanged live collections. */
window.CollectionView = class CollectionView {
  constructor(config) {
    this.config = config;
    this.generation = 0;
    this.index = 0;
    this.cursors = [];
    this.page = null;
    this.busy = false;
    const make = (tag, id, text) => {
      const element = document.createElement(tag);
      element.id = config.prefix + id;
      if (text) element.textContent = text;
      return element;
    };
    this.status = make("p", "Status");
    this.status.className = "collection-status";
    this.status.setAttribute("role", "status");
    this.nav = make("nav", "Navigation");
    this.nav.className = "collection-pagination";
    this.nav.setAttribute("aria-label", config.label + " 페이지 탐색");
    const button = (id, text, action) => {
      const element = make("button", id, text);
      element.type = "button";
      element.addEventListener("click", action);
      return element;
    };
    this.previous = button("Previous", "이전 페이지", () => { if (!this.busy && this.page && this.index > 0) this.load(this.index - 1, this.cursors[this.index - 1]); });
    this.next = button("Next", "다음 페이지", () => { if (!this.busy && this.page?.next_cursor) this.load(this.index + 1, this.page.next_cursor); });
    this.reload = button("Reload", "최신 목록 조회", () => this.load());
    this.label = make("span", "Page");
    this.nav.append(this.previous, this.label, this.next, this.reload);
    const tableRegion = config.body.closest(".history-wrap, .table-wrap");
    tableRegion.classList.add("collection-table"); tableRegion.tabIndex = 0;
    tableRegion.setAttribute("role", "region"); tableRegion.setAttribute("aria-label", config.label + " 표, 가로 스크롤 가능");
    this.hint = make("p", "ScrollHint", "표를 옆으로 밀면 모든 열을 확인할 수 있습니다.");
    this.hint.className = "collection-scroll-hint";
    tableRegion.before(this.hint); tableRegion.after(this.status, this.nav);
    this.paint();
  }
  reset() {
    this.generation++;
    this.controller?.abort(); clearTimeout(this.timer);
    this.page = null; this.error = null; this.identity = null; this.scope = null;
    this.cursors = []; this.index = 0; this.busy = false;
    this.paint();
  }
  destroy() {
    this.reset(); this.status.remove(); this.nav.remove(); this.hint.remove();
  }
  message() {
    if (this.busy) return "현재 신원과 목록을 확인하고 있습니다.";
    if (this.error) {
      if ([401, 403].includes(this.error.status) || this.error.callerChanged) return "조회 신원 또는 권한이 변경됐습니다. 연결 및 인증을 다시 적용하세요.";
      if (this.error.status === 409) return "목록 상태가 변경됐습니다. 최신 목록을 다시 조회하세요.";
      if (this.error.status === 410) return "조회 기준이 만료됐습니다. 최신 목록을 다시 조회하세요.";
      if (this.error.status === 501) return "이 환경에서는 해당 목록의 페이지 조회를 지원하지 않습니다.";
      return "목록을 확인할 수 없습니다. 최신 목록을 다시 조회하세요.";
    }
    return this.page ? `현재 ${this.page.items.length}건 · 전체 조건 일치 ${this.page.total_matches}건. 조회 후 상태가 바뀌면 목록을 다시 읽어야 합니다. 상세와 조치는 현재 상태를 별도로 확인합니다.` : "최신 목록 조회를 눌러 시작하세요.";
  }
  paint() {
    this.previous.disabled = this.busy || !this.page || this.index === 0;
    this.next.disabled = this.busy || !this.page?.next_cursor;
    this.reload.disabled = this.busy;
    this.label.textContent = this.page ? `${this.index + 1} / ${Math.max(1, Math.ceil(this.page.total_matches / 12))} 페이지` : "페이지 미확인";
    this.status.textContent = this.message();
    this.status.dataset.error = String(Boolean(this.error));
    this.config.render(this.page?.items || []);
    if (this.page) [...this.config.body.querySelectorAll("tr")].forEach((row, index) => { if (this.page.items[index]) row.dataset.collectionId = this.page.items[index][this.config.id]; });
    this.config.body.setAttribute("aria-busy", String(this.busy));
    if (!this.page) {
      const tr = document.createElement("tr"), td = document.createElement("td");
      td.colSpan = this.config.columns; td.textContent = this.message(); td.className = "table-empty";
      tr.append(td); this.config.body.replaceChildren(tr);
    }
  }
  async load(index = 0, cursor = null) {
    const c = this.config, context = c.context(), filters = c.filters?.() || {};
    if (!context.identity) { this.reset(); this.error = {status: 401}; this.paint(); return; }
    const scope = JSON.stringify(filters), old = this.page, identity = this.identity;
    const cursors = cursor ? [...this.cursors] : [];
    this.controller?.abort(); clearTimeout(this.timer);
    this.controller = new AbortController();
    const generation = ++this.generation;
    this.page = null; this.busy = true; this.error = null;
    if (!cursor) { this.cursors = []; this.index = 0; this.identity = null; }
    this.paint();
    const active = () => generation === this.generation && context.epoch === c.context().epoch && scope === JSON.stringify(c.filters?.() || {});
    const same = (a, b) => Boolean(a && b) && ["subject", "tenant_id", "auth_method"].every(k => typeof a[k] === "string" && a[k].length && a[k] === b[k]);
    const invalid = () => { throw new Error("Invalid live collection page"); };
    const changed = () => Object.assign(new Error("Caller changed"), {callerChanged: true});
    try {
      const options = {epoch: context.epoch, signal: this.controller.signal};
      const before = await c.request("/auth/me", options);
      if (!active()) return;
      if (!same(before, context.identity) || (cursor && !same(before, identity))) throw changed();
      const params = new URLSearchParams({limit: "12"});
      Object.entries(filters).forEach(([key, value]) => { if (value) params.set(key, value); });
      if (cursor) params.set("cursor", cursor);
      const page = await c.request(c.url + "?" + params, options);
      if (!active()) return;
      const after = await c.request("/auth/me", options);
      if (!active()) return;
      if (!same(before, after) || !same(before, c.context().identity)) throw changed();
      const token = value => typeof value === "string" && /^[A-Za-z0-9_-]{1,2048}$/.test(value);
      if (!page || !Array.isArray(page.items) || !Number.isSafeInteger(page.total_matches) || page.total_matches < 0 || page.total_matches > 10000 ||
          !token(page.page_cursor) || !(page.next_cursor === null || token(page.next_cursor)) || typeof page.snapshot_id !== "string" || !/^[a-f0-9]{64}$/.test(page.snapshot_id) ||
          page.snapshot_mode !== "unchanged_live_view" || page.historical_audit_snapshot !== false ||
          typeof page.snapshot_created_at !== "string" || typeof page.snapshot_expires_at !== "string" || !Number.isFinite(Date.parse(page.snapshot_created_at)) ||
          !(Date.parse(page.snapshot_expires_at) > Date.parse(page.snapshot_created_at)) || !(Date.parse(page.snapshot_expires_at) > Date.now())) invalid();
      if (cursor && (!old || this.scope !== scope || ["snapshot_id", "total_matches", "snapshot_created_at", "snapshot_expires_at"].some(k => old[k] !== page[k]))) invalid();
      if (page.items.length !== Math.max(0, Math.min(12, page.total_matches - index * 12)) || (index > 0 && index * 12 >= page.total_matches) ||
          (page.next_cursor !== null) !== (index * 12 + page.items.length < page.total_matches)) invalid();
      const ids = new Set();
      for (const row of page.items) {
        if (!row || row.tenant_id !== before.tenant_id || !c.validate(row) || typeof row[c.id] !== "string" || !row[c.id] || ids.has(row[c.id])) invalid();
        ids.add(row[c.id]);
      }
      if (cursor && index !== this.index && page.items.some(r => old.items.some(o => r[c.id] === o[c.id]))) invalid();
      cursors[index] = page.page_cursor;
      if (page.next_cursor) cursors[index + 1] = page.next_cursor;
      Object.assign(this, {page, index, identity: before, scope, cursors: cursors.slice(0, index + (page.next_cursor ? 2 : 1))});
      this.timer = setTimeout(() => {
        if (active() && this.page === page) { this.page = null; this.cursors = []; this.error = {status: 410}; this.paint(); }
      }, Math.min(2147483647, Math.max(0, Date.parse(page.snapshot_expires_at) - Date.now())));
    } catch (error) {
      if (active()) {
        this.page = null; this.cursors = []; this.error = error;
        if (error.callerChanged || [401, 403].includes(error.status)) c.authorityError?.(error);
      }
    } finally {
      if (active()) { this.busy = false; this.paint(); }
    }
  }
};
