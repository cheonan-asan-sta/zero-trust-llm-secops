/* Tenant-scoped login queue review. The browser sends review metadata only. */
(() => {
  "use strict";
  const $ = (id) => document.getElementById("loginQueue" + id);
  const ctx = window.dashboardContext;
  const {request, node, errorLabel} = ctx;
  const alertNames = {
    C01LoginQueueStatusUnavailable: "대기열 상태 확인 실패",
    C01LoginQueueBacklog: "대기 시간 확인 필요",
    C01LoginQueueHeld: "보류 항목 확인 필요",
    C01LoginQueueCapacityPressure: "대기열 용량 경고",
  };
  const outcomes = {approved: "승인·재전송 등록", deferred: "재시도 대기", held_again: "다시 보류", delivered: "분석 결과 확인"};
  const evidenceStates = {verified: "인증 근거 검증됨", missing: "인증 근거 없음", expired: "인증 근거 만료"};
  const reviewLabels = {
    expired_device_priority: "우선 검토 · 당시 회수 기기",
    verified_priority: "우선 검토 · 검증된 회수 기기",
    required: "운영자 검토 필요",
    not_required: "분석 당시 검토 불필요",
  };
  const causes = {
    transport_timeout: "연결 시간 초과", transport_connect: "API 연결 실패",
    transport_interrupted: "전송 중 연결 중단", receipt_invalid: "확인 응답 형식 오류",
    receipt_mismatch: "확인 응답과 이벤트 불일치",
    http_401: "인증 또는 근거 확인 실패", http_403: "권한 거부",
    http_409: "이벤트 내용 충돌", http_429: "API 요청 제한", http_503: "API 사용 불가",
  };
  const timestamp = (value) => value && Number.isFinite(Date.parse(value))
    ? new Date(value).toLocaleString("ko-KR", {hour12: false}) : "—";
  const cause = (row) => [
    causes[row.failure_code] ?? row.failure_code, row.http_status ? "HTTP " + row.http_status : null,
  ].filter(Boolean).join(" · ") || "—";
  let generation = 0;
  let scope = "";
  let loading = false;
  let reviewing = false;
  let selection = null;
  let after = 0;
  let next = null;
  let eventFilter = "";

  function clearForm(focus = false) {
    const trigger = selection?.trigger;
    selection = null;
    $("Approval").hidden = true;
    $("Approval").reset();
    $("Selected").textContent = "";
    if (focus && trigger?.isConnected) trigger.focus();
  }

  function clearView() {
    $("Summary").hidden = true;
    $("Review").hidden = true;
    for (const id of ["Summary", "HeldRows", "HistoryRows", "Alerts"]) $(id).replaceChildren();
  }

  function reset() {
    generation++;
    scope = "";
    loading = reviewing = false;
    after = 0;
    next = null;
    eventFilter = "";
    $("Search").reset();
    clearForm();
    clearView();
    $("Approve").disabled = $("Cancel").disabled = false;
    $("Status").textContent = "조회 신원을 확인한 뒤 대기열을 불러옵니다.";
    $("Refresh").disabled = true;
  }

  function select(row, identity, trigger) {
    if (reviewing) return;
    selection = {row, identity, trigger};
    $("Selected").textContent = [
      row.event_id, cause(row), "마지막 시도 " + timestamp(row.last_attempt_at), "시도 " + row.attempts + "회",
    ].join(" · ");
    $("Approval").hidden = false;
    $("Note").value = "";
    $("Note").focus();
  }

  function tableRow(values) {
    const row = node("tr");
    for (const value of values) row.append(node("td", value ?? "—"));
    return row;
  }

  function historyRow(entry) {
    const observed = timestamp(entry.observed_at);
    const detail = entry.actor
      ? [entry.actor, entry.note, cause(entry)].join(" · ")
      : entry.analysis_id
        ? (entry.duplicate ? "기존 결과 확인" : "분석 ID") + " · " + entry.analysis_id
        : cause(entry);
    const row = tableRow(["", entry.event_id, observed, detail]);
    const status = row.firstElementChild;
    status.append(node("strong", outcomes[entry.outcome]));
    if (entry.outcome === "delivered") {
      status.append(node("span", evidenceStates[entry.evidence_state] ?? "근거 상태 미기록", "login-queue-history-meta"));
      const decision = reviewLabels[entry.review_kind];
      if (decision) status.append(node("span", decision, "login-queue-history-review"));
    }
    status.append(node("span", observed + " · " + detail, "login-queue-history-mobile login-queue-history-meta"));
    return row;
  }

  function render(payload) {
    const queue = payload.queue;
    const metrics = queue ? [
      ["대기", queue.pending], ["보류", queue.held],
      ["가장 오래된 대기", timestamp(queue.oldest_pending_at)],
    ] : [];
    if (queue?.pending_age_unknown) metrics.push(["대기 시각 미확인", queue.pending_age_unknown]);
    $("Summary").replaceChildren(...metrics.map(([label, value]) => {
      const item = node("div");
      item.append(node("dt", label), node("dd", value));
      return item;
    }));
    $("Summary").hidden = !queue;
    const alerts = payload.alerts;
    $("Alerts").replaceChildren();
    if (alerts.state === "ready" && alerts.entries.length) {
      for (const entry of alerts.entries) {
        const label = alertNames[entry.name] ?? entry.name;
        const firing = entry.state === "firing";
        $("Alerts").append(node("li", label + " · " + (firing ? "발화 중" : "조건 확인 중"), firing ? "pill red" : "pill amber"));
      }
    } else {
      $("Alerts").append(node("li", {
        ready: "현재 경보 없음", disabled: "경보 연결 설정이 필요합니다.",
        unavailable: "현재 경보를 확인할 수 없습니다.",
      }[alerts.state]));
    }
    const review = payload.review;
    $("Review").hidden = !review;
    if (!review) return;
    $("HeldEmpty").hidden = review.held.length > 0;
    $("HeldTable").hidden = !review.held.length;
    $("HeldRows").replaceChildren(...review.held.map((entry) => {
      const row = tableRow([entry.event_id, cause(entry), timestamp(entry.last_attempt_at), entry.attempts]);
      const cell = node("td");
      const button = node("button", "검토", "button");
      button.type = "button";
      button.setAttribute("aria-label", entry.event_id + " 보류 검토");
      button.addEventListener("click", () => select(entry, review.identity, button));
      cell.append(button);
      row.append(cell);
      return row;
    }));
    next = review.next_after;
    $("Pager").hidden = after === 0 && next === null;
    $("First").disabled = after === 0;
    $("Next").disabled = next === null;
    $("HistoryEmpty").hidden = review.history.length > 0;
    $("HistoryTable").hidden = !review.history.length;
    $("HistoryRows").replaceChildren(...review.history.map(historyRow));
  }

  async function load(message) {
    if (!scope || loading || reviewing || selection) return;
    const ticket = generation;
    loading = true;
    $("Refresh").disabled = true;
    if ($("Summary").hidden) $("Status").textContent = "대기열을 불러오고 있습니다.";
    try {
      const params = new URLSearchParams({after: String(after)});
      if (eventFilter) params.set("event_id", eventFilter);
      const data = await request("/dashboard/login-queue?" + params);
      if (ticket !== generation || selection) return;
      render(data);
      $("Status").textContent = message ?? (!data.queue ? "대기열 상태를 확인할 수 없습니다." :
        data.review ? "" : "보류 원인과 재전송 이력은 대응 권한으로 조회합니다.");
    } catch (error) {
      if (ticket !== generation || selection) return;
      clearView();
      $("Status").textContent = error.status === 404 ? "로그인 대기열이 설정되지 않았습니다." : errorLabel(error);
    } finally {
      if (ticket === generation) {
        loading = false;
        $("Refresh").disabled = false;
      }
    }
  }

  function sync() {
    const {page, epoch, data} = ctx.state;
    const who = data.identity;
    const key = page === "evidence" && who ? JSON.stringify([epoch, who.subject, who.tenant_id, who.auth_method, who.roles]) : "";
    if (key !== scope) {
      reset();
      scope = key;
    }
    if (scope) void load();
  }

  $("Refresh").addEventListener("click", () => { clearForm(); void load(); });
  $("Search").addEventListener("submit", (event) => {
    event.preventDefault();
    if (loading || reviewing) return;
    eventFilter = $("EventFilter").value.trim();
    after = 0;
    clearForm();
    void load();
  });
  function changePage(cursor) {
    if (cursor === null || loading || reviewing) return;
    after = cursor;
    clearForm();
    void load();
  }

  $("First").addEventListener("click", () => changePage(0));
  $("Next").addEventListener("click", () => changePage(next));
  $("Cancel").addEventListener("click", () => clearForm(true));
  $("Approval").addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!selection || reviewing) return;
    const note = $("Note").value.trim();
    if (note.length < 3) {
      $("Status").textContent = "확인한 원인과 조치를 세 글자 이상 입력하세요.";
      $("Note").focus();
      return;
    }
    const {row, identity} = selection;
    const ticket = generation;
    reviewing = true;
    $("Approve").disabled = $("Cancel").disabled = $("Refresh").disabled = true;
    let message;
    try {
      await request("/dashboard/login-queue/approvals", {
        method: "POST", body: {event_id: row.event_id, hold_id: row.hold_id, note},
        ifMatch: row.etag, reviewIdentity: identity,
      });
      if (ticket !== generation) return;
      clearForm(true);
      message = "승인을 기록하고 분석 재전송 대기열에 넣었습니다.";
    } catch (error) {
      if (ticket !== generation) return;
      if ([401, 403, 409, 412, 428].includes(error.status)) {
        clearForm(true);
        message = error.status === 412 ? "보류 상태가 바뀌었습니다. 최신 원인을 확인한 뒤 다시 승인하세요." : errorLabel(error);
      } else {
        $("Status").textContent = errorLabel(error);
      }
    } finally {
      if (ticket === generation) {
        reviewing = false;
        $("Approve").disabled = $("Cancel").disabled = $("Refresh").disabled = false;
      }
    }
    if (message) void load(message);
  });

  window.dashboardLoginQueue = {sync, reset};
  reset();
  sync();
})();
