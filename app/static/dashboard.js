/* Same-origin observation UI. Credentials and demonstration capabilities stay in memory. */
(() => {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const pages = {
    overview: ["관제 개요", "보안 운영 현황", "접근 판단부터 세션 회수까지, 현재 상태를 한눈에 확인하세요."],
    logs: ["로그 탐색", "보안 로그 탐색", "위험도와 근거를 살피고, 개별 분석의 원문을 확인하세요."],
    sessions: ["세션과 접근", "세션과 접근 판단", "인증 이후에도 달라지는 신뢰 상태와 판단 이력을 확인하세요."],
    evidence: ["증거와 승인", "판단의 근거와 승인", "행위 문맥과 고위험 대응 요청을 현재 신원의 조회 범위에서 확인하세요."],
    demo: ["시연 시나리오", "지속 검증 시연", "합성 입력으로 실제 로컬 접근 정책의 동작을 확인하세요."],
  };
  const tones = {
    LOW: "teal",
    MEDIUM: "amber",
    HIGH: "red",
    CRITICAL: "purple",
    ALLOW: "teal",
    STEP_UP: "amber",
    HOLD: "amber",
    DENY: "red"
  };
  const colors = {
    LOW: "#50d6bc",
    MEDIUM: "#e7b86b",
    HIGH: "#f57a87",
    CRITICAL: "#b29bea"
  };
  const reviews = {
    PENDING: "검토 대기",
    IN_REVIEW: "조사 중",
    RESOLVED: "해결 완료",
    DISMISSED: "오탐 처리",
    NOT_REQUIRED: "검토 불필요"
  };
  const decisions = {
    ALLOW: "접근 허용",
    STEP_UP: "추가 인증",
    HOLD: "판단 보류",
    DENY: "접근 거부"
  };
  const actions = {
    ALLOW: "허용",
    REQUIRE_MFA: "추가 인증",
    REDUCE_PRIVILEGE: "권한 축소",
    ISOLATE_SESSION: "세션 격리",
    HOLD_FOR_REVIEW: "검토 후 결정"
  };
  const violations = {
    NORMAL: "정상 활동",
    CREDENTIAL_ANOMALY: "인증 이상",
    UNMANAGED_DEVICE: "미관리 기기",
    PRIVILEGE_ESCALATION: "권한 상승",
    LATERAL_MOVEMENT: "내부 이동",
    DATA_EXFILTRATION: "데이터 반출",
    UNKNOWN: "분류 미확정"
  };
  const endpoints = {
    health: "/health",
    identity: "/auth/me",
    metrics: "/metrics",
    logs: "/results?limit=100",
    sessions: "/zero-trust/sessions",
    signals: "/zero-trust/signals/status",
    inbox: "/zero-trust/signals/inbox"
  };
  const state = {
    page: "overview",
    credential: "",
    credentialType: "none",
    epoch: 0,
    controllers: new Set(),
    data: {},
    errors: {},
    pageNumber: 1,
    busy: false,
    detailSequence: 0,
    demo: {},
    toastTimer: null
  };
  const text = (id, value) => {
    $(id).textContent = value ?? "—";
  };
  const node = (tag, value, className) => {
    const item = document.createElement(tag);
    if (value !== undefined && value !== null) item.textContent = String(value);
    if (className) item.className = className;
    return item;
  };
  const num = (value) => typeof value === "number" && Number.isFinite(value) ? value.toLocaleString("ko-KR") : "—";
  const date = (value, full = false) => {
    const stamp = new Date(value);
    if (!value || Number.isNaN(stamp.getTime())) return "—";
    return stamp.toLocaleString("ko-KR", full ? {
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false
    } : {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false
    });
  };
  const badge = (value, tone = "neutral") => node("span", value, `pill ${tone}`);
  const empty = (message) => node("p", message, "empty");

  function errorLabel(error) {
    if (error.invalidResponse) return "서버 응답 형식을 확인할 수 없습니다. 데이터를 정상 결과로 표시하지 않습니다.";
    if (error.status === 401) return "인증이 필요합니다. 연결 및 인증에서 키를 입력하세요.";
    if (error.status === 403) return "조회 권한이 없습니다. 역할과 전송 신원을 확인하세요.";
    if (error.status === 404 || error.status === 503) return `이 기능을 조회할 수 없습니다 (HTTP ${error.status}). 서버 설정과 저장소를 확인하세요.`;
    if (error.name === "AbortError") return "요청 시간이 초과되었습니다. 다시 조회하세요.";
    return error.status ? `요청에 실패했습니다 (HTTP ${error.status}).` : "서버에 연결할 수 없습니다. 다시 조회하세요.";
  }

  function notify(message) {
    text("toast", message);
    $("toast").hidden = false;
    clearTimeout(state.toastTimer);
    state.toastTimer = setTimeout(() => {
      $("toast").hidden = true;
    }, 4500);
  }
  async function request(path, {
    body,
    allowDenied = false
  } = {}) {
    const epoch = state.epoch;
    const controller = new AbortController();
    state.controllers.add(controller);
    const timeout = setTimeout(() => controller.abort(), 12000);
    const headers = {
      Accept: "application/json"
    };
    if (state.credentialType === "api_key" && state.credential) headers["X-API-Key"] = state.credential;
    if (state.credentialType === "bearer" && state.credential) headers.Authorization = `Bearer ${state.credential}`;
    if (body !== undefined) headers["Content-Type"] = "application/json";
    try {
      const response = await fetch(path, {
        method: body === undefined ? "GET" : "POST",
        headers,
        body: body === undefined ? undefined : JSON.stringify(body),
        signal: controller.signal,
        cache: "no-store",
        redirect: "error"
      });
      if (epoch !== state.epoch) throw new DOMException("Connection changed", "AbortError");
      if (!response.ok && !(allowDenied && response.status === 403)) throw Object.assign(new Error("Request failed"), {
        status: response.status
      });
      let data;
      try {
        data = await response.json();
      } catch {
        throw Object.assign(new Error("Invalid JSON response"), {
          invalidResponse: true
        });
      }
      if (path === "/health" && response.headers.get("X-Secops-Data-Scope") === "synthetic-dashboard-demo") data.dashboard_demo = true;
      if (epoch !== state.epoch) throw new DOMException("Connection changed", "AbortError");
      return allowDenied ? {
        status: response.status,
        data
      } : data;
    } finally {
      clearTimeout(timeout);
      state.controllers.delete(controller);
    }
  }

  function checked(key, value) {
    const object = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
    const count = (v) => Number.isFinite(v) && v >= 0;
    const log = (v) => object(v) && typeof v.event_id === "string" && object(v.assessment) && object(v.policy_decision) && Array.isArray(v.assessment.evidence) && typeof v.assessment.risk_level === "string";
    const session = (v) => object(v) && typeof v.session_id === "string" && typeof v.decision === "string" && Number.isInteger(v.version) && Array.isArray(v.reason_codes);
    const response = (v) => object(v) && typeof v.request_id === "string" && Array.isArray(v.approved_by) && Array.isArray(v.reviews) && count(v.required_approvals);
    const shapes = {
      health: () => object(value) && ["local", "test", "production"].includes(value.environment) && typeof value.auth_mode === "string",
      identity: () => object(value) && typeof value.subject === "string" && typeof value.tenant_id === "string" && Array.isArray(value.roles),
      metrics: () => object(value) && count(value.total_analyses) && count(value.pending_review_count) && count(value.average_latency_ms) && object(value.risk_counts) && Object.values(value.risk_counts).every(count),
      logs: () => Array.isArray(value) && value.every(log),
      log: () => log(value),
      sessions: () => Array.isArray(value) && value.every(session),
      responses: () => Array.isArray(value) && value.every(response),
      response: () => response(value),
      context: () => Array.isArray(value) && value.every((v) => object(v) && typeof v.kind === "string" && typeof v.record_id === "string"),
      signals: () => object(value) && typeof value.ok === "boolean" && typeof value.configured === "boolean",
      inbox: () => object(value) && ["pending", "processing", "completed", "failed"].every((field) => count(value[field])),
    };
    if (!shapes[key]?.()) throw Object.assign(new Error("Invalid response shape"), {
      invalidResponse: true
    });
    return value;
  }
  // Never expose credentials or executable markup received in log fields.
  function redact(value) {
    if (Array.isArray(value)) return value.map(redact);
    if (value && typeof value === "object") return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, /(?:token|secret|password|authorization|api.?key|signature|cookie)/i.test(key) ? "[REDACTED]" : redact(item)]));
    if (typeof value === "string" && state.credential) return value.split(state.credential).join("[REDACTED]");
    return value;
  }

  function rawPanel(value, label = "JSON 원문 (민감 필드 제외)") {
    const details = node("details");
    details.append(node("summary", label), node("pre", JSON.stringify(redact(value), null, 2)));
    return details;
  }

  function fields(items) {
    const grid = node("div", null, "detail-grid");
    items.forEach(([key, value]) => {
      const dl = node("dl");
      dl.append(node("dt", key), node("dd", value ?? "—"));
      grid.append(dl);
    });
    return grid;
  }

  function detailsList(title, items) {
    const section = node("section");
    section.append(node("h3", title));
    const list = node("ul", null, "evidence-list");
    (items?.length ? items : ["기록된 근거가 없습니다."]).forEach((item) => list.append(node("li", item)));
    section.append(list);
    return section;
  }

  function openDetail(title, kicker) {
    text("detailTitle", title);
    text("detailKicker", kicker);
    $("detailBody").className = "detail-body";
    $("detailBody").replaceChildren(empty("기록을 불러오고 있습니다."));
    if (!$("detailDialog").open) $("detailDialog").showModal();
    return ++state.detailSequence;
  }
  async function showRecord(record, type) {
    const epoch = state.epoch;
    const sequence = openDetail(type === "log" ? "분석 기록 상세" : type === "session" ? "세션 판단 이력" : "대응 요청 상세", type.toUpperCase());
    try {
      const path = type === "log" ? `/results/${encodeURIComponent(record.event_id)}` : type === "session" ? `/zero-trust/sessions/${encodeURIComponent(record.session_id)}` : `/response/requests/${encodeURIComponent(record.request_id)}`;
      const item = checked(type === "session" ? "sessions" : type, await request(path));
      if (epoch !== state.epoch || sequence !== state.detailSequence) return;
      const body = $("detailBody");
      body.replaceChildren();
      if (type === "log") {
        body.append(fields([
          ["이벤트 ID", item.event_id],
          ["분석 시각", date(item.analyzed_at, true)],
          ["위험도 / 점수", `${item.assessment.risk_level} / ${item.assessment.risk_score}`],
          ["분석기", item.analyzer],
          ["검토 상태", reviews[item.review_status] || item.review_status],
          ["테넌트", item.tenant_id]
        ]));
        body.append(detailsList("판단 근거", [item.assessment.rationale, ...item.assessment.evidence]), detailsList("정책과 대응 제안", [item.policy_decision.reason, `제안: ${item.policy_decision.action} / 실행 모드: ${item.policy_decision.mode}`, "이 분석 제안만으로 외부 계정이나 기기를 차단하지 않습니다."]));
      } else if (type === "session") {
        body.append(node("p", `${item.length}개 버전의 서버 이력. 허용 유효성과 토큰 소비는 실제 접근 요청에서 별도 검사합니다.`, "scope-note"));
        [...item].reverse().forEach((entry) => {
          const section = node("section", null, "timeline-item");
          section.append(badge(`${entry.decision} / v${entry.version}`, tones[entry.decision]), node("p", `${date(entry.evaluated_at, true)} / ${entry.status}`), detailsList("정책 판단", entry.reason_codes), fields([
            ["세션", entry.session_id],
            ["주체", entry.user_id],
            ["자원", entry.resource_id],
            ["출처", entry.signal_trust === "verified_source" ? `검증된 출처: ${entry.signal_source_id}` : "합성 시연 신호"],
            ["허용 만료", date(entry.grant_expires_at, true)],
            ["정책 버전", entry.policy_version]
          ]));
          body.append(section);
        });
      } else {
        body.append(fields([
          ["요청 ID", item.request_id],
          ["상태", item.status],
          ["요청자", item.requester],
          ["대상", item.target?.id],
          ["작업", item.action],
          ["승인", `${item.approved_by.length} / ${item.required_approvals}`]
        ]), detailsList("요청 사유", [item.reason]), detailsList("검토 이력", item.reviews.map((review) => `${review.subject} / ${date(review.approved_at, true)} / ${review.reason}`)), node("p", "승인과 실행은 기존 API의 서로 다른 신원 및 권한 검사를 따릅니다. 실행 결과는 로컬 모의 대응입니다.", "scope-note"));
      }
      body.append(rawPanel(item));
    } catch (error) {
      if (epoch === state.epoch && sequence === state.detailSequence) $("detailBody").replaceChildren(empty(errorLabel(error)));
    }
  }

  function rowButton(record, type) {
    const button = node("button", "상세 ↗", "row-button");
    button.setAttribute("aria-label", `${record.event_id || record.session_id || record.request_id} 상세`);
    button.addEventListener("click", () => showRecord(record, type));
    return button;
  }

  function tableMessage(target, message, columns) {
    const row = node("tr");
    const cell = node("td");
    cell.colSpan = columns;
    cell.append(empty(message));
    row.append(cell);
    target.replaceChildren(row);
  }

  function renderLogRows(id, rows) {
    const target = $(id);
    target.replaceChildren();
    if (!state.data.logs) return tableMessage(target, state.errors.logs ? errorLabel(state.errors.logs) : "기록을 불러오고 있습니다.", 6);
    if (!rows.length) return tableMessage(target, "조건에 맞는 분석 기록이 없습니다.", 6);
    rows.forEach((record) => {
      const row = node("tr");
      const risk = node("td");
      risk.append(badge(record.assessment.risk_level, tones[record.assessment.risk_level]));
      const event = node("td");
      event.append(node("strong", violations[record.assessment.violation_type] || record.assessment.violation_type, "event-title"), node("span", record.event_id, "event-id mono"));
      const action = node("td");
      action.append(node("span", actions[record.policy_decision.action] || record.policy_decision.action), node("span", reviews[record.review_status] || record.review_status, "event-id"));
      const detail = node("td");
      detail.append(rowButton(record, "log"));
      row.append(risk, event, node("td", record.analyzer, "mono"), action, node("td", date(record.analyzed_at, true), "mono"), detail);
      target.append(row);
    });
  }

  function filteredLogs() {
    const query = $("logSearch").value.trim().toLocaleLowerCase();
    return (state.data.logs || []).filter((record) =>
      (!$("riskFilter").value || record.assessment.risk_level === $("riskFilter").value) &&
      (!$("analyzerFilter").value || record.analyzer === $("analyzerFilter").value) &&
      (!$("reviewFilter").value || record.review_status === $("reviewFilter").value) &&
      (!query || JSON.stringify(redact(record)).toLocaleLowerCase().includes(query)));
  }

  function renderLogs() {
    const rows = filteredLogs();
    const pageCount = Math.max(1, Math.ceil(rows.length / 12));
    state.pageNumber = Math.min(state.pageNumber, pageCount);
    text("logCount", state.data.logs ? `${rows.length}건 표시 / 조회 ${state.data.logs.length}건` : "조회 결과 없음");
    text("pageLabel", `${state.pageNumber} / ${pageCount} 페이지`);
    $("prevPage").disabled = state.pageNumber <= 1;
    $("nextPage").disabled = state.pageNumber >= pageCount;
    $("exportLogs").disabled = !state.data.logs || rows.length === 0;
    renderLogRows("logRows", rows.slice((state.pageNumber - 1) * 12, state.pageNumber * 12));
    renderLogRows("recentLogs", (state.data.logs || []).slice(0, 5));
  }

  function renderSessions() {
    const records = state.data.sessions;
    text("metricRevoked", records ? num(records.filter((item) => item.status === "REVOKED").length) : "—");
    text("sessionSample", records ? `/ ${records.length}건` : "");
    text("sessionCount", records ? `최근 ${records.length}개 세션 조회` : "조회 결과 없음");
    const target = $("sessionRows");
    target.replaceChildren();
    if (!records) return tableMessage(target, state.errors.sessions ? errorLabel(state.errors.sessions) : "세션을 불러오고 있습니다.", 7);
    const rows = records.filter((record) => !$("sessionFilter").value || record.decision === $("sessionFilter").value);
    if (!rows.length) return tableMessage(target, "조건에 맞는 세션이 없습니다.", 7);
    rows.forEach((record) => {
      const row = node("tr");
      const decision = node("td");
      decision.append(badge(decisions[record.decision] || record.decision, tones[record.decision]));
      const subject = node("td");
      subject.append(node("strong", record.user_id, "event-title"), node("span", record.session_id, "event-id mono"));
      const detail = node("td");
      detail.append(rowButton(record, "session"));
      row.append(decision, subject, node("td", record.resource_id, "mono"), node("td", record.signal_trust === "verified_source" ? "검증된 출처" : "합성 시연"), node("td", `v${record.version}`, "mono"), node("td", record.status, "mono"), detail);
      target.append(row);
    });
  }

  function svg(tag, attrs = {}) {
    const element = document.createElementNS("http://www.w3.org/2000/svg", tag);
    Object.entries(attrs).forEach(([key, value]) => element.setAttribute(key, value));
    return element;
  }

  function renderChart() {
    const container = $("activityChart");
    container.replaceChildren();
    if (!state.data.logs) {
      container.append(empty(state.errors.logs ? "분석 활동을 조회할 수 없습니다." : "분석 활동을 불러오고 있습니다."));
      text("chartSample", "");
      return;
    }
    const interval = 300000;
    const end = Math.floor(Date.now() / interval) * interval;
    const buckets = Array.from({
      length: 12
    }, (_, index) => ({
      time: end - (11 - index) * interval,
      total: 0,
      risk: 0
    }));
    state.data.logs.forEach((item) => {
      const stamp = Math.floor(new Date(item.analyzed_at).getTime() / interval) * interval;
      const bucket = buckets.find((b) => b.time === stamp);
      if (bucket) {
        bucket.total++;
        if (["HIGH", "CRITICAL"].includes(item.assessment.risk_level)) bucket.risk++;
      }
    });
    const count = buckets.reduce((sum, bucket) => sum + bucket.total, 0);
    text("chartSample", `/ ${count}건`);
    container.setAttribute("aria-label", `최근 60분 조회 표본 ${count}건, 고위험 ${buckets.reduce((sum, b) => sum + b.risk, 0)}건. 최신 구간은 진행 중입니다.`);
    const chart = svg("svg", {
      viewBox: "0 0 660 205",
      role: "presentation"
    });
    const peak = Math.max(4, ...buckets.map((bucket) => bucket.total));
    const x = (i) => 42 + i * 53;
    const y = (n) => 168 - (n / peak) * 135;
    for (let i = 0; i <= 4; i++) {
      const level = Math.round(peak * i / 4);
      chart.append(svg("line", {
        x1: 36,
        x2: 635,
        y1: y(level),
        y2: y(level),
        stroke: "#233040",
        "stroke-dasharray": "3 6"
      }));
      const label = svg("text", {
        x: 20,
        y: y(level) + 4,
        fill: "#8e9db2",
        "font-size": 10,
        "text-anchor": "end"
      });
      label.textContent = level;
      chart.append(label);
    }
    const points = (key) => buckets.map((b, i) => `${x(i)},${y(b[key])}`).join(" ");
    chart.append(svg("polygon", {
      points: `42,168 ${points("total")} 625,168`,
      fill: "#50d6bc",
      opacity: ".08"
    }));
    ["total", "risk"].forEach((key) => {
      chart.append(svg("polyline", {
        points: points(key),
        fill: "none",
        stroke: key === "total" ? "#50d6bc" : "#f57a87",
        "stroke-width": 2.2,
        "stroke-linejoin": "round"
      }));
      buckets.forEach((b, i) => {
        const dot = svg("circle", {
          cx: x(i),
          cy: y(b[key]),
          r: 3,
          fill: key === "total" ? "#50d6bc" : "#f57a87"
        });
        const title = svg("title");
        title.textContent = `${date(b.time)} ${key === "total" ? "전체" : "고위험"} ${b[key]}건`;
        dot.append(title);
        chart.append(dot);
      });
    });
    [0, 3, 6, 9, 11].forEach((i) => {
      const label = svg("text", {
        x: x(i),
        y: 196,
        fill: "#8e9db2",
        "font-size": 10,
        "text-anchor": "middle"
      });
      label.textContent = new Date(buckets[i].time).toLocaleTimeString("ko-KR", {
        hour: "2-digit",
        minute: "2-digit",
        hour12: false
      });
      chart.append(label);
    });
    container.append(chart);
  }

  function renderMetrics() {
    const metrics = state.data.metrics;
    text("metricTotal", num(metrics?.total_analyses));
    text("navLogCount", num(metrics?.total_analyses));
    text("metricRisk", metrics ? num((metrics.risk_counts.HIGH || 0) + (metrics.risk_counts.CRITICAL || 0)) : "—");
    text("metricReview", num(metrics?.pending_review_count));
    text("latencyMetric", metrics ? `누적 평균 응답 ${metrics.average_latency_ms.toFixed(2)} ms` : "평균 응답 —");
    text("donutTotal", num(metrics?.total_analyses));
    $("riskLegend").replaceChildren();
    let current = 0;
    const segments = [];
    Object.entries(colors).forEach(([risk, color]) => {
      const count = metrics?.risk_counts[risk] || 0;
      const next = current + (metrics?.total_analyses ? count / metrics.total_analyses * 100 : 0);
      segments.push(`${color} ${current}% ${next}%`);
      current = next;
      const row = node("div");
      const name = node("span");
      const dot = node("i", null, "legend-dot");
      dot.style.background = color;
      name.append(dot, node("span", risk));
      row.append(name, node("strong", metrics ? `${num(count)}건` : "—"));
      $("riskLegend").append(row);
    });
    $("riskDonut").style.background = metrics?.total_analyses ? `conic-gradient(${segments.join(",")})` : "#233040";
  }

  function renderPipeline() {
    const target = $("pipeline");
    target.replaceChildren();
    const signals = state.data.signals;
    const inbox = state.data.inbox;
    const entries = [
      ["신뢰 신호 레지스트리", signals ? (signals.ok ? (signals.configured ? `${signals.source_count}개 출처 설정` : "미설정") : "검증 실패") : "조회 불가", signals?.ok && signals.configured ? "teal" : "amber"],
      ["Inbox 처리 대기", inbox ? `${inbox.pending}건 대기 / ${inbox.processing}건 처리 중` : "조회 불가", "neutral"],
      ["Inbox 처리 결과", inbox ? `${inbox.completed}건 완료 / ${inbox.failed}건 실패` : "조회 불가", inbox?.failed ? "red" : "neutral"],
      ["worker 생존 상태", "이 API만으로 확인 불가", "neutral"],
    ];
    entries.forEach(([label, value, tone]) => {
      const row = node("div", null, "pipeline-row");
      row.append(node("span", label), badge(value, tone));
      target.append(row);
    });
  }

  function renderEvidence() {
    const context = $("contextHistory");
    context.replaceChildren();
    const history = state.data.context;
    if (!history) context.append(empty(state.errors.context ? errorLabel(state.errors.context) : "이력을 불러오고 있습니다."));
    else if (!history.length) context.append(empty("아직 기록된 행위 문맥 이력이 없습니다."));
    else {
      context.append(node("p", `조회 ${history.length}건 중 최근 50건 표시`, "scope-note"));
      [...history].sort((a, b) => new Date(b.created_at) - new Date(a.created_at)).slice(0, 50).forEach((entry) => {
        const row = node("div", null, "timeline-item");
        row.append(badge(entry.kind), node("h3", entry.record_id), node("p", `${entry.actor} / ${date(entry.created_at, true)}`));
        context.append(row);
      });
    }
    const target = $("responseList");
    target.replaceChildren();
    const responses = state.data.responses;
    if (!responses) target.append(empty(state.errors.responses ? errorLabel(state.errors.responses) : "요청을 불러오고 있습니다."));
    else if (!responses.length) target.append(empty("현재 신원으로 조회할 수 있는 대응 요청이 없습니다."));
    else responses.forEach((entry) => {
      const row = node("div", null, "response-item");
      row.append(badge(entry.status, entry.status === "EXECUTED" ? "teal" : "amber"), node("h3", `${entry.action} / ${entry.target?.id || "—"}`), node("p", entry.reason), node("p", `요청자 ${entry.requester} / 승인 ${entry.approved_by.length}명 / 필요 ${entry.required_approvals}명`), rowButton(entry, "response"));
      target.append(row);
    });
  }

  function render() {
    const health = state.data.health;
    text("modeBadge", health ? (health.dashboard_demo ? "합성 시연 데이터 / LOCAL" : `${health.environment.toUpperCase()} / ${health.auth_mode === "disabled" ? "인증 비활성" : "인증 사용"}`) : "연결 확인 필요");
    const identity = state.data.identity;
    text("authLabel", identity?.subject || "조회 신원 확인 필요");
    text("workspaceTenant", identity ? `Tenant / ${identity.tenant_id}` : "테넌트 확인 필요");
    text("identityInfo", identity ? `${identity.subject} / ${identity.tenant_id} / ${identity.roles.join(", ")}` : "현재 조회 신원을 확인할 수 없습니다.");
    text("analyzerMode", health ? {
      rule: "규칙 기반 분석",
      openai: "OpenAI 분석",
      hybrid: "규칙 + OpenAI"
    } [health.analyzer_mode] || health.analyzer_mode : "—");
    text("footerVersion", health ? `v${health.version} / ${health.environment.toUpperCase()} / ${Intl.DateTimeFormat().resolvedOptions().timeZone}` : "LOCAL FRAMEWORK");
    const errors = Object.entries(state.errors);
    const coreOkay = ["health", "identity", "metrics", "logs", "sessions"].every((key) => state.data[key]);
    text("connectionStatus", coreOkay ? (errors.length ? "일부 조회 기능 확인 필요" : "조회 API 연결됨") : "데이터 조회 확인 필요");
    $("statusDot").className = `status-dot ${coreOkay && !errors.length ? "online" : ""}`;
    $("notice").hidden = !errors.length;
    if (errors.length) text("notice", `${errors.length}개 조회 요청 실패. ${errorLabel(errors[0][1])} 실패한 영역은 이전 값을 표시하지 않습니다.`);
    renderMetrics();
    renderChart();
    renderLogs();
    renderSessions();
    renderPipeline();
    renderEvidence();
    updateDemoButtons();
  }
  async function refresh() {
    if (state.busy) return;
    const epoch = state.epoch;
    state.busy = true;
    $("refresh").disabled = true;
    const urls = {
      ...endpoints,
      ...(state.page === "evidence" ? {
        context: "/detections/context/history",
        responses: "/response/requests?limit=50"
      } : {})
    };
    try {
      await Promise.all(Object.entries(urls).map(async ([key, url]) => {
        try {
          const result = checked(key, await request(url));
          if (epoch === state.epoch) {
            state.data[key] = result;
            delete state.errors[key];
          }
        } catch (error) {
          if (epoch === state.epoch) {
            delete state.data[key];
            state.errors[key] = error;
          }
        }
      }));
      if (epoch !== state.epoch) return;
      if (Object.values(state.errors).some((error) => [401, 403].includes(error.status))) {
        state.detailSequence++;
        $("detailDialog").close();
        $("detailBody").replaceChildren();
      }
      text("lastUpdated", `마지막 조회 ${date(Date.now())}`);
      render();
    } finally {
      if (epoch === state.epoch) {
        state.busy = false;
        $("refresh").disabled = false;
        if (state.refreshRequested) {
          state.refreshRequested = false;
          refresh();
        }
      }
    }
  }

  function navigate() {
    const key = location.hash.slice(1);
    state.page = Object.hasOwn(pages, key) ? key : "overview";
    if (Object.hasOwn(pages, key)) window.scrollTo({ top: 0, behavior: "instant" });
    const [name, title, description] = pages[state.page];
    text("breadcrumb", name);
    text("pageTitle", title);
    text("pageDescription", description);
    document.querySelectorAll("[data-view]").forEach((section) => {
      section.hidden = section.dataset.view !== state.page;
    });
    document.querySelectorAll("[data-page]").forEach((link) => {
      if (link.dataset.page === state.page) link.setAttribute("aria-current", "page");
      else link.removeAttribute("aria-current");
    });
    document.title = `${name} | 천안아산역`;
    if (state.page === "evidence") {
      if (state.busy) state.refreshRequested = true;
      else refresh();
    }
  }

  function resetConnection(type, credential) {
    state.epoch++;
    state.controllers.forEach((controller) => controller.abort());
    state.credentialType = type;
    state.credential = credential;
    state.data = {};
    state.errors = {};
    state.busy = false;
    state.refreshRequested = false;
    state.pageNumber = 1;
    state.demo = {};
    state.detailSequence++;
    $("detailDialog").close();
    $("detailBody").replaceChildren();
    $("demoHistory").replaceChildren(node("li", "정상 세션을 생성하면 실행 기록이 표시됩니다.", "empty"));
    text("demoStatus", "대기");
    text("lastUpdated", "마지막 갱신 —");
    $("credential").value = "";
    $("connectionDialog").close();
    render();
    refresh();
  }

  function updateDemoButtons() {
    const supported = ["local", "test"].includes(state.data.health?.environment) && state.data.identity?.roles.includes("analyst");
    $("demoStart").disabled = !supported || state.demo.busy;
    $("demoAccess").disabled = !supported || state.demo.busy || !state.demo.token;
    $("demoCompromise").disabled = !supported || state.demo.busy || !state.demo.version || state.demo.compromised;
  }

  function demoTrace(message, tone = "neutral") {
    const target = $("demoHistory");
    target.querySelector(".empty")?.remove();
    const row = node("li");
    row.append(node("time", date(Date.now()), "mono"), node("p", message));
    target.prepend(row);
    while (target.children.length > 20) target.lastElementChild.remove();
    text("demoStatus", tone === "red" ? "접근 거부" : "실행됨");
    $("demoStatus").className = `pill ${tone}`;
  }
  async function runDemo(operation) {
    if (state.demo.busy || !["local", "test"].includes(state.data.health?.environment)) return;
    const epoch = state.epoch;
    state.demo.busy = true;
    updateDemoButtons();
    try {
      if (operation === "access") {
        const result = await request("/zero-trust/protected-access", {
          allowDenied: true,
          body: {
            session_id: state.demo.sessionId,
            resource_id: "zt-demo-documents",
            action: "READ",
            grant_token: state.demo.token
          }
        });
        if (epoch !== state.epoch) return;
        demoTrace(`HTTP ${result.status} / ${result.data.allowed ? "문서 접근 허용. 사용한 허용은 재사용할 수 없습니다." : `문서 접근 거부: ${result.data.reason_code}`}`, result.data.allowed ? "teal" : "red");
        return;
      }
      if (operation === "start") {
        const generated = await request("/events/simulate", {
          body: {
            scenario_id: "NORMAL-01",
            count: 1
          }
        });
        if (epoch !== state.epoch) return;
        const event = generated[0];
        delete event.ground_truth;
        event.user.role = "employee";
        event.resource = {
          resource_id: "zt-demo-documents",
          resource_type: "document",
          sensitivity: "internal"
        };
        event.auth_context.authentication_result = "success";
        event.auth_context.mfa = "success";
        state.demo = {
          busy: true,
          event,
          sessionId: `demo-${crypto.randomUUID()}`,
          version: 0,
          token: null
        };
      } else state.demo.event.device.security_posture = "compromised";
      state.demo.event.event_id = `signal-${crypto.randomUUID()}`;
      state.demo.event.timestamp = new Date().toISOString();
      const result = await request("/zero-trust/sessions/evaluate", {
        body: {
          session_id: state.demo.sessionId,
          expected_version: state.demo.version,
          event: state.demo.event
        }
      });
      if (epoch !== state.epoch) return;
      state.demo.version = result.session.version;
      if (result.grant_token) state.demo.token = result.grant_token;
      if (operation === "compromise") state.demo.compromised = true;
      demoTrace(`${operation === "start" ? "정상 세션 생성" : "침해 신호 재평가"}: ${result.session.decision} / ${result.session.status} / v${result.session.version}. ${result.session.reason_codes.join(", ")}`, tones[result.session.decision]);
      await refresh();
    } catch (error) {
      if (epoch === state.epoch) demoTrace(errorLabel(error), "amber");
    } finally {
      if (epoch === state.epoch) {
        state.demo.busy = false;
        updateDemoButtons();
      }
    }
  }
  $("refresh").addEventListener("click", refresh);
  document.querySelector(".skip-link").addEventListener("click", (event) => {
    event.preventDefault();
    $("content").focus();
    $("content").scrollIntoView();
  });
  window.addEventListener("hashchange", navigate);
  ["logSearch", "riskFilter", "analyzerFilter", "reviewFilter"].forEach((id) => $(id).addEventListener(id === "logSearch" ? "input" : "change", () => {
    state.pageNumber = 1;
    renderLogs();
  }));
  $("sessionFilter").addEventListener("change", renderSessions);
  $("prevPage").addEventListener("click", () => {
    state.pageNumber--;
    renderLogs();
  });
  $("nextPage").addEventListener("click", () => {
    state.pageNumber++;
    renderLogs();
  });
  $("exportLogs").addEventListener("click", () => {
    const blob = new Blob([JSON.stringify({
      scope: "current_tenant_recent_100_filtered",
      exported_at: new Date().toISOString(),
      records: redact(filteredLogs())
    }, null, 2)], {
      type: "application/json"
    });
    const url = URL.createObjectURL(blob);
    const link = node("a");
    link.href = url;
    link.download = `security-logs-${new Date().toISOString().slice(0, 10)}.json`;
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    notify("현재 필터의 로그를 내보냈습니다. 민감한 업무 정보가 포함될 수 있으니 공유 범위를 확인하세요.");
  });
  $("connectionButton").addEventListener("click", () => $("connectionDialog").showModal());
  $("closeConnection").addEventListener("click", () => {
    $("credential").value = "";
    $("connectionDialog").close();
  });
  $("connectionDialog").addEventListener("close", () => {
    $("credential").value = "";
  });
  $("closeDetail").addEventListener("click", () => $("detailDialog").close());
  $("detailDialog").addEventListener("close", () => {
    state.detailSequence++;
  });
  $("connectionForm").addEventListener("submit", (event) => {
    event.preventDefault();
    resetConnection($("credentialType").value, $("credentialType").value === "none" ? "" : $("credential").value.trim());
  });
  $("clearCredential").addEventListener("click", () => resetConnection("none", ""));
  $("demoStart").addEventListener("click", () => runDemo("start"));
  $("demoAccess").addEventListener("click", () => runDemo("access"));
  $("demoCompromise").addEventListener("click", () => runDemo("compromise"));
  const tick = () => text("clock", `${new Date().toLocaleDateString("ko-KR")} ${date(Date.now())}`);
  tick();
  setInterval(tick, 1000);
  navigate();
  render();
  refresh();
  setInterval(() => {
    if ($("autoRefresh").checked && !document.hidden && !state.demo.busy && !$("connectionDialog").open) refresh();
  }, 10000);
})();
