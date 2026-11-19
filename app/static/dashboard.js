/* Same-origin observation UI. Credentials and demonstration capabilities stay in memory. */
(() => {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const pages = {
    overview: ["관제 개요", "관제 개요", "분석 현황 및 접근 통제"],
    logs: ["로그 탐색", "로그 탐색", "이벤트 검색 및 분석 상세"],
    sessions: ["세션과 접근", "세션 상태", "접근 판단과 버전별 변경 이력"],
    evidence: ["증거와 승인", "이력 및 승인", "행위 문맥과 대응 요청의 처리 기록"],
    demo: ["시연 시나리오", "접근 테스트", "정상 접근 / 허용 재사용 / 세션 회수"],
    analysis: ["분석 및 탐지", "분석 및 탐지", "이벤트 분석, 정규화 및 탐지 규칙"],
    evaluation: ["평가 및 공개 로그", "평가 및 공개 로그", "재생 자료와 평가 조건을 확인한 뒤 실행합니다."],
    cases: ["사고 및 전송 관리", "사고 및 전송 관리", "사고 처리 이력과 외부 연계 전송 기록"],
    context: ["기준선 및 작업 승인", "기준선 및 작업 승인", "검증된 수집 기록과 실제 실행 증거 대조"],
    signals: ["신호 입력 및 세션 제어", "신호 입력 및 세션 제어", "서명 검증, 접수 영수증 및 접근 제어"],
    responses: ["대응 요청 및 승인", "대응 요청 및 승인", "요청자 외 검토자 두 명의 승인 후 모의 실행"],
    assurance: ["보안 통제 점검", "보안 통제 점검", "구현 근거와 현재 서버 준비 상태"],
    operations: ["실행 환경 및 모델 비교", "실행 환경 및 모델 비교", "관리자에게 허용된 로컬 실행 작업"],
  };
  const tones = {
    LOW: "teal",
    MEDIUM: "amber",
    HIGH: "red",
    CRITICAL: "critical",
    ALLOW: "teal",
    STEP_UP: "amber",
    HOLD: "amber",
    DENY: "red"
  };
  const colors = {
    CRITICAL: "#ae3038",
    HIGH: "#c16b43",
    MEDIUM: "#c29a42",
    LOW: "#7b9d8a"
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
    ACCESS_POLICY_VIOLATION: "접근 정책 위반",
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
    audit: {generation: 0, busy: false, page: null, cursors: [], index: 0,
      error: null, identity: null, scope: null, controller: null},
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

  const sessionView = new CollectionView({prefix: "sessionPages", label: "세션 목록", body: $("sessionRows"), columns: 7,
    url: "/zero-trust/session-pages", id: "session_id", request,
    context: () => ({epoch: state.epoch, identity: state.data.identity}),
    filters: () => ({decision: $("sessionFilter").value}),
    render: rows => { state.data.sessions = rows; renderSessions(); },
    authorityError: () => resetConnection("none", ""),
    validate: row => typeof row.user_id === "string" && typeof row.resource_id === "string" && Object.hasOwn(decisions, row.decision) &&
      ["ACTIVE", "STEP_UP_REQUIRED", "HELD", "REVOKED"].includes(row.status) && ["demo", "verified_source"].includes(row.signal_trust) &&
      Number.isSafeInteger(row.version) && row.version > 0 && (!$("sessionFilter").value || row.decision === $("sessionFilter").value)});
  const caseView = new CollectionView({prefix: "caseDashboardPages", label: "사고 목록", body: $("caseRows"), columns: 6,
    url: "/case-pages", id: "case_id", request, context: () => ({epoch: state.epoch, identity: state.data.identity}),
    render: renderCaseRows, authorityError: () => resetConnection("none", ""),
    validate: row => ["NEW", "TRIAGED", "INVESTIGATING", "CONTAINED", "RESOLVED", "CLOSED"].includes(row.status) && Number.isSafeInteger(row.version) && row.version > 0 && typeof row.updated_at === "string" && Number.isFinite(Date.parse(row.updated_at))});

  function errorLabel(error) {
    if (error.invalidResponse) return "서버 응답 형식이 올바르지 않습니다.";
    if (error.status === 401) return "인증이 필요합니다. 연결 및 인증에서 키를 입력하세요.";
    if (error.status === 403) return "조회 권한이 없습니다. 역할과 전송 신원을 확인하세요.";
    if (error.status === 404 || error.status === 503) return `조회할 수 없습니다 (HTTP ${error.status}). 서버 상태를 확인하세요.`;
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
    allowDenied = false,
    method,
    timeoutMs = 12000,
    operation = false,
    ifMatch,
    reviewIdentity,
    withMetadata = false,
    signal
  } = {}) {
    if (ifMatch !== undefined && !/^"r1-[a-f0-9]{64}"$/.test(ifMatch)) throw new Error("검토 버전을 다시 조회하세요.");
    if (reviewIdentity !== undefined && !/^[a-f0-9]{64}$/.test(reviewIdentity)) throw new Error("검토 신원을 다시 확인하세요.");
    const epoch = state.epoch;
    const controller = new AbortController();
    const abort = () => controller.abort();
    if (signal?.aborted) abort();
    else signal?.addEventListener("abort", abort, {once: true});
    state.controllers.add(controller);
    const timeout = setTimeout(() => controller.abort(), Math.min(timeoutMs, 120000));
    const headers = {
      Accept: "application/json"
    };
    if (state.credentialType === "api_key" && state.credential) headers["X-API-Key"] = state.credential;
    if (state.credentialType === "bearer" && state.credential) headers.Authorization = `Bearer ${state.credential}`;
    if (body !== undefined) headers["Content-Type"] = "application/json";
    if (operation) headers["X-Dashboard-Action"] = "1";
    if (ifMatch !== undefined) headers["If-Match"] = ifMatch;
    if (reviewIdentity !== undefined) headers["X-Review-Identity"] = reviewIdentity;
    try {
      const response = await fetch(path, {
        method: method || (body === undefined ? "GET" : "POST"),
        headers,
        body: body === undefined ? undefined : JSON.stringify(body),
        signal: controller.signal,
        cache: "no-store",
        redirect: "error"
      });
      if (epoch !== state.epoch) throw new DOMException("Connection changed", "AbortError");
      if (!response.ok && !(allowDenied && response.status === 403)) {
        let detail = "";
        try {
          const problem = (await response.json()).detail;
          detail = typeof problem === "string" ? problem : Array.isArray(problem) ? problem.map((item) =>
            (item.loc || []).join(".") + ": " + item.msg).join(" / ") : "";
        } catch { /* HTTP status still identifies an invalid error response. */ }
        throw Object.assign(new Error("Request failed"), {status: response.status, detail: detail.slice(0, 1000)});
      }
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
      if (withMetadata) return {data, etag: response.headers.get("ETag"), reviewIdentity: response.headers.get("X-Review-Identity"), reviewMode: response.headers.get("X-Review-Mode")};
      return allowDenied ? {
        status: response.status,
        data
      } : data;
    } finally {
      clearTimeout(timeout);
      state.controllers.delete(controller);
      signal?.removeEventListener("abort", abort);
    }
  }

  function sameReviewIdentity(left, right) {
    return Boolean(left && right) && ["subject", "tenant_id", "auth_method"].every((key) =>
      typeof left[key] === "string" && left[key].length > 0 && left[key] === right[key]);
  }
  async function readReviewObservation(eventId) {
    const epoch = state.epoch;
    const before = checked("identity", await request("/auth/me"));
    const response = await request(`/results/${encodeURIComponent(eventId)}`, {withMetadata: true});
    const record = checked("log", response.data);
    const after = checked("identity", await request("/auth/me"));
    if (epoch !== state.epoch || !sameReviewIdentity(before, after)) throw new Error("조회 중 신원이 변경됐습니다. 다시 조회하세요.");
    if (record.event_id !== eventId || record.tenant_id !== before.tenant_id || typeof record.analysis_id !== "string") throw new Error("조회 결과의 대상과 신원을 확인할 수 없습니다.");
    const identity = Object.fromEntries(["subject", "tenant_id", "auth_method"].map((key) => [key, before[key]]));
    return {record, identity, epoch, etag: response.etag, reviewIdentity: response.reviewIdentity, reviewMode: response.reviewMode};
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
      audit: () => object(value) && Array.isArray(value.items) && value.items.length <= 12 && value.items.every(log) &&
        Number.isSafeInteger(value.total_matches) && value.total_matches >= 0 &&
        /^[A-Za-z0-9_-]{1,2048}$/.test(value.page_cursor || "") &&
        (value.next_cursor === null || (typeof value.next_cursor === "string" && /^[A-Za-z0-9_-]{1,2048}$/.test(value.next_cursor))) &&
        /^[a-f0-9]{64}$/.test(value.snapshot_id || "") && value.historical_audit_snapshot === true &&
        ["sqlite_prefix", "unchanged_local_view"].includes(value.snapshot_mode) &&
        Number.isFinite(Date.parse(value.snapshot_created_at)) && Date.parse(value.snapshot_expires_at) > Date.parse(value.snapshot_created_at),
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
    if (value && typeof value === "object") return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, /(?:token|secret|password|authorization|api.?key|private.?key|signature|cookie|bearer|credential)/i.test(key) ? "[REDACTED]" : redact(item)]));
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

  function analysisEvidence(record) {
    const object = (value) => value && typeof value === "object" && !Array.isArray(value);
    const present = (value) => value !== undefined && value !== null;
    if (!present(record?.verification_context) && !present(record?.llm_trace) && !present(record?.verified_review_controls)) return null;
    const section = node("section", null, "analysis-evidence");
    section.setAttribute("aria-label", "분석 시점의 검증 근거와 LLM 조회");
    section.append(node("h3", "분석 시점의 검증 근거"));
    const context = record.verification_context;
    if (!object(context) || context.not_an_access_grant !== true) {
      section.append(node("p", "연결된 검증 근거의 형식을 확인할 수 없습니다. 원문과 서버 기록을 확인하세요.", "evidence-warning"));
      return section;
    }
    const count = (value, maximum = 10000000) => Number.isSafeInteger(value) && value >= 0 && value <= maximum;
    const safe = (value) => typeof value === "string" ? redact(value).slice(0, 192) : "미확인";
    const signal = object(context.signal) ? context.signal : {};
    const caller = object(context.caller) ? context.caller : {};
    const policy = object(context.policy) ? context.policy : {};
    const verified = signal.signature_verified === true && caller.session_operator_binding_verified === true;
    section.append(node("p", verified ?
      "수집기 서명과 당시 세션 요청자 연결을 확인한 기록입니다. 현재 접근 허용은 자원 요청에서 별도로 판단합니다." :
      "서명 또는 요청자 연결의 검증 상태가 불완전합니다. 이 기록으로 접근 권한을 판단하지 마세요.", verified ? "scope-note" : "evidence-warning"));
    const methods = {oidc: "OIDC", api_key: "API 키", disabled: "인증 비활성"};
    const mfa = {success: "성공 관측", failed: "실패 관측", unknown: "관측 미확인", not_required: "요구하지 않음 관측"};
    const values = [
      ["근거 수집 시각", date(context.collected_at, true)],
      ["기록된 근거 만료", date(context.valid_until, true)],
      ["수집기 서명", signal.signature_verified === true ? "검증됨" : "미확인"],
      ["요청자 인증", `${methods[caller.authentication_method] || "미확인"} / ${caller.session_operator_binding_verified === true ? "세션 요청자와 일치" : "연결 미확인"}`],
      ["서버의 MFA 요구", policy.mfa_required === true ? "필수" : policy.mfa_required === false ? "요구하지 않음" : "미확인"],
      ["수집기의 MFA 관측", mfa[signal.mfa_observation] || "미확인"],
      ["대상 사람의 독립 MFA 검증", caller.event_subject_mfa_independently_verified === true ? "확인됨" : "확인되지 않음"],
    ];
    const execution = object(context.execution) ? context.execution : null;
    if (execution) {
      const statuses = {complete: "완전한 관측", incomplete: "일부 관측 누락", conflict: "관측 간 충돌", missing: "관측 없음", unavailable: "유효한 관측 없음"};
      values.push(["실행 관측", statuses[execution.observation_status] || "미확인"]);
      const comparisons = execution.exact_field_comparisons;
      const complete = execution.comparison_scope_complete === true && Array.isArray(comparisons) && comparisons.length > 0 && comparisons.length <= 8 && comparisons.every((item) => object(item) && typeof item.one_coherent_policy_matches === "boolean");
      values.push(["실행 주체·목적지 비교", !complete ? "비교 근거 불완전" : comparisons.some((item) => item.one_coherent_policy_matches) ? "한 정책 안에서 모두 일치" : "한 정책 안에서 모두 일치하지 않음"]);
    }
    section.append(fields(values));
    const trace = record.llm_trace;
    if (present(trace)) {
      section.append(node("h4", "LLM 근거 사용"));
      const receipts = object(trace) && Array.isArray(trace.receipts) ? trace.receipts : [];
      const validTrace = object(trace) && trace.mode === "bounded_read_only_evidence_review" && count(trace.provider_calls, 3) && trace.provider_calls > 0 && receipts.length === trace.provider_calls;
      if (!validTrace) {
        section.append(node("p", "LLM 조회 이력의 형식을 확인할 수 없습니다.", "evidence-warning"));
      } else {
        const tools = {read_bound_execution_evidence: "실행 근거", read_current_session_history: "최근 세션 결정"};
        const reads = Array.isArray(trace.tools_executed) && trace.tools_executed.length <= 2 ? trace.tools_executed.map((name) => tools[name] || "알 수 없는 조회 기록") : ["조회 내역 미확인"];
        const knownUsage = receipts.every((item) => object(item) && count(item.input_tokens) && count(item.output_tokens));
        const usage = knownUsage ? `입력 ${num(receipts.reduce((sum, item) => sum + item.input_tokens, 0))} / 출력 ${num(receipts.reduce((sum, item) => sum + item.output_tokens, 0))} 토큰` : "일부 사용량 미확인";
        section.append(fields([
          ["제공자 요청", `${trace.provider_calls}회 / 최대 3회`],
          ["실행 근거 전달", Array.isArray(trace.prefetched_evidence) && trace.prefetched_evidence.includes("execution") ? "처음부터 제공" : reads.includes("실행 근거") ? "LLM 요청 후 제공" : execution ? "전달 방식 미확인" : "연결된 실행 근거 없음"],
          ["추가 조회", reads.length ? reads.join(", ") : "없음 · 기본 근거 사용"],
          ["제공자 사용량", usage],
          ["조치 도구", trace.write_tools_available === false ? "등록되지 않음" : "기록 확인 필요"],
        ]));
      }
    }
    const guard = record.verified_review_controls;
    if (present(guard)) {
      const reasons = {
        verified_provenance_incomplete: "수집기 서명 또는 요청자 연결 미확인",
        server_policy_requirements_not_satisfied: "서버의 자원·역할·행위·MFA 요건 미충족",
        current_session_not_usable: "현재 세션의 미사용 승인을 확인할 수 없음",
        execution_scope_not_proven: "실행 주체·목적지의 허용 범위를 입증하지 못함",
      };
      section.append(node("h4", "서버의 권고 안전 점검"));
      const validGuard = object(guard) && guard.scope === "verified_review_advisory_only" && typeof guard.action_adjusted === "boolean" && typeof guard.allow_recommendation_supported === "boolean" && Object.hasOwn(actions, guard.action_before_guard) && Object.hasOwn(actions, guard.action_after_guard) && Array.isArray(guard.restrictions) && guard.restrictions.length <= 4 && guard.restrictions.every((reason) => Object.hasOwn(reasons, reason));
      if (!validGuard) {
        section.append(node("p", "권고 안전 점검 기록의 형식을 확인할 수 없습니다.", "evidence-warning"));
      } else {
        section.append(node("p", guard.action_adjusted ? "서버가 허용 권고를 검토 대기로 제한했습니다." : "서버 점검 후에도 최종 접근 권한은 별도로 검사합니다."));
        section.append(fields([["안전 점검 전 권고", actions[guard.action_before_guard]], ["안전 점검 후 권고", actions[guard.action_after_guard]]]));
        if (guard.restrictions.length) section.append(detailsList("검토를 유지하는 사유", guard.restrictions.map((reason) => reasons[reason])));
      }
    }
    const citations = Array.isArray(record.assessment?.evidence) ? record.assessment.evidence.filter((path) => typeof path === "string" && path.startsWith("verified_session.")).slice(0, 20) : [];
    if (citations.length) {
      const details = node("details");
      details.append(node("summary", "LLM이 인용한 검증 근거"));
      const list = node("dl", null, "evidence-citations");
      citations.forEach((path) => {
        let value = context;
        for (const key of path.split(".").slice(1)) {
          if (!["__proto__", "prototype", "constructor"].includes(key) && object(value) && Object.hasOwn(value, key)) value = value[key];
          else { value = undefined; break; }
        }
        const row = node("div");
        const protectedValue = redact({[path]: value})[path];
        const shown = !present(value) ? "값을 확인할 수 없음" : typeof protectedValue === "object" ? JSON.stringify(protectedValue).slice(0, 192) : safe(String(protectedValue));
        row.append(node("dt", safe(path)), node("dd", shown));
        list.append(row);
      });
      details.append(list); section.append(details);
    }
    return section;
  }

  function openDetail(title) {
    text("detailTitle", title);
    $("detailBody").className = "detail-body";
    $("detailBody").replaceChildren(empty("기록을 불러오고 있습니다."));
    if (!$("detailDialog").open) $("detailDialog").showModal();
    return ++state.detailSequence;
  }
  async function showRecord(record, type) {
    const epoch = state.epoch;
    const sequence = openDetail(type === "log" ? "분석 기록" : type === "session" ? "세션 이력" : "대응 요청");
    try {
      const path = type === "log" ? `/results/${encodeURIComponent(record.event_id)}` : type === "session" ? `/zero-trust/sessions/${encodeURIComponent(record.session_id)}` : `/response/requests/${encodeURIComponent(record.request_id)}`;
      const reviewObservation = type === "log" ? await readReviewObservation(record.event_id) : null;
      const item = reviewObservation ? reviewObservation.record : checked(type === "session" ? "sessions" : type, await request(path));
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
        const evidence = analysisEvidence(item);
        if (evidence) body.append(evidence);
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
        ]), detailsList("요청 사유", [item.reason]), detailsList("검토 이력", item.reviews.map((review) => `${review.subject} / ${date(review.approved_at, true)} / ${review.reason}`)), node("p", "서로 다른 검토자 2명의 승인이 필요합니다. 실행 결과는 로컬 모의 대응입니다.", "scope-note"));
      }
      window.dashboardOperations?.detailActions(type, item, body, reviewObservation);
      body.append(rawPanel(item));
    } catch (error) {
      if (epoch === state.epoch && sequence === state.detailSequence) $("detailBody").replaceChildren(empty(errorLabel(error)));
    }
  }

  function rowButton(record, type) {
    const button = node("button", "상세", "row-button");
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

  function timestampCell(value) {
    const stamp = new Date(value);
    const cell = node("td", null, "mono event-time");
    if (!value || Number.isNaN(stamp.getTime())) {
      cell.textContent = "—";
      return cell;
    }
    const time = node("time", date(value));
    time.dateTime = stamp.toISOString();
    cell.title = date(value, true);
    cell.append(time, node("span", stamp.toLocaleDateString("ko-KR", {
      year: "numeric", month: "2-digit", day: "2-digit"
    }), "event-date"));
    return cell;
  }

  function renderLogRows(id, rows) {
    const target = $(id);
    target.replaceChildren();
    if (id === "logRows" && !state.audit.page) return tableMessage(target,
      state.audit.error ? auditError(state.audit.error) : state.audit.busy ? "기록을 불러오고 있습니다." : "최신 목록 조회를 눌러 기록을 확인하세요.", 6);
    if (id !== "logRows" && !state.data.logs) return tableMessage(target, state.errors.logs ? errorLabel(state.errors.logs) : "기록을 불러오고 있습니다.", 6);
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
      row.append(risk, event, node("td", record.analyzer, "mono"), action, timestampCell(record.analyzed_at), detail);
      target.append(row);
    });
  }

  function filteredLogs() {
    const query = $("logSearch").value.trim().toLocaleLowerCase();
    return (state.audit.page?.items || []).filter((record) =>
      (!$("analyzerFilter").value || record.analyzer === $("analyzerFilter").value) &&
      (!query || JSON.stringify(redact(record)).toLocaleLowerCase().includes(query)));
  }

  const auditScope = () => JSON.stringify([$("riskFilter").value, $("reviewFilter").value, $("auditQuery").value.trim(), $("auditAnalyzer").value]);
  function auditError(error) {
    if (error.status === 410) return "조회가 만료됐습니다. 최신 목록 조회를 눌러 다시 시작하세요.";
    if ([400, 409].includes(error.status)) return "이전 조회를 이어갈 수 없습니다. 최신 목록 조회를 눌러 다시 시작하세요.";
    if (error.status === 501) return "현재 서버는 감사 페이지 조회를 지원하지 않습니다. 관리자에게 문의하세요.";
    if (error.identityChanged) return "조회 신원이 변경됐습니다. 연결 및 인증을 확인한 뒤 최신 목록을 다시 조회하세요.";
    if (error.invalidResponse) return "감사 페이지 응답을 확인할 수 없습니다. 최신 목록을 다시 조회하세요.";
    return errorLabel(error) + " 최신 목록 조회로 다시 시도하세요.";
  }
  function resetAudit() {
    const audit = state.audit;
    audit.controller?.abort();
    audit.generation++;
    audit.busy = false; audit.page = null; audit.error = null;
    audit.cursors = []; audit.index = 0; audit.identity = null; audit.scope = null; audit.controller = null;
  }
  function auditIdentityChanged() {
    resetAudit();
    state.audit.error = {identityChanged: true};
    renderLogs();
  }
  async function loadAuditPage(index = 0, cursor = null, exporting = false) {
    const audit = state.audit, epoch = state.epoch;
    const old = audit.page, scope = auditScope();
    const identity = audit.identity;
    const history = cursor ? [...audit.cursors] : [];
    const localFilter = JSON.stringify([$("logSearch").value, $("analyzerFilter").value]);
    audit.controller?.abort();
    const controller = new AbortController(), generation = ++audit.generation;
    audit.controller = controller; audit.busy = true; audit.page = null; audit.error = null;
    if (!cursor) { audit.cursors = []; audit.index = 0; audit.identity = null; audit.scope = null; }
    renderLogs();
    const active = () => epoch === state.epoch && generation === audit.generation && scope === auditScope();
    const invalid = () => Object.assign(new Error("Invalid audit page"), {invalidResponse: true});
    const changed = () => Object.assign(new Error("Audit identity changed"), {identityChanged: true});
    try {
      const signal = controller.signal;
      const before = checked("identity", await request("/auth/me", {signal}));
      if (!active()) return false;
      if (!sameReviewIdentity(before, state.data.identity) || (cursor && !sameReviewIdentity(before, identity))) throw changed();
      const params = new URLSearchParams({limit: "12"});
      if ($("riskFilter").value) params.set("risk_level", $("riskFilter").value);
      if ($("reviewFilter").value) params.set("review_status", $("reviewFilter").value);
      if ($("auditQuery").value.trim()) params.set("q", $("auditQuery").value.trim());
      if ($("auditAnalyzer").value) params.set("analyzer", $("auditAnalyzer").value);
      if (cursor) params.set("cursor", cursor);
      const page = checked("audit", await request("/audit/results?" + params, {signal}));
      if (!active()) return false;
      const after = checked("identity", await request("/auth/me", {signal}));
      if (!active()) return false;
      if (!sameReviewIdentity(before, after) || !sameReviewIdentity(before, state.data.identity)) throw changed();
      if (cursor && (!old || audit.scope !== scope || old.snapshot_id !== page.snapshot_id ||
          old.total_matches !== page.total_matches || old.snapshot_expires_at !== page.snapshot_expires_at ||
          old.snapshot_created_at !== page.snapshot_created_at || old.snapshot_mode !== page.snapshot_mode)) throw invalid();
      if (cursor && index !== audit.index && page.items.some((record) => old.items.some((previous) => previous.analysis_id === record.analysis_id))) throw invalid();
      if (page.items.length !== Math.max(0, Math.min(12, page.total_matches - index * 12)) ||
          (page.next_cursor !== null) !== (index * 12 + page.items.length < page.total_matches) ||
          (index > 0 && index * 12 >= page.total_matches) ||
          new Set(page.items.map((record) => record.analysis_id)).size !== page.items.length ||
          !page.items.every((record) => record.tenant_id === before.tenant_id && typeof record.analysis_id === "string" && record.analysis_id.length > 0 &&
            (!$("riskFilter").value || record.assessment.risk_level === $("riskFilter").value) &&
            (!$("reviewFilter").value || record.review_status === $("reviewFilter").value) &&
            (!$("auditAnalyzer").value || record.analyzer === $("auditAnalyzer").value))) throw invalid();
      history[index] = page.page_cursor;
      if (page.next_cursor) history[index + 1] = page.next_cursor;
      audit.cursors = history.slice(0, index + (page.next_cursor ? 2 : 1));
      audit.page = page; audit.index = index; audit.identity = before; audit.scope = scope;
      if (exporting) {
        if (localFilter === JSON.stringify([$("logSearch").value, $("analyzerFilter").value])) exportAuditPage();
        else notify("검색 조건이 변경됐습니다. 현재 결과를 확인한 뒤 다시 저장하세요.");
      }
      return true;
    } catch (error) {
      if (active()) {
        audit.page = null; audit.cursors = []; audit.identity = null; audit.scope = null;
        audit.error = error;
        if (error.identityChanged || [401, 403].includes(error.status)) {
          state.detailSequence++; $("detailDialog").close(); $("detailBody").replaceChildren();
        }
      }
      return false;
    } finally {
      if (active()) { audit.busy = false; audit.controller = null; render(); }
    }
  }

  function renderLogs() {
    const audit = state.audit, page = audit.page, rows = filteredLogs();
    text("logCount", page ? `현재 페이지 ${rows.length}건 / 전체 조건 일치 ${num(page.total_matches)}건` : "조회 결과 없음");
    text("pageLabel", page ? `${audit.index + 1} / ${Math.max(1, Math.ceil(page.total_matches / 12))} 페이지` : "페이지 미확인");
    text("logSnapshot", audit.busy ? "감사 기록과 현재 조회 신원을 확인하고 있습니다." : audit.error ? auditError(audit.error) :
      page ? `${date(page.snapshot_created_at, true)} 기준 기록입니다. 최신 목록 조회로 갱신하세요. 상세와 검토는 현재 상태를 다시 확인합니다.` : "최신 목록 조회를 눌러 시작하세요.");
    $("logRows").setAttribute("aria-busy", String(audit.busy));
    $("prevPage").disabled = audit.busy || !page || audit.index <= 0;
    $("nextPage").disabled = audit.busy || !page || !page.next_cursor;
    $("exportLogs").disabled = audit.busy || !page || rows.length === 0;
    $("reloadAudit").disabled = audit.busy;
    renderLogRows("logRows", rows);
    renderLogRows("recentLogs", (state.data.logs || []).slice(0, 5));
  }

  function renderSessions() {
    const records = state.data.sessions;
    text("metricRevoked", records ? num(records.filter((item) => item.status === "REVOKED").length) : "—");
    text("sessionSample", records ? `/ 현재 페이지 ${records.length}건` : "");
    text("sessionCount", records ? `현재 페이지 ${records.length}개 세션 조회` : "조회 결과 없음");
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

  function renderCaseRows(rows) {
    const body = $("caseRows"); body.replaceChildren();
    const labels = {NEW: "신규", TRIAGED: "분류 완료", INVESTIGATING: "조사 중", CONTAINED: "봉쇄 확인", RESOLVED: "해결 완료", CLOSED: "종결"};
    rows.forEach(record => {
      const row = node("tr"), detail = node("td"), button = node("button", "현재 상세 열기", "button secondary");
      button.type = "button";
      button.addEventListener("click", () => window.dashboardOperations?.open("/cases/{case_id}", "GET", {case_id: record.case_id}));
      detail.append(button);
      row.append(node("td", record.case_id), node("td", date(record.updated_at, true)), node("td", labels[record.status]), node("td", record.assignee || "미배정"), node("td", record.version), detail);
      body.append(row);
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
        stroke: "#e1e6ec",
        "stroke-dasharray": "3 6"
      }));
      const label = svg("text", {
        x: 20,
        y: y(level) + 4,
        fill: "#687583",
        "font-size": 10,
        "text-anchor": "end"
      });
      label.textContent = level;
      chart.append(label);
    }
    const points = (key) => buckets.map((b, i) => `${x(i)},${y(b[key])}`).join(" ");
    chart.append(svg("polygon", {
      points: `42,168 ${points("total")} 625,168`,
      fill: "#547ca5",
      opacity: ".08"
    }));
    ["total", "risk"].forEach((key) => {
      chart.append(svg("polyline", {
        points: points(key),
        fill: "none",
        stroke: key === "total" ? "#547ca5" : "#b5353b",
        "stroke-width": 2.2,
        "stroke-linejoin": "round"
      }));
      buckets.forEach((b, i) => {
        const dot = svg("circle", {
          cx: x(i),
          cy: y(b[key]),
          r: 3,
          fill: key === "total" ? "#547ca5" : "#b5353b"
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
        fill: "#687583",
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
    text("riskTotal", num(metrics?.total_analyses));
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
    $("riskBar").style.background = metrics?.total_analyses ? `linear-gradient(to right,${segments.join(",")})` : "#e9edf1";
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
    text("modeBadge", health ? (health.dashboard_demo ? "합성 시연 데이터" : `${health.environment.toUpperCase()} / ${health.auth_mode === "disabled" ? "인증 비활성" : "인증 사용"}`) : "연결 확인 필요");
    const identity = state.data.identity;
    text("authLabel", identity?.subject || "조회 신원 확인 필요");
    text("workspaceTenant", identity ? `테넌트: ${identity.tenant_id}` : "테넌트 확인 필요");
    text("identityInfo", identity ? `${identity.subject} / ${identity.tenant_id} / ${identity.roles.join(", ")}` : "현재 조회 신원을 확인할 수 없습니다.");
    text("analyzerMode", health ? {
      rule: "규칙 기반 분석",
      openai: "OpenAI 분석",
      hybrid: "규칙 + OpenAI"
    } [health.analyzer_mode] || health.analyzer_mode : "—");
    text("footerVersion", health ? `v${health.version} / ${health.environment.toUpperCase()} / ${Intl.DateTimeFormat().resolvedOptions().timeZone}` : "LOCAL FRAMEWORK");
    const errors = [...Object.entries(state.errors), ...(state.audit.error ? [["audit", state.audit.error]] : [])];
    const coreOkay = ["health", "identity", "metrics", "logs", "sessions"].every((key) => state.data[key]);
    text("connectionStatus", coreOkay ? (errors.length ? "일부 조회 기능 확인 필요" : "조회 API 연결됨") : "데이터 조회 확인 필요");
    $("statusDot").className = `status-dot ${coreOkay && !errors.length ? "online" : ""}`;
    $("notice").hidden = !errors.length;
    if (errors.length) text("notice", `${errors.length}개 항목 조회 실패. ${errorLabel(errors[0][1])}`);
    renderMetrics();
    renderChart();
    renderLogs();
    renderSessions();
    renderPipeline();
    renderEvidence();
    updateDemoButtons();
    window.dashboardOperations?.sync();
  }
  async function refresh(options = {}) {
    if (state.busy) return;
    const epoch = state.epoch;
    const previousIdentity = state.data.identity;
    let identityChanged = false;
    const reload = options.resetAudit !== false && state.page === "logs";
    if (reload) { resetAudit(); renderLogs(); }
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
            if (key === "identity" && previousIdentity && !sameReviewIdentity(previousIdentity, result)) {
              identityChanged = true;
              auditIdentityChanged();
              sessionView.reset();
              caseView.reset();
            }
          }
        } catch (error) {
          if (epoch === state.epoch) {
            delete state.data[key];
            state.errors[key] = error;
            if (key === "identity") { resetAudit(); sessionView.reset(); caseView.reset(); state.audit.error = error; renderLogs(); }
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
      if (!identityChanged && state.page === "logs" && state.data.identity && !state.audit.busy &&
          (reload || (!state.audit.page && !state.audit.error))) await loadAuditPage();
      if (!identityChanged && state.data.identity && !sessionView.busy &&
          ((!sessionView.page && !sessionView.error) || (state.page === "sessions" && options.resetAudit !== false))) await sessionView.load();
      if (!identityChanged && state.page === "cases" && state.data.identity && !caseView.busy &&
          ((!caseView.page && !caseView.error) || options.resetAudit !== false)) await caseView.load();
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
    window.dashboardOperations?.navigate(state.page);
    if (state.page === "logs" && state.data.identity) loadAuditPage();
    if (state.page === "sessions" && state.data.identity) sessionView.load();
    if (state.page === "cases" && state.data.identity) caseView.load();
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
    sessionView.reset();
    caseView.reset();
    state.errors = {};
    state.busy = false;
    state.refreshRequested = false;
    resetAudit();
    state.demo = {};
    window.dashboardOperations?.reset();
    state.detailSequence++;
    $("detailDialog").close();
    $("detailBody").replaceChildren();
    $("demoHistory").replaceChildren(node("li", "실행 기록이 없습니다.", "empty"));
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
  $("refresh").addEventListener("click", () => refresh());
  document.querySelector(".skip-link").addEventListener("click", (event) => {
    event.preventDefault();
    $("content").focus();
    $("content").scrollIntoView();
  });
  window.addEventListener("hashchange", navigate);
  ["logSearch", "analyzerFilter"].forEach((id) => $(id).addEventListener(id === "logSearch" ? "input" : "change", renderLogs));
  $("auditSearchForm").addEventListener("submit", (event) => { event.preventDefault(); loadAuditPage(); });
  ["auditQuery", "auditAnalyzer"].forEach((id) => $(id).addEventListener(id === "auditQuery" ? "input" : "change", () => { resetAudit(); renderLogs(); }));
  ["riskFilter", "reviewFilter"].forEach((id) => $(id).addEventListener("change", () => loadAuditPage()));
  $("sessionFilter").addEventListener("change", () => sessionView.load());
  $("prevPage").addEventListener("click", () => {
    const audit = state.audit;
    if (!audit.busy && audit.page && audit.index > 0) loadAuditPage(audit.index - 1, audit.cursors[audit.index - 1]);
  });
  $("nextPage").addEventListener("click", () => {
    const audit = state.audit;
    if (!audit.busy && audit.page?.next_cursor) loadAuditPage(audit.index + 1, audit.page.next_cursor);
  });
  $("reloadAudit").addEventListener("click", () => loadAuditPage());
  $("exportLogs").addEventListener("click", () => {
    const audit = state.audit;
    if (!audit.busy && audit.page && filteredLogs().length) loadAuditPage(audit.index, audit.page.page_cursor, true);
  });
  function exportAuditPage() {
    const audit = state.audit;
    if (!audit.page || !filteredLogs().length) return;
    const blob = new Blob([JSON.stringify({
      scope: "current_tenant_audit_snapshot_page_filtered",
      historical_audit_snapshot: true,
      snapshot_id: audit.page.snapshot_id,
      snapshot_created_at: audit.page.snapshot_created_at,
      snapshot_expires_at: audit.page.snapshot_expires_at,
      snapshot_mode: audit.page.snapshot_mode,
      page_number: audit.index + 1,
      total_matches: audit.page.total_matches,
      filters: {risk_level: $("riskFilter").value, review_status: $("reviewFilter").value,
        q: $("auditQuery").value.trim(), analyzer: $("auditAnalyzer").value,
        page_search: $("logSearch").value, page_analyzer: $("analyzerFilter").value},
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
    notify(`현재 페이지의 검색 결과 ${filteredLogs().length}건을 저장했습니다.`);
  }
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
  window.dashboardContext = {request, node, redact, rawPanel, analysisEvidence, refresh, notify, errorLabel,
    readReviewObservation, sameReviewIdentity,
    get state() { return {epoch: state.epoch, page: state.page, data: state.data}; }};
  tick();
  setInterval(tick, 1000);
  navigate();
  render();
  refresh();
  setInterval(() => {
    if ($("autoRefresh").checked && !document.hidden && !state.demo.busy && !state.audit.busy && !$("connectionDialog").open) refresh({resetAudit: false});
  }, 10000);
})();
