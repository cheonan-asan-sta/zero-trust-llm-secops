/* Authenticated forms for the existing application contracts. No browser persistence. */
(() => {
  "use strict";
  const ctx = window.dashboardContext;
  delete window.dashboardContext;
  const {request, node, redact, rawPanel, errorLabel} = ctx;
  const current = () => ctx.state;
  const root = document.getElementById("operationsWorkspace");
  const groups = new Set(["analysis", "evaluation", "cases", "context", "signals", "responses", "assurance", "operations"]);
  const names = {
    scenario_id: "시나리오", count: "이벤트 수", event_id: "이벤트 ID", identifier: "기록 ID",
    request_id: "요청 ID", session_id: "세션 ID", expected_version: "확인한 버전",
    expected_session_version: "확인한 세션 버전", request_digest: "확인한 요청 해시",
    action: "작업", expires_at: "만료 시각", reason: "사유", note: "검토 메모",
    status: "처리 상태", review_status: "검토 상태", assignee: "담당자",
    baseline_id: "기준선 ID", approval_id: "작업 승인 ID", capture_ids: "검토한 수집 기록 ID 목록",
    capture_id: "수집 기록 ID", valid_from: "유효 시작", valid_until: "유효 종료",
    max_uses: "최대 사용 횟수", execution_policy: "실행 주체와 반출 목적지 조건",
    events: "입력 이벤트 목록", event: "입력 이벤트", policy: "상관분석 조건",
    analyzer: "분석기", concurrency: "동시 실행 수", runs_per_scenario: "시나리오별 반복 수",
    dataset_id: "자료 ID", control_id: "통제 ID", limit: "조회 건수", due_only: "전송 시각 도래 건만",
    resource_id: "자원 ID", grant_token: "접근 허용 토큰", signature: "서명",
    tenant_id: "테넌트", source_id: "신호 출처", key_id: "서명 키 ID",
    issued_at: "발급 시각", timestamp: "관측 시각", schema_version: "입력 형식 버전",
    user: "사용자", device: "기기", network: "접속 정보", resource: "보호 자원",
    auth_context: "인증 결과", behavior: "행위 정보", scope: "대상 범위",
    activity: "관측 활동", connection_ids: "연결 ID 목록", algorithm: "서명 알고리즘",
    assessment: "분석 판단", mode: "실행 방식", result: "실행 결과", created: "접수 시각",
    updated: "갱신 시각", actor: "실행자", error: "오류", models: "모델별 결과",
    observations: "관측 신호", observed_at: "관측 시각", expires_in_seconds: "유효시간(초)",
    evidence_sha256: "증거 해시", expected_case_version: "확인한 사고 버전",
    expected_attempt_count: "확인한 전송 시도 횟수", detail: "상세", body: "입력 자료",
    reviewer: "검토 담당자", outcome: "전송 결과", error_code: "오류 코드",
    version: "기록 버전", requester: "요청자", approved_by: "승인한 검토자", reviews: "검토 이력",
    required_approvals: "필요 승인 수", target: "대응 대상", target_current: "대상 상태 일치",
    simulation_only: "모의 실행", effect_applied: "외부 조치 적용", duplicate: "기존 요청 재조회",
    receipt_version: "처리 당시 버전", session_binding: "연결된 세션", subject: "사용자",
    received_at: "접수 시각", completed_at: "완료 시각", reason_codes: "판단 사유",
    decision: "접근 판단", signal_trust: "신호 검증 방식", evidence: "판단 근거",
    risk_score: "위험 점수", risk_level: "위험도", policy_decision: "대응 제안",
    analyzed_at: "분석 시각", latency_ms: "응답 시간 (ms)", budget: "호출 및 비용 집계",
    precision: "정밀도", recall: "재현율", f1: "F1", false_positive_rate: "오탐률",
    false_positives: "오탐", false_negatives: "미탐", abstentions: "판단 보류",
    requests_used: "사용 요청 수", stop_reason: "중단 사유", wire_verification: "요청 동일성 검증",
    verification_completed: "검증 항목 완료", checks: "검증 항목", label: "항목", passed: "통과",
    maintenance: "보관 정리 결과", cleanup: "검증 환경 정리 결과",
  };
  const enumNames = {
    LOGIN: "로그인", READ: "조회", DOWNLOAD: "다운로드", ADMIN: "관리 작업", REMOTE_ACCESS: "원격 접속",
    disable_account: "계정 사용 중지", isolate_device: "기기 격리", reduce_privilege: "권한 축소",
    rule: "규칙 분석", openai: "OpenAI", hybrid: "규칙 + OpenAI",
    PENDING: "검토 대기", IN_REVIEW: "조사 중", RESOLVED: "해결 완료", DISMISSED: "오탐 처리",
    NEW: "신규", TRIAGED: "분류 완료", INVESTIGATING: "조사 중", CONTAINED: "봉쇄 확인",
    CLOSED: "종결", simulation: "모의 실행",
    APPROVED: "승인 완료", EXECUTED: "모의 실행 완료", CANCELLED: "취소", EXPIRED: "만료", STALE: "대상 변경",
    SIMULATED: "모의 실행", SUCCEEDED: "완료", FAILED: "실패", INTERRUPTED: "중단 확인 필요",
    QUEUED: "접수 대기", RUNNING: "실행 중",
  };
  let catalog = null, loading = null, selection = null, activeGroup = null;
  let sequence = 0, busy = false, prepared = null, inputs = [], resultValue = null;
  let lastGrant = null, lastSession = null, jobTimer = null, capabilities = null, pendingJob = null;
  const label = (key) => names[key] || key;
  const roleLabel = (role) => ({viewer:"조회 사용자",analyst:"분석 담당자",responder:"대응 담당자",admin:"관리자"}[role] || role);
  const hints = {
    "/detections/context/baselines": "서명된 정상 수집 기록을 3건 이상 지정합니다. 유효 시작 시각은 등록 시각보다 늦어야 합니다.",
    "/detections/context/approvals": "승인 기간은 선택한 기준선의 유효기간 안에 있어야 합니다. 시작 시각을 과거로 지정할 수 없습니다.",
    "/zero-trust/sessions/evaluate": "합성 입력으로 로컬 접근 정책을 검증합니다. 수집기에서 받은 실제 관측은 서명 신호 접수 메뉴를 사용하세요.",
    "/detections/context/evaluate": "기준선과 승인 내역을 참고해 조사 후보를 판단합니다. 이 결과만으로 접근을 허용하거나 차단하지 않습니다.",
    "/integrations/outbox/{event_id}/attempt": "이미 수행한 외부 전송의 결과를 기록합니다. 이 화면에서 외부 시스템으로 전송하지는 않습니다.",
  };
  const roles = () => current().data.identity?.roles || [];
  const allowed = () => selection && roles().includes(selection.role) && !busy;
  const isWrite = () => selection && selection.method !== "GET";
  const message = (text, bad = false) => {
    const target = document.getElementById("operationMessage");
    if (target) {
      target.textContent = text;
      target.className = "operation-message" + (bad ? " error" : "");
    }
  };
  function button(text, handler, primary = false) {
    const result = node("button", text, "button " + (primary ? "primary" : "secondary"));
    result.type = "button";
    result.addEventListener("click", handler);
    return result;
  }
  function invalidate() {
    prepared = null;
    const panel = document.getElementById("operationConfirmation");
    if (panel) { panel.hidden = true; panel.replaceChildren(); }
  }
  function resolve(schema = {}) {
    if (schema.$ref) return resolve(catalog.schemas[schema.$ref.split("/").pop()]);
    if (schema.anyOf) return resolve(schema.anyOf.find((s) => s.type !== "null") || {});
    return schema;
  }
  function defaultValue(key, schema) {
    if (schema.default !== undefined && schema.default !== null) return schema.default;
    if (schema.const !== undefined) return schema.const;
    if (key === "request_id" || key === "approval_id" || key === "baseline_id") return "ui-" + crypto.randomUUID();
    if (key === "expires_at") return new Date(Date.now() + 240000).toISOString();
    if (key === "valid_from") return new Date(Date.now() + 300000).toISOString();
    if (key === "issued_at" || key === "timestamp") return new Date().toISOString();
    if (key === "valid_until") return new Date(Date.now() +
      (selection.path === "/detections/context/approvals" ? 1800000 : 3600000)).toISOString();
    if (key === "session_id" && lastSession) return lastSession.session_id;
    if (key === "resource_id" && lastSession) return lastSession.resource_id;
    if (key === "grant_token" && lastGrant) return lastGrant;
    if (key === "reviewer") return current().data.identity?.subject || "";
    return "";
  }
  function field(key, source, required, place, preset) {
    const schema = resolve(source);
    const wrapper = node("label", null, "operation-field");
    wrapper.append(node("span", label(key) + (required ? " *" : "")));
    let input;
    if (schema.enum || schema.const !== undefined) {
      input = node("select");
      if (!required) input.append(new Option("선택하지 않음", ""));
      (schema.enum || [schema.const]).forEach((value) => input.append(new Option(enumNames[value] || String(value), String(value))));
    } else if (schema.type === "boolean") {
      input = node("select");
      if (!required) input.append(new Option("기본값 사용", ""));
      input.append(new Option("예", "true"), new Option("아니요", "false"));
    } else if (["object", "array"].includes(schema.type) || schema.properties) {
      input = node("textarea");
      input.rows = 5;
      input.className = "mono";
      input.spellcheck = false;
      wrapper.classList.add("wide-field");
      input.placeholder = schema.type === "array" ? '["record-001"]' : "{}";
    } else {
      input = node("input");
      input.type = /token|signature/i.test(key) ? "password" :
        ["integer", "number"].includes(schema.type) ? "number" : "text";
      input.autocomplete = "off";
      if (schema.minLength) input.minLength = schema.minLength;
      if (schema.maxLength) input.maxLength = schema.maxLength;
      if (schema.minimum !== undefined) input.min = schema.minimum;
      if (schema.maximum !== undefined) input.max = schema.maximum;
      if (input.type === "number") input.step = schema.type === "integer" ? "1" : "any";
    }
    input.id = "op-" + place + "-" + key;
    input.name = key;
    input.required = required;
    const initial = preset !== undefined ? preset : defaultValue(key, schema);
    input.value = initial !== null && typeof initial === "object" ? JSON.stringify(initial, null, 2) : String(initial);
    input.addEventListener("input", invalidate);
    input.addEventListener("change", invalidate);
    if (key === "reviewer" && current().data.identity?.auth_method !== "disabled") input.readOnly = true;
    if (["expected_version", "expected_session_version", "request_digest", "expected_attempt_count"].includes(key) &&
        (selection.path.startsWith("/response/requests") || selection.path.endsWith("/revoke") ||
         selection.path.endsWith("/attempt") || (selection.path.startsWith("/cases/") && selection.method === "PATCH"))) {
      input.required = false;
      input.readOnly = true;
      input.placeholder = "실행 검토 시 서버에서 확인";
      wrapper.hidden = true;
    }
    wrapper.append(input);
    if (schema.format === "date-time") wrapper.append(node("small", "시간대 포함 ISO 시각. 예: 2026-11-16T09:00:00+09:00"));
    inputs.push({key, place, schema, input, required});
    return wrapper;
  }
  function describeResult(value, depth = 0) {
    if (depth > 4) return rawPanel(value, "세부 자료");
    if (Array.isArray(value)) {
      const area = node("div", null, "operation-records");
      area.append(node("p", value.length + "건" + (value.length > 100 ? " / 앞 100건 표시" : ""), "muted"));
      value.slice(0, 100).forEach((entry, index) => {
        const item = node("details", null, "operation-record");
        item.append(node("summary", entry?.title || entry?.request_id || entry?.case_id || entry?.event_id ||
          entry?.session_id || entry?.model_id || entry?.label || "기록 " + (index + 1)), describeResult(entry, depth + 1));
        area.append(item);
      });
      return area;
    }
    if (value && typeof value === "object") {
      const area = node("div"), grid = node("dl", null, "operation-result-grid");
      Object.entries(value).forEach(([key, item]) => {
        if (["request_digest", "input_digest_sha256", "evidence_sha256", "receipt_version"].includes(key)) return;
        if (item !== null && typeof item === "object") {
          const details = node("details");
          details.append(node("summary", label(key)), describeResult(item, depth + 1));
          area.append(details);
        } else {
          const row = node("div");
          const display = item === null ? "—" : typeof item === "boolean" ? (item ? "예" : "아니요") :
            Object.hasOwn(enumNames, item) ? enumNames[item] + " (" + item + ")" : String(item);
          row.append(node("dt", label(key)), node("dd", display));
          grid.append(row);
        }
      });
      area.prepend(grid);
      return area;
    }
    return node("p", value === null ? "—" : String(value));
  }
  function showResult(value) {
    resultValue = redact(value);
    const target = document.getElementById("operationResult");
    target.replaceChildren(describeResult(resultValue), rawPanel(resultValue));
    if (value?.grant_token && value?.session) {
      lastGrant = value.grant_token;
      lastSession = value.session;
    }
  }
  async function getCatalog() {
    if (catalog || !current().data.identity) return;
    if (loading) return loading;
    const epoch = current().epoch;
    loading = (async () => {
      try {
        const value = await request("/auth/dashboard-catalog");
        if (epoch !== current().epoch) return;
        if (!Array.isArray(value.operations) || !value.schemas) throw new Error("작업 목록 형식을 확인할 수 없습니다.");
        catalog = value;
        if (groups.has(current().page)) navigate(current().page, true);
      } catch (error) {
        if (epoch === current().epoch) message(errorLabel(error), true);
      } finally {
        if (epoch === current().epoch) loading = null;
      }
    })();
    return loading;
  }
  function readForm() {
    const params = {}, body = {};
    inputs.forEach(({key, place, schema, input, required}) => {
      if (input.readOnly) return;
      const raw = input.value.trim();
      if (!raw) {
        if (required) throw new Error(label(key) + " 항목을 입력하세요.");
        return;
      }
      let value = raw;
      if (["integer", "number"].includes(schema.type)) {
        value = Number(raw);
        if (!Number.isFinite(value) || (schema.type === "integer" && !Number.isInteger(value))) throw new Error(label(key) + " 값이 올바르지 않습니다.");
      } else if (schema.type === "boolean") value = raw === "true";
      else if (["object", "array"].includes(schema.type) || schema.properties) {
        try { value = JSON.parse(raw); } catch { throw new Error(label(key) + " JSON 형식을 확인하세요."); }
      }
      (place === "body" ? body : params)[key] = value;
    });
    let path = selection.path;
    selection.parameters.filter((p) => p.in === "path").forEach((p) => {
      path = path.replace("{" + p.name + "}", encodeURIComponent(params[p.name]));
    });
    const query = new URLSearchParams();
    selection.parameters.filter((p) => p.in === "query" && params[p.name] !== undefined)
      .forEach((p) => query.set(p.name, params[p.name]));
    if (query.size) path += "?" + query.toString();
    return {path, body: selection.body ? body : undefined, method: selection.method};
  }
  function stripLabels(value) {
    if (Array.isArray(value)) return value.map(stripLabels);
    if (value && typeof value === "object") return Object.fromEntries(Object.entries(value)
      .filter(([key]) => key !== "ground_truth").map(([key, item]) => [key, stripLabels(item)]));
    return value;
  }
  async function bindVersion(command) {
    const path = command.path.split("?")[0];
    const body = command.body;
    let record;
    if (path === "/response/requests" && body?.session_id) {
      const rows = await request("/zero-trust/sessions/" + encodeURIComponent(body.session_id));
      record = rows.at(-1);
      body.expected_session_version = record.version;
    } else if (/^\/response\/requests\/[^/]+\/(approvals|cancel|execute)$/.test(path)) {
      record = await request(path.replace(/\/(approvals|cancel|execute)$/, ""));
      body.expected_version = record.version;
      body.request_digest = record.request_digest;
      if (path.endsWith("/approvals") && record.requester === current().data.identity.subject) throw new Error("요청자는 자기 요청을 승인할 수 없습니다. 다른 검토자의 인증이 필요합니다.");
    } else if (/^\/zero-trust\/sessions\/[^/]+\/revoke$/.test(path)) {
      const rows = await request(path.replace(/\/revoke$/, ""));
      record = rows.at(-1);
      body.expected_version = record.version;
    } else if (selection.method === "PATCH" && path.startsWith("/cases/")) {
      record = await request(path);
      body.expected_version = record.version;
    } else if (path.startsWith("/integrations/outbox/") && path.endsWith("/attempt")) {
      record = await request(path.replace(/\/attempt$/, ""));
      if (inputs.some((i) => i.key === "expected_version")) body.expected_version = record.version;
      if (inputs.some((i) => i.key === "expected_attempt_count")) body.expected_attempt_count = record.attempt_count;
    }
    inputs.filter((i) => i.input.readOnly).forEach((i) => { i.input.value = body?.[i.key] ?? ""; });
    return record ? redact(record) : null;
  }
  function failure(error, writing) {
    const detail = error.detail ? " (" + redact(error.detail) + ")" : "";
    if (error.status === 409) return "기록이 변경됐거나 현재 상태에서는 실행할 수 없습니다. 다시 조회하고 내용을 검토하세요." + detail;
    if (error.status === 422) return "입력 값 또는 유효기간이 맞지 않습니다. 필수 항목과 입력 형식을 확인하세요." + detail;
    if (writing && (!error.status || error.status >= 500)) return "처리 결과를 확인하지 못했습니다. 요청 ID로 상태를 조회한 뒤 재시도하세요. 자동 재전송하지 않았습니다.";
    return error.status ? errorLabel(error) : error.message;
  }
  async function prepare() {
    if (!allowed()) return;
    const epoch = current().epoch, ticket = ++sequence;
    invalidate();
    try {
      const form = document.getElementById("operationForm");
      if (!form.reportValidity()) return;
      const command = readForm();
      if (command.body?.valid_from && Date.parse(command.body.valid_from) <= Date.now()) {
        throw new Error("유효 시작 시각을 현재보다 늦게 지정하세요. 소급 등록은 허용되지 않습니다.");
      }
      busy = true; sync();
      const bound = isWrite() ? await bindVersion(command) : null;
      if (epoch !== current().epoch || ticket !== sequence) return;
      if (command.path.startsWith("/analysis")) command.body = stripLabels(command.body);
      if (!isWrite()) {
        const value = await request(command.path, {method: "GET", timeoutMs: 120000});
        if (epoch !== current().epoch || ticket !== sequence) return;
        showResult(value); message("조회 완료");
        return;
      }
      const paid = (command.path.startsWith("/analysis") && current().data.health?.analyzer_mode !== "rule") ||
        (command.path === "/evaluation/run" && command.body?.analyzer !== "rule");
      prepared = {...command, epoch, ticket};
      const panel = document.getElementById("operationConfirmation");
      panel.replaceChildren(node("h3", "실행 전 확인"),
        node("p", current().data.identity.subject + " / " + current().data.identity.tenant_id, "mono"),
        node("p", paid ? "실제 모델 호출로 비용이 발생할 수 있습니다. 입력 건수와 분석기를 확인하세요." :
          command.path.includes("/response/requests") ? "외부 계정과 기기에 실제 조치를 수행하지 않는 모의 대응입니다." :
          "아래 입력과 대상에 대해 선택한 작업을 실행합니다."));
      if (bound) panel.append(describeResult(bound));
      panel.append(rawPanel(command.body || {}, "보낼 입력 확인"));
      const confirm = node("label", null, "operation-ack");
      const checkbox = node("input"); checkbox.type = "checkbox"; checkbox.id = "operationAcknowledge";
      confirm.append(checkbox, node("span", paid ? "호출 범위와 비용 발생을 확인했습니다." : "대상과 변경 내용을 확인했습니다."));
      const execute = button("확인한 내용으로 실행", executePrepared, true);
      execute.id = "operationExecute"; execute.disabled = true;
      checkbox.addEventListener("change", () => { execute.disabled = !checkbox.checked || busy; });
      panel.append(confirm, execute); panel.hidden = false;
      message("검토한 버전으로 실행합니다. 중간에 기록이 변경되면 서버가 거부합니다.");
    } catch (error) {
      if (epoch === current().epoch && ticket === sequence) { invalidate(); message(failure(error, false), true); }
    } finally {
      if (epoch === current().epoch && ticket === sequence) { busy = false; sync(); }
    }
  }
  async function executePrepared() {
    if (!prepared || !allowed() || !document.getElementById("operationAcknowledge")?.checked) return;
    const command = prepared, epoch = current().epoch;
    if (command.epoch !== epoch) return;
    busy = true; document.getElementById("operationExecute").disabled = true; sync();
    invalidate();
    try {
      const value = await request(command.path, {
        method: command.method, body: command.body, timeoutMs: 120000,
        allowDenied: command.path === "/zero-trust/protected-access",
      });
      if (epoch !== current().epoch || command.ticket !== sequence) return;
      showResult(value);
      message(command.path === "/zero-trust/protected-access" ?
        (value.data?.allowed ? "접근 허용" : "접근 거부") + " (HTTP " + value.status + ")" :
        command.path.endsWith("/execute") ? "모의 실행 결과를 확인하세요. 실제 외부 조치는 수행하지 않습니다." : "서버 처리 완료");
      ctx.refresh();
    } catch (error) {
      if (epoch === current().epoch && command.ticket === sequence) message(failure(error, true), true);
    } finally {
      if (epoch === current().epoch && command.ticket === sequence) { busy = false; sync(); }
    }
  }
  function selectOperation(operation, preset = {}) {
    sequence++; busy = false; prepared = null; selection = operation; inputs = []; resultValue = null;
    const host = document.getElementById("operationEditor"); host.replaceChildren();
    host.append(node("h2", operation.title), node("p", "필요 권한: " + roleLabel(operation.role), "muted"));
    if (hints[operation.path]) host.append(node("p", hints[operation.path], "operation-message"));
    const form = node("form", null, "operation-form"); form.id = "operationForm";
    form.addEventListener("submit", (event) => { event.preventDefault(); prepare(); });
    operation.parameters.forEach((p) => form.append(field(p.name, p.schema, p.required, p.in, preset[p.name])));
    if (operation.body) {
      const body = resolve(operation.body);
      Object.entries(body.properties || {}).filter(([key]) => key !== "ground_truth").forEach(([key, schema]) => {
        form.append(field(key, schema, body.required?.includes(key), "body", preset[key]));
      });
    }
    const controls = node("div", null, "operation-form-actions");
    const prepareButton = button(isWrite() ? "입력 검토" : "조회", prepare, true);
    prepareButton.id = "operationPrepare";
    controls.append(prepareButton);
    if (operation.body) {
      const file = node("input"); file.type = "file"; file.accept = ".json,application/json";
      file.id = "operationImport"; file.setAttribute("aria-label", "입력 JSON 불러오기");
      file.addEventListener("change", async () => {
        const epoch = current().epoch, ticket = sequence, source = file.files?.[0];
        if (!source || source.size > 1048576) { message("1MB 이하 JSON 파일을 선택하세요.", true); return; }
        try {
          const value = JSON.parse(await source.text());
          if (epoch !== current().epoch || ticket !== sequence) return;
          if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("JSON 객체가 필요합니다.");
          fillBody(value); message("입력 자료를 불러왔습니다. 실행 전 내용을 검토하세요.");
        } catch { if (epoch === current().epoch) message("입력 파일 형식을 확인하세요.", true); }
        finally { file.value = ""; }
      });
      const fileLabel = node("label", null, "operation-upload");
      fileLabel.append(node("span", "입력 자료 불러오기"), file); controls.append(fileLabel);
      if (operation.path === "/analysis" || operation.path === "/events/normalize" ||
          operation.path === "/detections/evaluate" || operation.path === "/zero-trust/sessions/evaluate") {
        const scenario = node("select"); scenario.id = "operationScenario";
        scenario.setAttribute("aria-label", "예제 시나리오");
        ["NORMAL-01","ZT-S01","ZT-S02","ZT-S03","ZT-S04","ZT-S05"].forEach((id) => scenario.append(new Option(id,id)));
        controls.append(scenario, button("합성 예제 불러오기", async () => {
          const epoch = current().epoch, ticket = sequence;
          try {
            const rows = await request("/events/simulate", {body: {scenario_id:scenario.value,count:1}});
            if (epoch !== current().epoch || ticket !== sequence) return;
            const event = stripLabels(rows[0]);
            event.event_id = "ui-event-" + crypto.randomUUID();
            event.timestamp = new Date().toISOString();
            if (operation.path === "/zero-trust/sessions/evaluate") fillBody({
              session_id: "ui-session-" + crypto.randomUUID(), expected_version: 0, event,
            }); else fillBody(event);
            message("합성 입력입니다. 정답 라벨을 제거했습니다.");
          } catch (error) { if (epoch === current().epoch) message(failure(error,false),true); }
        }));
      }
    }
    host.append(form, controls, node("p", "", "operation-message"));
    host.lastChild.id = "operationMessage";
    const confirmation = node("section", null, "operation-confirmation");
    confirmation.id = "operationConfirmation"; confirmation.hidden = true;
    const result = node("section", null, "operation-result");
    result.id = "operationResult";
    host.append(confirmation, result);
    sync();
  }
  function fillBody(body) {
    inputs.filter((i) => i.place === "body").forEach(({key,input}) => {
      if (body[key] !== undefined) input.value = body[key] !== null && typeof body[key] === "object" ?
        JSON.stringify(body[key],null,2) : String(body[key] ?? "");
    });
    invalidate();
  }
  function sync() {
    const identity = current().data.identity;
    const button = document.getElementById("operationPrepare");
    if (button) button.disabled = !allowed();
    if (selection && !roles().includes(selection.role)) message(
      identity ? "현재 사용자에게 " + roleLabel(selection.role) + " 권한이 필요합니다." : "연결 및 인증에서 사용자 신원을 확인하세요.", true);
    if (!catalog && identity && groups.has(current().page)) getCatalog();
  }
  function navigate(group, force = false) {
    root.hidden = !groups.has(group);
    if (root.hidden) { clearInterval(jobTimer); jobTimer = null; return; }
    if (activeGroup === group && !force) return;
    clearInterval(jobTimer); jobTimer = null;
    activeGroup = group; selection = null; inputs = []; invalidate(); sequence++; busy = false;
    root.replaceChildren();
    if (group === "operations") { renderJobs(); return; }
    if (!catalog) {
      const msg = node("p", "작업 목록을 불러오고 있습니다.", "empty");
      msg.id = "operationMessage"; root.append(msg); getCatalog(); return;
    }
    const layout = node("div", null, "operation-layout");
    const nav = node("div", null, "card operation-menu");
    const editor = node("div", null, "card operation-editor"); editor.id = "operationEditor";
    const options = catalog.operations.filter((op) => op.group === group);
    options.forEach((op) => {
      const item = button(op.title, () => {
        nav.querySelectorAll("button").forEach((b) => b.removeAttribute("aria-current"));
        item.setAttribute("aria-current", "true"); selectOperation(op);
      });
      item.dataset.operation = op.id; nav.append(item);
    });
    layout.append(nav, editor); root.append(layout);
    if (options.length) {
      nav.firstChild.setAttribute("aria-current", "true"); selectOperation(options[0]);
    }
  }
  async function open(path, method, preset = {}) {
    await getCatalog();
    const op = catalog?.operations.find((item) => item.path === path && item.method === method);
    if (!op) return;
    document.getElementById("detailDialog").close();
    location.hash = op.group;
    navigate(op.group, true);
    selectOperation(op, preset);
    root.querySelectorAll("[data-operation]").forEach((button) => {
      button.toggleAttribute("aria-current", button.dataset.operation === op.id);
    });
  }
  function detailActions(type, record, host) {
    const controls = node("div", null, "operation-form-actions");
    const responder = roles().includes("responder");
    if (type === "response" && responder) {
      const pending = ["PENDING","APPROVED"].includes(record.status);
      if (record.status === "PENDING" && record.requester !== current().data.identity.subject &&
          !record.approved_by.includes(current().data.identity.subject)) {
        controls.append(button("검토 승인", () => open("/response/requests/{identifier}/approvals", "POST", {identifier:record.request_id})));
      }
      if (["PENDING","APPROVED","STALE","EXPIRED"].includes(record.status)) {
        controls.append(button("요청 취소", () => open("/response/requests/{identifier}/cancel", "POST", {identifier:record.request_id})));
      }
      if (pending && record.status === "APPROVED") controls.append(button("모의 실행 검토", () => open("/response/requests/{identifier}/execute", "POST", {identifier:record.request_id})));
    } else if (type === "session" && responder) {
      const session = record.at(-1);
      if (session) controls.append(button("세션 회수", () => open("/zero-trust/sessions/{session_id}/revoke", "POST", {session_id:session.session_id})),
        button("대응 요청", () => open("/response/requests", "POST", {session_id:session.session_id})));
    } else if (type === "log" && responder) {
      controls.append(button("검토 상태 변경", () => open("/results/{event_id}/review", "PATCH", {event_id:record.event_id})));
    }
    if (controls.children.length) host.append(controls);
  }
  async function renderJobs() {
    const epoch = current().epoch, ticket = sequence;
    const panel = node("div", null, "card operation-editor");
    panel.append(node("h2","실행 환경 작업"), node("p",
      "대시보드가 관리하는 별도 Docker 환경입니다. 현재 조회 중인 앱과 저장소를 공유하지 않습니다. 복원은 해당 환경의 기존 토큰을 무효화하며 정지는 자료를 보존합니다.", "muted"));
    const msg = node("p","관리자 설정을 확인하고 있습니다.","operation-message"); msg.id = "operationMessage";
    panel.append(msg); root.append(panel);
    if (!roles().includes("admin") || !["api_key","oidc"].includes(current().data.identity?.auth_method)) {
      message("개별 인증을 사용하는 관리자 연결이 필요합니다. 합성 시연 모드에서는 호스트 작업을 실행할 수 없습니다.",true); return;
    }
    try {
      capabilities = await request("/dashboard/jobs/capabilities");
      if (epoch !== current().epoch || ticket !== sequence) return;
      if (!capabilities.enabled) { message("서버의 DASHBOARD_OPERATIONS_DIRECTORY 설정이 필요합니다.",true); return; }
      const form = node("form",null,"operation-form");
      const actionLabel = node("label",null,"operation-field"), action = node("select");
      action.id="jobAction";
      capabilities.actions.forEach((item) => {
        const option = new Option(item.title + (item.available ? "" : " (서버 설정 필요)"),item.id);
        option.disabled=!item.available; action.append(option);
      });
      actionLabel.append(node("span","작업"),action);
      const reasonLabel=node("label",null,"operation-field"), reason=node("input");
      reason.id="jobReason";reason.required=true;reason.minLength=3;reason.maxLength=300;
      reasonLabel.append(node("span","실행 사유"),reason);
      const budgetLabel=node("label",null,"operation-field"), budget=node("input");
      budget.type="number";budget.step="0.01";budget.min="0";budget.max=String(capabilities.max_live_usd);
      budget.value="0";budget.id="jobBudget";budgetLabel.append(node("span","실호출 비용 상한 (USD)"),budget);
      const ack=node("label",null,"operation-ack"), box=node("input"); box.type="checkbox";box.required=true;box.id="jobConfirm";
      ack.append(box,node("span","선택한 작업의 중단 및 비용 영향을 확인했습니다."));
      const run=button("작업 실행",async()=>{
        if (!form.reportValidity() || !box.checked || busy) return;
        const activeEpoch=current().epoch, activeTicket=sequence;
        const payload={action:action.value,reason:reason.value,confirmed:true,max_usd:Number(budget.value)};
        const fingerprint=JSON.stringify(payload);
        if(!pendingJob || pendingJob.fingerprint!==fingerprint)pendingJob={fingerprint,requestId:crypto.randomUUID()};
        const requestId=pendingJob.requestId;
        busy=true;run.disabled=true;
        message("접수 중 / 요청 ID: " + requestId);
        try {
          const job=await request("/dashboard/jobs",{operation:true,body:{
            request_id:requestId,...payload,
          }});
          if(activeEpoch!==current().epoch || activeTicket!==sequence)return;
          message("접수됨 / 요청 ID: "+job.id);box.checked=false;
          await refreshJobs();
        }catch(error){
          if(activeEpoch===current().epoch && activeTicket===sequence)message(failure(error,true)+" / 요청 ID: "+requestId,true);
        }finally{
          if(activeEpoch===current().epoch && activeTicket===sequence){busy=false;run.disabled=false;}
        }
      },true);
      run.id="jobRun";
      form.addEventListener("submit",(e)=>e.preventDefault());
      form.append(actionLabel,reasonLabel,budgetLabel,ack);
      panel.append(form,run);
      const records=node("div",null,"operation-job-list");records.id="operationJobs";panel.append(records);
      let previousJobs = "";
      const refreshJobs=async()=>{
        try{
          const rows=await request("/dashboard/jobs");
          if(epoch!==current().epoch || ticket!==sequence)return;
          const snapshot=JSON.stringify(rows);
          if(snapshot===previousJobs)return;
          previousJobs=snapshot;
          records.replaceChildren();
          rows.forEach((job)=>{
            const item=node("article",null,"response-item");
            item.append(node("h3",capabilities.actions.find((a)=>a.id===job.action)?.title||job.action),
              node("p",job.id,"mono"),node("p",job.status+" / "+job.actor+" / "+job.reason));
            if(job.error)item.append(node("p",job.error,"operation-message error"));
            if(job.result)item.append(describeResult(redact(job.result)));
            records.append(item);
          });
        }catch(error){if(epoch===current().epoch && ticket===sequence)message(failure(error,false),true);}
      };
      action.addEventListener("change",()=>{box.checked=false;budgetLabel.hidden=action.value!=="m6-live";});
      reason.addEventListener("input",()=>{box.checked=false;});
      budget.addEventListener("input",()=>{box.checked=false;});
      budgetLabel.hidden=true; message("관리자 전용 작업 환경이 연결됐습니다.");
      await refreshJobs();
      jobTimer=setInterval(()=>{if(!document.hidden&&!busy)refreshJobs();},5000);
    }catch(error){if(epoch===current().epoch && ticket===sequence)message(failure(error,false),true);}
  }
  function reset() {
    sequence++; busy=false;prepared=null;catalog=null;loading=null;selection=null;inputs=[];
    lastGrant=null;lastSession=null;resultValue=null;capabilities=null;pendingJob=null;activeGroup=null;
    clearInterval(jobTimer);jobTimer=null;root.replaceChildren();
  }
  window.dashboardOperations={sync,navigate,reset,open,detailActions};
  navigate(current().page);
})();
