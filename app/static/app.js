const state = {
  epoch: 0,
  credential: "",
  credentialType: "none",
  identity: null,
  controllers: new Set(),
  observation: null,
  preparedReview: null,
  reviewRevision: 0,
  resultSequence: 0,
  loadingResult: false,
  scenarios: [],
  selected: null,
  running: false,
  analyzerMode: "rule",
  evaluating: false,
  latestResult: null,
  reviewing: false,
  replaying: false,
  caseCreating: false,
};

const $ = (id) => document.getElementById(id);
const initialMain = document.querySelector("main").cloneNode(true);
const sameIdentity = (left, right) => Boolean(left && right) &&
  ["subject", "tenant_id", "auth_method"].every((key) => typeof left[key] === "string" && left[key].length > 0 && left[key] === right[key]);
const strongReviewTag = (value) => typeof value === "string" && /^"r1-[a-f0-9]{64}"$/.test(value);
const reviewBinding = (value) => typeof value === "string" && /^[a-f0-9]{64}$/.test(value);

const riskLabels = {
  LOW: "낮음",
  MEDIUM: "보통",
  HIGH: "높음",
  CRITICAL: "심각",
};

const violationLabels = {
  NORMAL: "정상 접근",
  CREDENTIAL_ANOMALY: "자격 증명 이상",
  ACCESS_POLICY_VIOLATION: "접근 정책 위반",
  UNMANAGED_DEVICE: "미관리 기기",
  PRIVILEGE_ESCALATION: "권한 상승",
  LATERAL_MOVEMENT: "내부 횡단 이동",
  DATA_EXFILTRATION: "데이터 유출",
  UNKNOWN: "미확인 위협",
};

const actionLabels = {
  ALLOW: "접근 허용",
  REQUIRE_MFA: "추가 MFA 요청",
  REDUCE_PRIVILEGE: "권한 축소 검토",
  ISOLATE_SESSION: "세션 격리 검토",
  HOLD_FOR_REVIEW: "사람 검토 대기",
};

const analyzerLabels = {
  rule: "규칙 분석",
  openai: "OpenAI 분석",
  hybrid: "하이브리드 분석",
};

const reviewStatusLabels = {
  NOT_REQUIRED: "검토 불필요",
  PENDING: "검토 대기",
  IN_REVIEW: "조사 중",
  RESOLVED: "해결 완료",
  DISMISSED: "오탐 처리",
};

const caseStatusLabels = {
  NEW: "신규",
  TRIAGED: "분류 완료",
  INVESTIGATING: "조사 중",
  CONTAINED: "봉쇄 확인",
  RESOLVED: "해결 완료",
  CLOSED: "종결",
};

async function request(path, options = {}) {
  const epoch = state.epoch, credential = state.credential;
  if (options.epoch !== undefined && options.epoch !== epoch) throw new DOMException("연결이 변경됐습니다.", "AbortError");
  if (!path.startsWith("/") || path.startsWith("//")) throw new Error("같은 서버의 API만 사용할 수 있습니다.");
  if (options.ifMatch !== undefined && !strongReviewTag(options.ifMatch)) throw new Error("검토 버전을 다시 조회하세요.");
  if (options.reviewIdentity !== undefined && !reviewBinding(options.reviewIdentity)) throw new Error("검토 신원을 다시 확인하세요.");
  const controller = new AbortController();
  state.controllers.add(controller);
  const timer = setTimeout(() => controller.abort(), options.timeoutMs || 12000);
  const headers = {Accept: "application/json"};
  if (options.body !== undefined) headers["Content-Type"] = "application/json";
  if (state.credentialType === "api_key" && credential) headers["X-API-Key"] = credential;
  if (state.credentialType === "bearer" && credential) headers.Authorization = `Bearer ${credential}`;
  if (options.ifMatch !== undefined) headers["If-Match"] = options.ifMatch;
  if (options.reviewIdentity !== undefined) headers["X-Review-Identity"] = options.reviewIdentity;
  try {
    const response = await fetch(path, {
      method: options.method || "GET", body: options.body, headers, signal: controller.signal,
      redirect: "error", cache: "no-store", credentials: "omit",
    });
    if (epoch !== state.epoch) throw new DOMException("연결이 변경됐습니다.", "AbortError");
    let data;
    try { data = await response.json(); }
    catch { throw Object.assign(new Error("서버 응답을 확인할 수 없습니다."), {status: response.status, invalidResponse: true}); }
    if (epoch !== state.epoch) throw new DOMException("연결이 변경됐습니다.", "AbortError");
    if (!response.ok && !(options.allowDenied && response.status === 403)) {
      const detail = typeof data.detail === "string" ? data.detail.slice(0, 500) : `요청 실패 (${response.status})`;
      throw Object.assign(new Error(credential ? detail.split(credential).join("[REDACTED]") : detail), {status: response.status});
    }
    return options.withMetadata ? {data, etag: response.headers.get("ETag"),
      reviewIdentity: response.headers.get("X-Review-Identity"), reviewMode: response.headers.get("X-Review-Mode")} :
      options.allowDenied ? {data, ok: response.ok, status: response.status} : data;
  } finally {
    clearTimeout(timer);
    state.controllers.delete(controller);
  }
}

function setHealth(health) {
  state.analyzerMode = health.analyzer_mode;
  $("healthDot").className = "health-dot online";
  $("healthText").textContent = `${health.analyzer_mode.toUpperCase()} · 정상 운영`;
  $("footerVersion").textContent = `SIMULATION ONLY · v${health.version}`;
}

function setHealthError() {
  $("healthDot").className = "health-dot error";
  $("healthText").textContent = "서버 연결 확인 필요";
}

function renderScenarios() {
  const grid = $("scenarioGrid");
  grid.replaceChildren();
  $("scenarioCount").textContent = `${state.scenarios.length}개`;

  state.scenarios.forEach((scenario) => {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "scenario-card";
    button.dataset.scenarioId = scenario.scenario_id;

    const code = document.createElement("span");
    code.className = "code";
    code.textContent = scenario.scenario_id;
    const name = document.createElement("strong");
    name.textContent = scenario.name;
    const tactic = document.createElement("small");
    tactic.textContent = `${scenario.attack_tactic} · 예상 ${riskLabels[scenario.expected_risk]}`;

    button.append(code, name, tactic);
    button.addEventListener("click", () => selectScenario(scenario));
    grid.append(button);
  });
}

function selectScenario(scenario) {
  state.selected = scenario;
  document.querySelectorAll(".scenario-card").forEach((card) => {
    card.classList.toggle("selected", card.dataset.scenarioId === scenario.scenario_id);
  });

  const container = $("selectedScenario");
  container.replaceChildren();
  const code = document.createElement("span");
  code.className = "selected-code";
  code.textContent = scenario.scenario_id;
  const title = document.createElement("h2");
  title.textContent = scenario.name;
  const description = document.createElement("p");
  description.textContent = `${scenario.attack_tactic} 관점의 합성 이벤트입니다. ${scenario.detection_conditions.length}개 구조화 조건으로 교차 확인하며, 예상 위험도와 분석 입력은 분리됩니다.`;
  container.append(code, title, description);
  $("analyzeButton").disabled = false;
}

function setRunning(running, message, isError = false) {
  state.running = running;
  $("analyzeButton").disabled = running || !state.selected;
  $("analyzeButton").querySelector("span").textContent = running
    ? "분석 진행 중…"
    : "선택 시나리오 분석";
  $("runState").textContent = message;
  $("runState").className = `run-state${running ? " running" : ""}${isError ? " error" : ""}`;
}

async function runAnalysis() {
  const epoch = state.epoch;
  if (!state.selected || state.running) return;
  const analyzerLabel = analyzerLabels[state.analyzerMode] || state.analyzerMode.toUpperCase();
  setRunning(true, `합성 이벤트를 생성하고 ${analyzerLabel} 및 정책 검증을 진행하고 있습니다.`);

  try {
    const events = await request("/events/simulate", {
      method: "POST",
      body: JSON.stringify({ scenario_id: state.selected.scenario_id, count: 1 }),
    });
    if (epoch !== state.epoch) return;
    delete events[0].ground_truth;
    const result = await request("/analysis", {
      method: "POST",
      epoch,
      body: JSON.stringify(events[0]),
    });
    renderResult(result);
    await openResult(result.event_id, false);
    if (epoch !== state.epoch) return;
    await refreshSummary();
    if (epoch !== state.epoch) return;
    setRunning(false, "분석이 완료됐습니다. 아래 결과는 실제 조치가 아닌 대응 미리보기입니다.");
  } catch (error) {
    if (epoch !== state.epoch) return;
    setRunning(false, `분석하지 못했습니다: ${error.message}`, true);
  }
}

function renderResult(result, shouldScroll = true, observation = null) {
  invalidateReview();
  state.observation = observation;
  state.latestResult = result;
  const assessment = result.assessment;
  const decision = result.policy_decision;
  $("resultEmpty").hidden = true;
  $("resultContent").hidden = false;
  $("resultAnalyzer").textContent = `${result.analyzer.toUpperCase()} · ${result.event_id}`;
  $("riskCard").dataset.risk = assessment.risk_level;
  $("riskScore").textContent = assessment.risk_score;
  $("scoreBar").style.width = `${assessment.risk_score}%`;
  $("riskLevel").textContent = `${assessment.risk_level} · ${riskLabels[assessment.risk_level]}`;
  $("violationType").textContent = violationLabels[assessment.violation_type] || assessment.violation_type;
  $("confidence").textContent = `신뢰도 ${Math.round(assessment.confidence * 100)}%`;
  $("rationale").textContent = assessment.rationale;
  $("recommendedAction").textContent = actionLabels[decision.action] || decision.action;
  $("decisionReason").textContent = decision.reason;
  $("reviewState").textContent = decision.requires_human_review
    ? "● 사람 검토 필요"
    : "● 자동 정책 확인 완료";
  $("latency").textContent = `응답 시간 ${(result.latency_ms / 1000).toFixed(2)}초`;

  const controls = $("decisionControls");
  controls.replaceChildren();
  (decision.controls_applied || []).forEach((item) => {
    const chip = document.createElement("span");
    chip.textContent = item;
    controls.append(chip);
  });

  const evidence = $("evidenceList");
  evidence.replaceChildren();
  const items = assessment.evidence.length ? assessment.evidence : ["명시적 위험 신호 없음"];
  items.forEach((item) => {
    const chip = document.createElement("span");
    chip.textContent = item;
    evidence.append(chip);
  });

  const detection = result.detection;
  const normalized = result.normalized_event;
  const detectionList = $("detectionMatches");
  detectionList.replaceChildren();
  if (detection && normalized) {
    $("pipelineVersion").textContent = `OCSF ${normalized.provenance.schema_version} · SIGMA ${detection.specification_version}`;
    const matches = detection.matches || [];
    if (matches.length) {
      matches.forEach((match) => {
        const chip = document.createElement("span");
        chip.dataset.level = match.level;
        chip.textContent = `${match.title} · v${match.version}`;
        detectionList.append(chip);
      });
    } else {
      const chip = document.createElement("span");
      chip.dataset.level = "informational";
      chip.textContent = "승인 규칙 일치 없음";
      detectionList.append(chip);
    }
    $("detectionDigest").textContent = `${detection.evaluated_rule_count}개 승인 규칙 · 입력 ${normalized.provenance.source_sha256.slice(0, 12)}… · 규칙집 ${detection.ruleset_digest_sha256.slice(0, 12)}…`;
  } else {
    $("pipelineVersion").textContent = "이전 분석 기록";
    $("detectionDigest").textContent = "이 기록에는 표준화·탐지 버전 정보가 없습니다.";
  }

  renderReviewWorkflow(result);
  if (shouldScroll) {
    $("resultSection").scrollIntoView({ behavior: "smooth", block: "start" });
  }
}

function renderReviewWorkflow(result) {
  const workflow = $("reviewWorkflow");
  const status = result.review_status || "NOT_REQUIRED";
  workflow.hidden = status === "NOT_REQUIRED";
  if (workflow.hidden) return;

  const badge = $("reviewStatusBadge");
  badge.textContent = reviewStatusLabels[status] || status;
  badge.dataset.status = status;
  $("reviewerInput").value = state.observation?.identity.subject || "";
  $("reviewNoteInput").value = result.review_note || "";
  $("reviewFeedback").textContent = result.review_updated_at
    ? `${formatTime(result.review_updated_at)} · ${result.reviewer}`
    : "조회한 분석과 현재 검토 신원을 확인한 뒤 변경 내용을 선택하세요.";
  if (!state.observation) $("reviewFeedback").textContent = "현재 결과 다시 조회를 눌러 검토 버전과 신원을 확인하세요.";
  else if (state.observation.reviewMode !== "conditional") $("reviewFeedback").textContent = "현재 서버는 버전을 확인한 검토를 지원하지 않습니다. 관리자에게 문의하세요.";
  else if (!["api_key", "oidc"].includes(state.observation.identity.auth_method)) $("reviewFeedback").textContent = "개별 인증으로 연결한 뒤 현재 결과를 다시 조회하세요.";
  else if (!strongReviewTag(state.observation.etag) || !reviewBinding(state.observation.reviewIdentity)) $("reviewFeedback").textContent = "조회 버전 또는 신원을 확인할 수 없습니다. 현재 결과를 다시 조회하세요.";
  else if (!state.identity?.roles.includes("responder")) $("reviewFeedback").textContent = "현재 계정에는 검토 권한이 없습니다.";
  syncReviewControls();
}

const reviewTransitions = {
    PENDING: ["IN_REVIEW", "RESOLVED", "DISMISSED"],
    IN_REVIEW: ["IN_REVIEW", "RESOLVED", "DISMISSED"],
    RESOLVED: ["IN_REVIEW"],
    DISMISSED: ["IN_REVIEW"],
};
function reviewUsable() {
  const observed = state.observation;
  return Boolean(observed && observed.epoch === state.epoch && observed.reviewMode === "conditional" &&
    strongReviewTag(observed.etag) && reviewBinding(observed.reviewIdentity) &&
    ["api_key", "oidc"].includes(observed.identity.auth_method) &&
    sameIdentity(observed.identity, state.identity) && state.identity.roles.includes("responder"));
}
function syncReviewControls() {
  const status = state.latestResult?.review_status;
  document.querySelectorAll("[data-review-status]").forEach((button) => {
    const targetStatus = button.dataset.reviewStatus;
    button.disabled = state.reviewing || state.loadingResult || !reviewUsable() || !reviewTransitions[status]?.includes(targetStatus);
    if (targetStatus === "IN_REVIEW") {
      button.textContent = ["RESOLVED", "DISMISSED"].includes(status)
        ? "검토 재개"
        : status === "IN_REVIEW"
          ? "메모 저장"
          : "검토 시작";
    }
  });
  $("reviewReload").disabled = state.reviewing || state.loadingResult || !state.latestResult;
  $("reviewExecute").disabled = state.reviewing || !state.preparedReview || !$("reviewAcknowledge").checked;
}

function invalidateReview() {
  state.reviewRevision++;
  state.preparedReview = null;
  $("reviewConfirmation").hidden = true;
  $("reviewAcknowledge").checked = false;
  $("reviewExecute").disabled = true;
}
function failReview(error, submitted) {
  if ([412, 428].includes(error.status)) return "조회한 검토 버전이 변경됐습니다. 현재 결과를 다시 조회하고 내용을 확인하세요.";
  if ([401, 403].includes(error.status) || error.reviewCaller) return "검토 신원 또는 권한이 변경됐습니다. 연결을 확인하고 현재 결과를 다시 조회하세요.";
  if (submitted) return "검토 저장 여부를 확인하지 못했습니다. 현재 기록을 다시 조회하세요. 자동 재전송하지 않았습니다.";
  return error.message;
}
async function requireReviewCaller(observed) {
  const identity = await request("/auth/me", {epoch: observed.epoch});
  if (!sameIdentity(identity, observed.identity) || !sameIdentity(state.identity, observed.identity) ||
      !Array.isArray(identity.roles) || !identity.roles.includes("responder")) {
    throw Object.assign(new Error("검토 신원이 변경됐습니다."), {reviewCaller: true});
  }
}
async function openResult(eventId, shouldScroll = true) {
  const epoch = state.epoch, sequence = ++state.resultSequence;
  invalidateReview(); state.observation = null; state.loadingResult = true; state.reviewing = false;
  $("reviewFeedback").textContent = "현재 결과와 호출 신원을 확인하고 있습니다.";
  syncReviewControls();
  const active = () => epoch === state.epoch && sequence === state.resultSequence;
  try {
    const before = await request("/auth/me", {epoch});
    const response = await request(`/results/${encodeURIComponent(eventId)}`, {withMetadata: true, epoch});
    const after = await request("/auth/me", {epoch});
    if (!active()) return;
    if (!sameIdentity(before, after) || !sameIdentity(before, state.identity)) throw Object.assign(new Error("조회 중 신원이 변경됐습니다."), {reviewCaller: true});
    const result = response.data;
    if (!result || result.event_id !== eventId || result.tenant_id !== before.tenant_id || typeof result.analysis_id !== "string" ||
        !result.assessment || !Array.isArray(result.assessment.evidence) || !result.policy_decision) throw new Error("조회 결과를 확인할 수 없습니다.");
    renderResult(result, shouldScroll, {record: result, identity: before, epoch, ...response});
  } catch (error) {
    if (active()) {
      $("reviewFeedback").textContent = failReview(error, false);
      $("runState").textContent = "현재 결과를 조회하지 못했습니다. 연결 및 인증을 확인한 뒤 다시 조회하세요.";
    }
  } finally {
    if (active()) { state.loadingResult = false; syncReviewControls(); }
  }
}
async function prepareReview(status) {
  if (!state.latestResult || state.reviewing || state.loadingResult || !reviewUsable()) return;
  const observed = state.observation, epoch = state.epoch, sequence = state.resultSequence;
  if (!reviewTransitions[observed.record.review_status]?.includes(status)) return;
  const note = $("reviewNoteInput").value.trim();
  if (["RESOLVED", "DISMISSED"].includes(status) && note.length < 3) {
    $("reviewFeedback").textContent = "완료 또는 오탐 처리에는 검토 메모가 필요합니다.";
    return;
  }

  invalidateReview();
  const revision = state.reviewRevision;
  state.reviewing = true; syncReviewControls();
  try {
    await requireReviewCaller(observed);
    if (epoch !== state.epoch || sequence !== state.resultSequence || revision !== state.reviewRevision) return;
    state.preparedReview = {observed, epoch, sequence, revision, status, note: note || null};
    $("reviewConfirmationSummary").textContent = `검토자: ${observed.identity.subject} / ${observed.identity.tenant_id}\n분석: ${observed.record.analysis_id}\n조회한 상태: ${reviewStatusLabels[observed.record.review_status]}\n변경할 상태: ${reviewStatusLabels[status]}\n메모: ${note || "없음"}`;
    $("reviewConfirmation").hidden = false;
    $("reviewFeedback").textContent = "조회한 버전과 신원으로만 저장합니다. 내용을 확인하고 저장하세요.";
  } catch (error) {
    if (epoch === state.epoch && sequence === state.resultSequence) {
      state.observation = null; invalidateReview();
      $("reviewFeedback").textContent = failReview(error, false);
    }
  } finally {
    if (epoch === state.epoch && sequence === state.resultSequence) { state.reviewing = false; syncReviewControls(); }
  }
}
async function executeReview() {
  const command = state.preparedReview;
  if (!command || state.reviewing || !reviewUsable() || !$("reviewAcknowledge").checked || command.revision !== state.reviewRevision) return;
  const {epoch, sequence, observed} = command;
  invalidateReview(); const revision = state.reviewRevision;
  state.reviewing = true; syncReviewControls();
  let submitted = false;
  try {
    await requireReviewCaller(observed);
    if (epoch !== state.epoch || sequence !== state.resultSequence || revision !== state.reviewRevision) return;
    submitted = true;
    const response = await request(`/results/${encodeURIComponent(observed.record.event_id)}/review`, {
      method: "PATCH", body: JSON.stringify({status: command.status, note: command.note}),
      ifMatch: observed.etag, reviewIdentity: observed.reviewIdentity, withMetadata: true, epoch,
    });
    if (epoch !== state.epoch || sequence !== state.resultSequence) return;
    const updated = response.data;
    if (!updated || updated.event_id !== observed.record.event_id || updated.analysis_id !== observed.record.analysis_id ||
        updated.tenant_id !== observed.identity.tenant_id || updated.reviewer !== observed.identity.subject ||
        updated.review_status !== command.status || updated.review_note !== command.note || !strongReviewTag(response.etag) ||
        response.etag === observed.etag || response.reviewIdentity !== observed.reviewIdentity) throw new Error("검토 저장 응답을 확인할 수 없습니다.");
    renderResult(updated, false);
    $("reviewFeedback").textContent = "검토를 저장했습니다. 추가 검토는 현재 결과를 다시 조회하세요.";
    await refreshSummary();
  } catch (error) {
    if (epoch === state.epoch && sequence === state.resultSequence) {
      state.observation = null; invalidateReview();
      $("reviewFeedback").textContent = failReview(error, submitted);
    }
  } finally {
    if (epoch === state.epoch && sequence === state.resultSequence) { state.reviewing = false; syncReviewControls(); }
  }
}

function formatTime(value) {
  if (!value) return "-";
  return new Intl.DateTimeFormat("ko-KR", {
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
  }).format(new Date(value));
}

function renderHistory(results) {
  const epoch = state.epoch;
  const body = $("historyBody");
  body.replaceChildren();
  if (!results.length) {
    const row = document.createElement("tr");
    const cell = document.createElement("td");
    cell.colSpan = 7;
    cell.className = "table-empty";
    cell.textContent = "아직 분석 기록이 없습니다.";
    row.append(cell);
    body.append(row);
    return;
  }

  results.forEach((result) => {
    const row = document.createElement("tr");
    const values = [
      formatTime(result.analyzed_at),
      result.event_id,
      result.analyzer.toUpperCase(),
      result.assessment.risk_level,
      actionLabels[result.policy_decision.action] || result.policy_decision.action,
    ];
    values.forEach((value, index) => {
      const cell = document.createElement("td");
      cell.textContent = value;
      if (index === 3) cell.className = `table-risk ${value}`;
      row.append(cell);
    });

    const reviewCell = document.createElement("td");
    const reviewBadge = document.createElement("span");
    const reviewStatus = result.review_status || "NOT_REQUIRED";
    reviewBadge.className = `review-badge ${reviewStatus.toLowerCase()}`;
    reviewBadge.textContent = reviewStatusLabels[reviewStatus] || reviewStatus;
    reviewCell.append(reviewBadge);
    row.append(reviewCell);

    const actionCell = document.createElement("td");
    const openButton = document.createElement("button");
    openButton.type = "button";
    openButton.className = "table-action";
    openButton.textContent = "열기";
    openButton.addEventListener("click", () => { if (epoch === state.epoch) openResult(result.event_id); });
    actionCell.append(openButton);
    row.append(actionCell);
    body.append(row);
  });
}

async function refreshSummary() {
  const epoch = state.epoch;
  try {
    const [metrics, results] = await Promise.all([
      request("/metrics"),
      request("/results?limit=8"),
    ]);
    if (epoch !== state.epoch) return;
    $("totalAnalyses").textContent = metrics.total_analyses;
    $("highRiskCount").textContent =
      (metrics.risk_counts.HIGH || 0) + (metrics.risk_counts.CRITICAL || 0);
    $("pendingReviewCount").textContent = metrics.pending_review_count || 0;
    $("openaiCount").textContent =
      (metrics.analyzer_counts.openai || 0) + (metrics.analyzer_counts.hybrid || 0);
    $("latestEvent").textContent = metrics.latest_event_id || "-";
    $("averageLatency").textContent = `${metrics.average_latency_ms.toFixed(1)}ms`;
    $("p95Latency").textContent = `${metrics.p95_latency_ms.toFixed(1)}ms`;
    renderHistory(results);
  } catch (_) {
    if (epoch !== state.epoch) return;
    $("historyBody").innerHTML = '<tr><td colspan="7" class="table-empty">기록을 불러오지 못했습니다.</td></tr>';
  }
}

function renderCases(cases) {
  const body = $("caseBody");
  body.replaceChildren();
  if (!cases.length) {
    const row = document.createElement("tr");
    const cell = document.createElement("td");
    cell.colSpan = 6;
    cell.className = "table-empty";
    cell.textContent = "아직 생성된 사고 케이스가 없습니다.";
    row.append(cell);
    body.append(row);
    return;
  }
  cases.forEach((record) => {
    const row = document.createElement("tr");
    const values = [
      formatTime(record.updated_at),
      record.case_id,
      record.severity_id,
      caseStatusLabels[record.status] || record.status,
      record.assignee || "미배정",
      `v${record.version}`,
    ];
    values.forEach((value, index) => {
      const cell = document.createElement("td");
      cell.textContent = value;
      if (index === 3) cell.className = `case-status ${record.status.toLowerCase()}`;
      row.append(cell);
    });
    body.append(row);
  });
}

function renderOutbox(records) {
  const body = $("outboxBody");
  body.replaceChildren();
  if (!records.length) {
    const row = document.createElement("tr");
    const cell = document.createElement("td");
    cell.colSpan = 6;
    cell.className = "table-empty";
    cell.textContent = "아직 생성된 연동 이벤트가 없습니다.";
    row.append(cell);
    body.append(row);
    return;
  }
  records.forEach((record) => {
    const row = document.createElement("tr");
    const values = [
      formatTime(record.event.time),
      record.event.id,
      `v${record.event.data.case_version}`,
      record.status,
      `${record.attempt_count}/${record.max_attempts}`,
      formatTime(record.next_attempt_at),
    ];
    values.forEach((value, index) => {
      const cell = document.createElement("td");
      cell.textContent = value;
      if (index === 3) cell.className = `delivery-status ${record.status.toLowerCase()}`;
      row.append(cell);
    });
    body.append(row);
  });
}

async function refreshCases() {
  const epoch = state.epoch;
  try {
    const [metrics, cases, outboxMetrics, outboxRecords] = await Promise.all([
      request("/cases/metrics"),
      request("/cases?limit=8"),
      request("/integrations/outbox/metrics"),
      request("/integrations/outbox?limit=8"),
    ]);
    if (epoch !== state.epoch) return;
    $("caseTotal").textContent = metrics.total_cases;
    $("caseOpen").textContent = metrics.open_case_count;
    $("caseUnassigned").textContent = metrics.unassigned_case_count;
    $("caseLatest").textContent = metrics.latest_case_id || "-";
    renderCases(cases);
    $("outboxPending").textContent = outboxMetrics.pending_count;
    $("outboxRetry").textContent = outboxMetrics.retry_scheduled_count;
    $("outboxDelivered").textContent = outboxMetrics.delivered_count;
    $("outboxDeadLetter").textContent = outboxMetrics.dead_letter_count;
    $("outboxDue").textContent = outboxMetrics.due_count;
    renderOutbox(outboxRecords);
  } catch (_) {
    if (epoch !== state.epoch) return;
    $("caseBody").innerHTML = '<tr><td colspan="6" class="table-empty">케이스를 불러오지 못했습니다.</td></tr>';
    $("outboxBody").innerHTML = '<tr><td colspan="6" class="table-empty">연동 이벤트를 불러오지 못했습니다.</td></tr>';
  }
}

async function createDemoCase() {
  const epoch = state.epoch;
  if (state.caseCreating) return;
  state.caseCreating = true;
  $("caseCreateButton").disabled = true;
  $("caseCreateButton").textContent = "상관분석 중…";
  $("caseState").textContent = "5개 합성 공격 이벤트를 묶어 사고 근거와 케이스를 생성하고 있습니다.";
  try {
    const threatScenarios = state.scenarios.filter((scenario) => scenario.category === "THREAT");
    const generated = await Promise.all(
      threatScenarios.map((scenario) => request("/events/simulate", {
        method: "POST",
        body: JSON.stringify({ scenario_id: scenario.scenario_id, count: 1 }),
      })),
    );
    if (epoch !== state.epoch) return;
    const events = generated.flat();
    const result = await request("/cases/from-events", {
      method: "POST",
      epoch,
      body: JSON.stringify({
        events,
        note: "대시보드에서 합성 공격 체인의 상관분석 결과를 케이스로 생성했습니다.",
      }),
    });
    await refreshCases();
    if (epoch !== state.epoch) return;
    $("caseState").textContent = result.created_case_count
      ? "새 사고 케이스를 생성했습니다. 실제 조치는 수행되지 않았으며 담당자 분류를 기다립니다."
      : "동일한 증거의 기존 케이스를 재사용했습니다. 중복 케이스는 생성하지 않았습니다.";
  } catch (error) {
    if (epoch !== state.epoch) return;
    $("caseState").textContent = `케이스를 생성하지 못했습니다: ${error.message}`;
  } finally {
    if (epoch !== state.epoch) return;
    state.caseCreating = false;
    $("caseCreateButton").disabled = false;
    $("caseCreateButton").textContent = "합성 공격 케이스 생성";
  }
}

function formatPercent(value) {
  return `${Math.round(value * 100)}%`;
}

function renderAssurance(summary) {
  $("assuranceRegistryVersion").textContent = `REGISTRY ${summary.registry_version}`;
  $("assuranceRate").textContent = formatPercent(summary.implementation_rate);
  $("implementedControls").textContent = summary.status_counts.implemented || 0;
  $("partialControls").textContent = summary.status_counts.partially_implemented || 0;
  $("plannedControls").textContent = summary.status_counts.planned || 0;
  $("assuranceEvidence").textContent = summary.evidence_count;
  $("overdueControls").textContent = summary.overdue_control_ids.length;
  $("overdueControls").className = summary.overdue_control_ids.length
    ? "metric-fail"
    : "metric-pass";
  $("assuranceState").textContent = summary.valid
    ? `${summary.total_controls}개 통제의 구조와 증적 연결을 확인했습니다.`
    : "통제대장 구조를 다시 확인해야 합니다.";

  const domains = $("assuranceDomains");
  domains.replaceChildren();
  Object.entries(summary.domain_counts).forEach(([domain, count]) => {
    const item = document.createElement("span");
    item.textContent = `${domain.replaceAll("_", " ")} · ${count}`;
    domains.append(item);
  });
}

async function loadAssuranceSummary() {
  const epoch = state.epoch;
  try {
    renderAssurance(await request("/assurance/summary"));
  } catch (error) {
    if (epoch !== state.epoch) return;
    $("assuranceState").textContent = `통제 준비도를 불러오지 못했습니다: ${error.message}`;
  }
}

function renderEvaluationDetails(result) {
  const body = $("evaluationBody");
  body.replaceChildren();
  result.scenario_breakdown.forEach((scenario) => {
    const row = document.createElement("tr");
    const values = [
      scenario.scenario_id,
      scenario.total_cases,
      formatPercent(scenario.risk_accuracy),
      formatPercent(scenario.action_accuracy),
      scenario.error_count,
      `${scenario.p95_latency_ms.toFixed(1)}ms`,
    ];
    values.forEach((value) => {
      const cell = document.createElement("td");
      cell.textContent = value;
      row.append(cell);
    });
    body.append(row);
  });
  $("evaluationDuration").textContent = `전체 ${result.duration_ms.toFixed(1)}ms · 동시 처리 4건`;
  $("evaluationDetails").hidden = false;
}

async function runEvaluation() {
  const epoch = state.epoch;
  if (state.evaluating) return;
  state.evaluating = true;
  $("evaluationButton").disabled = true;
  $("evaluationButton").textContent = "평가 진행 중…";
  $("evaluationState").textContent = `${state.analyzerMode.toUpperCase()} 분석기로 기준 사례를 반복 확인하고 있습니다.`;

  try {
    const result = await request("/evaluation/run", {
      method: "POST",
      timeoutMs: 120000,
      body: JSON.stringify({ analyzer: state.analyzerMode, runs_per_scenario: 5, concurrency: 4 }),
    });
    $("evaluationGrid").hidden = false;
    $("riskAccuracy").textContent = formatPercent(result.risk_accuracy);
    $("actionAccuracy").textContent = formatPercent(result.action_accuracy);
    $("threatF1").textContent = formatPercent(result.threat_f1);
    $("jsonValidity").textContent = formatPercent(result.json_valid_rate);
    $("evaluationErrorRate").textContent = formatPercent(result.error_rate);
    $("evaluationThroughput").textContent = `${result.throughput_per_second.toFixed(1)}/초`;
    $("evaluationP50").textContent = `${result.p50_latency_ms.toFixed(1)}ms`;
    $("evaluationP95").textContent = `${result.p95_latency_ms.toFixed(1)}ms`;
    const passed = Object.values(result.targets_met).every(Boolean);
    $("targetResult").textContent = passed ? "통과" : "보완 필요";
    $("targetResult").className = passed ? "metric-pass" : "metric-fail";
    renderEvaluationDetails(result);
    $("evaluationState").textContent = `${result.total_cases}개 사례 평가 완료 · ${result.analyzer.toUpperCase()} 분석기`;
  } catch (error) {
    if (epoch !== state.epoch) return;
    $("evaluationState").textContent = `평가하지 못했습니다: ${error.message}`;
  } finally {
    if (epoch !== state.epoch) return;
    state.evaluating = false;
    $("evaluationButton").disabled = false;
    $("evaluationButton").textContent = "40개 안정성 평가";
  }
}

function renderReplayDetails(result) {
  const body = $("replayBody");
  body.replaceChildren();
  result.results.forEach((item) => {
    const row = document.createElement("tr");
    const values = [
      item.dataset.provider,
      item.dataset.expected_label === "threat" ? "공격" : "정상",
      item.records.length,
      item.finding_count,
      item.incidents.length,
      item.window_summaries.map((summary) => `${summary.window_minutes}분`).join(" · "),
      `${item.entity_graph.node_count} 노드 / ${item.entity_graph.edge_count} 연결`,
      item.expectation_met ? "통과" : "보완 필요",
    ];
    values.forEach((value, index) => {
      const cell = document.createElement("td");
      cell.textContent = value;
      if (index === 7) cell.className = item.expectation_met ? "metric-pass" : "metric-fail";
      row.append(cell);
    });
    body.append(row);
  });
  $("replayDetails").hidden = false;
}

function renderQualityDetails(result) {
  $("qualityPrecision").textContent = formatPercent(result.precision);
  $("qualityRecall").textContent = formatPercent(result.recall);
  $("qualityF1").textContent = formatPercent(result.f1);
  $("qualityFpr").textContent = formatPercent(result.false_positive_rate);
  $("qualityParseRate").textContent = formatPercent(result.parse_success_rate);
  $("qualityMappingRate").textContent = formatPercent(result.mapping_completeness);
  $("qualityRuleCoverage").textContent = `${result.supported_rule_count}/${result.approved_rule_count}`;
  $("qualityGate").textContent = result.gate_passed ? "통과" : "보완 필요";
  $("qualityGate").className = result.gate_passed ? "metric-pass" : "metric-fail";
  $("qualityFingerprint").textContent = `평가 지문 ${result.evaluation_fingerprint_sha256.slice(0, 12)}`;

  const body = $("qualityRuleBody");
  body.replaceChildren();
  result.rules.forEach((rule) => {
    const evaluated = rule.evaluation_status === "evaluated";
    const row = document.createElement("tr");
    const values = [
      rule.title,
      rule.positive_support,
      evaluated ? formatPercent(rule.precision) : "-",
      evaluated ? formatPercent(rule.recall) : "-",
      evaluated ? formatPercent(rule.f1) : "-",
      formatPercent(rule.false_positive_rate),
      evaluated ? (rule.targets_met ? "통과" : "보완 필요") : "표본 없음",
    ];
    values.forEach((value, index) => {
      const cell = document.createElement("td");
      cell.textContent = value;
      if (index === 6 && evaluated) cell.className = rule.targets_met ? "metric-pass" : "metric-fail";
      row.append(cell);
    });
    body.append(row);
  });
  $("qualityDetails").hidden = false;
}

function renderIncidentQualityDetails(result) {
  $("incidentPrecision").textContent = formatPercent(result.precision);
  $("incidentRecall").textContent = formatPercent(result.recall);
  $("incidentF1").textContent = formatPercent(result.f1);
  $("incidentFpr").textContent = formatPercent(result.false_positive_rate);
  $("incidentWindowAccuracy").textContent = formatPercent(result.window_accuracy);
  $("incidentGraphAccuracy").textContent = formatPercent(result.graph_structure_accuracy);
  $("incidentDedupAccuracy").textContent = formatPercent(result.deduplication_accuracy);
  $("incidentSupport").textContent = `${result.positive_dataset_support} · ${result.negative_dataset_support}`;
  $("incidentQualityGate").textContent = result.gate_passed ? "통과" : "보완 필요";
  $("incidentQualityGate").className = result.gate_passed ? "metric-pass" : "metric-fail";
  $("incidentQualityFingerprint").textContent = `평가 지문 ${result.evaluation_fingerprint_sha256.slice(0, 12)}`;

  const body = $("incidentQualityBody");
  body.replaceChildren();
  result.datasets.forEach((dataset) => {
    const passed = dataset.incident_classification_correct
      && dataset.window_match
      && dataset.graph_structure_match
      && dataset.deduplication_match;
    const row = document.createElement("tr");
    const values = [
      dataset.dataset_id,
      dataset.expected_incident_count,
      dataset.observed_incident_count,
      dataset.observed_windows_minutes.length
        ? dataset.observed_windows_minutes.map((window) => `${window}분`).join(" · ")
        : "없음",
      `${dataset.observed_entity_node_count}/${dataset.expected_entity_node_count} 노드 · ${dataset.observed_entity_edge_count}/${dataset.expected_entity_edge_count} 연결`,
      `${dataset.observed_deduplicated_count}/${dataset.expected_deduplicated_count}`,
      passed ? "통과" : "보완 필요",
    ];
    values.forEach((value, index) => {
      const cell = document.createElement("td");
      cell.textContent = value;
      if (index === 6) cell.className = passed ? "metric-pass" : "metric-fail";
      row.append(cell);
    });
    body.append(row);
  });
  $("incidentQualityDetails").hidden = false;
}

async function runPublicReplay() {
  const epoch = state.epoch;
  if (state.replaying) return;
  state.replaying = true;
  $("replayButton").disabled = true;
  $("replayButton").textContent = "재생 검증 중…";
  $("replayState").textContent = "공개 로그 무결성, 탐지 결과와 사고 상관관계를 확인하고 있습니다.";

  try {
    const [result, quality, incidentQuality] = await Promise.all([
      request("/replay/public/run", { method: "POST", timeoutMs: 120000 }),
      request("/evaluation/detection-quality"),
      request("/evaluation/incident-quality"),
    ]);
    $("replayGrid").hidden = false;
    $("replayDatasetCount").textContent = result.dataset_count;
    $("replayEventCount").textContent = result.event_count;
    $("replayFindingCount").textContent = result.finding_count;
    $("replayIncidentCount").textContent = result.incident_count;
    $("replayExpectation").textContent = result.expectations_met ? "통과" : "보완 필요";
    $("replayExpectation").className = result.expectations_met ? "metric-pass" : "metric-fail";
    renderReplayDetails(result);
    renderQualityDetails(quality);
    renderIncidentQualityDetails(incidentQuality);
    $("replayState").textContent = result.expectations_met && quality.gate_passed && incidentQuality.gate_passed
      ? "공개 고정 표본 12건의 회귀 기준을 통과했습니다. 확장 합성 평가와 실제 기업 성능은 별도로 확인해야 합니다."
      : "공개 로그 회귀 기준을 통과하지 못한 항목이 있습니다.";
  } catch (error) {
    if (epoch !== state.epoch) return;
    $("replayState").textContent = `공개 로그를 재생하지 못했습니다: ${error.message}`;
  } finally {
    if (epoch !== state.epoch) return;
    state.replaying = false;
    $("replayButton").disabled = false;
    $("replayButton").textContent = "공개 로그 12건 재생";
  }
}

async function initialize() {
  const epoch = state.epoch;
  try {
    const [health, scenarios, identity] = await Promise.all([request("/health"), request("/scenarios"), request("/auth/me")]);
    if (epoch !== state.epoch) return;
    if (!identity || !Array.isArray(identity.roles) || !sameIdentity(identity, identity)) throw new Error("조회 신원을 확인할 수 없습니다.");
    state.identity = identity;
    $("workbenchIdentity").textContent = `${identity.subject} / ${identity.tenant_id} / ${identity.roles.join(", ")}`;
    setHealth(health);
    state.scenarios = scenarios;
    renderScenarios();
  } catch (_) {
    if (epoch !== state.epoch) return;
    state.identity = null;
    $("workbenchIdentity").textContent = "신원을 확인하지 못했습니다. 연결 및 인증을 확인하세요.";
    setHealthError();
    $("scenarioGrid").textContent = "서버와 연결되지 않았습니다.";
  }
  await Promise.all([refreshSummary(), refreshCases(), loadAssuranceSummary()]);
}

const zt = { sessionId: null, event: null, version: 0, token: null, busy: false };
const ztDecisions = { ALLOW: "허용", STEP_UP: "추가 인증", HOLD: "판단 보류", DENY: "거부" };
const ztStatuses = { ACTIVE: "활성", STEP_UP_REQUIRED: "재인증 필요", HELD: "보류", REVOKED: "허용 회수" };
const ztReasons = {
  POLICY_SATISFIED: "정책 충족", FRESH_MFA_REQUIRED: "MFA 성공 신호 필요",
  DEVICE_COMPROMISED: "기기 침해", HIGH_RISK: "고위험", SESSION_ALREADY_REVOKED: "회수된 세션",
  NETWORK_CONTEXT_CHANGED: "접속 맥락 변경", SIGNAL_INCOMPLETE: "신호 불충분",
  SIGNAL_EXPIRED_OR_FUTURE: "신호 시각 만료 또는 오류", ELEVATED_RISK: "위험 상승",
  SESSION_NOT_AUTHORIZED: "세션 허용 회수 또는 추가 검증 필요", GRANT_INVALID: "유효한 허용 없음",
  SCOPE_DENIED: "허용 범위 밖의 접근", POLICY_CHANGED: "정책 변경으로 허용 만료",
  GRANT_EXPIRED: "허용 유효기간 만료", GRANT_ALREADY_USED: "이미 사용한 허용",
  SIGNED_MFA_CHALLENGE_REQUIRED: "현재 재인증 요청에 연결된 서명 신호 필요",
  SIGNAL_SOURCE_REVOKED: "수집기 신뢰 설정 변경 또는 키 만료",
  SIGNAL_PROOF_EXPIRED: "서명 신호 만료",
};

async function refreshSignedSessions() {
  const epoch = state.epoch;
  const button = $("ztSignedRefresh");
  button.disabled = true;
  try {
    const [status, sessions] = await Promise.all([
      request("/zero-trust/signals/status"), request("/zero-trust/sessions"),
    ]);
    $("ztSignalStatus").textContent = !status.ok ? "수집기 등록 정보를 읽을 수 없어 서명 접근을 차단합니다."
      : status.configured ? `공개키 등록 정보 정상 · 등록 수집기 ${status.source_count}개`
      : "서명 수집기가 설정되지 않았습니다. 로컬 수집기를 설정한 뒤 조회하세요.";
    const rows = sessions.filter((session) => session.signal_trust === "verified_source");
    const body = $("ztSignedSessions");
    body.replaceChildren();
    rows.forEach((session) => {
      const row = document.createElement("tr");
      const challenge = session.challenge_expires_at
        ? `대기 · ${new Date(session.challenge_expires_at).toLocaleTimeString("ko-KR")}까지` : "대기 요청 없음";
      [session.session_id, `${session.signal_source_id} / ${session.signal_key_id}`, session.version,
        `${ztDecisions[session.decision]} · ${ztStatuses[session.status]}`, challenge,
        session.reason_codes.map((code) => ztReasons[code] || code).join(" · "),
      ].forEach((value) => { const cell = document.createElement("td"); cell.textContent = value; row.append(cell); });
      body.append(row);
    });
    if (!rows.length) {
      const row = document.createElement("tr");
      const cell = document.createElement("td");
      cell.colSpan = 6;
      cell.className = "table-empty";
      cell.textContent = "최근 100개 세션에 서명 수집기 세션이 없습니다.";
      row.append(cell);
      body.append(row);
    }
  } catch (error) {
    if (epoch !== state.epoch) return;
    $("ztSignalStatus").textContent = `서명 세션 조회 실패: ${error.message}`;
    $("ztSignedSessions").replaceChildren();
  } finally {
    if (epoch !== state.epoch) return;
    button.disabled = false;
  }
}

async function renderZt(session) {
  const epoch = state.epoch;
  $("ztDecision").textContent = ztDecisions[session.decision];
  $("ztStatus").textContent = ztStatuses[session.status];
  $("ztRisk").textContent = session.risk_score;
  $("ztPolicy").textContent = session.policy_version;
  const history = await request(`/zero-trust/sessions/${encodeURIComponent(zt.sessionId)}`, {epoch});
  $("ztHistory").replaceChildren();
  history.forEach((item) => {
    const row = document.createElement("tr");
    [item.version, item.resource_id, ztDecisions[item.decision], item.risk_score,
      item.reason_codes.map((code) => ztReasons[code] || code).join(" · "),
      item.grant_expires_at ? new Date(item.grant_expires_at).toLocaleTimeString("ko-KR") : "없음",
    ].forEach((value) => { const cell = document.createElement("td"); cell.textContent = value; row.append(cell); });
    $("ztHistory").append(row);
  });
}

async function operateZt(operation) {
  const epoch = state.epoch;
  if (zt.busy) return;
  zt.busy = true;
  document.querySelectorAll("#zeroTrustSection button").forEach((button) => { button.disabled = true; });
  try {
    if (operation === "access") {
      // Keep an old capability to demonstrate denial after a session decision changes.
      const response = await request("/zero-trust/protected-access", {
        method: "POST", allowDenied: true, epoch,
        body: JSON.stringify({ session_id: zt.sessionId, resource_id: "zt-demo-documents",
          action: "READ", grant_token: zt.token || "no-grant-available-000000000000000000" }),
      });
      const result = response.data;
      $("ztFeedback").textContent = response.ok && result.allowed
        ? "모의 문서 접근 허용. 이 허용은 한 번 사용됐습니다. 다음 접근은 새 평가가 필요합니다."
        : `모의 문서 접근 거부 (${response.status}) · ${ztReasons[result.reason_code] || "정책 확인 실패"}`;
      return;
    }
    if (operation === "start") {
      const generated = await request("/events/simulate", { method: "POST",
        body: JSON.stringify({ scenario_id: "NORMAL-01", count: 1 }) });
      if (epoch !== state.epoch) return;
      zt.event = generated[0];
      delete zt.event.ground_truth;
      zt.event.user.role = "employee";
      zt.event.resource = { resource_id: "zt-demo-documents", resource_type: "document", sensitivity: "internal" };
      zt.event.auth_context.authentication_result = "success";
      zt.event.auth_context.mfa = "success";
      zt.sessionId = `demo-${crypto.randomUUID()}`;
      zt.version = 0;
      zt.token = null;
    } else if (operation === "challenge") {
      zt.event.auth_context.mfa = "unknown";
    } else if (operation === "recover") {
      zt.event.auth_context.mfa = "success";
    } else if (operation === "compromise") {
      zt.event.device.security_posture = "compromised";
    }
    zt.event.event_id = `signal-${crypto.randomUUID()}`;
    zt.event.timestamp = new Date().toISOString();
    const result = await request("/zero-trust/sessions/evaluate", { method: "POST", epoch,
      body: JSON.stringify({ session_id: zt.sessionId, expected_version: zt.version, event: zt.event }) });
    zt.version = result.session.version;
    if (result.grant_token) zt.token = result.grant_token;
    await renderZt(result.session);
    if (epoch !== state.epoch) return;
    $("ztFeedback").textContent = `${ztDecisions[result.session.decision]} · ${result.session.reason_codes.map((code) => ztReasons[code] || code).join(" · ")}. 모의 문서 접근으로 집행 결과를 확인하세요.`;
  } catch (error) {
    if (epoch !== state.epoch) return;
    $("ztFeedback").textContent = `세션 처리를 완료하지 못했습니다: ${error.message}`;
  } finally {
    if (epoch !== state.epoch) return;
    zt.busy = false;
    document.querySelectorAll("#zeroTrustSection button").forEach((button) => {
      button.disabled = button.id !== "ztStart" && !zt.version;
    });
  }
}

function bindWorkbenchControls() {
  $("ztStart").addEventListener("click", () => operateZt("start"));
  $("ztAccess").addEventListener("click", () => operateZt("access"));
  $("ztChallenge").addEventListener("click", () => operateZt("challenge"));
  $("ztRecover").addEventListener("click", () => operateZt("recover"));
  $("ztCompromise").addEventListener("click", () => operateZt("compromise"));
  $("ztSignedRefresh").addEventListener("click", refreshSignedSessions);
  $("analyzeButton").addEventListener("click", runAnalysis);
  $("refreshButton").addEventListener("click", refreshSummary);
  $("evaluationButton").addEventListener("click", runEvaluation);
  $("replayButton").addEventListener("click", runPublicReplay);
  $("caseCreateButton").addEventListener("click", createDemoCase);
  document.querySelectorAll("[data-review-status]").forEach((button) => {
    button.addEventListener("click", () => prepareReview(button.dataset.reviewStatus));
  });
  $("reviewReload").addEventListener("click", () => {
    if (state.latestResult && !state.reviewing) openResult(state.latestResult.event_id, false);
  });
  $("reviewNoteInput").addEventListener("input", () => { invalidateReview(); syncReviewControls(); });
  $("reviewAcknowledge").addEventListener("change", syncReviewControls);
  $("reviewExecute").addEventListener("click", executeReview);
  $("reviewCancel").addEventListener("click", () => { invalidateReview(); syncReviewControls(); });
}
function resetConnection(type, credential) {
  state.epoch++;
  state.controllers.forEach((controller) => controller.abort());
  state.controllers.clear();
  Object.assign(state, {credentialType: type, credential, identity: null, observation: null,
    preparedReview: null, selected: null, scenarios: [], latestResult: null, analyzerMode: "rule",
    reviewing: false, loadingResult: false, running: false, evaluating: false, replaying: false, caseCreating: false});
  state.resultSequence++; state.reviewRevision++;
  Object.assign(zt, {sessionId: null, event: null, version: 0, token: null, busy: false});
  document.querySelector("main").replaceChildren(...[...initialMain.childNodes].map((child) => child.cloneNode(true)));
  $("workbenchCredential").value = "";
  $("workbenchCredentialType").value = type;
  $("workbenchIdentity").textContent = "현재 연결의 신원을 확인하고 있습니다.";
  setHealthError();
  bindWorkbenchControls();
  initialize();
}
$("workbenchConnectionForm").addEventListener("submit", (event) => {
  event.preventDefault();
  const type = $("workbenchCredentialType").value;
  resetConnection(type, type === "none" ? "" : $("workbenchCredential").value.trim());
});
$("workbenchDisconnect").addEventListener("click", () => resetConnection("none", ""));
[$("workbenchCredential"), $("workbenchCredentialType")].forEach((input) => {
  input.addEventListener("input", () => {
    invalidateReview(); state.observation = null; syncReviewControls();
    $("reviewFeedback").textContent = "연결 정보를 수정했습니다. 적용한 뒤 현재 결과를 다시 조회하세요.";
  });
});
bindWorkbenchControls();
initialize();
