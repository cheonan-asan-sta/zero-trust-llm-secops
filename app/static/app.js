const state = {
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

const riskLabels = {
  LOW: "낮음",
  MEDIUM: "보통",
  HIGH: "높음",
  CRITICAL: "심각",
};

const violationLabels = {
  NORMAL: "정상 접근",
  CREDENTIAL_ANOMALY: "자격 증명 이상",
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
  const response = await fetch(path, {
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
    ...options,
  });

  if (!response.ok) {
    let message = `요청 실패 (${response.status})`;
    try {
      const body = await response.json();
      if (body.detail) message = body.detail;
    } catch (_) {
      // The status code remains the safe fallback message.
    }
    throw new Error(message);
  }
  return response.json();
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
  if (!state.selected || state.running) return;
  const analyzerLabel = analyzerLabels[state.analyzerMode] || state.analyzerMode.toUpperCase();
  setRunning(true, `합성 이벤트를 생성하고 ${analyzerLabel} 및 정책 검증을 진행하고 있습니다.`);

  try {
    const events = await request("/events/simulate", {
      method: "POST",
      body: JSON.stringify({ scenario_id: state.selected.scenario_id, count: 1 }),
    });
    const result = await request("/analysis", {
      method: "POST",
      body: JSON.stringify(events[0]),
    });
    renderResult(result);
    await refreshSummary();
    setRunning(false, "분석이 완료됐습니다. 아래 결과는 실제 조치가 아닌 대응 미리보기입니다.");
  } catch (error) {
    setRunning(false, `분석하지 못했습니다: ${error.message}`, true);
  }
}

function renderResult(result, shouldScroll = true) {
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
  $("reviewerInput").value = result.reviewer || $("reviewerInput").value;
  $("reviewNoteInput").value = result.review_note || "";
  $("reviewFeedback").textContent = result.review_updated_at
    ? `${formatTime(result.review_updated_at)} · ${result.reviewer}`
    : "담당자를 지정해 검토를 시작하세요.";

  const allowedTransitions = {
    PENDING: ["IN_REVIEW", "RESOLVED", "DISMISSED"],
    IN_REVIEW: ["IN_REVIEW", "RESOLVED", "DISMISSED"],
    RESOLVED: ["IN_REVIEW"],
    DISMISSED: ["IN_REVIEW"],
  };
  document.querySelectorAll("[data-review-status]").forEach((button) => {
    const targetStatus = button.dataset.reviewStatus;
    button.disabled = state.reviewing || !allowedTransitions[status]?.includes(targetStatus);
    if (targetStatus === "IN_REVIEW") {
      button.textContent = ["RESOLVED", "DISMISSED"].includes(status)
        ? "검토 재개"
        : status === "IN_REVIEW"
          ? "메모 저장"
          : "검토 시작";
    }
  });
}

async function submitReview(status) {
  if (!state.latestResult || state.reviewing) return;
  const reviewer = $("reviewerInput").value.trim();
  const note = $("reviewNoteInput").value.trim();
  if (reviewer.length < 2) {
    $("reviewFeedback").textContent = "담당자 이름을 두 글자 이상 입력하세요.";
    return;
  }
  if (["RESOLVED", "DISMISSED"].includes(status) && note.length < 3) {
    $("reviewFeedback").textContent = "완료 또는 오탐 처리에는 검토 메모가 필요합니다.";
    return;
  }

  state.reviewing = true;
  $("reviewFeedback").textContent = "검토 상태를 저장하고 있습니다…";
  document.querySelectorAll("[data-review-status]").forEach((button) => {
    button.disabled = true;
  });

  try {
    const updated = await request(
      `/results/${encodeURIComponent(state.latestResult.event_id)}/review`,
      {
        method: "PATCH",
        body: JSON.stringify({ status, reviewer, note: note || null }),
      },
    );
    state.reviewing = false;
    renderResult(updated, false);
    await refreshSummary();
  } catch (error) {
    state.reviewing = false;
    renderReviewWorkflow(state.latestResult);
    $("reviewFeedback").textContent = `저장하지 못했습니다: ${error.message}`;
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
    openButton.addEventListener("click", () => renderResult(result));
    actionCell.append(openButton);
    row.append(actionCell);
    body.append(row);
  });
}

async function refreshSummary() {
  try {
    const [metrics, results] = await Promise.all([
      request("/metrics"),
      request("/results?limit=8"),
    ]);
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

async function refreshCases() {
  try {
    const [metrics, cases] = await Promise.all([
      request("/cases/metrics"),
      request("/cases?limit=8"),
    ]);
    $("caseTotal").textContent = metrics.total_cases;
    $("caseOpen").textContent = metrics.open_case_count;
    $("caseUnassigned").textContent = metrics.unassigned_case_count;
    $("caseLatest").textContent = metrics.latest_case_id || "-";
    renderCases(cases);
  } catch (_) {
    $("caseBody").innerHTML = '<tr><td colspan="6" class="table-empty">케이스를 불러오지 못했습니다.</td></tr>';
  }
}

async function createDemoCase() {
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
    const events = generated.flat();
    const result = await request("/cases/from-events", {
      method: "POST",
      body: JSON.stringify({
        events,
        note: "대시보드에서 합성 공격 체인의 상관분석 결과를 케이스로 생성했습니다.",
      }),
    });
    await refreshCases();
    $("caseState").textContent = result.created_case_count
      ? "새 사고 케이스를 생성했습니다. 실제 조치는 수행되지 않았으며 담당자 분류를 기다립니다."
      : "동일한 증거의 기존 케이스를 재사용했습니다. 중복 케이스는 생성하지 않았습니다.";
  } catch (error) {
    $("caseState").textContent = `케이스를 생성하지 못했습니다: ${error.message}`;
  } finally {
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
  try {
    renderAssurance(await request("/assurance/summary"));
  } catch (error) {
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
  if (state.evaluating) return;
  state.evaluating = true;
  $("evaluationButton").disabled = true;
  $("evaluationButton").textContent = "평가 진행 중…";
  $("evaluationState").textContent = `${state.analyzerMode.toUpperCase()} 분석기로 기준 사례를 반복 확인하고 있습니다.`;

  try {
    const result = await request("/evaluation/run", {
      method: "POST",
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
    $("evaluationState").textContent = `평가하지 못했습니다: ${error.message}`;
  } finally {
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
  if (state.replaying) return;
  state.replaying = true;
  $("replayButton").disabled = true;
  $("replayButton").textContent = "재생 검증 중…";
  $("replayState").textContent = "공개 로그 무결성, 탐지 결과와 사고 상관관계를 확인하고 있습니다.";

  try {
    const [result, quality, incidentQuality] = await Promise.all([
      request("/replay/public/run", { method: "POST" }),
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
      ? "탐지·사건 상관분석과 정상 로그 오탐 억제의 정량 품질 기준을 모두 통과했습니다."
      : "공개 로그 회귀 기준을 통과하지 못한 항목이 있습니다.";
  } catch (error) {
    $("replayState").textContent = `공개 로그를 재생하지 못했습니다: ${error.message}`;
  } finally {
    state.replaying = false;
    $("replayButton").disabled = false;
    $("replayButton").textContent = "공개 로그 12건 재생";
  }
}

async function initialize() {
  try {
    const [health, scenarios] = await Promise.all([request("/health"), request("/scenarios")]);
    setHealth(health);
    state.scenarios = scenarios;
    renderScenarios();
  } catch (_) {
    setHealthError();
    $("scenarioGrid").textContent = "서버와 연결되지 않았습니다.";
  }
  await Promise.all([refreshSummary(), refreshCases(), loadAssuranceSummary()]);
}

$("analyzeButton").addEventListener("click", runAnalysis);
$("refreshButton").addEventListener("click", refreshSummary);
$("evaluationButton").addEventListener("click", runEvaluation);
$("replayButton").addEventListener("click", runPublicReplay);
$("caseCreateButton").addEventListener("click", createDemoCase);
document.querySelectorAll("[data-review-status]").forEach((button) => {
  button.addEventListener("click", () => submitReview(button.dataset.reviewStatus));
});
initialize();
