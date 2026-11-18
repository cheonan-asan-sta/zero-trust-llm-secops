"""Presentation metadata for existing, authenticated application operations."""

# This is navigation metadata, not an authorization list. Every operation retains
# its original dependency and service checks. Internal metrics are not exposed.
OPERATIONS = [
    ("responses", "고위험 대응 요청", "POST", "/response/requests", "responder"),
    ("responses", "대응 요청 목록", "GET", "/response/requests", "viewer"),
    ("responses", "대응 요청 상세", "GET", "/response/requests/{identifier}", "viewer"),
    ("responses", "대응 검토 승인", "POST", "/response/requests/{identifier}/approvals", "responder"),
    ("responses", "대응 요청 취소", "POST", "/response/requests/{identifier}/cancel", "responder"),
    ("responses", "승인된 대응 모의 실행", "POST", "/response/requests/{identifier}/execute", "responder"),
    ("analysis", "시나리오 목록", "GET", "/scenarios", "viewer"),
    ("analysis", "시나리오 상세", "GET", "/scenarios/{scenario_id}", "viewer"),
    ("analysis", "합성 이벤트 생성", "POST", "/events/simulate", "analyst"),
    ("analysis", "이벤트 분석", "POST", "/analysis", "analyst"),
    ("analysis", "검증된 세션·실행 근거 분석", "POST", "/analysis/verified-session", "analyst"),
    ("analysis", "서버 실행 근거 분석", "POST", "/analysis/native-service", "analyst"),
    ("analysis", "필요 근거 조회형 LLM 분석", "POST", "/analysis/evidence-review", "analyst"),
    ("analysis", "이벤트 묶음 분석", "POST", "/analysis/batch", "analyst"),
    ("analysis", "이벤트 정규화", "POST", "/events/normalize", "analyst"),
    ("analysis", "탐지 규칙 평가", "POST", "/detections/evaluate", "analyst"),
    ("analysis", "탐지 규칙 목록", "GET", "/detections/rules", "viewer"),
    ("analysis", "사고 상관분석", "POST", "/incidents/correlate", "analyst"),
    ("analysis", "공개 세션 평가", "POST", "/detections/public/evaluate", "analyst"),
    ("analysis", "대응 정책 미리보기", "POST", "/response/preview", "analyst"),
    ("analysis", "분석 검토 상태 변경", "PATCH", "/results/{event_id}/review", "responder"),
    ("analysis", "검증된 감사 기록 페이지", "GET", "/audit/results", "viewer"),
    ("evaluation", "공개 로그 목록", "GET", "/replay/public/datasets", "viewer"),
    ("evaluation", "공개 로그 전체 재생", "POST", "/replay/public/run", "analyst"),
    ("evaluation", "선택 공개 로그 재생", "POST", "/replay/public/{dataset_id}", "analyst"),
    ("evaluation", "시나리오 검증", "POST", "/scenarios/evaluate", "analyst"),
    ("evaluation", "반복 분석 평가", "POST", "/evaluation/run", "admin"),
    ("evaluation", "탐지 품질 보고서", "GET", "/evaluation/detection-quality", "viewer"),
    ("evaluation", "사고 품질 보고서", "GET", "/evaluation/incident-quality", "viewer"),
    ("evaluation", "탐지 벤치마크", "GET", "/evaluation/detection-benchmark", "viewer"),
    ("cases", "사고 목록", "GET", "/cases", "viewer"),
    ("cases", "사고 상세", "GET", "/cases/{case_id}", "viewer"),
    ("cases", "사고 현황", "GET", "/cases/metrics", "viewer"),
    ("cases", "이벤트로 사고 등록", "POST", "/cases/from-events", "analyst"),
    ("cases", "사고 상태 변경", "PATCH", "/cases/{case_id}", "responder"),
    ("cases", "전송 대기 목록", "GET", "/integrations/outbox", "viewer"),
    ("cases", "전송 상세", "GET", "/integrations/outbox/{event_id}", "viewer"),
    ("cases", "전송 현황", "GET", "/integrations/outbox/metrics", "viewer"),
    ("cases", "누락 전송 기록 복구", "POST", "/integrations/outbox/reconcile", "admin"),
    ("cases", "전송 시도 결과 기록", "POST", "/integrations/outbox/{event_id}/attempt", "responder"),
    ("context", "서명된 수집 기록 등록", "POST", "/detections/context/captures", "analyst"),
    ("context", "실행 증거 등록", "POST", "/detections/context/execution-evidence", "analyst"),
    ("context", "정상 작업 기준선 등록", "POST", "/detections/context/baselines", "admin"),
    ("context", "작업 승인 등록", "POST", "/detections/context/approvals", "responder"),
    ("context", "행위 문맥 평가", "POST", "/detections/context/evaluate", "analyst"),
    ("context", "기준선 회수", "POST", "/detections/context/baselines/{identifier}/revoke", "admin"),
    ("context", "작업 승인 회수", "POST", "/detections/context/approvals/{identifier}/revoke", "responder"),
    ("signals", "서명 신호 접수", "POST", "/zero-trust/signals/inbox", "analyst"),
    ("signals", "신호 접수 영수증", "GET", "/zero-trust/signals/inbox/{event_id}", "viewer"),
    ("signals", "서명 신호 즉시 평가", "POST", "/zero-trust/signals/evaluate", "analyst"),
    ("signals", "세션 평가", "POST", "/zero-trust/sessions/evaluate", "analyst"),
    ("signals", "세션 회수", "POST", "/zero-trust/sessions/{session_id}/revoke", "responder"),
    ("signals", "보호 자원 접근", "POST", "/zero-trust/protected-access", "analyst"),
    ("signals", "접근 정책 조회", "GET", "/zero-trust/policies", "viewer"),
    ("assurance", "보안 통제 요약", "GET", "/assurance/summary", "viewer"),
    ("assurance", "보안 통제 목록", "GET", "/assurance/controls", "admin"),
    ("assurance", "보안 통제 상세", "GET", "/assurance/controls/{control_id}", "admin"),
    ("assurance", "서버 준비 상태", "GET", "/health/ready", "viewer"),
]


def catalog(app):
    specification = app.openapi()
    result = []
    for group, title, method, path, role in OPERATIONS:
        definition = specification["paths"][path][method.lower()]
        result.append({
            "id": definition["operationId"], "group": group, "title": title,
            "method": method, "path": path, "role": role,
            "parameters": [p for p in definition.get("parameters", [])
                           if p["in"] in {"path", "query"}],
            "body": definition.get("requestBody", {}).get("content", {}).get(
                "application/json", {}).get("schema"),
        })
    return {"operations": result, "schemas": specification["components"]["schemas"]}
