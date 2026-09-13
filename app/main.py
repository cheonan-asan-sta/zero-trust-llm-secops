from functools import lru_cache
from pathlib import Path
from time import perf_counter

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.analyzers import OpenAIAnalyzer, RuleBasedAnalyzer
from app.analyzers.base import Analyzer
from app.config import get_settings
from app.models import (
    AnalysisResult,
    MetricsSummary,
    PolicyDecision,
    ResponsePreviewRequest,
    ScenarioSummary,
    SecurityEvent,
    SimulationRequest,
)
from app.scenarios import SCENARIOS, generate_events
from app.services.audit import AuditStore
from app.services.policy import enforce_assessment_safety, response_preview

settings = get_settings()
static_dir = Path(__file__).parent / "static"
app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="합성 이벤트 기반 제로 트러스트 위험 분석 및 대응 시뮬레이션 API",
)
app.mount("/static", StaticFiles(directory=static_dir), name="static")
audit_store = AuditStore(settings.audit_log_path)


@lru_cache
def get_analyzer() -> Analyzer:
    current = get_settings()
    if current.analyzer_mode == "openai":
        return OpenAIAnalyzer(current)
    return RuleBasedAnalyzer()


@app.get("/health")
def health() -> dict:
    return {
        "status": "ok",
        "version": settings.app_version,
        "analyzer_mode": settings.analyzer_mode,
    }


@app.get("/", include_in_schema=False)
def dashboard() -> FileResponse:
    return FileResponse(static_dir / "index.html")


@app.get("/scenarios", response_model=list[ScenarioSummary])
def scenarios() -> list[ScenarioSummary]:
    return SCENARIOS


@app.post("/events/simulate", response_model=list[SecurityEvent])
def simulate(request: SimulationRequest) -> list[SecurityEvent]:
    try:
        return generate_events(request.scenario_id, request.count)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=f"Unknown scenario: {exc.args[0]}") from exc


@app.post("/analysis", response_model=AnalysisResult)
async def analyze(event: SecurityEvent) -> AnalysisResult:
    started = perf_counter()
    try:
        analyzer = get_analyzer()
    except ValueError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    try:
        assessment = await analyzer.analyze(event)
    except Exception as exc:
        raise HTTPException(status_code=502, detail="Analysis provider failed") from exc

    safe_assessment = enforce_assessment_safety(assessment)
    decision = response_preview(safe_assessment)
    result = AnalysisResult(
        event_id=event.event_id,
        analyzer=analyzer.name,
        assessment=safe_assessment,
        policy_decision=decision,
        latency_ms=round((perf_counter() - started) * 1000, 2),
    )
    await audit_store.save(result)
    return result


@app.post("/response/preview", response_model=PolicyDecision)
def preview(request: ResponsePreviewRequest) -> PolicyDecision:
    return response_preview(request.assessment)


@app.get("/metrics", response_model=MetricsSummary)
def metrics() -> MetricsSummary:
    return audit_store.metrics()


@app.get("/results", response_model=list[AnalysisResult])
def recent_results(limit: int = 20) -> list[AnalysisResult]:
    safe_limit = min(max(limit, 1), 100)
    return audit_store.recent(safe_limit)


@app.get("/results/{event_id}", response_model=AnalysisResult)
def result(event_id: str) -> AnalysisResult:
    record = audit_store.get(event_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Result not found")
    return record
