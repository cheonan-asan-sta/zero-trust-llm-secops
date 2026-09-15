import asyncio
from functools import lru_cache
from pathlib import Path
from time import perf_counter

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from mangum import Mangum

from app.analyzers import HybridAnalyzer, OpenAIAnalyzer, RuleBasedAnalyzer
from app.analyzers.base import Analyzer
from app.config import get_settings
from app.models import (
    AnalysisResult,
    BatchAnalysisRequest,
    BatchAnalysisResult,
    EvaluationRequest,
    EvaluationSummary,
    EventScenarioEvaluation,
    MetricsSummary,
    PolicyDecision,
    ResponsePreviewRequest,
    ScenarioSummary,
    SecurityEvent,
    SimulationRequest,
)
from app.scenarios import SCENARIOS, generate_events, get_scenario
from app.services.audit import create_audit_store
from app.services.evaluation import run_evaluation
from app.services.policy import enforce_assessment_safety, response_preview
from app.services.scenario_evaluator import evaluate_scenarios

settings = get_settings()
static_dir = Path(__file__).parent / "static"
app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="합성 이벤트 기반 제로 트러스트 위험 분석 및 대응 시뮬레이션 API",
)
app.mount("/static", StaticFiles(directory=static_dir), name="static")
audit_store = create_audit_store(settings)


@lru_cache
def get_analyzer() -> Analyzer:
    current = get_settings()
    return build_analyzer(current.analyzer_mode)


def build_analyzer(mode: str) -> Analyzer:
    if mode == "openai":
        return OpenAIAnalyzer(get_settings())
    if mode == "hybrid":
        return HybridAnalyzer(get_settings())
    return RuleBasedAnalyzer()


@app.get("/health")
def health() -> dict:
    return {
        "status": "ok",
        "version": settings.app_version,
        "analyzer_mode": settings.analyzer_mode,
        "audit_backend": settings.audit_backend,
    }


@app.get("/", include_in_schema=False)
def dashboard() -> FileResponse:
    return FileResponse(static_dir / "index.html")


@app.get("/scenarios", response_model=list[ScenarioSummary])
def scenarios() -> list[ScenarioSummary]:
    return SCENARIOS


@app.get("/scenarios/{scenario_id}", response_model=ScenarioSummary)
def scenario(scenario_id: str) -> ScenarioSummary:
    try:
        return get_scenario(scenario_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=f"Unknown scenario: {exc.args[0]}") from exc


@app.post("/events/simulate", response_model=list[SecurityEvent])
def simulate(request: SimulationRequest) -> list[SecurityEvent]:
    try:
        return generate_events(request.scenario_id, request.count)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=f"Unknown scenario: {exc.args[0]}") from exc


@app.post("/scenarios/evaluate", response_model=EventScenarioEvaluation)
def evaluate_event_scenarios(event: SecurityEvent) -> EventScenarioEvaluation:
    return evaluate_scenarios(event, SCENARIOS)


@app.post("/analysis", response_model=AnalysisResult)
async def analyze(event: SecurityEvent) -> AnalysisResult:
    try:
        analyzer = get_analyzer()
    except ValueError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    try:
        return await _analyze_event(event, analyzer)
    except Exception as exc:
        raise HTTPException(status_code=502, detail="Analysis provider failed") from exc


@app.post("/analysis/batch", response_model=BatchAnalysisResult)
async def analyze_batch(request: BatchAnalysisRequest) -> BatchAnalysisResult:
    try:
        analyzer = get_analyzer()
    except ValueError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    semaphore = asyncio.Semaphore(3)

    async def analyze_with_limit(event: SecurityEvent) -> AnalysisResult:
        async with semaphore:
            return await _analyze_event(event, analyzer)

    try:
        results = await asyncio.gather(*(analyze_with_limit(event) for event in request.events))
    except Exception as exc:
        raise HTTPException(status_code=502, detail="Batch analysis provider failed") from exc
    return BatchAnalysisResult(
        analyzer=analyzer.name,
        requested=len(request.events),
        completed=len(results),
        results=results,
    )


async def _analyze_event(event: SecurityEvent, analyzer: Analyzer) -> AnalysisResult:
    started = perf_counter()
    assessment = await analyzer.analyze(event)
    safe_assessment = enforce_assessment_safety(assessment, event)
    decision = response_preview(safe_assessment, event)
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
    return response_preview(request.assessment, request.event)


@app.post("/evaluation/run", response_model=EvaluationSummary)
async def evaluate(request: EvaluationRequest) -> EvaluationSummary:
    try:
        analyzer = build_analyzer(request.analyzer)
    except ValueError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    return await run_evaluation(analyzer, request.runs_per_scenario)


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


handler = Mangum(app, lifespan="off")
