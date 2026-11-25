from prometheus_client import Histogram

ANALYSIS_PHASE_DURATION = Histogram(
    "secops_analysis_phase_duration_seconds",
    "Elapsed time by stage of analysis and structured model response handling",
    ("phase",),
    buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 2.5, 3, 4, 5, 10, 30),
)
