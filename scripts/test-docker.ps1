[CmdletBinding()]
param(
    [ValidateRange(1024, 65535)]
    [int]$Port = 18080,
    [string]$ImageTag = "zero-trust-llm-secops:local-test"
)

$ErrorActionPreference = "Stop"
if ($PSVersionTable.PSVersion.Major -ge 7) {
    $PSNativeCommandUseErrorActionPreference = $true
}

$projectRoot = Split-Path -Parent $PSScriptRoot
$containerName = "zero-trust-llm-secops-smoke"
$testImageTag = "${ImageTag}-tests"
$existing = docker ps -a --filter "name=^/$containerName$" --format "{{.Names}}"
if ($existing) {
    throw "A container named $containerName already exists. Remove it before running this test."
}

try {
    docker build `
        --platform linux/amd64 `
        --provenance=false `
        --file "$projectRoot\Dockerfile.test" `
        --tag $testImageTag `
        $projectRoot
    docker run --rm $testImageTag

    docker build `
        --platform linux/amd64 `
        --provenance=false `
        --file "$projectRoot\Dockerfile" `
        --tag $ImageTag `
        $projectRoot
    docker run `
        --detach `
        --name $containerName `
        --read-only `
        --cap-drop ALL `
        --security-opt no-new-privileges:true `
        --tmpfs /tmp:rw,noexec,nosuid,size=64m `
        --tmpfs /data:rw,noexec,nosuid,uid=10001,gid=10001,mode=0700,size=64m `
        --env ANALYZER_MODE=rule `
        --env CASE_LOG_PATH=/data/cases.jsonl `
        --publish "127.0.0.1:${Port}:8000" `
        $ImageTag | Out-Null

    $baseUrl = "http://127.0.0.1:$Port"
    $health = $null
    for ($attempt = 1; $attempt -le 30; $attempt++) {
        try {
            $health = Invoke-RestMethod -Method Get -Uri "$baseUrl/health" -TimeoutSec 2
            break
        } catch {
            Start-Sleep -Seconds 1
        }
    }
    if (-not $health -or $health.status -ne "ok" -or $health.analyzer_mode -ne "rule") {
        throw "Container health check did not become ready in rule mode."
    }
    if ($health.version -ne "0.14.0" -or $health.auth_mode -ne "disabled") {
        throw "Container did not start with the expected local security profile."
    }
    $readiness = Invoke-RestMethod -Method Get -Uri "$baseUrl/health/ready" -TimeoutSec 2
    if (
        $readiness.status -ne "ready" -or
        -not $readiness.audit.ok -or
        -not $readiness.case_management.valid -or
        $readiness.case_management.response_mode -ne "simulation" -or
        -not $readiness.assurance.valid -or
        $readiness.assurance.total_controls -ne 18 -or
        $readiness.normalization.schema_version -ne "1.9.0" -or
        -not $readiness.detection.valid -or
        $readiness.detection.approved_rule_count -ne 6 -or
        $readiness.correlation.output_class_uid -ne 2005 -or
        -not $readiness.correlation.entity_graph_enabled -or
        ($readiness.correlation.windows_minutes -join ",") -ne "5,30,1440" -or
        -not $readiness.public_replay.valid -or
        $readiness.public_replay.dataset_count -ne 3 -or
        -not $readiness.detection_quality.valid -or
        $readiness.detection_quality.f1 -lt 0.95 -or
        -not $readiness.incident_quality.valid -or
        $readiness.incident_quality.f1 -lt 0.95 -or
        $readiness.incident_quality.graph_structure_accuracy -lt 1.0
    ) {
        throw "Audit or assurance registry integrity readiness check failed."
    }
    $headerCheck = Invoke-WebRequest `
        -Method Get `
        -Uri "$baseUrl/health/live" `
        -Headers @{ "X-Request-ID" = "docker-qa-request" } `
        -TimeoutSec 2
    if (
        $headerCheck.Headers["X-Request-ID"] -ne "docker-qa-request" -or
        $headerCheck.Headers["X-Content-Type-Options"] -ne "nosniff"
    ) {
        throw "Request tracing or security headers are missing."
    }

    $events = Invoke-RestMethod `
        -Method Post `
        -Uri "$baseUrl/events/simulate" `
        -ContentType "application/json" `
        -Body '{"scenario_id":"ZT-S05","count":1}'
    $analysisBody = $events[0] | ConvertTo-Json -Depth 20 -Compress
    $analysis = Invoke-RestMethod `
        -Method Post `
        -Uri "$baseUrl/analysis" `
        -ContentType "application/json" `
        -Body $analysisBody
    $evaluation = Invoke-RestMethod `
        -Method Post `
        -Uri "$baseUrl/evaluation/run" `
        -ContentType "application/json" `
        -Body '{"analyzer":"rule","runs_per_scenario":5,"concurrency":4}'
    $publicReplay = Invoke-RestMethod `
        -Method Post `
        -Uri "$baseUrl/replay/public/run" `
        -ContentType "application/json"
    $detectionQuality = Invoke-RestMethod `
        -Method Get `
        -Uri "$baseUrl/evaluation/detection-quality"
    $incidentQuality = Invoke-RestMethod `
        -Method Get `
        -Uri "$baseUrl/evaluation/incident-quality"

    $caseEvents = @()
    foreach ($scenarioId in @("ZT-S01", "ZT-S02", "ZT-S03", "ZT-S04", "ZT-S05")) {
        $generated = Invoke-RestMethod `
            -Method Post `
            -Uri "$baseUrl/events/simulate" `
            -ContentType "application/json" `
            -Body (@{ scenario_id = $scenarioId; count = 1 } | ConvertTo-Json -Compress)
        $caseEvents += @($generated)[0]
    }
    $caseCreation = Invoke-RestMethod `
        -Method Post `
        -Uri "$baseUrl/cases/from-events" `
        -ContentType "application/json" `
        -Body (@{
            events = $caseEvents
            note = "Docker QA correlated synthetic evidence into an incident case."
        } | ConvertTo-Json -Depth 20 -Compress)
    if (
        $caseCreation.created_case_count -ne 1 -or
        $caseCreation.reused_case_count -ne 0 -or
        $caseCreation.cases[0].status -ne "NEW" -or
        $caseCreation.cases[0].response_mode -ne "simulation"
    ) {
        throw "Incident case creation did not produce one simulation-only NEW case."
    }
    $caseRecord = $caseCreation.cases[0]
    foreach ($nextStatus in @("TRIAGED", "INVESTIGATING", "CONTAINED", "RESOLVED", "CLOSED")) {
        $caseRecord = Invoke-RestMethod `
            -Method Patch `
            -Uri "$baseUrl/cases/$($caseRecord.case_id)" `
            -ContentType "application/json" `
            -Body (@{
                status = $nextStatus
                expected_version = $caseRecord.version
                assignee = "Docker QA"
                note = "Docker QA verified the $nextStatus lifecycle checkpoint."
            } | ConvertTo-Json -Compress)
    }
    $caseMetrics = Invoke-RestMethod -Method Get -Uri "$baseUrl/cases/metrics"
    $caseReadiness = Invoke-RestMethod -Method Get -Uri "$baseUrl/health/ready"
    if (
        $caseRecord.status -ne "CLOSED" -or
        $caseRecord.version -ne 6 -or
        $caseRecord.history.Count -ne 6 -or
        $caseMetrics.total_cases -ne 1 -or
        $caseMetrics.open_case_count -ne 0 -or
        -not $caseReadiness.case_management.ok -or
        $caseReadiness.case_management.verified_lines -ne 6
    ) {
        throw "Incident case lifecycle, metrics, or hash-chain readiness check failed."
    }

    if ($analysis.assessment.risk_level -notin @("HIGH", "CRITICAL")) {
        throw "Threat smoke test returned an unexpectedly low risk."
    }
    if ($analysis.review_status -ne "PENDING") {
        throw "High-risk analysis did not enter the review queue."
    }
    if (
        $analysis.normalized_event.provenance.schema_version -ne "1.9.0" -or
        $analysis.detection.evaluated_rule_count -ne 6 -or
        $analysis.detection.matches.Count -lt 1
    ) {
        throw "OCSF normalization or Sigma detection evidence is missing."
    }

    $reviewUrl = "$baseUrl/results/$($analysis.event_id)/review"
    $inReview = Invoke-RestMethod `
        -Method Patch `
        -Uri $reviewUrl `
        -ContentType "application/json" `
        -Body '{"status":"IN_REVIEW","reviewer":"Docker QA"}'
    if ($inReview.review_status -ne "IN_REVIEW") {
        throw "Analysis could not be assigned to an analyst."
    }
    $resolved = Invoke-RestMethod `
        -Method Patch `
        -Uri $reviewUrl `
        -ContentType "application/json" `
        -Body '{"status":"RESOLVED","reviewer":"Docker QA","note":"Cost-free container smoke test completed."}'
    if ($resolved.review_status -ne "RESOLVED") {
        throw "Analysis review could not be resolved."
    }

    if (-not ($evaluation.targets_met.PSObject.Properties.Value -notcontains $false)) {
        throw "Rule evaluation did not meet every target."
    }
    if ($evaluation.error_count -ne 0 -or $evaluation.total_cases -ne 40) {
        throw "Stability evaluation returned errors or an unexpected sample size."
    }
    if (
        -not $publicReplay.expectations_met -or
        $publicReplay.dataset_count -ne 3 -or
        $publicReplay.event_count -ne 12 -or
        $publicReplay.incident_count -ne 1 -or
        $publicReplay.results[0].entity_graph.node_count -lt 1 -or
        $publicReplay.results[0].incidents[0].window_minutes -ne 5
    ) {
        throw "Public attack/benign replay or incident correlation failed."
    }
    if (
        -not $detectionQuality.gate_passed -or
        $detectionQuality.precision -lt 0.95 -or
        $detectionQuality.recall -lt 0.95 -or
        $detectionQuality.false_positive_rate -gt 0.05 -or
        $detectionQuality.parse_success_rate -lt 1.0 -or
        $detectionQuality.mapping_completeness -lt 1.0
    ) {
        throw "Detection quality regression gate failed."
    }
    if (
        -not $incidentQuality.gate_passed -or
        $incidentQuality.precision -lt 0.95 -or
        $incidentQuality.recall -lt 0.95 -or
        $incidentQuality.false_positive_rate -gt 0.05 -or
        $incidentQuality.window_accuracy -lt 1.0 -or
        $incidentQuality.graph_structure_accuracy -lt 1.0 -or
        $incidentQuality.deduplication_accuracy -lt 1.0
    ) {
        throw "Incident quality regression gate failed."
    }

    [ordered]@{
        status = "passed"
        analyzer = $health.analyzer_mode
        event_id = $analysis.event_id
        risk = $analysis.assessment.risk_level
        action = $analysis.assessment.recommended_action
        review_status = $resolved.review_status
        audit_integrity = $readiness.audit.ok
        case_integrity = $caseReadiness.case_management.ok
        case_status = $caseRecord.status
        case_version = $caseRecord.version
        assurance_registry_integrity = $readiness.assurance.valid
        assurance_control_count = $readiness.assurance.total_controls
        ocsf_schema_version = $readiness.normalization.schema_version
        sigma_rules = $readiness.detection.approved_rule_count
        public_replay_events = $publicReplay.event_count
        correlated_incidents = $publicReplay.incident_count
        detection_precision = $detectionQuality.precision
        detection_recall = $detectionQuality.recall
        detection_rule_coverage = $detectionQuality.rule_coverage_rate
        incident_precision = $incidentQuality.precision
        incident_recall = $incidentQuality.recall
        incident_false_positive_rate = $incidentQuality.false_positive_rate
        incident_window_accuracy = $incidentQuality.window_accuracy
        incident_graph_accuracy = $incidentQuality.graph_structure_accuracy
        incident_deduplication_accuracy = $incidentQuality.deduplication_accuracy
        evaluation_cases = $evaluation.total_cases
        risk_accuracy = $evaluation.risk_accuracy
        action_accuracy = $evaluation.action_accuracy
        error_rate = $evaluation.error_rate
        throughput_per_second = $evaluation.throughput_per_second
        p50_latency_ms = $evaluation.p50_latency_ms
        p95_latency_ms = $evaluation.p95_latency_ms
    } | ConvertTo-Json -Compress
} catch {
    $failedContainer = docker ps -a --filter "name=^/$containerName$" --format "{{.Names}}"
    if ($failedContainer -eq $containerName) {
        docker logs $containerName
    }
    throw
} finally {
    $created = docker ps -a --filter "name=^/$containerName$" --format "{{.Names}}"
    if ($created -eq $containerName) {
        docker rm --force $containerName | Out-Null
    }
}
