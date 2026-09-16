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
        -Body '{"analyzer":"rule","runs_per_scenario":1}'

    if ($analysis.assessment.risk_level -notin @("HIGH", "CRITICAL")) {
        throw "Threat smoke test returned an unexpectedly low risk."
    }
    if ($analysis.review_status -ne "PENDING") {
        throw "High-risk analysis did not enter the review queue."
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

    [ordered]@{
        status = "passed"
        analyzer = $health.analyzer_mode
        event_id = $analysis.event_id
        risk = $analysis.assessment.risk_level
        action = $analysis.assessment.recommended_action
        review_status = $resolved.review_status
        evaluation_cases = $evaluation.total_cases
        risk_accuracy = $evaluation.risk_accuracy
        action_accuracy = $evaluation.action_accuracy
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
