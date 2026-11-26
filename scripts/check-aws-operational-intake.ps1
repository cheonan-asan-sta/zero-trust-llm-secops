[CmdletBinding()]
param(
    [string]$Profile = "aitest-target",
    [string]$Region = "ap-northeast-2",
    [ValidatePattern('^\d{12}$')]
    [string]$TargetAccount = "172585182454",
    [ValidatePattern('^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$')]
    [string]$ArchiveBucket,
    [ValidatePattern('^\d{12}$')]
    [string]$ArchiveOwner
)

if ([bool]$ArchiveBucket -ne [bool]$ArchiveOwner) {
    throw "ArchiveBucket and ArchiveOwner must be provided together."
}

$PSNativeCommandUseErrorActionPreference = $false

$commonArgs = @("--profile", $Profile, "--region", $Region, "--no-cli-pager",
                "--cli-connect-timeout", "8", "--cli-read-timeout", "12")

function Invoke-Inventory([string[]]$Arguments) {
    $output = & aws @commonArgs @Arguments --output json 2>&1
    $exitCode = $LASTEXITCODE
    $message = $output -join [Environment]::NewLine
    if ($exitCode -eq 0) {
        return [ordered]@{ status = "ok"; value = ($message | ConvertFrom-Json) }
    }
    $status = switch -Regex ($message) {
        'session has expired|ExpiredToken|Unable to locate credentials|not logged in' { "authentication_required"; break }
        'AccessDenied|UnauthorizedOperation' { "access_denied"; break }
        'ObjectLockConfigurationNotFoundError' { "object_lock_missing"; break }
        default { "aws_call_failed" }
    }
    return [ordered]@{ status = $status }
}

$caller = Invoke-Inventory @("sts", "get-caller-identity", "--query", "Account")
$report = [ordered]@{ target_account = $TargetAccount; region = $Region; read_only = $true }
if ($caller.status -ne "ok") {
    $report.status = $caller.status
    $report | ConvertTo-Json -Depth 5
    return
}
if ($caller.value -cne $TargetAccount) {
    $report.status = "wrong_account"
    $report | ConvertTo-Json -Depth 5
    return
}

$report.status = "verified_account"
$report.identity_center = Invoke-Inventory @(
    "sso-admin", "list-instances", "--query", "length(Instances)"
)
$report.project_log_groups = Invoke-Inventory @(
    "logs", "describe-log-groups", "--log-group-name-prefix", "/aws/lambda/zero-trust-llm-secops",
    "--query", "length(logGroups)"
)
$report.client_vpn_endpoints = Invoke-Inventory @(
    "ec2", "describe-client-vpn-endpoints", "--query", "length(ClientVpnEndpoints)"
)
if ($ArchiveBucket) {
    $report.archive_owner_is_separate = $ArchiveOwner -cne $TargetAccount
    $report.archive_object_lock = Invoke-Inventory @(
        "s3api", "get-object-lock-configuration", "--bucket", $ArchiveBucket,
        "--expected-bucket-owner", $ArchiveOwner, "--query",
        "ObjectLockConfiguration.{enabled:ObjectLockEnabled,default_mode:Rule.DefaultRetention.Mode}"
    )
}
$report | ConvertTo-Json -Depth 5
