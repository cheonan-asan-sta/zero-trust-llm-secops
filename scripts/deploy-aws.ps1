[CmdletBinding()]
param(
    [string]$TargetAccount = "172585182454",
    [string]$Region = "ap-northeast-2",
    [string]$Profile = "",
    [string]$StackPrefix = "zero-trust-llm-secops",
    [ValidateSet("rule", "openai", "hybrid")]
    [string]$AnalyzerMode = "rule",
    [string]$OpenAIApiKeySecretArn = "",
    [string]$ImageTag = ""
)

$ErrorActionPreference = "Stop"
if ($PSVersionTable.PSVersion.Major -ge 7) {
    $PSNativeCommandUseErrorActionPreference = $true
}
$projectRoot = Split-Path -Parent $PSScriptRoot
$awsArgs = @()
if ($Profile) {
    $awsArgs = @("--profile", $Profile)
}

if (-not $ImageTag) {
    $ImageTag = (git -C $projectRoot rev-parse --short HEAD).Trim()
    if (git -C $projectRoot status --porcelain) {
        $timestamp = (Get-Date).ToUniversalTime().ToString("yyyyMMddHHmmss")
        $ImageTag = "$ImageTag-working-$timestamp"
    }
}

if ($AnalyzerMode -ne "rule" -and -not $OpenAIApiKeySecretArn) {
    throw "OpenAI and hybrid modes require an AWS Secrets Manager ARN via -OpenAIApiKeySecretArn."
}

$functionUrlAuthType = if ($AnalyzerMode -ne "rule") { "AWS_IAM" } else { "NONE" }

$currentAccount = (aws @awsArgs sts get-caller-identity --query Account --output text).Trim()
if ($currentAccount -ne $TargetAccount) {
    throw "AWS account guard failed. Expected $TargetAccount but current credentials use $currentAccount."
}

docker info *> $null

$registryStack = "$StackPrefix-registry"
$appStack = "$StackPrefix-app"

aws @awsArgs cloudformation deploy `
    --region $Region `
    --stack-name $registryStack `
    --template-file "$projectRoot\infra\ecr.yaml" `
    --no-fail-on-empty-changeset

$repositoryUri = (aws @awsArgs cloudformation describe-stacks `
    --region $Region `
    --stack-name $registryStack `
    --query "Stacks[0].Outputs[?OutputKey=='RepositoryUri'].OutputValue" `
    --output text).Trim()

$registryHost = $repositoryUri.Split("/")[0]
aws @awsArgs ecr get-login-password --region $Region |
    docker login --username AWS --password-stdin $registryHost | Out-Null

$imageIdentifier = "${repositoryUri}:${ImageTag}"
docker build `
    --platform linux/amd64 `
    --provenance=false `
    --file "$projectRoot\Dockerfile.lambda" `
    --tag $imageIdentifier `
    $projectRoot
docker push $imageIdentifier

$appParameters = @(
    "ImageIdentifier=$imageIdentifier",
    "FunctionName=$StackPrefix",
    "TableName=$StackPrefix-audit",
    "AnalyzerMode=$AnalyzerMode",
    "FunctionUrlAuthType=$functionUrlAuthType"
)
if ($OpenAIApiKeySecretArn) {
    $appParameters += "OpenAIApiKeySecretArn=$OpenAIApiKeySecretArn"
}

aws @awsArgs cloudformation deploy `
    --region $Region `
    --stack-name $appStack `
    --template-file "$projectRoot\infra\lambda.yaml" `
    --capabilities CAPABILITY_IAM `
    --parameter-overrides $appParameters `
    --no-fail-on-empty-changeset

$serviceUrl = (aws @awsArgs cloudformation describe-stacks `
    --region $Region `
    --stack-name $appStack `
    --query "Stacks[0].Outputs[?OutputKey=='ServiceUrl'].OutputValue" `
    --output text).Trim()

Write-Output "Deployment complete: $serviceUrl"
