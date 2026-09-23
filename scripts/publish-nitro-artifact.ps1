param(
    [string]$Profile = 'preprod',
    [string]$Region = 'ap-southeast-1',
    [string]$StackName = 'olea-dowsure-nitro-preprod',
    [string]$ArtifactKey = 'nitro/enclave-context.tar.gz'
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$archive = Join-Path $env:TEMP 'olea-nitro-enclave-context.tar.gz'
$bucket = (aws cloudformation describe-stacks --stack-name $StackName --profile $Profile --region $Region --query "Stacks[0].Outputs[?OutputKey=='EnclaveArtifactBucket'].OutputValue" --output text).Trim()
if (-not $bucket) { throw "Stack $StackName has no EnclaveArtifactBucket output." }

if (Test-Path $archive) { Remove-Item $archive -Force }
Push-Location $root
try {
    tar -czf $archive nitro-enclave
} finally {
    Pop-Location
}

aws s3 cp $archive "s3://$bucket/$ArtifactKey" --profile $Profile --region $Region
Write-Output "Uploaded s3://$bucket/$ArtifactKey"
Write-Output "Re-run the host bootstrap through SSM or restart the instance after uploading the artifact."
