# Make sure Win32-OpenSSH's ssh-add and ssh-keygen are there for the
# OpenSSH tests, which use them over named pipes.
#
# Windows' own OpenSSH Client feature is used when present, and installed
# when not. If that fails, the Chocolatey `openssh` package is installed
# instead, and SSH_AGENT_KIT_OPENSSH points the tests at it.

$ErrorActionPreference = 'Stop'

function Find-OpenSSH([string] $dir) {
    foreach ($tool in 'ssh', 'ssh-add', 'ssh-keygen') {
        if (-not (Test-Path "$dir\$tool.exe")) { return $false }
    }
    return $true
}

$dir = "$env:SystemRoot\System32\OpenSSH"
if (-not (Find-OpenSSH $dir)) {
    Write-Host "OpenSSH not in $dir; adding Windows' OpenSSH Client"
    try {
        Get-WindowsCapability -Online -Name 'OpenSSH.Client*' |
            Where-Object State -ne 'Installed' |
            Add-WindowsCapability -Online | Out-Null
    } catch {
        Write-Host "Adding the OpenSSH Client failed: $_"
    }
}
if (-not (Find-OpenSSH $dir)) {
    Write-Host 'Installing the Chocolatey openssh package'
    choco install openssh --yes --no-progress
    if ($LASTEXITCODE -ne 0) { throw "choco install openssh failed ($LASTEXITCODE)" }
    $dir = "$env:ProgramFiles\OpenSSH-Win64"
    if (-not (Find-OpenSSH $dir)) { throw "OpenSSH not found in $dir after installing it" }
    "SSH_AGENT_KIT_OPENSSH=$dir" | Out-File -FilePath $env:GITHUB_ENV -Append -Encoding utf8
}

# ssh-add -V looks for an agent before printing, so ask ssh.
& "$dir\ssh.exe" -V
Write-Host "Using OpenSSH in $dir"
exit 0
