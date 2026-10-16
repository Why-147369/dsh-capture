<#
.SYNOPSIS
    dsh-capture elevated helper.

.DESCRIPTION
    Runs one capture job with administrator rights, then exits. Launched by
    lib/elevate.js through `Start-Process -Verb RunAs`, which is what produces
    the UAC prompt; nothing stays elevated afterwards.

    The helper deliberately performs no string interpolation of caller data.
    The job file is read with Get-Content | ConvertFrom-Json and every value is
    passed to pktmon as a separate argv element through the call operator, so a
    crafted capture name or filter cannot become part of a command line.

    Job file (JSON):
        { "action": "start"|"stop"|"probe",
          "payload": { ... },          # action specific
          "resultPath": "<abs path>" }  # where to write the JSON result

    Result file (JSON):
        { "ok": bool, "action": str, "error": str|null, "data": {...}, "log": [str] }

.NOTES
    Exit codes: 0 = job ran (see result file for ok), 2 = bad job file,
    3 = refused (not elevated).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$JobPath
)

$ErrorActionPreference = 'Stop'
$log = New-Object System.Collections.Generic.List[string]

function Write-Result {
    param(
        [string]$ResultPath,
        [bool]$Ok,
        [string]$Action,
        [string]$ErrorMessage,
        $Data
    )
    $payload = [ordered]@{
        ok     = $Ok
        action = $Action
        error  = $ErrorMessage
        data   = $Data
        log    = $log
    }
    try {
        ($payload | ConvertTo-Json -Depth 12) | Set-Content -LiteralPath $ResultPath -Encoding UTF8
    } catch {
        # Nothing else we can do; the caller reports a missing result file.
    }
}

# --- validate the job file -------------------------------------------------
if (-not (Test-Path -LiteralPath $JobPath -PathType Leaf)) {
    Write-Error "job file not found: $JobPath"
    exit 2
}
try {
    $job = Get-Content -LiteralPath $JobPath -Raw | ConvertFrom-Json
} catch {
    Write-Error "job file is not valid JSON: $_"
    exit 2
}
$action = [string]$job.action
$resultPath = [string]$job.resultPath
$payload = $job.payload
if ([string]::IsNullOrWhiteSpace($resultPath)) {
    Write-Error 'job file has no resultPath'
    exit 2
}

# --- confirm we are actually elevated -------------------------------------
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
$isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$log.Add("elevated=$isAdmin user=$($identity.Name)")
if (-not $isAdmin) {
    # Start-Process -Verb RunAs should have handled this; refuse loudly instead
    # of silently running a capture that would fail at the driver anyway.
    Write-Result -ResultPath $resultPath -Ok $false -Action $action `
        -ErrorMessage 'helper is not elevated; UAC may have been bypassed' -Data $null
    exit 3
}

$pktmon = Join-Path $env:SystemRoot 'System32\PktMon.exe'
if (-not (Test-Path -LiteralPath $pktmon)) {
    Write-Result -ResultPath $resultPath -Ok $false -Action $action `
        -ErrorMessage 'pktmon.exe not found (needs Windows 10 1809+ / Windows 11)' -Data $null
    exit 0
}

try {
    switch ($action) {

        'probe' {
            $out = & $pktmon filter list 2>&1 | Out-String
            $code = $LASTEXITCODE
            $log.Add("filter list exit=$code")
            Write-Result -ResultPath $resultPath -Ok ($code -eq 0) -Action $action `
                -ErrorMessage ($(if ($code -eq 0) { $null } else { "pktmon filter list failed (exit $code)" })) `
                -Data @{ output = $out.Trim(); exitCode = $code }
        }

        'start' {
            $name = if ($payload -and $payload.name) { [string]$payload.name } else { "capture-$([DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss'))" }
            $dir  = if ($payload -and $payload.dir) { [string]$payload.dir } else { $env:TEMP }
            if (-not (Test-Path -LiteralPath $dir)) {
                New-Item -ItemType Directory -Force -Path $dir | Out-Null
            }
            $etl = Join-Path $dir "$name.etl"
            if (Test-Path -LiteralPath $etl) { Remove-Item -LiteralPath $etl -Force }

            # Replace the driver's filter set, then add the requested rules.
            & $pktmon filter remove 2>&1 | Out-Null
            $applied = New-Object System.Collections.Generic.List[string]
            if ($payload -and $payload.filters) {
                foreach ($f in $payload.filters) {
                    $a = @('filter', 'add', '--name', "dsh-capture-$([DateTime]::UtcNow.Ticks)")
                    if ($f.ip)       { $a += @('--ip', [string]$f.ip) }
                    if ($f.port)     { $a += @('--port', [string]$f.port) }
                    if ($f.protocol) { $a += @('--transport', ([string]$f.protocol).ToUpperInvariant()) }
                    $r = & $pktmon @a 2>&1 | Out-String
                    $applied.Add("$($a -join ' ') -> exit=$LASTEXITCODE $($r.Trim())")
                }
            }

            $pktSize = if ($payload -and $payload.pktSize) { [int]$payload.pktSize } else { 256 }
            $args = @('start', '--capture', '--comp', 'nics', '--pkt-size', "$pktSize", '--file-name', $etl)
            if ($payload -and $payload.maxFileMb) { $args += @('--file-size', ([string]([int]$payload.maxFileMb))) }

            $out = & $pktmon @args 2>&1 | Out-String
            $code = $LASTEXITCODE
            $log.Add("start exit=$code")
            $log.AddRange($applied)
            $ok = ($code -eq 0)
            Write-Result -ResultPath $resultPath -Ok $ok -Action $action `
                -ErrorMessage ($(if ($ok) { $null } else { "pktmon start failed (exit $code): $($out.Trim())" })) `
                -Data @{ etl = $etl; exitCode = $code; output = $out.Trim(); filters = $applied }
        }

        'stop' {
            $out = & $pktmon stop 2>&1 | Out-String
            $code = $LASTEXITCODE
            & $pktmon filter remove 2>&1 | Out-Null
            $log.Add("stop exit=$code")
            # "no session" is not an error for our purposes.
            $notRunning = $out -match 'no.*(session|trace)|未在|没有'
            Write-Result -ResultPath $resultPath -Ok ($code -eq 0 -or $notRunning) -Action $action `
                -ErrorMessage $null -Data @{ exitCode = $code; output = $out.Trim(); wasRunning = (-not $notRunning) }
        }

        default {
            Write-Result -ResultPath $resultPath -Ok $false -Action $action `
                -ErrorMessage "unknown action '$action' (expected start|stop|probe)" -Data $null
        }
    }
} catch {
    Write-Result -ResultPath $resultPath -Ok $false -Action $action `
        -ErrorMessage "helper threw: $_" -Data $null
}

exit 0
