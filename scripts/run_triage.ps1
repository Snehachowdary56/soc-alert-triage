# Runs the triage pipeline and shows the escalated tickets (Windows PowerShell).
Set-Location (Join-Path $PSScriptRoot "..")
python -m triage --out output @args
$tickets = Import-Csv output\tickets.csv
Write-Host ""
Write-Host "Escalated tickets:"
$tickets | Where-Object { $_.escalate -eq "yes" } | Format-Table ticket_id, severity, score, type -AutoSize
Write-Host ("High severity count: " + @($tickets | Where-Object { $_.severity -eq "High" }).Count)
