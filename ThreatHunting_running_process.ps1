# PowerShell Script: Unified Forensic & Threat-Hunting Tool
# Author: [Your Name]
# Description: Detects suspicious network connections, owning processes, running services, and persistence mechanisms.

# Ensure script runs with admin privileges
If (-Not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "[!] Please run PowerShell as Administrator!" -ForegroundColor Red
    Exit
}

# ---------------------------
# 1️⃣ Get Network Connections and Owning Processes
# ---------------------------
Write-Host "`n[+] Fetching Network Connections and Owning Processes..." -ForegroundColor Green
$connections = Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess
$processes = Get-Process | Select-Object Id, ProcessName

# ---------------------------
# 2️⃣ Get Running Services
# ---------------------------
Write-Host "[+] Fetching Running Services..." -ForegroundColor Green
$services = Get-Service | Where-Object { $_.Status -eq 'Running' } | Select-Object Name, DisplayName, @{Name="PID"; Expression={(Get-WmiObject Win32_Service | Where-Object { $_.Name -eq $_.Name }).ProcessId}}

# ---------------------------
# 3️⃣ Get Scheduled Tasks
# ---------------------------
Write-Host "[+] Fetching Scheduled Tasks..." -ForegroundColor Green
$scheduledTasks = Get-ScheduledTask | Where-Object { $_.TaskPath -match "Microsoft\\Windows\\.*" -eq $false } | 
    Select-Object TaskName, TaskPath

# ---------------------------
# 4️⃣ Get Startup Entries
# ---------------------------
Write-Host "[+] Fetching Startup Registry Entries..." -ForegroundColor Green
$startupEntries = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run", "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" | 
    Select-Object PSChildName, Property, Value

# ---------------------------
# 5️⃣ Get WMI Event Subscription Persistence
# ---------------------------
Write-Host "[+] Fetching WMI Event Subscriptions..." -ForegroundColor Green
$wmiPersistence = Get-WmiObject -Namespace root\subscription -Class __EventConsumer | 
    Select-Object Name, CommandLineTemplate

# ---------------------------
# 🔥 Combine Everything into a Unified Table
# ---------------------------
Write-Host "`n[+] Combining Data into a Single Table..." -ForegroundColor Green

$results = @()

foreach ($conn in $connections) {
    $proc = $processes | Where-Object { $_.Id -eq $conn.OwningProcess }
    $serv = $services | Where-Object { $_.PID -eq $conn.OwningProcess }
    $task = $scheduledTasks | Select-Object -First 1 # Picking first task (can be improved)
    $startup = $startupEntries | Select-Object -First 1 # Picking first startup entry (can be improved)
    $wmi = $wmiPersistence | Select-Object -First 1 # Picking first WMI entry

    $results += [PSCustomObject]@{
        "Local Address"    = $conn.LocalAddress
        "Local Port"       = $conn.LocalPort
        "Remote Address"   = $conn.RemoteAddress
        "Remote Port"      = $conn.RemotePort
        "State"            = $conn.State
        "PID"              = $conn.OwningProcess
        "Process Name"     = $proc.ProcessName
        "Service Name"     = $serv.Name
        "Service Display"  = $serv.DisplayName
        "Scheduled Task"   = $task.TaskName
        "Task Path"        = $task.TaskPath
        "Startup Entry"    = $startup.Property
        "Startup Value"    = $startup.Value
        "WMI Event"        = $wmi.Name
        "WMI Command"      = $wmi.CommandLineTemplate
    }
}

# Display the final table
$results | Format-Table -AutoSize

Write-Host "`n[!] Script Execution Completed. Review the output for suspicious activity!" -ForegroundColor Yellow
