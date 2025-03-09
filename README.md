### **📄 README.md – Forensic Network & Persistence Analysis Script**  

---

# **Forensic Network & Persistence Analysis**  
🔍 **A PowerShell script for detecting suspicious network connections, running processes, associated services, and persistence mechanisms (Scheduled Tasks, Startup Entries, WMI Event Subscriptions).**  

## **🚀 Features**  
✅ Identifies **active network connections** and **owning processes** (PID & Process Name)  
✅ Detects **running services** linked to suspicious processes  
✅ Enumerates **Scheduled Tasks** for possible persistence  
✅ Lists **Startup Registry Entries** that may indicate unauthorized access  
✅ Detects **WMI Event Subscription persistence techniques**  
✅ Outputs **all findings in a single structured table**  

---

## **📌 Usage Instructions**  
### **Prerequisites**  
- Requires **Windows PowerShell 5.1+** or **PowerShell Core**  
- Must be run with **Administrator privileges**  

### **💻 Running the Script**  
1️⃣ **Open PowerShell as Administrator**  
2️⃣ Clone or download the repository:  
   ```powershell
   git clone https://github.com/YourRepo/Forensic-Analysis.git
   cd Forensic-Analysis
   ```
3️⃣ Run the script:  
   ```powershell
   .\Forensic-Analysis.ps1
   ```
4️⃣ Review the **formatted table output** for suspicious activity  

---

## **📊 Sample Output**  
| Local Address | Local Port | Remote Address | Remote Port | State   | PID  | Process Name | Service Name | Task Name   | Startup Entry | WMI Event  |
|--------------|-----------|---------------|------------|--------|------|--------------|--------------|-------------|--------------|------------|
| 192.168.1.10 | 443       | 104.18.32.47  | 443        | ESTABLISHED | 1345 | chrome.exe   | NULL         | NULL        | NULL         | NULL       |
| 0.0.0.0      | 135       | 0.0.0.0       | 0          | LISTENING   | 820  | svchost.exe  | RpcEptMapper | NULL        | NULL         | NULL       |
| 192.168.1.10 | 22        | 8.8.8.8       | 22         | ESTABLISHED | 2456 | putty.exe    | NULL         | NULL        | StartupApp   | WMI-Persistence |

---

## **🛠️ Customization**  
You can modify the script to:  
- **Alert on specific PIDs, services, or remote IPs**  
- **Log output to a file** using `Export-Csv`  
- **Integrate with SIEM tools** for further analysis  

### **🔹 Example: Export to CSV**  
```powershell
$results | Export-Csv -Path forensic_results.csv -NoTypeInformation
```

---

## **📖 References**  
- [Windows Event Logging for Security](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/basic-security-audit-network-traffic)  
- [PowerShell Security Best Practices](https://docs.microsoft.com/en-us/powershell/scripting/learn/deep-dives/security-best-practices)  

---

## **⚠️ Disclaimer**  
🚨 This script is for **defensive cybersecurity and forensic analysis** purposes only.  
**Unauthorized use against systems you don’t own is illegal.**  

---

## **📩 Contributing**  
💡 Found an issue or want to suggest an enhancement?  
Feel free to submit a **pull request** or open an **issue** in this repository.  

---

## **📜 License**  
🔓 This project is licensed under the **MIT License** – feel free to use, modify, and share.  

---

Would you like any **additional sections, such as automated alerts or SIEM integration?** 🚀
