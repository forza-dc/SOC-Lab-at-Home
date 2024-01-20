# 👨🏻‍💻 🌎 🔐 Building a SOC Analysis Lab Environment At Home 👨🏻‍💻 🌎 🔐
## Lab Overview

This SOC Analyst home lab is an excellent opportunity to learn new skills beyond the basics and fundamentals. It involves a hands-on experience such as setting up virtualized environments, deploying operating systems, honing command line proficiency, and establishing C2 servers. The primary goal of the lab is to provide practical cybersecurity skills, addressing both offensive and defensive roles. It encompasses telemetry and EDR analysis using tools like Sysmon and LimaCharlie.
Through this structured exploration, individuals gain a comprehensive understanding of security operations. This knowledge serves as a solid base for a seamless transition into cloud security engineering, enhancing proficiency in handling various cybersecurity challenges.

![image](https://github.com/forza-dc/SOC-Lab-at-Home/blob/main/SOC%20Lab%20Image%20final.jpg) 

## Lab Requirements:

- **Virtualization Platform:**
  - VMware Workstation

- **Operating Systems:**
  - Ubuntu Server VM
    - [Download Ubuntu ISO](https://releases.ubuntu.com/22.04.1/ubuntu-22.04.1-live-server-amd64.iso)
  - Windows VM
    - [Download WinDev2311Eval.zip](https://developer.microsoft.com/en-us/windows/downloads/virtual-machines/)

- **Security Tools:**
  - LimaCharlie
    - Create an account and configure EDR on Windows VM
  - Sliver Framework
    - Set up a Command & Control server on Linux VM

- **Networking:**
  - Internet connection for VM downloads and configurations
  - SSH for Linux VM access

- **Administrative Privileges:**
  - Ensure administrative privileges for VM configurations
  - Disable Windows Defender on Windows VM


## VMware Workstation Configuration:

  - Open VMware Workstation and go to Edit and "Virtual Network Editor.
  - Create new VMnet with NAT configurations.

## UbuntuServer VM Installation and Configuration:

 - Download Ubuntu Server ISO and create a VM.
 - Remember to check Install OpenSSHserver check box during installation.
 - Ping google.com from Ubuntu Server terminal (ping–c 4 google.com).

![image](https://github.com/forza-dc/SOC-Lab-at-Home/blob/main/SOC%20Lab%20Img%202.png) 


## Windows VM Installation and Configuration:

- Download WinDev2311Eval.zip.
- Right click on WinDev2311Eval file and open with VMware workstation.


### Disabling Windows Defender:

1. After import, windows VM will login automatically with Username User. To disable windows defender, click on start à Settings.
2. Click Privacy & Security.
3. Open Windows Security.
4. Click Manage Settings.
5. Toggle OFF the "Tamper Protection" switch. When prompted, click "Yes".
6. Toggle every other option OFF as well.
7. Right click on start menu icon and type cmd, and open it as Administrator.
8. Type following command in cmd and press Enter.
![image](https://github.com/forza-dc/SOC-Lab-at-Home/blob/main/SOC%20Lab%20Img%203.png)
9. Again right click on start menu icon, click on "Run" and type "msconfig" and press Enter.
10. Go to "Boot" tab and select "Boot Options". Check the box for "Safe boot" and "Minimal".
11. When prompted, click on Restart.
12. Now, in Safe Mode, we'll disable some services via the Registry. Click the "Start" menu icon Type "regedit" into the search bar and hit Enter. For each of the following registry locations, you'll need to browse to the key, find the "Start" value, and change it to 4.
    
            Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Sense
            Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdBoot
            Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinDefend
            Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdNisDrv
            Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdNisSvc
            Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdFilter
13. Again right click on start menu icon and click "Run" and type "msconfig".
14. Go to "Boot" tab and select "Boot Options". Uncheck the box for "Safe boot", click Apply and OK.

### Prevent the VM from going into standby:

After windows reboot in normal mode, open cmd with Administrative privileges and type following commands:

            powercfg /change standby-timeout-ac 0 
            powercfg /change standby-timeout-dc 0 
            powercfg /change monitor-timeout-ac 0 
            powercfg /change monitor-timeout-dc 0 
            powercfg /change hibernate-timeout-ac 0 
            powercfg /change hibernate-timeout-dc 0

## Install LimaCharlie EDR on Windows VM:

1. LimaCharlie is a very powerful "SecOps Cloud Platform". It not only comes with a cross- platform EDR agent, but also handles all of the log shipping/ingestion and has a threat detection engine. Create free account on [https://app.limacharlie.io/login](https://app.limacharlie.io/login). After creation of account, log in. Once logged into LimaCharlie, create an organization.
2. Once the organization is created, click "Add Sensor".
3. Select Windows, Provide a description such as: Windows VM - Lab, Click Create.
   
![image](https://github.com/forza-dc/SOC-Lab-at-Home/blob/main/SOC%20Lab%20Image%204.jpg) 

5. Specify the x86–64 (.exe) sensor.

![image](https://github.com/forza-dc/SOC-Lab-at-Home/blob/main/SOC%20Lab%20Image%205.jpg) 

6. Download the selected installer.
7. Open an Administrative PowerShell prompt and paste the following command.

![image](https://github.com/forza-dc/SOC-Lab-at-Home/blob/main/SOC%20Lab%20Image%206.jpg)

8. Next, we will copy the install command provided by LimaCharlie which contains the installation key. Paste this command into your open terminal.

![image](https://github.com/forza-dc/SOC-Lab-at-Home/blob/main/SOC%20Lab%20Image%207.jpg)

8.If everything worked correctly, in the LimaCharlie web UI you should also see the sensor reporting in.

![image](https://github.com/forza-dc/SOC-Lab-at-Home/blob/main/SOC%20Lab%20Image%208.jpg)

9. Now let's configure LimaCharlie to also ship the Sysmon event logs alongside its own EDR telemetry. In the left-side menu, click "Artifacts". Next to "Artifact Collection Rules" click "Add Rule".

![image](https://github.com/forza-dc/SOC-Lab-at-Home/blob/main/SOC%20Lab%20Image%209.jpg)

            Enter following details:
            Name: windows-sysmon-logs
            Platforms: Windows
            Path Pattern: wel://Microsoft-Windows-Sysmon/Operational:*
            Retention Period: 10
            Then Click "Save Rule"



## Setup Attack System:



## Output Report Generated by OWASP ZAP

The generated report presents the comprehensive security scan report produced by OWASP ZAP. The report contains detailed insights into potential vulnerabilities, security risks, and recommendations identified during the automated assessment of the target web application. Analyzing this report is crucial for understanding and addressing security weaknesses to enhance the overall resilience of the web application against potential cyber threats.

![image](https://github.com/forza-dc/Enhancing-Web-Application-Security-DevSecOps-and-OWASP-ZAP/blob/main/OwaspZap%20Report.png) 
![image](https://github.com/forza-dc/Enhancing-Web-Application-Security-DevSecOps-and-OWASP-ZAP/blob/main/Security%20Alert%20with%20Details.png) 

The report indicates a minimal presence of high-risk issues (0), a moderate number of medium (5) and low-risk (7) alerts, alongside several informational findings (9). False positives remain absent (0), reflecting a balanced risk posture overall.

| Summary of Alerts  | Risk Level      | Number of Alerts |
|--------------------|-----------------|------------------|
|     :no_entry_sign: | High            |        0         |
|     :warning:       | Medium          |        5         |
|     :large_blue_diamond: | Low         |        7         |
|     :information_source: | Informational |        9         |
|     :white_check_mark: | False Positives|        0         |

## Conclusion

After the completion of the scan, no high-risk vulnerabilities were found. However, a considerable number of medium and low-risk issues, alongside informational findings, were detected.
Medium-risk vulnerabilities, observed in instances such as the absence of Anti-CSRF tokens, improperly configured Content Security Policy (CSP) headers, and the omission of Anti-clickjacking headers, identify potential weak points that, if left unattended, could lead to security breaches.
Furthermore, low-risk concerns, such as the absence of the SameSite attribute in cookies, potential Cross-Domain JavaScript Source File Inclusions, and misconfigured headers, while not posing an immediate threat, highlight areas where reinforcing security measures could enhance the web application's defense posture.

👨🏻‍💻 🚀 In summary, the OWASP ZAP Vulnerability Scanner effectively identifies a range of vulnerabilities and areas for enhancement within the scanned site. By addressing these findings through suitable mitigation strategies - such as implementing missing security headers, refining input validation, and improving session management - the potential attack surface can be significantly reduced, fortifying the overall security stance of the site against potential threats. 👨🏻‍💻 🚀
