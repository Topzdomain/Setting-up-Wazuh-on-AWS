<h2 align="center"> SETTING UP WAZUH ON AWS</h2>

Wazuh is a Security Information and Event Management (SIEM) tool that provides monitoring, detection, and alerting of security events and incidents both on cloud networks and On-premises networks. For cloud security in AWS, it can be set up to monitor cloud infrastructures using Amazon Guardduty, Amazon Inspector, AWS Cloudtrail, AWS Web Application Firewall, VPC and other services running on AWS. For this project, I'll be setting up Wazuh to monitor two Windows machines (one is a Windows 11 which is my host machine and the other is a Windows 10 machine on my VM) and Kali Linux on my VM.

First is to launch an EC2 instance to host Wazuh. it requires at least 4 vCPU, 8 GiB memory and 30 GiB root volume (storage capacity) or more depending on the workload. Also, I have already downloaded a key pair (wazuh.pem) which I am going to use for secure sign-in to the Ubuntu AMI (Amazon Machine Image). I also configured the security groups (SG) before launching the EC2 instance.

<p>
<img src="https://github.com/Topzdomain/Setting-up-Wazuh-on-AWS/blob/main/screen_shots/ec2-instance-launch-img1.png" height="60%" width="40%"/>
<img src="https://github.com/Topzdomain/Setting-up-Wazuh-on-AWS/blob/main/screen_shots/ec2-instance-launch-img2.png" height="60%" width="50%"/>
</p>

<p align="center">
<img src="https://github.com/Topzdomain/Setting-up-Wazuh-on-AWS/blob/main/screen_shots/ec2-instance-launch-img3.png" height="60%" width="40%"/>
</p>

The next step is to set up the security groups to open port 22 for SSH, 443 for the wazuh dashboard and other ports for wazuh server, wazuh agent, wazuh indexer and other services. All the ports recommended in the wazuh documentation were configured. I set the source IP for the inbound rules to any IP (IPv4) because the ec2 instance would be terminated as soon as I am done with the project.

<p align="center">
<img src="https://github.com/Topzdomain/Setting-up-Wazuh-on-AWS/blob/main/screen_shots/Ports-required.png" height="60%" width="40%"/>
</p>

<p align="center">
<img src="https://github.com/Topzdomain/Setting-up-Wazuh-on-AWS/blob/main/screen_shots/SG-ports-configured.png" height="60%" width="80%"/>
</p>

Next step is to SSH into the Ubuntu server hosting the wazuh

```commandline
ssh -i wazuh.pem ubuntu@server_ip_address
```
After gaining entry into the Ubuntu server using SSH, I ran the code below to download the wazuh installation script from their website and after a successful download, sudo is used to elevate the privileges to install the Wazuh Siem tool on the server. At the end of the installation, a username and password for the wazuh dashboard is provided.

```commandline
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh && sudo bash ./wazuh-install.sh -a
```
<p align="center">
<img src="https://github.com/Topzdomain/Setting-up-Wazuh-on-AWS/blob/main/screen_shots/installation-of-wazuh-on-ubuntu-server-completed.png" height="60%" width="80%"/>
</p>

Then click on the public IPv4 DNS link on the ec2 creation page to access the Wazuh dashboard and sign in with the credentials provided.

<p align="center">
<img src="https://github.com/Topzdomain/Setting-up-Wazuh-on-AWS/blob/main/screen_shots/loging-into-wazuh-dashboard.png" height="40%" width="40%"/>
</p>

<p align="center">
<img src="https://github.com/Topzdomain/Setting-up-Wazuh-on-AWS/blob/main/screen_shots/Wazuh-dashboard.png" height="45%" width="80%"/>
</p>

Next is to install the wazuh agent on the two Windows machines. On the wazuh dashboard which is currently without an agent to monitor as at set-up completion, I clicked on the add agent link and followed the prompts to install the agents on my machines. 

<p align="center">
<img src="https://github.com/Topzdomain/Setting-up-Wazuh-on-AWS/blob/main/screen_shots/Agent-installation.png" height="45%" width="55%"/>
</p>


The following code was then run on Powershell as an administrator on both Windows devices.

Windows 11

```commandline
Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.7.3-1.msi -OutFile ${env.tmp}\wazuh-agent; msiexec.exe /i ${env.tmp}\wazuh-agent /q WAZUH_MANAGER='54.83.89.64' WAZUH_AGENT_GROUP='default' WAZUH_AGENT_NAME='Windows11' WAZUH_REGISTRATION_SERVER='54.83.89.64'
```

Windows 10 Pro (VM)

```commandline
Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.7.3-1.msi -OutFile ${env.tmp}\wazuh-agent; msiexec.exe /i ${env.tmp}\wazuh-agent /q WAZUH_MANAGER='54.83.89.64' WAZUH_REGISTRATION_SERVER='54.83.89.64'
```
Kali Linux (VM)

```commandline
wget https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.7.3-1_amd64.deb && sudo WAZUH_MANAGER='54.242.196.154' WAZUH_AGENT_GROUP='default' WAZUH_AGENT_NAME='Kali-Linux' dpkg -i ./wazuh-agent_4.7.3-1_amd64.deb
```

To Start Wazuh Service on the Windows Machine

```commandline
NET START WazuhSvc
```

To Start Wazuh Service on the Kali Linux

```commandline
sudo systemctl daemon-reload
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent
```

<h3 align="left"> Challenges Encountered</h3>

I encountered some challenges installing the wazuh agent on my Windows 11, even though the agent was installed and the report from the "NET START WazuhSvc" command shows that the wazuh service had started, it was still not reflecting on the wazuh dashboard. So to resolve this issue, I went to all apps on my Windows start menu, navigated to the ossec-agent folder that contained the Windows agent app, launched the app. On the app dialogue box, I clicked on the manage tab and clicked on start to start the service. I clicked on refresh, then save. The wazuh agent started working and the endpoint could be monitored from the wazuh dashboard. I was able to use the wazuh report of security events to fix some security issues on my device.

<p align="center">
<img src="https://github.com/Topzdomain/Setting-up-Wazuh-on-AWS/blob/main/screen_shots/wazuh-agent-app.png" height="500%" width="35%"/>
</p>

<h3 align="left"> Uninstalling Wazuh Agent on Windows</h3>

To stop the wazuh from monitoring the Windows machine, the wazuh agent on the Windows machine needs to be uninstalled. From the Windows start menu in all apps, locate the ossec-agent folder. Click on the uninstall agent. Another way is to uninstall the wazuh agent app from settings i.e. Settings>>Apps>>Apps & features

<p align="center">
<img src="https://github.com/Topzdomain/Setting-up-Wazuh-on-AWS/blob/main/screen_shots/uninstalling-wazuh-agent.png" height="50%" width="70%"/>
</p>

After the agent has been uninstalled, delete the ossec-agent folder in Program Files (x86) on the Local Disk

<h3 align="left"> Uninstalling Wazuh Agent on Kali</h3>

```commandline
apt remove wazuh-agent
```
To remove the ossec file 

```commandline
rm -r /var/ossec/
```

<h3 align="left"> References</h3>

https://documentation.wazuh.com/current/quickstart.html

Metrics on the wazuh dashboard
<p align="center">
<img src="https://github.com/Topzdomain/Setting-up-Wazuh-on-AWS/blob/main/screen_shots/pcid-monitoring-dashboard.png" height="70%" width="90%"/>
</p>
<h5 align="center"> screenshot of wazuh dashboard showing compliance issues on the Windows 11 endpoint</h5>

<p align="center">
<img src="https://github.com/Topzdomain/Setting-up-Wazuh-on-AWS/blob/main/screen_shots/examining-security-event-for-windows11.png" height="70%" width="90%"/>
</p>
<h5 align="center"> screenshot of wazuh dashboard showing a security issue that need to be fix and its severity level</h5>







