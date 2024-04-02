<h2 align="center"> SETTING UP WAZUH ON AWS</h2>

Wazuh is a Security Information and Event Management (SIEM) tool that provides monitoring, detection, and alerting of security events and incidents both on cloud networks and On-premises networks. For cloud security in AWS, it can be set up to monitor cloud infrastructures using Amazon Guardduty, Amazon Inspector, AWS Cloudtrail, AWS Web Application Firewall, VPC and other services running on AWS. For this project, I'll be setting up Wazuh to monitor two windows machines (one is a windows 11 which is my host machine and the other a windows 10 machine on vm) and kali linux on my vm.

First is to launch an EC2 instance to host Wazuh. it requires at least 4 vCPU, 8 GiB memory and 30 GiB root volume (storage capacity) or more depending on the workload. Also, I have already downloaded a key pair (wazuh.pem) which I am going to use for secure sign in to the ubuntu AMI (Amazon Machine Image). I also configured the security groups (SG) before launching the EC2 instance.

	screenshot 1-image ec2 configuation
	screenshot 2-
Next step is to set up the security groups to open port 22 for ssh, 443 for the wazuh dashboard and other ports for wazuh server, wazuh agent, wazuh indexer and other services. All the ports recomended in wazuh documentation were configured. I set the source ip for the inbound rules to any ip (IPv4) because the ec2 instance would be terminated as soon as I am done with the project.

	screenshot 1-recommended ports 
	screenshot 2-opened ports

Next step is to ssh into the ubuntu server hosting the wazuh

```commandline
ssh -i wazuh.pem ubuntu@server_ip_address
```
After gaining entry into the ubuntu server using ssh, I ran the code below to download the wazuh installation script from their website and after a successful download, sudo is used to elevate the privileges to install the wazuh siem tool on the server. At the end of the installation, a username and password for the wazuh dashboard is provided.

```commandline
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh && sudo bash ./wazuh-install.sh -a
```
	screenshot of installation completion

Then click on the public IPv4 dns link on the ec2 creation page to access the dashboard and sign in with the credentials provided.

	screenshot 1-link to click
	screenshot 2-wazuh dashboard

Next is to install the wazuh agent on the two windows machine. On the wazuh dashboard which is without an agent to monitor as at set up completion, I clicked on the add agent link and followed the prompts to install the agents on my machines. 

	screenshot of agent installation set-up

The following code was then run on powershell as an administrator on both windows devices.

Windows 11

```commandline
Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.7.3-1.msi -OutFile ${env.tmp}\wazuh-agent; msiexec.exe /i ${env.tmp}\wazuh-agent /q WAZUH_MANAGER='54.83.89.64' WAZUH_AGENT_GROUP='default' WAZUH_AGENT_NAME='Windows11' WAZUH_REGISTRATION_SERVER='54.83.89.64'
```

Windows 10 Pro (vm)

```commandline
Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.7.3-1.msi -OutFile ${env.tmp}\wazuh-agent; msiexec.exe /i ${env.tmp}\wazuh-agent /q WAZUH_MANAGER='54.83.89.64' WAZUH_REGISTRATION_SERVER='54.83.89.64'
```
Kali Linux (vm)

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

I encountered some challenges installing the wazuh agent on my windows 11, even though the agent installed and report from the "NET START WazuhSvc" command shows that the wazuh service had started, it was still not reflecting on the wazuh dashboard. So in other to resolve this issue, I went to 
all apps on my windows start menu, navigated to the ossec-agent folder that contained the windows agent app, launched the app. On the app dialogue box, i clicked on the manage tab, clicked on start to start the service. I clicked on refresh, then save. The wazuh agent then started working and the endpoint could be monitored from the wazuh dashboard. I was able to use the wazuh report of security event to fix some security issues on my device.

	screenshot of wazuh agent

<h3 align="left"> Uninstalling Wazuh Agent on Windows</h3>

To stop the wazuh from monitoring the windows machine, the wazuh agent on the windows machine needs to be uninstalled. From the windows start menu in all apps, locate the ossec-agent folder. Click on the uninstall agent. Another way is to uninstall the wazuh agent app from settings i.e. Settings>>Apps>>Apps & features

	screenshot showing uninstall agent

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
	screenshots with label










