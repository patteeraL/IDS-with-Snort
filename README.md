# IDS with Snort

## Overview

This repository focuses on configuring and utilizing the Snort Intrusion Detection System (IDS) to monitor and detect network activity. The objective is to practice setting up Snort, writing custom rules, and using Metasploit to simulate reconnaissance and attack attempts.

The VirtualBox appliance from [Firewall Config Lab](https://github.com/patteeraL/Firewall-Config-Lab.git) will be reused. Ensure all VMs are restarted to reset iptables configurations. 

## Tools Used

`Snort` : Open-source IDS/IPS for monitoring and detecting network threats.

`Metasploit Framework` : A penetration testing tool used for ethical hacking and security assessments.

`Wireshark` : A packet analyzer for monitoring network traffic.

## Lab Environment

`Server A` : Running Snort to detect attacks (IP: 192.168.70.5).

`Server B` : Running Metasploit to simulate attacks (IP: 192.168.70.6).

`Network` : 192.168.70.0/24.

`Client A & Client B` : Should remain powered off to avoid interference.

Ensure that both servers have promiscuous mode set to Allow All in VirtualBox.

## Tasks

### 0. Set up
Install the Metasploit Framework edition (free) on Server B.

Enter the command: 
```
msfconsole
```
to start the Metasploit console. If you are asked if you like to use and setup a new database, then answer “yes”.

During the installation of Snort, it automatically detects the network interfaces and configures them for use with Snort.

To verify that Snort is installed successfully, run the following command to check Snort's version:
```
snort --version
```
### 1. Check Connectivity

Start Wireshark on Server A and capture packets from interface 192.168.70.5.

From Server B, run a ping command:

```
ping 192.168.70.5
```

Verify that ICMP echo and reply packets appear in Wireshark. If not, diagnose connectivity issues.

### 2. Detect Incoming Pings with Snort

Install Snort on Server A:

```
sudo apt install snort
```

Configure Snort to listen on interface (check with ip a).

Set the local network range as `192.168.70.0/24`.

Edit the Snort configuration file `/etc/snort/snort.conf`:

Comment out the line:
```
# include $RULE_PATH/icmp-info.rules
```
Add the following rule to `/etc/snort/rules/local.rules` :

```
alert icmp 192.168.70.6 any -> 192.168.70.5 any (msg:"ICMP message detected"; sid:2000001;)
```

Start Snort:

```
sudo snort -i (your-interface) -A console -c /etc/snort/snort.conf
```

Ping from Server B:

```
ping 192.168.70.5
```

Verify that Snort alerts appear in the console.

### 3. Detect TCP Port Scanning

Install Metasploit on Server B:

```
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && chmod 755 msfinstall && ./msfinstall
```

Start Metasploit:

```
sudo msfconsole
```

Select the SYN port scanning module:

```
use auxiliary/scanner/portscan/syn
```

Configure target and scanning parameters:

```
set RHOSTS 192.168.70.5
set INTERFACE your-interface
set PORTS 1-500
```
Start Wireshark on Server A to capture the scanning traffic. 

Open `Edit>Preferences>Protocols>TCP` . Uncheck the Relative sequence numbers option to make Wireshark display the actual sequence numbers.

Run the scan:

```
run
```

Identify open ports and analyze TCP handshake differences in Wireshark. We should be able to see in Wireshark pairs of TCP packets – a SYN request from Server B to Server A and a reply (typically RST/ACK) going in the opposite direction.

After scanning is completed, Metaploit will show the list of all open ports in the range entered.

These are ports used by an application or service that awaits incoming connections. We can see which open ports we have found on Server A and to what services they belong using:
```
cat /etc/services | grep 22
cat /etc/services | grep 80
cat /etc/services | grep 443
```

The TCP header in the traffic captured with Wireshark on Server A by running 
```
telnet 192.168.70.5
```
to connect to a closed port (default port 23) and capture the packets on Server B.

Next, test the open ports on Server A. If, for example, port 22 (SSH) is open, run:
```
telnet 192.168.70.5 22
```

The main difference between Telnet and scanning packets is that Telnet completes the full TCP handshake (`SYN`, `SYN-ACK`, `ACK`) and involves data exchange. In contrast, port scanning sends `SYN` packets and receives `SYN-ACK` or `RST-ACK` responses without completing the handshake or exchanging data. 

Scanning packets typically show pairs of `SYN` and `RST-ACK` for closed ports, or `SYN-ACK` for open ports, unlike the full handshake in `Telnet`.

Verify the pattern holds by running the ssh command:
```
ssh 192.168.70.5
```

### 4. Detect Possible port scan - SYN packet

Write a Snort rule to detect `Possible port scan - SYN packets` by adding to `/etc/snort/rules/local.rules` :

```
alert tcp 192.168.70.6 any -> 192.168.70.5 1:1023 (msg:"Possible port scan - SYN packets"; flags:S; threshold: type both, track by_src, count 10, seconds 5; classtype:attempted-recon; sid:100001; rev:1;)
```

Run a Port Scan (Using Metasploit)
```
sudo msfconsole
use auxiliary/scanner/portscan/tcp
set RHOSTS 192.168.70.5
set PORTS 1-1023
```
The command `run` on Server B and see matching alerts from snort on Server A using command: 
```
sudo snort -i (your-interface) -A console -c /etc/snort/snort.conf
```
Run the SSH command on Server B:
```
ssh 192.168.70.5
```
and see matching alerts from snort on Server A using command:
```
sudo snort -i (your-interface) -A console -c /etc/snort/snort.conf
```
This rule effectively detects port scanning by monitoring rapid bursts of `SYN` packets sent to multiple ports, a common pattern in scanning activities that do not complete the `TCP` handshake. In contrast, benign traffic like `SSH` or `Telnet` typically completes the handshake and limits `SYN` packets to a single port. The threshold condition further ensures that routine connection attempts do not trigger false alerts.

### 5. Detect DoS attack
Select the auxiliary/dos/tcp/synflood module in Metasploit using command:
```
use auxiliary/dos/tcp/synflood
```
From Server B, we will configure the module to attack Server A (192.168.70.5) over the interface.

Set Module Parameters:
```
set RHOSTS 192.168.70.5
set INTERFACE your-interface
set PORTS 80
set FLOODTIME 30
```
Open Wireshark and command `run` on the `msf6`
Use Wireshark to study the malicious traffic and identify patterns that can be detected with snort.

We can see the high volume of `SYN` requests without completion of the `TCP` handshake. 

Create a snort rule to detect high-frequency `SYN` packets:
```
alert tcp any any -> 192.168.70.5 80 (msg:"SYN flood detected"; flags:S; threshold:type both, track by_src, count 20, seconds 5; classtype:attempted-dos; sid:100002; rev:1;)
```
To verify the Snort Rule Detects Port Scanning, we use the command `run` on Server B and see matching alerts from snort on Server A using command: 
```
sudo snort -i (your-interface) -A console -c /etc/snort/snort.conf
```
After running the scan, the SYN flood was detected.

Run the `SSH` command on Server B:
```
ssh 192.168.70.5
```
and see matching alerts from snort on Server A using command:
```
sudo snort -i enp0s7 -A console -c /etc/snort/snort.conf
```
it not show any alerts when running SSH.

### 6. Detect incoming rogue SSH connections
Select the `auxiliary/scanner/ssh/ssh_login` module in Metasploit

Create a File with Login Names and Passwords (given in this repository: `account.txt`)

Set the `USERPASS_FILE` variable to the complete path of the file `accounts.txt` and others Module Parameters:
```
set USERPASS_FILE accounts.txt
set RHOSTS 192.168.70.5
set RPORTS 22
```
Run and Monitor the traffic in WireShark
```
run
```
We should see the `SSH` handshake traffic between the attacker (Metasploit) and Server A. 

Compare Malicious Traffic to Benign`SSH` Traffic
```
ssh yourusername@192.168.70.5
```

The initial handshake appears the `SSH` version string:

"SSH-2.0-OpenSSH_7.6p1" (malicious traffic) 
"SSH-2.0-OpenSSH_8.9p1" (benign traffic)

By identifying these patterns, we can distinguish between normal and rogue `SSH` traffic. Create a snort rule to detect Rogue `SSH` Connection - Malicious Version:
```
alert tcp 192.168.70.6 any -> 192.168.70.5 22 (msg:"Rogue SSH Connection - Malicious Version";
content:"SSH-2.0-OpenSSH_7.6p1"; sid:1000005; rev:1;)
```
To verify the Snort Rule Detects Port Scanning, we will use the command `run` on Server B and see matching alerts from snort on Server A using command: 
```
sudo snort -i enp0s7 -A console -c /etc/snort/snort.conf
```

Then, we now verify the Snort Rule Does Not Generate Alerts for Benign Traffic by running the SSH command on Server B:
```
ssh yourusername@192.168.70.5
```
and see matching alerts from snort on Server A using command:
```
sudo snort -i enp0s7 -A console -c /etc/snort/snort.conf
```
And, it will not show any alerts when running SSH.

### Additional Resources

[Snort Documentation](https://www.snort.org/#documents)

[Metasploit Unleashed](https://www.offsec.com/metasploit-unleashed/)

[Wireshark User Guide](https://www.wireshark.org/docs/wsug_html_chunked/)

#### In this project, I will provide you only the following:

- `snort.conf`: The main Snort configuration file.
- `local.rules`: Custom Snort rules created for the lab.
- `account.txt`: A file for the last implementation.

Good Luck!
