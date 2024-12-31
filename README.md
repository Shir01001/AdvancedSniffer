# AdvancedSniffer
Sniffer capable of mainly on the fly analysis of http/https packets.  
Using different techniques to route victim's traffic to attacking machine.  
Working on linux systems.
## Installation
Clone respository  
```git clone https://github.com/Shir01001/AdvancedSniffer.git```  
Download and extract necessary binaries  
```./install.sh```

Iptables are needed on system  
```pip install -r requirements.txt```  

    sudo apt install iptables

On externally managed systems:  
```sudo apt install iptables python-pyshark python-argparse python-pyscapy python-colorama```

On victim machine:
Certificates on mitm.it website  
```certutil -addstore root mitmproxy-ca-cert.pem```

## Usage
  
Terminal usage:
```sudo python3 main.py --interface interface```  
Gui usage:
```sudo python3 main.py -g 1```


Arguments:  
-i --interface sets interface to use (default is wlan0)  
-m --mac-address sets target mac address for arp poisoning  
-t --target_ip sets ip address of target for arp poisoning  
-r --router_ip sets ip address for network's gateway  
-v --verbosity adds information to output for debug purposes
-g --gui when set to 1 enables graphical interface

    mitmdump --listen-host local_ip --listen-port 8080 --flow-detail 4 '~bq pass'

## Core functionalities
1. Arp poisoning
2. Http server for phishing and serving wpad file
3. Sniffer for http requests
4. Dns spoofing
5. Automatically routing requests through proxy server

## Attack chain for https
1. Social engineering for adding certificate to victim's system.
2. Arp poisoning victim's system.
3. Dns spoofing request for wpad file.
4. Serving wpad file for automatic detection of proxies.
5. Routing all of traffic 

## Common Issues
1. Arp problems, check if listening on right interface (default interface is wlan0)
2. DNS problems, check if given network gateway is correct, if custom dns server is running in network you might have bad luck
3. Serving wpad file problems, check if victim's system has automatic proxy detection enabled (should be on by default)

## Verbosity Levels
0 No messages  
1 Basic messages  
2 All messages, warnings from libraries, basic summaries of intercepted/sniffed packets

## Resources used
Extremely helpful video on which this project's attack chain is based:  
https://www.youtube.com/watch?v=Oi_kQE1zyPs  
Thanks for it to:  
https://www.youtube.com/@hacktheclown

For gui using tkinter with Forest-ttk-theme:  
https://github.com/rdbende/Forest-ttk-theme
## Sources for images
http server basic templates
Representation of arp attack:  
https://www.geeksforgeeks.org/what-is-arp-spoofing-arp-poisoning-attack/  
Representation of dns hijacking:  
https://www.riskcrew.com/wp-content/uploads/2021/01/DNS-Hyjacking.jpg

## Disclaimer
This software is to be used only for educational purposes.

