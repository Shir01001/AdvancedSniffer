# AdvancedSniffer
Sniffer capable of mainly on the fly analysis of http/https packets.  
Using different techniques to route victim's traffic to attacking machine.
# Installation
Iptables are needed on system  
```pip install -r requirements.txt```

# Usage
  
Run as administrator:
```python3 main.py --interface interface```

Arguments:  
-i --interface sets interface to use (default is wlan0)  
-m --mac-address sets target mac address for arp poisoning  
-a --address sets ip address of target for arp poisoning  
-v --verbosity adds information to output for debug purposes

    mitmdump --listen-host local_ip --listen-port 8080 --flow-detail 4 '~bq pass'

# Core functionalities
1. Arp poisoning
2. Http server for phishing and serving wpad file
3. Sniffer for http requests
4. Dns spoofing
5. Automatically routing requests through proxy server

# Attack chain for https
1. Social engineering for adding certificate to victim's system.
2. Arp poisoning victim's system.
3. Dns spoofing request for wpad file.
4. Serving wpad file for automatic detection of proxies.
5. Routing all of traffic 


# Common Issues
1. Arp problems, check if listening on right interface (default interface is wlan0)
2. DNS problems, check if given network gateway is correct, if custom dns server is running in network you might have bad luck
3. Serving wpad file problems, check if victim's system has automatic proxy detection enabled (should be on by default)

# Verbosity Levels
0 No messages  
1 Basic messages  
2 All messages, warnings from libraries, basic summaries of intercepted/sniffed packets

# Resources used
Extremely helpful video on which this project's attack chain is based: https://www.youtube.com/watch?v=Oi_kQE1zyPs  
Thanks for it to: https://www.youtube.com/@hacktheclown
# Sources for images
http server basic templates
Representation of arp attack:
https://www.geeksforgeeks.org/what-is-arp-spoofing-arp-poisoning-attack/
Representation of dns hijacking https://www.riskcrew.com/wp-content/uploads/2021/01/DNS-Hyjacking.jpg


# Disclaimer
This software is to be used only for educational purposes.

