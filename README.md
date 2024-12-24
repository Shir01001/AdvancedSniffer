# AdvancedSniffer
Sniffer capable of mainly on the fly analysis of packets.
Additional functions: arp poisoning, dns poisoning, built-in http server for phishing
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

# Core functionalities
1. Arp poisoning
2. Http server for phishing
3. Sniffer for http requests
4. Dns spoofing

# Sources
http server basic templates
Representation of arp attack:
https://www.geeksforgeeks.org/what-is-arp-spoofing-arp-poisoning-attack/
Representation of dns hijacking https://www.riskcrew.com/wp-content/uploads/2021/01/DNS-Hyjacking.jpg


# Disclaimer
This software is to be used only for educational purposes.

