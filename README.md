Stealth Port Scan using TCP/SYN method.

```bash
# install
# also you can use pip
pipx install stealth-port-scan

# usage
stealth-port-scan -h

# requires sudo to send raw packets
# you can specify hostname, ip adress, ip range or cidr
sudo stealth-port-scan -a www.linux.org.ru

# if you have problems with secure_path
# sudo: stealth-port-scan: command not found
sudo env "PATH=$PATH" stealth-port-scan ...

sudo $(which stealth-port-scan) ...

# or just clone repo and run
sudo ./stealth_port_scan.py ...
```
