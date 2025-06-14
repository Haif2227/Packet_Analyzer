# Packet_Analyzer

The simple Packet Analyzer that should capture the packets and refhrase it from the current running interface (eg:eth0) and also save the capture file as (.pcap) format and It should Analyze the raw packet and display in the readable fromat

## 🚀 Quick Setup
This will automatically download the necessary package.

```bash
git clone https://github.com/Haif2227/Packet_Analyzer.git
cd Packet_Analyzer
chmod +x install.sh
./install.sh
```

## 🚀 Run the Packet Analyzer to capture the live packet

Once installed, start sniffing packets with:

```bash
sudo python3 packet_analyzer.py -i eth0
```
1) sudo = run in the super user mode 
2) python3 = version of python 
3) packet_analyzer.py = name of the file that should contain the code
4) -i = interface like (wlan0,eth0)

## Usage

| Option | Description                      |
| ------ | -------------------------------- |
| `-i`   | Interface to sniff (e.g., wlan0) |
| `-c`   | Number of packets to capture     |
| `-f`   | BPF Filter (e.g., `tcp`, `udp`)  |

   
###  Replace eth0 with your network interface. To find available interfaces:
```bash
ip a
```
Output(eg):
```bash
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host noprefixroute 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 08:00:27:xx:xx:xx brd ff:ff:ff:ff:ff:ff
    inet 10.0.x.x/24 brd 10.0.x.x scope global dynamic noprefixroute eth0
       valid_lft 77757sec preferred_lft 77757sec
    inet6 xxxx:xx:94f3:abcd:xxxx:abcd/64 scope link noprefixroute 
       valid_lft forever preferred_lft forever
3: docker0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state DOWN group default 
    link/ether xx:42:xx:xx:xx:xx brd ff:ff:ff:ff:ff:ff
    inet 172.xx.x.x/16 brd 172.xx.255.255 scope global docker0
       valid_lft forever preferred_lft forever
```


### To quit the packet_sniffer use CTRL+C that should save the capture pcap file in the (capture/capture.pcap) automatically

## 🚀 Run the Packet Analyzer to analyze the capture pcap file 

```bash
sudo python3 analyzer.py -r capture/capture.pcap
```
-r = read the capture file












