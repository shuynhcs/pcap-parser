# pcap-parser

## Description
Extract TCP and UDP packet metadata from a PCAP file into csv using DPKT.

## Specifications
Metadata are captured based on traffic flows identified by source and destination IP adresses and port numbers. Fields captured or calculated are:
1. Timestamp
2. Protocol
3. Type of service
4. Time to live (TTL)
5. Source IP
6. Source Port
7. Destination IP
8. Destination Port
9. TCP flags
10. Total bytes
11. Duration
12. Total number of packets
13. Inter-arrival Time (IAT)
14. Average packet size
15. Average bytes per second
17. Average packets per second

## Usage:
The default csv file name is `data.csv` if path not specified.  

`[python/python3] pcap-parser.py -f <pcap file path> -c <csv file path>`
