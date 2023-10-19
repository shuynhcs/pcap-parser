import argparse
import csv
import dpkt
from dpkt.ip import IP
from dpkt.ethernet import Ethernet
import socket
import datetime


tcp_flag_map = {dpkt.tcp.TH_SYN : 'SYN',
                dpkt.tcp.TH_ACK : 'ACK',
                dpkt.tcp.TH_FIN : 'FIN',
                dpkt.tcp.TH_PUSH : 'PSH',
                dpkt.tcp.TH_RST : 'RST',
                dpkt.tcp.TH_URG : 'URG',
                }

def dumpflow(flows, flow, package_data):

    # Check if ip & port tuple in flows
    if flows.get(flow): 
        flows[flow]['bytes'] += package_data['bytes']
        flows[flow]['IAT'] = package_data['ts'] - flows[flow]['ts'] 
        flows[flow]['duration'] += flows[flow]['IAT']
        flows[flow]['ts'] = package_data['ts']
        flows[flow]['packets'] += 1
        if flows[flow]['duration'] > 0:
            flows[flow]['bytes_s'] = flows[flow]['bytes']/flows[flow]['duration']
            flows[flow]['packets_s'] = flows[flow]['packets']/flows[flow]['duration']
        flows[flow]['avg_pkt_size'] = flows[flow]['bytes']/float(flows[flow]['packets'])
        for key in tcp_flag_map.values():
            flows[flow][key] += package_data[key]
        
    else:
        # Append new flow
        flows[flow] = package_data
    
    return tuple(flows[flow].values())

def main():

    parser = argparse.ArgumentParser()
    parser.add_argument("--file", "-f", help="Enter pcap file name to be parsed.")
    parser.add_argument("--csv", "-c", help="Enter csv file name to be written to.")
    args = parser.parse_args()

    try: 
        # Open pcap file to read
        p_open = open(args.file, 'rb')
        pcap = dpkt.pcap.Reader(p_open)
    except:
        print("Could not open file.")

    if args.csv:
        csv_file = args.csv
    else:
        csv_file = "data.csv"

    # Open csv file to write
    c_open = open(csv_file, 'w', newline='')
    c = csv.writer(c_open)

    # Write header row
    header = ('time_stamp', 'protocol', 'type_of_service', 'time_to_live',
                'src_ip', 'src_port', 'dst_ip', 'dst_port', 'pkt_bytes',
                'syn', 'ack', 'fin','psh', 'rst', 'urg',
                'syn_count', 'ack_count', 'fin_count','psh_count', 'rst_count', 'urg_count',
                'flow_bytes','duration','packets','IAT','avg_pkt_size','bytes_s','packets_s')
    c.writerow(header)
    
    # Create flow tuples & set of unique ips
    tcp_flows = {}
    other_flows = {}
    ips = set()

    for ts, buf in pcap: 
    
        # Unpack 802.11 frame here: buf -> eth

        # Unpack the Ethernet frame & fetch ip data
        eth = dpkt.ethernet.Ethernet(buf)
        if eth.type != dpkt.ethernet.ETH_TYPE_IP:
            continue
        ip = eth.data

        # Get TIME, LENGTH, PROTOCOL
        time_stamp = str(datetime.datetime.utcfromtimestamp(ts)) # Might need slicing
        pkt_bytes = len(eth)
        #protocol = ip.get_proto(ip.p).__name__
        protocol = ip.p

        # Get TOS, TTL
        type_of_service = ip.tos
        time_to_live = ip.ttl

        # Get SOURCE IP, SOURCE PORT, DESTINATION IP, DESTINATION PORT
        src_ip = socket.inet_ntoa(ip.src)
        src_port = ip.data.sport
        dst_ip = socket.inet_ntoa(ip.dst)
        dst_port = ip.data.dport

        # Update a set of unique source and destination ips
        ips.add(src_ip)
        ips.add(dst_ip)
        
        # Store ip & port tuple -> flow
        flow = sorted([(src_ip, src_port), (dst_ip, dst_port)])
        flow = (flow[0], flow[1])

        
        # Initialize a dictionary of flow data
        pkt_data = {}

        # Get PROTOCOL
        # If packet protocol is TCP
        if ip.p == dpkt.ip.IP_PROTO_TCP:
            flows = tcp_flows
            tcp = ip.data
            
            # Update flags
            for key in tcp_flag_map.keys():
                pkt_data[tcp_flag_map[key]] = 1 if (tcp.flags & key) else 0
            
            
        # If packet protocol is UDP    
        else:
            flows = other_flows

            # Update flags
            for key in tcp_flag_map.keys():
                pkt_data[tcp_flag_map[key]] = 0

        packet_flags = tuple(pkt_data.values())   

        # Update packet data
        pkt_data['bytes'] = pkt_bytes
        pkt_data['duration'] = 0
        pkt_data['packets'] = 1
        pkt_data['IAT'] = 0
        pkt_data['avg_pkt_size'] = pkt_bytes
        pkt_data['bytes_s'] = float('inf')
        pkt_data['packets_s'] = float('inf')
        pkt_data['ts'] = float(ts)
        
        metadata = (time_stamp, protocol, type_of_service, time_to_live,
                     src_ip, src_port, dst_ip, dst_port, pkt_bytes)
        flow_stats = dumpflow(flows, flow, pkt_data)
        
        data = metadata + packet_flags + flow_stats[:-1] # Exclude current timestamp
        c.writerow(data)

    # Close files
    c_open.close()
    p_open.close()

if __name__ == "__main__":
    main()
    

