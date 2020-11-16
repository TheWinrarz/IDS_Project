from scapy.all import *
import datetime

packet_ips = []
rules = []

def load_rules(filename):
    f = open(filename, "r")
    for rule in f.readlines():
        rule = rule.rstrip('\n')
        if (len(rule) > 0):
            if (rule[0] != "#"):
                rule = rule.split(',')
                rule[0] = rule[0].strip()
                rule[1] = rule[1].strip()
                rule[2] = rule[2].strip()
                rule[3] = rule[3].strip()
                rules.append((rule[0], rule[1], rule[2], rule[3]))
    f.close()

def alert(alert_string):
    print("Suspicious packet detected")
    log = open("incident_log", "a+")
    log.write(alert_string)
    log.close()

def check(s_ip, d_ip, s_port, d_port):
    suspicious = False
    for rule in rules:
        #SOURCE IP
        if rule[0] == "*" or rule[0] == s_ip:
	    #SOURCE PORT
            if rule[1] == "*" or rule[1] == s_port or s_port is not None:
	        #DESTINATION IP
                if rule[2] == "*" or rule[2] == d_ip:
		    #DESTINATION IP
                    if rule[3] == "*" or rule[3] == d_port or d_port is not None:
                        suspicious = True
    return suspicious

def consider(packet):
    src_ip = packet[0][1].src
    dst_ip = packet[0][1].dst
    try:
        s_port = packet.sport
    except AttributeError:
        s_port = "ICMP"
    try:
        d_port = packet.dport
    except AttributeError:
        d_port = "ICMP"
    string = "===============sniffer.py==============\n"
    string = string + "Time: " + str(datetime.datetime.now()) + "\n"
    string = string + "Source IP: " + src_ip + " - Source Port: " + str(s_port) + "\n"
    string = string + "Destination IP: " + dst_ip + " - Destination Port: " + str(d_port) + "\n"
    if (check(src_ip, dst_ip, str(s_port), str(d_port))):
        alert(string)






load_rules("ids_rules")
try:
    sniff(filter="ip", prn=consider)
except KeyboardInterrupt:
    print("Goodbye")
