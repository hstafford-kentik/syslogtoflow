#!/usr/bin/python3

import argparse
import datetime
import signal
import time
import json
import ipaddress
import re
import scapy
from scapy.all import *
import socketserver
import threading
import queue

signal_received = 0

flowqueue = queue.Queue()

if os.getuid() != 0:
        print ("You need to be root to run this, sorry.")
        exit()

parser = argparse.ArgumentParser(description='UDP packets producer with scapy')
parser.add_argument('-c', '--config_file', dest='config_file',
                                        help='Configuration file path')


args = parser.parse_args()

if args.config_file:
        config_file = args.config_file
else:
        config_file = "./log2flow.conf"

configfile = open(config_file, 'r')
config = ''
for line in configfile:
        config += re.sub("\#+.*\n", "\n", line)   ## remove comments before trying to parse json.
config = json.loads(config)
print(json.dumps(config, indent=2))


def clamp(value,max,min):
        if value > max:
                return max
        elif value < min:
                return min
        else:
                return value





class MyUDPRequestHandler(socketserver.DatagramRequestHandler):
        def handle(self):
                global samplecount
                # Receive and print the datagram received from client
                #print("Recieved one request from {}".format(self.client_address[0]))
                datagram = self.rfile.readline().strip()
                #print("Datagram Recieved from client is:".format(datagram))
                #print(datagram)
                logline = str(datagram, 'UTF-8')
                #print (logline)
                for searchTerm in config['inputs']:
                        if searchTerm['search'] in logline:
                                samplecount += 1
                                if samplecount == int(searchTerm['sampling']):
                                        samplecount = 0
                                        flowqueue.put(logline)
                                        flowqueue.join()



# tnow = time.time()
# pkt = IP(src=config['global']['srcFlowIP'],dst=config['global']['destFlowIP'])/UDP(dport=config['global']['destFlowPort'])/NetflowHeader(version=5)/NetflowHeaderV5(unixSecs=tnow)
# flowcount = 0
samplecount = 0

def flowsender():
        lastsent = time.time()
        logtime = time.time()
        tnow = time.time()
        pkt = IP(src=config['global']['srcFlowIP'],dst=config['global']['destFlowIP'])/UDP(dport=config['global']['destFlowPort'])/NetflowHeader(version=5)/NetflowHeaderV5(unixSecs=tnow)
        flowcount = 0
        samplecount = 0
        while True:
                tnow = time.time()
                if tnow - logtime > 30:
                        logtime = tnow
                        print ('Processed '+str(flowcount)+' flows so far.')
                if flowqueue.qsize() >= int(config['global']['maxFlowsPerPacket']) or tnow - lastsent > int(config['global']['maxTimeBetweenSending']):
                        lastsent = tnow
                        logqueue = []
                        for n in range(0,int(config['global']['maxFlowsPerPacket'])):
                                if flowqueue.empty() != True:
                                        item = flowqueue.get()  # block and wait for items
                                        #print(n,item)
                                        logqueue.append(item)
                                        flowqueue.task_done()
                        flowData = {}
                        for logline in logqueue:
                                #print ('foo')
                                for searchTerm in config['inputs']:
                                        if searchTerm['search'] in logline:
                                                samplecount += 1
                                                if samplecount == int(searchTerm['sampling']):
                                                        samplecount = 0
                                                        #flowqueue.put(logline)
                                                        #flowqueue.join()
                                                        for key in searchTerm['overrides'].keys():
                                                                flowData[key]=searchTerm['overrides'][key]
                                                        for key in searchTerm['field_map']:
                                                                if key not in flowData.keys():
                                                                        found = re.findall(searchTerm['field_map'][key],logline)
                                                                        if len(found) > 0:
                                                                                flowData[key] = found[0]
                                                                        else:
                                                                                flowData[key] = searchTerm['defaults'][key]
                                                                if key in searchTerm['transformations'].keys():
                                                                        if flowData[key] in searchTerm['transformations'][key].keys():
                                                                                flowData[key]=searchTerm['transformations'][key][flowData[key]]
                                                        #print (flowcount,flowData)
                                                        netflow = NetflowRecordV5(src=flowData['source_ip'],dst=flowData['destination_ip'],nexthop="0.0.0.0",\
                                                        input=int(flowData['source_interface']),output=int(flowData['destination_interface']),\
                                                        dpkts=int(flowData['packets']),dOctets=int(flowData['octets']),\
                                                        first=100,last=300,srcport=int(flowData['source_port']),\
                                                        dstport=int(flowData['destination_port']),pad1=0,tcpFlags=0x00,\
                                                        prot=int(flowData['protocol']),tos=0x00,src_as=0,dst_as=0,\
                                                        src_mask=0,dst_mask=0,pad2=0)
                                                        #print(int(packets),int(octets))
                                                        #flowPacket = NetflowHeader(version=5)/NetflowHeaderV5(count=1,unixSecs=tnow)/netflow
                                                        pkt/=netflow
                                                        flowcount += 1
                        ## Now send the packet
                        send(pkt,verbose=0)
                        #print ('Sent '+str(flowcount)+' flows.')
                        #lastsent = tnow
                        pkt = IP(src=config['global']['srcFlowIP'],dst=config['global']['destFlowIP'])/UDP(dport=config['global']['destFlowPort'])/NetflowHeader(version=5)/NetflowHeaderV5(unixSecs=tnow)


# Turn-on the worker thread.
threading.Thread(target=flowsender, daemon=True).start()

# Create a Server Instance
UDPServerObject = socketserver.ThreadingUDPServer(("192.168.2.13", 5050), MyUDPRequestHandler)

# Make the server wait forever serving connections
UDPServerObject.allow_reuse_address=True
UDPServerObject.serve_forever()

exit()
