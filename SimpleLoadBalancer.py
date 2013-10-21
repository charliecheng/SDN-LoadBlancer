from pox.core import core
from pox.openflow import *
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.arp import arp
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.ethernet import ethernet
from pox.lib.addresses import EthAddr, IPAddr
log = core.getLogger()
import time
import random


class Entry (object):
    """
    Similar to the one in l3learning.py
    Use IP address to match port and MAC address
    """
    def __init__(self, port, mac):
        self.port = port #inport
        self.mac = mac
    

class SimpleLoadBalancer(object):
    def __init__(self, service_ip, server_ips = []): #initialize
        core.openflow.addListeners(self)
        #write your code here!!!
        self.service_ip=service_ip
        self.server_ips=server_ips
        print "The service_ip is: "+ str(service_ip)+'\n'
        print "The serer_ips are:"+'\n'
        for i in server_ips:
            print str(i)+'\n'
        self.arpTable={} #arpTable dictionanry
        self.mapping={}  #mapping table


    def _handle_ConnectionUp(self, event): #new switch connection
        self.lb_mac = EthAddr("0A:00:00:00:00:01") #fake mac of load balancer
        self.connection = event.connection
        #write your code here!!!
        ##Send initial ARP request to the servers
        for i in self.server_ips:
            r = arp()
            r.hwtype=1
            r.prototype=0x0800
            r.hwlen=6
            r.opcode = arp.REQUEST
            r.hwsrc = self.lb_mac
            r.protosrc=self.service_ip
            r.protodst=i
            r.hwdst = EthAddr("00:00:00:00:00:00")
           # print "APR Message:  "+ str(r)
            e = ethernet(type=0x0806,src=self.lb_mac,dst=EthAddr("FF:FF:FF:FF:FF:FF"))
            e.set_payload(r)
           # print "Ethernet Frame: "+ str(e)
            #"""
            msg = of.ofp_packet_out()
            msg.data=e.pack()
            msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
            msg.in_port=of.OFPP_NONE
            self.connection.send(msg)
            #print "Send the inital ARP request to the server of "+str(i)+" !!"
       # """

    def update_lb_mapping(self, client_ip): #update load balancing mapping
        #write your code here!!!
        #This function will be called only when there is no matching flows for the client_ip
        #Thus we need to clear the previous record of the client that is time out and creat the new mapping record
        if client_ip in self.mapping.keys():
            del self.mapping[client_ip]
        self.mapping[client_ip]=random.choice(self.server_ips)
        return


    def send_proxied_arp_reply(self, packet, connection, outport, requested_mac):
        #write your code here!!!
        r = arp()
        r.hwtype=1
        r.prototype=0x0800
        r.hwlen=6
        r.opcode = arp.REPLY
        r.hwsrc = self.lb_mac
        r.protodst=packet.payload.protosrc
        r.hwdst=packet.src
        if packet.payload.protosrc in self.server_ips: # ARP reply to server, set the source ip in ARP to the original client ip
            r.protosrc=packet.payload.protodst
        elif packet.payload.protodst == self.service_ip: #ARP reply to client, set the source ip in ARP to the fake service address
            r.protosrc=self.service_ip
        e = ethernet(type=0x0806,src=self.lb_mac,dst=packet.src)
        e.set_payload(r)
        msg=of.ofp_packet_out()
        msg.data=e.pack()
        msg.actions.append(of.ofp_action_output(port=outport))
        connection.send(msg)
        return


    def install_flow_rule_client_to_server(self, connection, outport, client_ip,
            server_ip, buffer_id=of.NO_BUFFER):
        #write your code here!!!
        inport=self.arpTable[client_ip].port #client inport at the switch
        #Match rules: All the client IP packets to the server port, expiring idle time 10s
        mymatch=of.ofp_match(in_port=inport,dl_type=0x800)
        msg=of.ofp_flow_mod()
        msg.match=mymatch
        msg.idle_timeout=10
        msg.actions.append(of.ofp_action_dl_addr.set_src(self.lb_mac))
        msg.actions.append(of.ofp_action_dl_addr.set_dst(self.arpTable[server_ip].mac))
        msg.actions.append(of.ofp_action_nw_addr.set_dst(server_ip))
        msg.actions.append(of.ofp_action_output(port =outport))
        msg.buffer_id=buffer_id
        connection.send(msg)
        print "Add a temp flow from client to server"
        print str(client_ip)+" to "+str(server_ip)
        return

    def install_flow_rule_server_to_client(self, connection, outport, server_ip,
            client_ip, buffer_id=of.NO_BUFFER):
        #write your code here!!!
        inport=self.arpTable[server_ip].port
        #Match rule: All the ip packets from the server port that going to client_ip go to the port where the client_ip connected
        mymatch=of.ofp_match(in_port=inport,dl_type=0x800,nw_dst=client_ip)
        msg=of.ofp_flow_mod()
        msg.match=mymatch
        msg.actions.append(of.ofp_action_dl_addr.set_dst(self.arpTable[client_ip].mac))
        msg.actions.append(of.ofp_action_dl_addr.set_src(self.lb_mac))
        msg.actions.append(of.ofp_action_nw_addr.set_src(self.service_ip))
        msg.actions.append(of.ofp_action_output(port=outport))
        msg.buffer_id=buffer_id
        connection.send(msg)
        print "Add a permanent flow from server to client"
        print str(server_ip)+" to "+str(client_ip)
        return
        

    def _handle_PacketIn(self, event):
        packet = event.parsed
        connection = event.connection
        inport = event.port
       # print str(packet.type)
        if packet.type == packet.ARP_TYPE:
            if packet.payload.opcode == arp.REPLY:
                # Save the server ip-mac-port to the table
               # print "Here comes an ARP reply packet\nfrom IP:"+str(packet.payload.protosrc)+"\nwith MAC address of "+str(packet.src)+"\nfrom the port:"+str(inport)
                if packet.payload.protosrc in self.arpTable.keys():
                    return
                else:
                    newEntry=Entry(inport,packet.src)
                    self.arpTable[packet.payload.protosrc]=newEntry
                    print "\nNew Entry added to the arp table: "
                    print "IP: "+str(packet.payload.protosrc)+" Mac: "+str(packet.src)+" Port: "+str(inport)
            if packet.payload.opcode == arp.REQUEST:
                if packet.payload.protodst == self.service_ip: #If it is an ARP request from clients, first save the client ip-mac-port to the table
                    if not packet.payload.protosrc in self.arpTable.keys():
                        newEntry=Entry(inport,packet.src)
                        self.arpTable[packet.payload.protosrc]=newEntry
                        print "\nNew Entry added to the arp table: "
                        print "IP: "+str(packet.payload.protosrc)+" Mac: "+str(packet.src)+" Port: "+str(inport)
                self.send_proxied_arp_reply(packet,connection,inport,self.lb_mac)
               # send_proxied_arp_reply(self, packet, connection, outport, requested_mac):
                return
                    

            
        elif packet.type == packet.IP_TYPE:
            #write your code here!!!
            ip_packet=packet.payload
            if ip_packet.srcip in self.server_ips: #ip packet from server,install the server-to-client rule and resend the packet
                print "IP packet from server"
                outport=self.arpTable[ip_packet.dstip].port
                self.install_flow_rule_server_to_client(connection, outport, ip_packet.srcip,ip_packet.dstip, buffer_id=event.ofp.buffer_id)
            else: #ip packet from client, install the client-to-server rull and resend the packet
                print "IP packet from client" 
                self.update_lb_mapping(ip_packet.srcip)
                tempserverip=self.mapping[ip_packet.srcip]
                outport=self.arpTable[tempserverip].port
                self.install_flow_rule_client_to_server(connection, outport, ip_packet.srcip,tempserverip, buffer_id=event.ofp.buffer_id)
        else:
           # log.info("Unknown Packet type: %s" % packet.type)
            return
        return

   #launch application with following arguments:
   #ip: public service ip, servers: ip addresses of servers (in string format) 
def launch(ip, servers):
    log.info("Loading Simple Load Balancer module")
    server_ips = servers.replace(","," ").split()
    server_ips = [IPAddr(x) for x in server_ips]
    service_ip = IPAddr(ip)
    core.registerNew(SimpleLoadBalancer, service_ip, server_ips)
