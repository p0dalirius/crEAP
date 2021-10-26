#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : crEAP.py
# crEAP is a utility which will identify WPA Enterprise Mode Encryption types and if
# insecure protocols are in use, crEAP will harvest Radius usernames and handshakes.
# Author: Snizz, Podalirius
#
# Requirements:  Should be run as root/sudo.
#
# Python Scapy Community (scapy-com) - Dev version of Scapy which supports additional
# filters such as EAP types.  Get @ https://bitbucket.org/secdev/scapy-com
#
# Airmon-ng, airodump-ng (Aircrack-ng Suite - http://www.aircrack-ng.org/)
#
# Screen for terminal managment/ease of launching airodump (requirement for
# Promiscuous/Channel hopping to capture the EAPOL packets)

import argparse
from scapy.layers.dot11 import Dot11
from scapy.layers.eap import eap_types, EAP
from scapy.all import *
import sys
import subprocess
import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

### Logger

class Logger(object):
    def __init__(self, debug=False, logfile=None, nocolors=False):
        super(Logger, self).__init__()
        self.__debug = debug
        self.__nocolors = nocolors
        self.logfile = logfile
        #
        if self.logfile is not None:
            if os.path.exists(self.logfile):
                k = 1
                while os.path.exists(self.logfile + (".%d" % k)):
                    k += 1
                self.logfile = self.logfile + (".%d" % k)
            open(self.logfile, "w").close()

    def print(self, message=""):
        nocolor_message = re.sub("\x1b[\[]([0-9;]+)m", "", message)
        if self.__nocolors:
            print(nocolor_message)
        else:
            print(message)
        if self.logfile is not None:
            f = open(self.logfile, "a")
            f.write(nocolor_message + "\n")
            f.close()

    def info(self, message):
        nocolor_message = re.sub("\x1b[\[]([0-9;]+)m", "", message)
        if self.__nocolors:
            print("[info] %s" % nocolor_message)
        else:
            print("[info] %s" % message)
        if self.logfile is not None:
            f = open(self.logfile, "a")
            f.write(nocolor_message + "\n")
            f.close()

    def debug(self, message):
        if self.__debug == True:
            nocolor_message = re.sub("\x1b[\[]([0-9;]+)m", "", message)
            if self.__nocolors:
                print("[debug] %s" % nocolor_message)
            else:
                print("[debug] %s" % message)
            if self.logfile is not None:
                f = open(self.logfile, "a")
                f.write("[debug] %s" % nocolor_message + "\n")
                f.close()

    def error(self, message):
        nocolor_message = re.sub("\x1b[\[]([0-9;]+)m", "", message)
        if self.__nocolors:
            print("[error] %s" % nocolor_message)
        else:
            print("[error] %s" % message)
        if self.logfile is not None:
            f = open(self.logfile, "a")
            f.write("[error] %s" % nocolor_message + "\n")
            f.close()

    def warning(self, message):
        nocolor_message = re.sub("\x1b[\[]([0-9;]+)m", "", message)
        if self.__nocolors:
            print("[warning] %s" % nocolor_message)
        else:
            print("[warning] %s" % message)
        if self.logfile is not None:
            f = open(self.logfile, "a")
            f.write("[warning] %s" % nocolor_message + "\n")
            f.close()

###

class crEAP(object):

    md5challenge = {}
    requser = {}
    user = {}
    userid = {}
    username = {}
    userlist = []
    checked = []
    bssids = {}

    def __init__(self, interface, channel, logger):
        super(crEAP, self).__init__()
        self.logger = logger
        self.interface = interface
        self.channel = channel

    def run(self):
        # Interface Foo
        try:
            self.logger.warning("Enabling monitor interface and channel ...")
            subprocess.Popen("airmon-ng check kill", shell=True, stdout=subprocess.PIPE).stdout.read()
            subprocess.Popen("airmon-ng start %s" % self.interface, shell=True, stdout=subprocess.PIPE).stdout.read()
            self.interface = self.interface + "mon"
        except Exception as e:
            self.logger.warning("Unable to enable MONITOR mode, exiting.\n")

        if int(self.channel) <= 14:
            try:
                subprocess.Popen(['screen -dmS crEAP'], shell=True, stdout=subprocess.PIPE).stdout.read()
                cmd = "stuff $" + "'sudo airodump-ng -c %s %s'" % (self.channel, self.interface)
                subprocess.Popen(['screen -r crEAP -X ' + cmd], shell=True, stdout=subprocess.PIPE).stdout.read()
                self.logger.warning("Listening in the 2.4GHZ spectrum.")
            except Exception as e:
                self.logger.warning("Unable to set promiscuous mode, exiting.\n")
        else:
            try:
                subprocess.Popen(['screen -dmS crEAP'], shell=True, stdout=subprocess.PIPE).stdout.read()
                cmd = "stuff $" + "'sudo airodump-ng --band a -c %s %s'" % (self.channel, self.interface)
                subprocess.Popen(['screen -r crEAP -X ' + cmd], shell=True, stdout=subprocess.PIPE).stdout.read()
                self.logger.warning("Listening in the 5GHZ spectrum.")
            except Exception as e:
                self.logger.warning("Unable to set promiscuous mode, exiting.\n")

        logger.info("Sniffing for EAPOL packets on %s channel %s ...  (Press Ctrl+C to exit)" % (options.interface, options.channel))
        conf.iface = options.interface
        sniff(iface=options.interface, prn=self.eapol_header)
        logger.info("self.user requested interrupt, cleaning up monitor interface and exiting ...")
        logger.info("Cleaning up interfaces ...")
        subprocess.Popen("screen -X -S crEAP kill", shell=True, stdout=subprocess.PIPE).stdout.read()
        subprocess.Popen("sudo airmon-ng stop " + self.interface, shell=True, stdout=subprocess.PIPE).stdout.read()

    def eapol_header(self, packet):
        for pkt in packet:
            self.get_bssid(pkt)
            try:
                if pkt.haslayer(EAP):
                    if pkt[EAP].type == 1:
                        # Identified an EAP authentication
                        self.userid = pkt[EAP].id
                        if pkt[EAP].code == 2:
                            self.user = pkt[EAP].identity
                    # EAP-MD5 - Credit to EAPMD5crack for logic assistance
                    if pkt[EAP].type == 4:
                        # Found EAP-MD5
                        EAPID = pkt[EAP].id
                        if pkt[EAP].code == 1:
                            self.md5challenge[EAPID] = pkt[EAP].load[1:17]
                            network = self.bssids[pkt.addr2]
                            self.logger.info("MD5 Authentication Detected")
                            self.logger.info("BSSID:         " + (network))
                            self.logger.info("Auth ID:       " + str(self.userid))
                            self.logger.info("self.user ID:  " + str(self.user))
                            self.logger.info("MD5 Challenge: " + self.md5challenge[EAPID].encode("hex"))
                            self.addtolist(self.user)
                        elif pkt[EAP].code == 2:
                            self.md5challenge[EAPID] = pkt[EAP].load[1:17]
                            self.logger.info("MD5 Response:  " + self.md5challenge[EAPID].encode("hex"))
                    # EAP-PEAP
                    elif pkt[EAP].type == 25:
                        # Found EAP-PEAP
                        if pkt[EAP].code == 2:
                            network = self.bssids[pkt.addr1]  # reverse as it is the destination mac (Client->Server Identify)
                            self.logger.info("EAP-PEAP Authentication Detected")
                            self.logger.info("BSSID:         " + (network))
                            self.logger.info("Auth ID:       " + str(self.userid))
                            self.logger.info("self.user ID:  " + str(self.user))
                            self.addtolist(self.user)
                    # EAP-TLS
                    elif pkt[EAP].type == 1:
                        # Found EAP-TLS Response Identity
                        if pkt[EAP].code == 1:
                            network = self.bssids[pkt.addr2]
                            self.user = str(self.user).strip("{}")
                            if len(self.user) != 0:
                                self.logger.info("EAP-TLS Response ID Detected")
                                self.logger.info("BSSID:        " + (network))
                                self.logger.info("Auth ID:      " + str(self.userid))
                                self.logger.info("self.user ID: " + str(self.user))
                                self.addtolist(self.user)
                    elif pkt[EAP].type == 13:
                        # Found EAP-TLS
                        if pkt[EAP].code == 2:
                            self.logger.info("EAP-TLS Authentication Detected")
            except Exception as e:
                raise e

    def get_bssid(self, pkt):
        newvalues = []
        if pkt.haslayer(Dot11):
            if pkt.type == 0 and pkt.subtype == 8:
                for item in self.bssids.values():
                    if pkt.info in item:
                        break
                    elif pkt.addr2 in item:
                        break
                    else:
                        newvalues.append({pkt.addr2: pkt.info})
        for nv in newvalues:
            self.bssids.update(nv)

    def addtolist(self, user):
        # if self.username not in UserList:
        self.userlist.append(user)
        checked = []
        for item in self.userlist:
            if item not in checked:
                checked.append(item)


banner = r"""
                          ___________   _____ ___________
                 __________\_   _____/  /  _  \______    \ 
               _/ ___\_  __ \    __)_   /  /_\  \|     ___/
               \  \___|  | \/       \ /  |   \  \    |
                \___  >__| /_______  /\____|__  /____|      v3.0
                    \/             \/         \/
    crEAP is a utility which will identify WPA Enterprise Mode Encryption types and
    if insecure protocols are in use, crEAP will harvest usernames and handshakes.
"""


def parseArgs():
    parser = argparse.ArgumentParser(description="Description message")
    parser.add_argument("--debug", dest="debug", action="store_true", default=False, help="Debug mode.")
    parser.add_argument("--no-colors", dest="no_colors", action="store_true", default=False, help="No colors mode.")
    parser.add_argument("-l", "--logfile", dest="logfile", type=str, default=None, help="Log file to save output to.")
    #
    parser.add_argument('-r', '--read', dest='pcap', required=False, help='[OPTIONAL] Read from PCAP file, else live capture is default.')
    parser.add_argument('-i', '--interface', dest='interface', required=False, help='[OPTIONAL] Wireless interface to capture.')
    parser.add_argument('-c', '--channel', dest='channel', required=False, help='[OPTIONAL] Wireless channel to monitor. 2.4/5GHZ spectrums supported so long as your adapter supports it. The ALFA AWUS051NHv2 is recommended for dual band support.')
    return parser.parse_args()


if __name__ == '__main__':
    options = parseArgs()
    logger = Logger(debug=options.debug, nocolors=options.no_colors, logfile=options.logfile)

    # Got root/sudo?
    if os.geteuid() != 0:
        logger.warning("Script not started as root. Try running 'sudo %s'" % (' '.join(sys.argv)))
        sys.exit(0)

    # Prerequisites checks:
    requirement = [['airmon-ng'], ['airodump-ng'], ['screen', '-v']]
    for r in requirement:
        try:
            subprocess.call(r, stdout=open("/dev/null", "w"))
        except OSError:
            logger.error("Missing %s dependency, exiting." % r)
            sys.exit(0)

    # Main and EAPOL-HEADER

    if options.pcap is not None:
        try:
            logger.warning("Searching for EAPOL packets from PCAP %s" % options.pcap)
            creapy = crEAP("dummy", 0, logger)
            creapy.eapol_header(rdpcap(options.pcap))
            logger.info("Unique Harvested Users:")
            print(creapy.checked)
            print("\n")
        except Exception as e:
            raise
    elif options.interface is not None and options.channel is not None:
        creapy = crEAP(options.interface, options.channel, logger)
        try:
            creapy.run()
            logger.info("Unique Harvested Users:")
            print(creapy.checked)
            print("\n")
        except Exception as e:
            raise
    else:
        print("Either --pcap or (--interface, --channel) are required.")
