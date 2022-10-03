import scapy.all as scapy
import threading

deauthpaquet = 0
def DetecteurDeauth(p) :
    if p.type==0 and p.subtype==12 :
        global deauthpaquet
        deauthpaquet += 1
        if deauthpaquet == 50 :
            print("Une attaque deauth à lieu veuiller surveiller votre reseau")
            return

def sniffer():
    print("Si une attaque deauth ce produit vous serez signalez")
    p = scapy.sniff(iface="wlan0mon", stop_filter = DetecteurDeauth)

