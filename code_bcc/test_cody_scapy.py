from scapy.all import *
import struct

# Indirizzo del server (dove gira il codice eBPF)
server_ip = "172.20.10.5"  # Cambia con l'indirizzo del server
server_port = 80  # Cambia con la porta appropriata
client_port = RandShort()  # Porta casuale del client

# Invia il pacchetto SYN al server
syn_packet = IP(dst=server_ip) / TCP(sport=client_port, dport=server_port, flags="S", seq=100)
syn_ack_packet = sr1(syn_packet)

# Estrarre il SYN cookie (32 bit inferiori del campo seq) dal pacchetto SYN-ACK
cookie_and_mss = syn_ack_packet.seq
syn_cookie = cookie_and_mss & 0xFFFFFFFF  # Prendi solo i 32 bit inferiori

# Incrementa di 1 il numero di sequenza per l'ACK
ack_number = syn_ack_packet.ack

# Invia il pacchetto ACK con il SYN cookie come numero di sequenza
ack_packet = IP(dst=server_ip) / TCP(sport=client_port, dport=server_port, flags="A", seq=syn_ack_packet.ack, ack=syn_cookie + 1)
send(ack_packet)

print(f"Sent ACK packet with seq={syn_ack_packet.ack} and ack={syn_cookie + 1} to {server_ip}")
