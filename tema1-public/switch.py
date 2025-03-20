import sys
import struct
import wrapper
import threading
import time
from wrapper import recv_from_any_link, send_to_link, get_switch_mac, get_interface_name

class BPDU:
    def __init__(self, root_bridge_id, root_path_cost, transmitting_bridge_id, port_id):
        self.R = root_bridge_id
        self.c = root_path_cost
        self.T = transmitting_bridge_id
        self.p = port_id

port_states = {}  # Dicționar pentru a ține evidența stării fiecărui port

def read_config():
    config_data = {}
    with open("configs/switch" + switch_id + ".cfg", 'r') as f:
        lines = f.readlines()
        
        switch_priority = int(lines[0].strip())

        index = 1
        while index < len(lines):
            line = lines[index].strip()
            parts = line.split()
            interface = parts[0]
            if parts[1] == 'T':
                config_data[interface] = 'T'
            else:
                vlan_id = int(parts[1])
                config_data[interface] = vlan_id
            index += 1
    print(config_data)
    return config_data, switch_priority

def forward_frame(target_interface, vlan, config, data, length, interface):
    if get_port_state(target_interface) == 'BLOCKING':
        print(f"[STP] Cadru abandonat pe interfața {target_interface} (stare BLOCKING)")
        return

    frame_data = data
    target_interface1 = get_interface_name(target_interface)
    interface1 = get_interface_name(interface)
    interface_config = config[interface1]
    target_port_config = config[target_interface1]
    
    if vlan == -1:
        vlan = config[interface1]

    if target_port_config == 'T':
        if interface_config != 'T':
            frame_data = data[:12] + create_vlan_tag(vlan) + data[12:]
            new_length = length + 4
        else:
            new_length = length
        send_to_link(target_interface, new_length, frame_data)
    else:
        if vlan == target_port_config:
            if interface_config == 'T':
                frame_data = data[:12] + data[16:]
                new_length = length - 4
            else:
                new_length = length
            send_to_link(target_interface, new_length, frame_data)
        else:
            print(f"[DROP] Cadru VLAN ID {vlan} nu corespunde VLAN ID portului de acces {target_port_config}")

def parse_ethernet_header(data):
    dest_mac = data[0:6]
    src_mac = data[6:12]
    ether_type = (data[12] << 8) + data[13]

    vlan_id = -1
    if ether_type == 0x8200:
        vlan_tci = int.from_bytes(data[14:16], byteorder='big')
        vlan_id = vlan_tci & 0x0FFF
        ether_type = (data[16] << 8) + data[17]

    return dest_mac, src_mac, ether_type, vlan_id

def create_vlan_tag(vlan_id):
    return struct.pack('!H', 0x8200) + struct.pack('!H', vlan_id & 0x0FFF)

def send_bdpu_every_sec():
    global switch_priority, root_bridge_id, own_bridge_id, root_path_cost, interfaces
    while True:
        time.sleep(1)
        if switch_priority == root_bridge_id:
            send_bpdu(root_bridge_id, own_bridge_id, root_path_cost, interfaces)

def create_bpdu(root_bridge_id, sender_bridge_id, root_path_cost):
    flags = 0
    bpdu = struct.pack(
        "!B8sI8sHHHHH",
        flags,
        root_bridge_id,
        root_path_cost,
        sender_bridge_id,
        0,
        1,
        20,
        2,
        15
    )
    return bpdu

def better(b1, b2):
    return ((b1.R < b2.R) or
            ((b1.R == b2.R) and (b1.c < b2.c)) or
            ((b1.R == b2.R) and (b1.c == b2.c) and (b1.T < b2.T)) or
            ((b1.R == b2.R) and (b1.c == b2.c) and (b1.T == b2.T) and (b1.p < b2.p)))

# Dicționar pentru a urmări BPDUs procesate pe interfață pentru a preveni inundațiile multiple
processed_bpdus_per_interface = {}

def handle_received_bpdu(data, interface):
    flags, received_root_bridge_id, received_root_path_cost, sender_bridge_id, port_id, _, _, _, _ = struct.unpack("!B8sI8sHHHHH", data)
    
    global root_bridge_id, root_path_cost, root_port

    if interface not in processed_bpdus_per_interface:
        processed_bpdus_per_interface[interface] = set()

    bpdu_id = (received_root_bridge_id, sender_bridge_id, port_id)

    if bpdu_id in processed_bpdus_per_interface[interface]:
        print(f"[BPDU] BPDU duplicat pe interfața {interface}, ignorat.")
        return

    processed_bpdus_per_interface[interface].add(bpdu_id)
    
    current_bpdu = BPDU(root_bridge_id, root_path_cost, own_bridge_id, root_port)
    received_bpdu = BPDU(received_root_bridge_id, received_root_path_cost, sender_bridge_id, port_id)
    
    if better(received_bpdu, current_bpdu):
        print(f"[BPDU] Nou switch rădăcină detectat pe interfața {interface}")
        root_bridge_id = received_root_bridge_id
        root_path_cost = received_root_path_cost + 10
        root_port = interface
        for p in interfaces:
            if p != root_port:
                print(f"[STP] Interfața {p} blocată pentru a preveni buclele")
                set_port_state(p, 'BLOCKING')
    elif root_bridge_id == received_root_bridge_id and root_path_cost > received_root_path_cost + 10:
        root_path_cost = received_root_path_cost + 10
        root_port = interface
        set_port_state(root_port, 'LISTENING')

def set_port_state(interface, state):
    port_states[interface] = state
    print(f"Setând portul {interface} la {state}")

def get_port_state(interface):
    return port_states.get(interface, 'BLOCKING')

def send_bpdu(root_bridge_id, sender_bridge_id, root_path_cost, interfaces):
    bpdu = create_bpdu(root_bridge_id, sender_bridge_id, root_path_cost)
    for interface in interfaces:
        send_to_link(interface, len(bpdu), bpdu)
        print(f"[BPDU] BPDU trimis pe interfața {interface} cu root ID {root_bridge_id.hex()} și costul căii {root_path_cost}")

def is_unicast(mac):
    return mac[0] & 1 == 0

# Dicționar pentru a urmări numărul de inundații per MAC necunoscut
flood_count = {}
MAX_FLOOD_COUNT = 1  # Setează limita maximă de încercări de inundație per MAC

def reset_flood_count():
    while True:
        time.sleep(60)
        flood_count.clear()

def main():
    global switch_id, root_bridge_id, root_path_cost, own_bridge_id, root_port, switch_priority, interfaces

    switch_id = sys.argv[1]
    MAC_Table = {}
    config, switch_priority = read_config()
    own_bridge_id = struct.pack('!Q', switch_priority)
    root_bridge_id = own_bridge_id
    root_path_cost = 0
    root_port = None

    num_interfaces = wrapper.init(sys.argv[2:])
    interfaces = range(0, num_interfaces)
    
    for p in interfaces:
        port_states[p] = 'LISTENING'

    print("# Pornind switch-ul cu id {}".format(switch_id), flush=True)
    print("[INFO] MAC-ul switch-ului", ':'.join(f'{b:02x}' for b in get_switch_mac()))

    t = threading.Thread(target=send_bdpu_every_sec)
    t.start()
    
    t_reset_flood = threading.Thread(target=reset_flood_count)
    t_reset_flood.start()

    while True:
        interface, data, length = recv_from_any_link()
        if interface < 0 or data is None or length <= 0:
            continue

        dest_mac, src_mac, ethertype, vlan_id = parse_ethernet_header(data)

        if ethertype == 0x42:
            handle_received_bpdu(data, interface)
            continue

        dest_mac_str = ':'.join(f'{b:02x}' for b in dest_mac)
        src_mac_str = ':'.join(f'{b:02x}' for b in src_mac)

        print(f'Am primit cadru de dimensiune {length} pe interfața {interface}', flush=True)
        print(f'MAC destinație: {dest_mac_str}')
        print(f'MAC sursă: {src_mac_str}')
        print(f'EtherType: {ethertype}')

        MAC_Table[src_mac_str] = interface

        if is_unicast(dest_mac):
            if dest_mac_str in MAC_Table:
                target_interface = MAC_Table[dest_mac_str]
                print(f"[UNICAST] Forwarding frame to known destination MAC {dest_mac_str} on interface {target_interface}")
                forward_frame(target_interface, vlan_id, config, data, length, interface)
            else:
                if dest_mac_str not in flood_count:
                    flood_count[dest_mac_str] = 0
                if flood_count[dest_mac_str] < MAX_FLOOD_COUNT:
                    print(f"[FLOOD] Destinație MAC necunoscută unicast {dest_mac_str}, inundând la toate celelalte interfețe")
                    flood_count[dest_mac_str] += 1
                    for p in interfaces:
                        if p != interface:
                            forward_frame(p, vlan_id, config, data, length, interface)
                else:
                    print(f"[DROP] Limita maximă de inundații atinsă pentru MAC-ul destinație {dest_mac_str}. Cadru abandonat.")
        else:
            print(f"[BROADCAST] Trimit cadru la toate celelalte interfețe pentru MAC-ul destinație {dest_mac_str}")
            for p in interfaces:
                if p != interface:
                    forward_frame(p, vlan_id, config, data, length, interface)

if __name__ == "__main__":
    main()
