# IMPORTS
from scapy.all import PcapReader, PcapWriter, PcapNgReader, PcapNgWriter
import os

# Bad ethertypes
BAD_TYPES = {0xc0a8, 0xa8c0} 
# Fix to IPv4
FIX_TO = 0x0800        

# Check if the file is a PCAPNG file
def is_pcapng(path: str) -> bool:
    with open(path, "rb") as f:
        return f.read(4) == b"\x0a\x0d\x0d\x0a"

def u16(b):
    return (b[0] << 8) | b[1]

def patch_inner_ethertype_in_sll_v1(pkt_bytes):
    # HEADER SLL v1: 16 bytes
    # 0-1  pkttype
    # 2-3  hatype
    # 4-11 adrr
    # 12-13 addr len
    # 14-15 proto [ etype ] -> sll.etype = 0x0003 => payload is an ethernet II frame encapsulated
    # IF etype==0x0003 and pkttype==4 -> at offset (16+12) there are the 2 bytes of the Ethernet inner EtherType
    if len(pkt_bytes) < 16 + 14:
        # Too short for inner Ethernet [ SLL(16) + ETH(14) ]
        return None, None  
    # Packet type field
    pkttype = u16(pkt_bytes[0:2])
    # SLL EtherType field
    sll_etype = u16(pkt_bytes[14:16])

    # Packet characteristic : 'sent by us' and Ethernet encapsulated
    if pkttype != 4:          
        return None, None
    if sll_etype != 0x0003: 
        return None, None
    # Offset of the Ethernet inner EtherType
    inner_off = 16 + 12
    inner_type = u16(pkt_bytes[inner_off:inner_off+2])
    # Patch the inner EtherType if it is in the BAD_TYPES
    if inner_type in BAD_TYPES:
        patched = bytearray(pkt_bytes)
        patched[inner_off]     = (FIX_TO >> 8) & 0xFF
        patched[inner_off + 1] = FIX_TO & 0xFF
        return bytes(patched), inner_type
    return None, None

def ghostbuster():
    inp = input("\033[37mFile [ \033[90m.pcap • .pcapng \033[37m] : \033[0m")
    if not os.path.exists(inp):
        print(f"\033[1;91mError 🔥\n\033[0;90mFile not found: {inp}\n\033[0m")
        return
    outn = input("\033[37mOutput filename [ \033[90mdefault: clean_sanitized.pcap \033[37m] : \033[0m").strip() or "clean_sanitized.pcap"
    outp = os.path.join(os.path.dirname(os.path.abspath(inp)), outn)

    input_is_pcapng = is_pcapng(inp)
    r = PcapNgReader(inp) if input_is_pcapng else PcapReader(inp)
    w = PcapNgWriter(outp) if input_is_pcapng else PcapWriter(outp)

    # File statistics
    total = 0
    fixed_eth_direct = 0
    fixed_sll_inner  = 0
    fixed_inner_0xa8c0 = 0

    for pkt in r:
        total += 1
        # Scapy preserves the original bytes
        raw_bytes = bytes(pkt.original)  
        patched = None
        # Patch the inner EtherType in SLL v1 
        pbytes, inner_prev = patch_inner_ethertype_in_sll_v1(raw_bytes)
        if pbytes is not None:
            patched = pbytes
            fixed_sll_inner += 1
            if inner_prev == 0xa8c0:
                fixed_inner_0xa8c0 += 1
        # IF not patched as SLL-embedded... 
        # Try the pure Ethernet case
        if patched is None:
            # Read the EtherType from the raw bytes
            if len(raw_bytes) >= 14:
                et = u16(raw_bytes[12:14])
                if et in BAD_TYPES:
                    patched = bytearray(raw_bytes)
                    patched[12] = (FIX_TO >> 8) & 0xFF
                    patched[13] = FIX_TO & 0xFF
                    patched = bytes(patched)
                    fixed_eth_direct += 1
        # Write the patched packet
        if patched is not None:
            # Write the patched bytes
            w.write(patched)
        else:
            w.write(pkt)
    r.close(); w.close()

    # Log the results
    print("\033[1;92m\nDone\033[0m")
    print(f"\033[90mOutput: {outp}\033[0m\n")
    print(f"\033[90mTotal packets: {total}\033[0m\n")
    print(f"\033[90mFixed inner EtherType in SLL v1 (0xc0a8/0xa8c0 --→ 0x0800): {fixed_sll_inner} (of which 0xa8c0: {fixed_inner_0xa8c0})\033[0m\n")
    print(f"\033[90mFixed direct Ethernet EtherType (0xc0a8/0xa8c0 --→ 0x0800): {fixed_eth_direct}\033[0m\n")

if __name__ == "__main__":
    print("\n\033[1;37mGhostbuster 👻\033[0m\n\033[90mSLL v1 inner-EtherType patcher\n\033[0m")
    ghostbuster()