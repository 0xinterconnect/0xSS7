# Author: 0xinterconnect - 2025
import socket
from sctp import sctpsocket_tcp
import struct

def build_m3ua_aspup():
    # M3UA Header:
    # Version (1 byte), Reserved (1 byte), Message Class (1 byte), Message Type (1 byte), Message Length (4 bytes)
    version = 0x01
    reserved = 0x00
    msg_class = 0x03  # ASPSM
    msg_type = 0x01   # ASPUP
    length = 8  # No parameters in simple ASPUP
    header = struct.pack("!BBBBI", version, reserved, msg_class, msg_type, length)
    return header  # No body/parameters

def test_m3ua():
    src_ip = '0.0.0.0'
    src_port = 2905
    dest_ip = input("Enter the destination IP: ")
    dest_port = int(input("Enter the destination port: "))

    try:
        # Create SCTP socket
        sock = sctpsocket_tcp(socket.AF_INET)
        sock.bind((src_ip, src_port))
        print(f"✅ Bound to {src_ip}:{src_port}")

        # Connect to remote M3UA peer
        sock.connect((dest_ip, dest_port))
        print(f"✅ Connected to {dest_ip}:{dest_port}")

        # Build and send ASPUP
        aspup = build_m3ua_aspup()
        sock.sctp_send(aspup)
        print("📤 Sent M3UA ASPUP")

        # Receive response
        sock.settimeout(5)
        response = sock.recv(1024)

        if response:
            version, _, msg_class, msg_type, msg_len = struct.unpack("!BBBBI", response[:8])
            print(f"📥 Received M3UA message: Class={msg_class}, Type={msg_type}, Length={msg_len}")
            if msg_class == 3 and msg_type == 4:
                print("✅ Received ASPUP_ACK")
            else:
                print("⚠️ Received unexpected M3UA message")
        else:
            print("❌ No response received.")

    except Exception as e:
        print(f"❌ Error: {e}")
    finally:
        sock.close()
        print("🔒 Socket closed.")

if __name__ == "__main__":
    test_m3ua()
