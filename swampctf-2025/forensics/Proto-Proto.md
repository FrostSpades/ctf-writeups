# Proto Proto
Writeup by: Ethan Andrews (UofUsec)

## Description
Moto Moto likes you. But not enough to explain how his server works. We got a pcap of the client and server communicating. Can you figure out how the server works and retrieve the flag?

## Writeup
### Initial Looks
We are given a pcap file. We can analyze the pcap file using Wireshark.

![image](https://github.com/user-attachments/assets/a4baea57-bcdc-436d-8670-bd30b0369f5c)

Looking around we can see a UDP packet of interest. The data section contains words like flag.txt.

![image](https://github.com/user-attachments/assets/7da21f70-6923-4961-acb3-384d0a389c65)

Specifically, we notice that this was data was transferred using UDP. We can filter the wireshark packets for other UDP Packets.

![image](https://github.com/user-attachments/assets/832ead73-0a1b-4657-b58d-70f63bd01b27)

We can actually see the flag being transported in the data section. This clearly indicates that the server is at the
ip `127.19.0.2`. Unfortunately, this is not the real flag.

### Server Behavior Analysis
We can analyze what interactions had taken place for the server to have sent the flag. Knowing that the ip is at
`127.19.0.2` we can look at packets 107-111 to analyze the behavior.

Packet 108

![image](https://github.com/user-attachments/assets/244f060d-3521-4db3-bc16-3919e8f1286d)

Packet 109

![image](https://github.com/user-attachments/assets/46fccd57-ded5-4b4d-a92f-668377f56bca)

We can see that the client sends `0x0208flag.txt` or `0208666c61672e747874` in hex and the server responds with the flag. We can try to mimick this behavior.

### UDP Python
We can write a UDP client in python to send structured data.

```python
import socket

# Replace with real address and port number
server_address = ('address', port)

hex_data = "0208666c61672e747874"
data = bytes.fromhex(hex_data)

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

try:
    sock.sendto(data, server_address)

    # Receive 100 bytes
    response, server = sock.recvfrom(100)
    print(f"Received response: {response}")

finally:
    sock.close()
```

After executing this program, we can see that it returns the flag:

![image](https://github.com/user-attachments/assets/3d993608-e1e1-496d-929a-e64a39192933)


## Important Concepts
- Wireshark
- UDP
