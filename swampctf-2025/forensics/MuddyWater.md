# MuddyWater
Writeup by: Ethan Andrews (UofUsec)

## Description
We caught a threat actor, called MuddyWater, bruteforcing a login for our Domain Controller. We have a packet capture of the intrustion. Can you figure out which account they logged in to and what the password is?

Flag format is swampCTF{username:password}

## Writeup
### Initial Looks
We are given a pcap file. Opening this file in Wireshark, we see that someone is trying to bruteforce authentication in the
SMB2 NTLMv2 protocol.

![image](https://github.com/user-attachments/assets/6eacde7a-e6a3-4371-8294-b101fe0de2c4)

This protocol involves several steps, most noticeably, we can see if the attempt was successful. In this example,
someone is trying to log into a user named shadowbytefox. And the server responded with STATUS_LOGON_FAILURE meaning
that it was an unsuccessful attempt.

Our first instinct might be to manually go through each of these attempts and determine which one was successful. However,
it becomes apparent that there are too many packets for this to be feasible, as there are 97,948 packets in total.

### Using Scapy
We will transition away from using Wireshark and will use python to give us a little more control over our search. Python
has a package named Scapy that allows us to analyze pcap files.

First, we'll create a python program that reads in the pcap file and extracts the packets. NOTE: I recommend using
`jupyter notebook` as reading in a pcap file this large takes a significant amount of time.

```python
from scapy.all import *

packets = rdpcap('muddywater.pcap')
```

We can analyze an individual packet to look at the layers and the different fields it contains. Specifically, we will
analyze packets 43-46.

```python
for i, packet in enumerate(packets):
    if i >= 42 and i < 46:
        print(packet)
        print(ls(packet))
```

We can see that server responses contain a SMB2_Session_Setup_Response header. We can also see that the server response
to logon requests have a status code that we can obtain.

![image](https://github.com/user-attachments/assets/1f49ad68-ed38-4acd-b9f1-23aacd8d0e92)

By doing some research, we find out that if a NTLMv2 login was successful, it will return a status code of 0x0. So now we know
that we are looking for a packet with a SMB2_Session_Setup_Response header and a status code of 0x0.

```python
for i, packet in enumerate(packets):
    if packet.haslayer("SMB2_Session_Setup_Response"):
        status = hex(packet.Status)

        if status == "0x0":
            print(packet)
            print(f"Packet Number: {i + 1}")
```

We see a single packet of interest:

![image](https://github.com/user-attachments/assets/87c4d694-925e-41e6-97bf-ae2ff0e924e3)

We can now verify this in wireshark, and we can clearly see the successful login attempt.

![image](https://github.com/user-attachments/assets/d2ebedc3-22c2-4947-8294-3d14e7dd6a01)

We can also look at the previous packets sent and see that the packets associated with this request are packets
72069 and 72065.

### NTLMv2 Hash
Unfortunately, we are not finished as passwords are not sent over plaintext. In order to obtain the password, we will
need to crack the password hash.

NTLMv2 hashes are in a very specific format. The format is
```
username::domain:server_challenge:NTProofStr:NTLMv2Response_without_NTProofStr
```

We can find the username and domain in packet 72074:

![image](https://github.com/user-attachments/assets/955f11e1-87e9-4ecc-9f0f-a43f3721177d)

```
Username: hackbackzip
Domain: DESKTOP-0TNOE4V
```

We can find the server_challenge in packet 72065.

![image](https://github.com/user-attachments/assets/6377d45b-918c-4f90-b774-b09b9d83037b)

```
Server Challenge: d102444d56e078f4
```

We can find the NTProofStr and the NTLMv2Response in packet 72069.

![image](https://github.com/user-attachments/assets/4d759276-cf8f-413a-94ef-a891b31d9b33)

IMPORTANT: The NTLMv2Response is not the same as NTLMv2Response_without_NTProofStr.
We will need to manually remove the NTProofStr from the NTLMv2Response to get the NTLMv2Response_without_NTProofStr. Luckily,
as we can see, the NTProofStr is the first part of the NTLMv2Response, so removing it is simple. 

```
NTProofStr: eb1b0afc1eef819c1dccd514c9623201
NTLMv2 Response: eb1b0afc1eef819c1dccd514c962320101010000000000006f233d3d9f9edb01755959535466696d0000000002001e004400450053004b0054004f0050002d00300054004e004f0045003400560001001e004400450053004b0054004f0050002d00300054004e004f0045003400560004001e004400450053004b0054004f0050002d00300054004e004f0045003400560003001e004400450053004b0054004f0050002d00300054004e004f00450034005600070008006f233d3d9f9edb010900280063006900660073002f004400450053004b0054004f0050002d00300054004e004f004500340056000000000000000000

NTLMv2 Response Without NTProofStr: 01010000000000006f233d3d9f9edb01755959535466696d0000000002001e004400450053004b0054004f0050002d00300054004e004f0045003400560001001e004400450053004b0054004f0050002d00300054004e004f0045003400560004001e004400450053004b0054004f0050002d00300054004e004f0045003400560003001e004400450053004b0054004f0050002d00300054004e004f00450034005600070008006f233d3d9f9edb010900280063006900660073002f004400450053004b0054004f0050002d00300054004e004f004500340056000000000000000000
```

Putting all these parts together we get the final hash:
```
hackbackzip::DESKTOP-0TNOE4V:d102444d56e078f4:eb1b0afc1eef819c1dccd514c9623201:01010000000000006f233d3d9f9edb01755959535466696d0000000002001e004400450053004b0054004f0050002d00300054004e004f0045003400560001001e004400450053004b0054004f0050002d00300054004e004f0045003400560004001e004400450053004b0054004f0050002d00300054004e004f0045003400560003001e004400450053004b0054004f0050002d00300054004e004f00450034005600070008006f233d3d9f9edb010900280063006900660073002f004400450053004b0054004f0050002d00300054004e004f004500340056000000000000000000
```

We can then simply crack the hash using hashcat.
```
hashcat -m 5600 hash.txt rockyou.txt
```

This gives us the password.

![image](https://github.com/user-attachments/assets/505ff489-07f0-4c36-a292-41dd01605556)

Now we have the username and the password, and thus the flag.

## Important Concepts
- Wireshark
- pcap files
- Scapy
- NTLMv2
- Hashcat
