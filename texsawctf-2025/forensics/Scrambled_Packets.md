# Scrambled Packets
Writeup by: Ethan Andrews

## Description
I accidentally broke my message and it got all mixed up with everything else. Can you help me get it back?

flag format: TexSAW{flag}

## Writeup
### Initial Looks
We are given a pcap file. Opening this file in wireshark we see HTTP, DNS, ICMP, and TCP packets.

![image](https://github.com/user-attachments/assets/e6149f52-604c-401d-a75d-52ad312577ff)

### Packet Analysis
Filtering the http packets, we only see GET requests, none of which seem to contain any important data.

![image](https://github.com/user-attachments/assets/803bc51a-d79e-4577-9b4c-f59dfc033283)

The same is true for the DNS and TCP packets.

However, for the ICMP packets (filtering out the DNS packets), we noticeably see that they contain a data section.

![image](https://github.com/user-attachments/assets/ece7c48b-b47d-4d03-9708-5b69fb61a108)

Most of the data sections are very large, but there are noticeably some requests with only a single byte.

![image](https://github.com/user-attachments/assets/2e6d20c9-4ebf-4aee-80c2-7d235e05f671)

We notice that each of these packets that only contain a single byte each come from a specific icmp identifier 0x3c56.

We can then filter for only these packets.

![image](https://github.com/user-attachments/assets/c5e75e7e-1ee9-46fe-a53f-2f934b1c45e1)

We notice that the replies contain the same byte of data as the requests, so we will filter out the replies as well.

![image](https://github.com/user-attachments/assets/856f785f-60d5-4476-9f16-f7f345ec8601)

So now if we extract each of the bytes of data in order by sequence number, we get the flag:

![image](https://github.com/user-attachments/assets/e6ceec42-34f3-4c5a-bc9e-2c9f8adb4e40)

Flag: TexSAW{not_the_fake_one}

## Important Concepts
- Wireshark

