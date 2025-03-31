# Preferential Treatment
Writeup by: Ethan Andrews (UofUsec)

## Description
We have an old Windows Server 2008 instance that we lost the password for. Can you see if you can find one in this packet capture?

## Writeup
### Initial Looks
We are given a pcap file. After opening it in Wireshark, we can see that it uses the SMB Protocol.

![image](https://github.com/user-attachments/assets/74bafbc7-b7a2-4f5e-b685-28fe6163ec5b)

Luckily, the file is very short, so we can look through each of the packets. Noticeably, we can see packet 39 that contains
a large amount of data.

![image](https://github.com/user-attachments/assets/7e89ad4f-9f4d-4d35-8a6a-43b3928b30bf)

### Packet Analyzing
Looking through the data we can see following xml data.

```xml
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EC16-4b4c-9934-544FC6D24D26}">
    <User clsid="{DF5F1855-52E5-4d24-8B1A-D9BDE98BA1D1}" name="swampctf.com\Administrator" image="2"
          changed="2018-07-18 20:46:06" uid="{EF57DA28-5F69-4530-A59E-AAB58578219D}">
        <Properties action="U" newName="" fullName="" description=""
                    cpassword="dAw7VQvfj9rs53A8t4PudTVf85Ca5cmC1Xjx6TpI/cS8WD4D8DXbKiWIZslihdJw3Rf+ijboX7FgLW7pF0K6x7dfhQ8gxLq34ENGjN8eTOI="
                    changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="swampctf.com\Administrator"/>
    </User>
</Groups>
```

Based on the description, it appears that the cpassword field is the field of interest. By doing some research, we see
that we can crack cpassword's by using `gpp-decrypt`.

```bash
gpp-decrypt dAw7VQvfj9rs53A8t4PudTVf85Ca5cmC1Xjx6TpI/cS8WD4D8DXbKiWIZslihdJw3Rf+ijboX7FgLW7pF0K6x7dfhQ8gxLq34ENGjN8eTOI=
```

Then we can see that this returns the flag:

![image](https://github.com/user-attachments/assets/a113ea4e-64e9-4f8e-83d7-02d2dcd03625)

## Importance Concepts
- Wireshark
- pcap files
- cpassword
