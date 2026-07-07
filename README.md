# Computer Networking: Wireshark Project

The project focuses on a deep understanding of the web protocol stack (HTTP/TCP/IP), understanding the behavior of servers, diagnosing the performance issues of networks, and mastery over standard tools in the networking & cybersecurity indeustry (Wireshark and curl).

The project consists of four phases, with Phase 1,2,3 are mandatory & Phase 4 being optional.

**All four phases have been implemented.**

<br>

We try 3 site with curl: `neverssl.com` , `icio.us` , `babytree.com`
and their capture file & images saved in captures folder & images folder.

However, in the following steps we continued all analysis just on `neverssl.com`


## Author

- **Ahmad Mofti - 40217023170**


<br>


## Phase-1: Setup environment & Packet Capturing

In this phase, we capture the packets in Wireshark.
- 1- First, we open Wireshark and choose the active interface (wi-fi) and start capturing.
- 2- then, we send this request in CMD for "http://neverssl.com"
  <br>
  <br>
  ```bash
  curl http://neverssl.com
  ```
  (We can use "curl -I" to see the server header responses, or "curl -L" to tracking the change paths)
<br>

- 3- We going back to wireshark and stop the capturing.
- 4- Saving the result as a `.pcapng` file.

  <br>
  <img width="1919" height="1023" alt="image" src="https://github.com/user-attachments/assets/e097ab07-8e00-4a95-975d-a60b9bcd4e1b" />
  <br>
  
  (The `.pcapng` file has been saved in `captures` folder)


<br>


## Phase-2 : Analysing Headers & Protocol Stack

- We appling the `http` filter in Wireshark, to filter the related packets. In our scenario, this leaves us with:

<img width="1068" height="298" alt="image" src="https://github.com/user-attachments/assets/b11900d2-dcd7-43f7-8e46-f6d8b60f6f13" />




### Applicaiton Layer

- Determining the `Host name` , `HTTP version` , `User-Agent header` :

<img width="1922" height="602" alt="image" src="https://github.com/user-attachments/assets/6056fc5e-90f9-4cc6-a1e8-f0fb34944c9f" />

<br>
<br>

We can extract the requirements specified by the project:

| Host | HTTP Protocol Version | User-Agent Header |
| :---: | :---: | :---: |
| neverssl.com\r\n | HTTP/1.1 | curl/8.19.0\r\n |

<br>

### Transport Layer

- Determining the `Source Port` , `Destination Port` , `Transport Protocol name` :

<img width="1923" height="870" alt="image" src="https://github.com/user-attachments/assets/a47cdd59-53b6-4933-b6cf-a6eeb03d9a14" />

<br>
<br>

We can extract the requirements specified by the project:

| Protocol | Source Port | Destination Port |
| :---: | :---: | :---: |
| TCP | 4562 | 80 |

<br>

### Network Layer

- Determining the `Source IP` , `Destination IP` :

<img width="1925" height="685" alt="image" src="https://github.com/user-attachments/assets/ec430d77-2a8e-4be5-980e-f7ed4d9cca08" />

<br>
<br>

We can extract the requirements specified by the project:

| Protocol | Source Address | Destination Address |
| :---: | :---: | :---: |
| IPv4 | 192.168.1.102 | 34.223.124.45 |

<br>


## Phase-3 : Server behavior analysis & RTT timing

In this scenario, we can see the response packet (info: HTTP/1.1 200 OK) easily, because `http` filter, kept 2 packets at all:

<img width="1919" height="1020" alt="image" src="https://github.com/user-attachments/assets/63816d78-cd94-4bee-b55c-d99029489d25" />


<br>
<br>

But generally, we can:
- Right click on GET request packet
- choose `Follow`
- Choose `TCP Stream`

now, we can see the packets that are relevant to this TCP Stream, and find the first Response packet:


<img width="1392" height="761" alt="image" src="https://github.com/user-attachments/assets/91a29cd4-197d-4fb1-985a-dac1d7064a20" />

<br>
<br>

<img width="1533" height="762" alt="image" src="https://github.com/user-attachments/assets/9a3aed4b-4a18-40a1-90c9-77ae8681fee7" />


<br>
<br>
<br>

### Finding `Status Code` & `Time Delta`

- #### Status Code:

<img width="1919" height="895" alt="image" src="https://github.com/user-attachments/assets/d4f47937-980d-493e-8aca-b38667ad4440" />

<br>
<br>

**Status Code: 200**

**Meaning:** The `HTTP 200 OK` shows that the request has been successfully fulfilled. The meaning and format of a 200 OK response vary depending on the HTTP request method. For a GET request, it indicates that the requested resource was successfully retrieved by the server and included in the response body.

<br>


- #### Time Delta:

WE can see the RTT in `Time since request` in Application layer , and also we can minus the times of that two packets:

$RTT= 4.218 - 3.827 = 391.6799$ millisecond

<img width="1918" height="867" alt="image" src="https://github.com/user-attachments/assets/9cac6930-312f-426a-92ae-ff84b8ae1eb7" />

<br>
<br>

Within the full traffic view:


<img width="1918" height="1020" alt="image" src="https://github.com/user-attachments/assets/acabc953-e9a1-40ab-908c-b3911ee01943" />


<br>
<br>





#### Slowing scenario

A delay exceeding 2 seconds in the `Time Delta` field is caused by **internal server processing latency**.

The hypothesis of client-side involvement is ruled out, as the source system merely enters a passive wait state after transmitting the request. 

Furthermore, network bandwidth limitations cannot be the cause of this bottleneck; the initial response packet is minimal in size and not bulky, allowing it to traverse the communication channel effortlessly.

Consequently, this latency demonstrates that the server's backend consumed substantial time processing and constructing the response data.


<br>
<br>


## Phase 4(Optional)

In this phase we wrote a script in language `Go` that reads a Wireshark capture file (.pcap or .pcapng), parses the HTTP packets in it, and prints a one-line summary for each: source/destination IP:port, and either the request line or the response status code.

<br>

### How To Run

<br>

Going to the correct path:

```bash
cd phase-4
```

Install dependencies:

```bash
go mod tidy
```


Run:

```
go run . path/to/YourCapture.pcapng
```

You can use `go run .` against `go run . path/to/capture.pcapng` and it use the default file in project (neverssl)
