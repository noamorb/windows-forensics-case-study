# Windows Forensics Lab Case Study

A cybersecurity lab case study by **Noam Orbach** ([noamorb](https://github.com/noamorb)).

I recovered an embedded Word document using Python and verified all 19 ZIP entries. In a Windows memory image, I used Volatility 3 to associate a TCP record with a process, then used TShark output from a separate capture to cross-check the destination IP.

[DOCX recovery](#1-recovering-an-embedded-docx) · [Memory and DNS findings](#2-windows-memory-and-dns-correlation)

## Investigation workflow

| Step | Tool | What I checked |
| --- | --- | --- |
| Locate and recover the document | Python, ZIP signatures | Located the embedded archive, then checked its internal format and CRCs. |
| Identify processes and network records | Volatility 3 | Compared process lists, checked the parent process and identified the endpoint associated with PID 2800. |
| Compare with packet evidence | TShark, Hunter | Checked whether the destination IP appeared in the DNS answers and reviewed the timestamps to see what could be linked. |

## 1. Recovering an embedded DOCX

The input, `carver.001`, was 165,884 bytes. File identification reported a ZIP archive with prepended data. A signature scan located the first ZIP local header at byte offset 111,316. Python's ZIP directory parser agreed with that offset. I copied the byte range from that offset to the end of the sample and inspected the resulting package without opening it in Word.

| Check | Result |
| --- | --- |
| Recovered size | 54,568 bytes |
| ZIP integrity | CRC passed for all 19 entries |
| File type | DOCX, confirmed by the main document content type in `[Content_Types].xml` |
| Source SHA-256 | `5a07b8e8fda5d3a2575ed95ca7599b82ef353a9f9e776fc813e79da1aaa6675d` |
| Output SHA-256 | `b92666fce9eadaef0f003ed5ee450fd5c9e52efcc366f1f71e179c82c16e8abd` |

An independent read of the recovered file matched the reported output hash and CRC checks. The package contained document XML, branding images and core metadata. The recovered bytes establish the presence of an embedded document. The sample does not establish a deletion history.

## 2. Windows memory and DNS correlation

I used Volatility 3 (2.28.2) on a 256 MiB lab memory image. Automatic symbol retrieval returned a connection error. I obtained the matching kernel PDB over HTTPS, converted it to Volatility's symbol format and reran the analysis with local symbols. `windows.info` reported a 32-bit Windows system with PAE and build 6001. Its implausible processor count was excluded from interpretation.

`pslist` and `pstree` each returned 45 unique PIDs. `psscan` returned 49 rows covering 45 unique PIDs. I compared process records by PID and used the tree to recover parent context. Repeated scan hits were treated as additional records for a PID.

| Evidence | Observation |
| --- | --- |
| Process tree | `explorer.exe` (PID 2708) was listed as the parent of `vmx32to64.exe` (PID 2800). |
| Command line and loaded image | Both showed `C:\Windows\System32\vmx32to64.exe`. No arguments were visible. |
| Volatility network scan | A TCPv4 record from `192.168.225.129:1043` to `104.28.16.29:443`, state `CLOSED`, was attributed to PID 2800. |
| DNS capture | Frame 225 contained a DNS response for `games.samsclass.info` with A records `104.28.16.29` and `104.28.17.29`. |

The records share the IP address `104.28.16.29`. The memory endpoint had no reported creation time, and the PCAP timestamps were unusable. The IP match is a correlation lead. The evidence does not establish a common session, a hostname for the process connection, or the executable's publisher or intent.

Memory image SHA-256: `726a454b6bd3b093af4c6f60920a0e404938f37323edb6b685f8b1f637b876c8`.

## Attribution

Noam Orbach ran the lab analysis in Kali Linux. [Hunter DNS Matcher](https://github.com/noamorb/hunter-dns-matcher) was used to extract and verify the DNS evidence. AI assisted with scripting, troubleshooting and drafting.
