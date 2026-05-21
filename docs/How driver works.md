CreateFileW -> new node
0x228014 -> MAC -> match file to MAC (last created file)
    array with hFile -> MAC
GetOverlappedResult/ReadFile -> 
_/-> recv(...) -> parse Ethernet packet -> MAC
 \-> hFile -> MAC -> filter by MAC or broadcast MACs -> match -> send if match

index 0 CreateFileW ignore for node


| Operation | IOCTL code | Hex response you must return |
|-----------|------------|-------------------------------|
| Query adapter info | `0x22C004` | `00 00 00 00 [MAC 6 bytes] 00 00` |
| All other IOCTLs | any | `TRUE`, 0 bytes returned (no‑op) |

| Direction | Operation | Example data (full frame) |
|-----------|-----------|----------------------------|
| Local → remote (outbound) | `ReadFile` returns | `[Ethernet: DstMac=remote, SrcMac=local, EtherType=0x0800] [IP: proto=TCP, srcIP=local, dstIP=remote] [TCP: SYN, …]` |
| Remote → local (inbound) | `WriteFile` receives | `[Ethernet: DstMac=local, SrcMac=remote, EtherType=0x0800] [IP: proto=TCP, srcIP=remote, dstIP=local] [TCP: SYN‑ACK, …]` |

The driver **never generates TCP responses** – it is a pure pipe. The VPN application handles all ARP replies, TCP retransmissions, encryption, and tunnel management.

## Radmin VPN Miniport Driver – Control IOCTL Reference

The virtual adapter driver **\Device\RVPNNETMP** exposes a set of private IOCTL codes that allow a user‑mode VPN application to configure the adapter, query its state, install MAC filters, and retrieve the current hardware address. All IOCTLs are sent using `DeviceIoControl` to the handle returned by `CreateFile("\\\\.\\RVPNNETMP", ...)`.

---

### IOCTL Dispatch Overview

Internally, the driver’s `IRP_MJ_DEVICE_CONTROL` handler maps the incoming `IoControlCode` to a worker function via a switch on the code (extracted from `Parameters.DeviceIoControl.IoControlCode`). The following table lists every supported code, the corresponding handler, and a description of its parameters and behaviour.

RvControlSvc.exe uses 0x224020 0x224018 0x22801c 0x228014 0x22c004.

| IOCTL Code   | Handler            | Direction | Purpose |
|--------------|-------------------|-----------|---------|
| `0x224010`   | `FUN_140004b5c`    | Out only  | Query fixed‑size adapter information (184 bytes) |
| `0x224018`   | `FUN_140004e3c`    | Out only  | Read a 32‑bit status flag from the adapter |
| `0x224020`   | `FUN_140004afc`    | Out only  | Query a one‑byte status and clear a notification bit |
| `0x228014`   | `FUN_140005474`    | In only   | Add a 6‑byte MAC address filter (multicast/unicast) |
| `0x22801C`   | `FUN_1400053b8`    | In only   | Set a filter type (1, 2 or 3) on a previously added filter |
| `0x228024`   | `FUN_1400052d4`    | In/Out    | Enable or disable a MAC filter |
| `0x22C004`   | `FUN_14000552c`    | In/Out    | Set packet filter and retrieve the adapter’s MAC address |

All codes return `TRUE` on success via the Win32 call; the number of bytes transferred is placed in `lpBytesReturned`.

---

### Detailed IOCTL Descriptions

---

#### 1. `0x224010` – Get Adapter Information Structure (continued)

**Handler function:** `FUN_140004b5c`

**Source data**  
The handler obtains a pointer to the adapter’s **statistics block** via `FUN_140002aac`, which returns `ADAPTER_CONTEXT + 0x1C0`. This block contains a set of 32‑bit and 64‑bit counters/values maintained by the driver.

**Data written**  
The function copies **44 × 32‑bit values** followed by **one 64‑bit value** into the output buffer. The decompilation shows writes at offsets `+0x10`, `+0x14`, …, `+0xBC` for the dwords and at `+0xC0` for the qword. This means the real structure includes a **16‑byte header** (reserved, zero‑filled) before the actual statistics payload.

**Output buffer layout (C definition)**

```c
#pragma pack(push, 1)
typedef struct _RVPN_ADAPTER_STATISTICS {
    // --- Header (16 bytes) ---
    UCHAR  Reserved[16];                  // always zero

    // --- Statistics counters (44 × 32‑bit) ---
    ULONG  Counter[44];                   // see detailed field mapping below

    // --- Additional 64‑bit value ---
    ULONGLONG  ExtraQword;                // final counter / timestamp
} RVPN_ADAPTER_STATISTICS, *PRVPN_ADAPTER_STATISTICS;
#pragma pack(pop)
```

**Total size:**  16 + (44×4) + 8 = **200 bytes (0xC8)**.

> 📌 **Why `0xB8`?**  
> The driver checks that the output buffer is **at least `0xB8` (184) bytes** and sets the I/O status to return exactly `0xB8` bytes. This value corresponds to the **payload** (counter array + extra qword) **without** the 16‑byte header. Because the header is always zero, the user‑mode application can simply treat the first 184 bytes as the statistics block – the header zeros are harmless padding.

**Field breakdown**

The 44 dwords correspond to internal counters and configuration values maintained by the virtual adapter. Although the decompiled code does not assign symbolic names, the **position** of each element can be inferred from cross‑references in the driver. A likely interpretation is:

| Index | Offset in buffer | Typical meaning                           |
|-------|------------------|-------------------------------------------|
| 0‑3   | 0x10‑0x1C        | Packet filter flags, MAC address bytes    |
| 4‑7   | 0x20‑0x2C        | Multicast address list (first entries)    |
| 8‑11  | 0x30‑0x3C        | OID list / supported statistics           |
| 12‑23 | 0x40‑0x6C        | Send / receive counters (various)         |
| 24‑27 | 0x70‑0x7C        | Adapter state flags, media connect status |
| 28‑31 | 0x80‑0x8C        | Additional address filters                |
| 32‑35 | 0x90‑0x9C        | Power management / wake‐up counters       |
| 36‑43 | 0xA0‑0xBC        | Further statistics                        |
| final | 0xC0‑0xC7        | 64‑bit counter (e.g., bytes received)     |

---

#### 2. `0x224018` – Read Adapter Status Flag
- **Input buffer**: None.
- **Output buffer**: Exactly 4 bytes.
- **Return value**: `0` if the flag could be read; `-0x7ffffffb` if output buffer is smaller than 4 bytes.

Returns the 32‑bit value located at offset `0x70` of the miniport adapter. This is a bitmask holding various adapter‑wide flags (e.g., power state, OID processing state). Applications can poll this flag to monitor adapter status changes.

---

#### 3. `0x224020` – Query and Acknowledge Notification Flag
- **Input buffer**: None.
- **Output buffer**: At least 1 byte.
- **Return value**: `0` on success; `-0x3fffff40` on invalid handle; `0xc0000206` if output buffer is empty.

Reads the low‑byte of the adapter’s field at offset `0x144` (masked with `0xFFFFFF20`), writes it to the output buffer, and then **clears bit 0** of the adapter’s status mask at offset `0x70`. This is typically used to query a notification flag (e.g., “link change”) and simultaneously acknowledge it so that the same event is not reported again.

---

#### 4. `0x228014` – Add MAC Address Filter
- **Input buffer**: Exactly 6 bytes (the MAC address to filter).
- **Output buffer**: Not used.
- **Return value**: `0` on success; `-0x3ffffff3` if the filter context could not be obtained; `0xc000000d` (invalid parameter) if input size is not 6.

Configures the driver to accept frames with a particular destination MAC address. A new filter entry is created, the 6‑byte MAC address is stored inside it, and the entry is linked into the adapter’s active filter list. This may be used to add multicast addresses or to set the adapter’s own MAC address for an upper‑layer protocol binding.

---

#### 5. `0x22801C` – Set Filter Type
- **Input buffer**: 4 bytes (an integer: 1, 2 or 3).
- **Output buffer**: Not used.
- **Return value**: `0` on success; `0xc00000ef` if the integer is out of range.

Used in conjunction with `0x228014`. After adding a filter, this IOCTL sets the filter type by writing the integer into the filter context at offset `0x60`. The allowed values are `1` (unicast?), `2` (multicast?) and `3` (broadcast?). The exact semantics correspond to the NDIS packet filter flags the user‑mode application wishes to emulate.

---

#### 6. `0x228024` – Enable or Disable a MAC Filter
- **Input buffer**: 1 byte (0 = disable, non‑zero = enable).
- **Output buffer**: Not used (the caller may observe the number of bytes transferred as 1).
- **Return value**: `0` on success; `-0x3ffffff3` if the filter context could not be obtained.

Removes the filter from its current list and, if the input byte is non‑zero, inserts it into the **active** filter list (`adapter + 0x10030`). A disabled filter no longer participates in packet matching. This IOCTL effectively toggles the filter’s participation.

---

#### 7. `0x22C004` – Set Packet Filter & Get MAC Address
- **Input buffer**: 8 bytes, containing two 32‑bit values:
  - **First dword** – Command selector, must be `4` to perform the operation.
  - **Second dword** – New packet filter bits (written to adapter offset `0x6C`).
- **Output buffer**: At least 12 bytes:
  - **Offset 0** (4 bytes): Status code (`0` = success, `1` = failure because first dword was not `4`).
  - **Offset 4** (4 bytes): First 4 bytes of the adapter’s current MAC address.
  - **Offset 8** (2 bytes): Last 2 bytes of the adapter’s MAC address.
  - **Offset 10** (2 bytes): Uninitialised (often zero).
- **Return value**: `0` on success; `-0x3fffff40` on invalid handle; `-0x3ffffdfa` if buffer sizes are wrong.

This IOCTL combines setting the *packet filter* (the NDIS OID_GEN_CURRENT_PACKET_FILTER equivalent) and returning the adapter’s permanent MAC. The application uses it to instruct the virtual adapter which types of frames to accept (e.g., directed, multicast, broadcast) and to retrieve the randomly assigned address that the operating system sees.

### General Error Codes

| Error Code          | Meaning                                      |
|---------------------|----------------------------------------------|
| `-0x3fffff40`       | Invalid adapter handle (the adapter is gone) |
| `-0x7ffffffb`       | Output buffer too small for the required data|
| `-0x3ffffff3`       | Could not obtain the internal filter context |
| `-0x3ffffdfa`       | Input/output buffer sizes mismatched         |
| `0xc0000206`        | Zero‑length output buffer when required      |
| `0xc00000bb`        | General “not supported” (unhandled code)     |
| `0xc000000d`        | Invalid parameter (wrong size/type)          |
