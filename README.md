# Radmin VPN TAP Emulator
❌ Packet duplication and RX/TX instability – Radmin VPN TAP Emulator experimental.

This project emulates the Radmin VPN kernel driver (`\\.\RVPNNETMP`) and bridges its Ethernet traffic to a userspace TAP device (e.g., a Linux TAP interface) via a custom UDP protocol. It allows Radmin VPN to run under Wine (Linux).

## Better Alternatives to Radmin VPN Emulation

This driver emulation is unstable and not production‑ready.  
For reliable, secure connectivity, consider replacing Radmin VPN with one of the following native solutions.

### 1. IPv6
If your ISP supports IPv6 (and most do today), you can connect peers directly using globally routable IPv6 addresses — no NAT, no port forwarding, no proprietary “VLAN over Internet” tricks.

*Why this is powerful:*
*   Every device gets its own global address, so peer‑to‑peer connections work exactly like Radmin VPN but without any additional software.
*   No NAT traversal, no relay servers.
*   Faster, simpler, and built into every modern OS.

**Check whether IPv6 is already working for you:**  
Visit **[test-ipv6.com](https://test-ipv6.com)**. This open‑source site runs entirely in your browser and tests IPv6 reachability, Dual‑Stack behaviour, and DNS resolution. It has been helping users diagnose IPv6 problems since 2010 and is now maintained by a Regional Internet Registry for the public benefit.

Once IPv6 is confirmed working, you can use direct connection in apps/games.

### 2. Tailscale
Zero‑config mesh VPN powered by WireGuard.  
Free for up to 100 devices, works everywhere.
```bash
curl -fsSL https://tailscale.com/install.sh | sh
sudo tailscale up
```
All devices get a stable private IP (100.x.y.z) and can communicate directly.

### 3. WireGuard
Fast, kernel‑level VPN. Easy to set up in a hub‑and‑spoke or mesh topology.

### 4. L2TP/IPsec
Built into every Linux distribution.  

---

| Feature          | Radmin VPN Emulator  | Native Solutions (IPv6 / Tailscale / WireGuard / L2TP) |
|------------------|----------------------|----------------------------------------------------------|
| Stability        | Experimental         | Rock‑solid, kernel‑backed                                |
| Security         | ?                    | Fully encrypted by default                               |
| IPv6 support     |                      | First‑class (especially IPv6‑only setups)                |
| Production ready | ❌                   | ✅                                                       |

Pick the alternative that best fits your network – any of them will be far more reliable than this driver emulation.







## Features
- Hooks `CreateFileW`, `ReadFile`, `WriteFile`, `DeviceIoControl`, `CloseHandle` and `GetOverlappedResult` to simulate the `\\.\RVPNNETMP` device.
- Bridges all Radmin VPN Ethernet frames to a **Linux TAP** interface (Wine) or to a userspace proxy (Windows).
- MAC-based filtering (unicast, multicast, broadcast) as expected by the VPN client.
- Two deployment methods:
  - **Method 1 (Wine):** Inject a DLL (`hooklib.dll`) into `RadminVPN.exe`.
  - **Method 2 (Windows):** Replace the original `RvROLClient.dll` with a generated proxy.

---

## Known Issues

- **Packet duplication and RX/TX instability** – do not use in production.
- **Log files can become huge** – see [Log Management](#log-management) below.

---

## Prerequisites

- **CMake** ≥ 3.15
- **MinGW-w64** (i686‑w64‑mingw32) for cross‑compiling Windows binaries
- **Python 3** (only for Method 2)

---

## Building

Clone the repository and create a build directory:

```bash
mkdir build && cd build
```

### Method 1 – Wine (hooklib injection)

Builds `hooklib.dll`, `inject.exe`, and `start_rvpn.exe`.  
Skips the Windows‑only `RvROLClient.dll` proxy.

```bash
cmake -DBUILD_WINDOWS_COMPONENTS=OFF ..
cmake --build .
```

**After building:**  
Copy `hooklib.dll`, `inject.exe`, and `start_rvpn.exe` from `build/` into Radmin VPN’s installation directory (`Program Files (x86)/Radmin VPN/`).

**Build the Linux TAP bridge:**

```bash
gcc -o linux_tap linux_tap.c -lpthread
```

**Run the bridge** (as root if TAP creation is needed):

```bash
./linux_tap tap1 12345
```

Then start Radmin VPN with Wine.

### Method 2 – Windows (proxy DLL, for testing only)

Generates a proxy `RvROLClient.dll` that replaces the original.

1. **Rename** the original `RvROLClient.dll` to `RvROLClient_orig.dll` and place it **inside the source tree** (alongside `CMakeLists.txt`).  
   The build system will read it and create the proxy stubs.

2. Configure and build:

```bash
cmake -DBUILD_WINDOWS_COMPONENTS=ON ..
cmake --build .
```

3. Copy the newly built `RvROLClient.dll` from `build/` to Radmin VPN’s folder, **overwriting** the original.

---

## Configuration

The emulator reads a simple text‑based configuration file named `radmin.conf` from the same directory as the hook DLL (`hooklib.dll` / `RvROLClient.dll`).  
If the file does not exist, it is automatically created with default values.

### File Location
- **Method 1 (Wine):** `Program Files (x86)/Radmin VPN/radmin.conf`
- **Method 2 (Windows):** same folder as `RvROLClient.dll`

### Parameters

| Key       | Default       | Description                                                                 |
|-----------|---------------|-----------------------------------------------------------------------------|
| `driver`  | `linux_tap`   | **Not currently used** – reserved for future backend selection.             |
| `tap_addr`| `127.0.0.1`   | IP address of the Linux TAP bridge (UDP server).                            |
| `tap_port`| `12345`       | UDP port of the Linux TAP bridge. Must match the port used by `linux_tap`. |

> **Note:** The `driver` field is ignored by the current implementation; only the `linux_tap` backend is supported. Changing this value has no effect.

### Example (`radmin.conf`)
```ini
# Radmin VPN emulation driver config
# driver = linux_tap
driver=linux_tap
# When driver=linux_tap, these are used:
tap_addr=127.0.0.1
tap_port=12345
```
## Log Management

All logging goes to `rvpn_inject.log`.

| Environment | Log location                              |
|-------------|-------------------------------------------|
| Wine        | `%TEMP%\rvpn_inject.log` (typically `/AppData/Local/Temp/`) |
| Windows     | `C:\Windows\Temp\rvpn_inject.log`         |

**Because the driver logs every API call, the file can quickly grow to several gigabytes.**  
- **Clear it periodically:** delete the file while Radmin VPN is closed.  
- **Disable logging permanently:** comment out `InitLog()` and all `LogMsg()` calls in `inject.c`, then rebuild.

---

## Service Startup Tip

To prevent conflicts, set the Radmin control service to **Manual** start instead of Automatic:

```bash
wine reg add "HKLM\System\CurrentControlSet\Services\RvControlSvc" /v Start /t REG_DWORD /d 3 /f
```

Service start type values:
- `2` = Automatic
- `3` = Manual
- `4` = Disabled

---

## Troubleshooting

- **Inject fails?** Make sure the process has the right permissions and the DLL is in the correct directory.  
- **No network?** Verify the Linux TAP bridge is running and the TAP interface (`tap1`) is up.  
- **Fatal error about missing `RvROLClient_orig.dll`:** Copy the original DLL into the project root before building for Method 2.

---

## License

This project is provided “as is” without warranty of any kind. See the source files for individual licensing details.
