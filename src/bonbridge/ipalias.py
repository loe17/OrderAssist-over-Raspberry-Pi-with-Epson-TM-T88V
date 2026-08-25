"""Find free IP addresses and hand them to the printers automatically.

Why this exists
---------------

A POS application such as OrderAssist addresses a receipt printer as
``<ip>:9100`` and offers no way to change the port.  One device with two USB
printers therefore needs **two IP addresses** - one per print group - because
the address is the only thing that distinguishes them.

Until now that meant doing it by hand: pick an address, hope it is free,
create a systemd unit per address, type the address into the printer entry.
Three chances to get it wrong, and the most common failure is silent: an
address that is free *today* gets handed to a phone by the router tomorrow,
and from then on receipts go missing without anything on the device looking
broken.

This module does the same job with the two things a human cannot easily do:
it **asks the network** whether an address is really free, and it **keeps
asking** afterwards.

How "free" is decided
---------------------

By ARP, the way RFC 5227 (IPv4 Address Conflict Detection) specifies it:

* An ARP *request* for the candidate address is broadcast with the sender
  protocol address set to **0.0.0.0**.  That is the important detail - a probe
  must not claim the address it is asking about, otherwise the probe itself
  would poison every ARP cache on the segment with an address we do not own
  yet.
* If anything answers, the address is taken - and the answering MAC address is
  recorded, which is what later distinguishes "somebody else took it" from
  "this is our own alias".
* Three probes are sent, because a single lost broadcast would otherwise look
  like an empty address.

ARP is authoritative here in a way that ping is not: hosts routinely drop
ICMP echo (every Windows machine does by default) but no IPv4 host can refuse
to answer ARP and still use the network.  A ping-based check would happily
declare a busy Windows PC's address free.

Where a raw socket is not available - not Linux, or the daemon was stripped of
``CAP_NET_RAW`` - the module falls back to ``ping`` plus the kernel's
neighbour table and says so in the result, rather than pretending to the same
level of confidence.

The DHCP problem, stated plainly
--------------------------------

Verifying an address is free proves nothing about tomorrow.  If the chosen
address lies inside the router's DHCP pool, the router may lease it to another
device later and the collision is real.  So:

* candidates are taken from the **top of the subnet** by default, which is
  where DHCP pools least often reach, and
* the address stays under observation: every ``monitor_interval`` seconds each
  alias is probed again, and an answer from a foreign MAC becomes a health
  warning naming the intruder.

Neither replaces excluding the range from the DHCP pool in the router, and the
web interface says so at the point where the feature is switched on.

Persistence
-----------

Addresses added with ``ip addr add`` are gone after a reboot.  Rather than
writing systemd units, BonBridge records what it created in ``state.json`` and
re-creates it at start-up - after probing again, so an address that was taken
over in the meantime is not blindly re-claimed but replaced.

References
----------
* RFC 5227, IPv4 Address Conflict Detection:
  https://www.rfc-editor.org/rfc/rfc5227
* RFC 826, An Ethernet Address Resolution Protocol:
  https://www.rfc-editor.org/rfc/rfc826
* ``ip-address(8)`` (iproute2): https://man7.org/linux/man-pages/man8/ip-address.8.html
"""

from __future__ import annotations

import logging
import re
import shutil
import socket
import struct
import subprocess
import sys
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

from . import state

log = logging.getLogger(__name__)

ETH_P_ARP = 0x0806
ARP_REQUEST = 1
ARP_REPLY = 2
BROADCAST_MAC = b"\xff" * 6
ZERO_MAC = b"\x00" * 6

#: Label prefix for addresses BonBridge created.  ``ip`` requires a label to
#: start with the interface name followed by a colon, so the full label looks
#: like ``eth0:bb1``.  It is what makes our own aliases recognisable in
#: ``ip addr`` output even after a restart with an empty state file.
LABEL_PREFIX = "bb"

#: Section name in state.json.
STATE_SECTION = "ip_aliases"

DEFAULT_SETTINGS: Dict[str, Any] = {
    "auto_assign": False,
    "interface": "auto",
    "range": "auto",
    "probe_attempts": 3,
    "monitor": True,
    "monitor_interval": 300.0,
    "candidates": 6,
}


# --------------------------------------------------------------------------
# Address arithmetic (no ipaddress module gymnastics, just integers)
# --------------------------------------------------------------------------


def ip_to_int(address: str) -> int:
    return struct.unpack(">I", socket.inet_aton(address))[0]


def int_to_ip(value: int) -> str:
    return socket.inet_ntoa(struct.pack(">I", value & 0xFFFFFFFF))


def network_range(address: str, prefixlen: int) -> Tuple[int, int]:
    """First and last *usable host* address of the subnet, as integers."""
    if prefixlen < 0 or prefixlen > 32:
        raise ValueError("prefix length out of range")
    mask = (0xFFFFFFFF << (32 - prefixlen)) & 0xFFFFFFFF if prefixlen else 0
    network = ip_to_int(address) & mask
    broadcast = network | (~mask & 0xFFFFFFFF)
    if prefixlen >= 31:  # /31 and /32 have no network/broadcast convention
        return network, broadcast
    return network + 1, broadcast - 1


def same_subnet(a: str, b: str, prefixlen: int) -> bool:
    mask = (0xFFFFFFFF << (32 - prefixlen)) & 0xFFFFFFFF if prefixlen else 0
    return (ip_to_int(a) & mask) == (ip_to_int(b) & mask)


def parse_range(spec: str) -> Optional[Tuple[int, int]]:
    """``"192.168.1.240-192.168.1.250"`` or ``"192.168.1.240-250"``."""
    spec = (spec or "").strip()
    if not spec or spec.lower() == "auto":
        return None
    if "-" not in spec:
        try:
            single = ip_to_int(spec)
        except OSError:
            return None
        return single, single
    left, right = spec.split("-", 1)
    left = left.strip()
    right = right.strip()
    try:
        start = ip_to_int(left)
    except OSError:
        return None
    try:
        end = ip_to_int(right) if "." in right else (start & 0xFFFFFF00) | int(right)
    except (OSError, ValueError):
        return None
    if end < start:
        start, end = end, start
    return start, end


# --------------------------------------------------------------------------
# What the machine currently has
# --------------------------------------------------------------------------

_IP_LINE = re.compile(
    r"^\d+:\s+(?P<dev>\S+)\s+inet\s+(?P<addr>\d+\.\d+\.\d+\.\d+)/(?P<plen>\d+)\s+(?P<rest>.*)$"
)


def _run(command: List[str], timeout: float = 5.0) -> Tuple[int, str]:
    try:
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            check=False,
        )
        return result.returncode, result.stdout.decode("utf-8", "replace").strip()
    except FileNotFoundError:
        return 127, f"{command[0]} not found"
    except subprocess.TimeoutExpired:
        return 124, "timeout"
    except OSError as exc:  # pragma: no cover - defensive
        return 1, str(exc)


def parse_addresses(text: str) -> List[Dict[str, Any]]:
    """Parse ``ip -o -4 addr show`` output into dictionaries.

    Kept separate from the subprocess call so it can be tested with captured
    output on any machine.
    """
    entries: List[Dict[str, Any]] = []
    for line in text.splitlines():
        line = line.strip()
        match = _IP_LINE.match(line)
        if not match:
            continue
        # ``ip -o`` folds the second line in with a literal backslash, which
        # would otherwise end up glued to the last token (``eth0:bb1\``).
        rest = match.group("rest").replace("\\", " ")
        device = match.group("dev")
        label = ""
        for token in rest.split():
            if token.startswith(device + ":"):
                label = token
                break
        if not label and rest.split() and rest.split()[-1] == device:
            label = device
        entries.append(
            {
                "interface": device,
                "address": match.group("addr"),
                "prefixlen": int(match.group("plen")),
                "label": label,
                "secondary": "secondary" in rest.split(),
                "dynamic": "dynamic" in rest.split(),
                "managed": bool(label) and label.startswith(f"{device}:{LABEL_PREFIX}"),
            }
        )
    return entries


def list_addresses() -> List[Dict[str, Any]]:
    code, output = _run(["ip", "-o", "-4", "addr", "show", "scope", "global"])
    if code != 0:
        log.debug("ip addr show failed (%s): %s", code, output)
        return []
    return parse_addresses(output)


def primary_address(interface: str = "auto") -> Optional[Dict[str, Any]]:
    """The address a new alias should be modelled on.

    Preference: a real (non-managed, non-secondary) address, on the requested
    interface if one was named.  Managed aliases are skipped on purpose -
    deriving the subnet from our own alias would survive a mistake forever.
    """
    entries = list_addresses()
    wanted = (interface or "auto").strip()
    candidates = [e for e in entries if not e["managed"]]
    if wanted and wanted != "auto":
        candidates = [e for e in candidates if e["interface"] == wanted]
    for entry in candidates:
        if not entry["secondary"]:
            return entry
    return candidates[0] if candidates else None


def managed_addresses() -> List[Dict[str, Any]]:
    return [entry for entry in list_addresses() if entry["managed"]]


def local_mac(interface: str) -> Optional[bytes]:
    try:
        with open(f"/sys/class/net/{interface}/address", "r", encoding="ascii") as handle:
            text = handle.read().strip()
    except OSError:
        return None
    try:
        return bytes(int(part, 16) for part in text.split(":"))
    except ValueError:
        return None


def format_mac(raw: Optional[bytes]) -> str:
    if not raw:
        return ""
    return ":".join(f"{byte:02x}" for byte in raw)


def default_gateway() -> str:
    """Read the IPv4 default gateway from ``/proc/net/route``."""
    try:
        with open("/proc/net/route", "r", encoding="ascii") as handle:
            for line in handle.readlines()[1:]:
                fields = line.split()
                if len(fields) > 2 and fields[1] == "00000000":
                    packed = struct.pack("<I", int(fields[2], 16))
                    return socket.inet_ntoa(packed)
    except (OSError, ValueError):
        pass
    return ""


# --------------------------------------------------------------------------
# Is this address free?  (RFC 5227 probe)
# --------------------------------------------------------------------------

HAVE_AF_PACKET = hasattr(socket, "AF_PACKET") and sys.platform.startswith("linux")


def build_arp_probe(sender_mac: bytes, target_ip: str) -> bytes:
    """An ARP request with sender IP 0.0.0.0, exactly as RFC 5227 requires."""
    ethernet = BROADCAST_MAC + sender_mac + struct.pack(">H", ETH_P_ARP)
    arp = (
        struct.pack(">HHBBH", 1, 0x0800, 6, 4, ARP_REQUEST)
        + sender_mac
        + socket.inet_aton("0.0.0.0")
        + ZERO_MAC
        + socket.inet_aton(target_ip)
    )
    frame = ethernet + arp
    if len(frame) < 60:  # pad to the minimum Ethernet frame size
        frame += b"\x00" * (60 - len(frame))
    return frame


def parse_arp_frame(frame: bytes) -> Optional[Dict[str, Any]]:
    """Return sender MAC/IP and operation of an ARP frame, or ``None``."""
    if len(frame) < 42:
        return None
    if struct.unpack(">H", frame[12:14])[0] != ETH_P_ARP:
        return None
    htype, ptype, hlen, plen, oper = struct.unpack(">HHBBH", frame[14:22])
    if htype != 1 or ptype != 0x0800 or hlen != 6 or plen != 4:
        return None
    return {
        "operation": oper,
        "sender_mac": frame[22:28],
        "sender_ip": socket.inet_ntoa(frame[28:32]),
        "target_ip": socket.inet_ntoa(frame[38:42]),
    }


def arp_probe(
    interface: str,
    target_ip: str,
    attempts: int = 3,
    wait: float = 0.6,
) -> Dict[str, Any]:
    """Ask the segment who owns ``target_ip``.

    Returns ``{"supported", "in_use", "mac", "error"}``.  ``supported`` is
    ``False`` when no raw socket could be opened - the caller then decides
    whether to fall back, rather than getting a confident "free" that was
    never actually tested.
    """
    result: Dict[str, Any] = {"supported": False, "in_use": False, "mac": "", "error": ""}
    if not HAVE_AF_PACKET:
        result["error"] = "AF_PACKET not available on this platform"
        return result
    mac = local_mac(interface)
    if not mac:
        result["error"] = f"cannot read MAC address of {interface}"
        return result

    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ARP))
    except (OSError, AttributeError) as exc:
        result["error"] = f"raw socket: {exc}"
        return result

    result["supported"] = True
    frame = build_arp_probe(mac, target_ip)
    try:
        sock.bind((interface, socket.htons(ETH_P_ARP)))
        sock.settimeout(0.2)
        for _ in range(max(1, attempts)):
            try:
                sock.send(frame)
            except OSError as exc:
                result["error"] = f"send: {exc}"
                return result
            deadline = time.monotonic() + wait
            while time.monotonic() < deadline:
                try:
                    data = sock.recv(1024)
                except socket.timeout:
                    continue
                except OSError as exc:
                    result["error"] = f"recv: {exc}"
                    return result
                parsed = parse_arp_frame(data)
                if not parsed or parsed["sender_ip"] != target_ip:
                    continue
                if parsed["sender_mac"] == mac:
                    # Our own frame, seen on the packet socket - not an answer.
                    continue
                if parsed["operation"] not in (ARP_REQUEST, ARP_REPLY):
                    continue
                result["in_use"] = True
                result["mac"] = format_mac(parsed["sender_mac"])
                return result
    finally:
        try:
            sock.close()
        except OSError:
            pass
    return result


def ping_probe(target_ip: str, timeout: float = 1.0) -> Dict[str, Any]:
    """Fallback check: ping once, then look in the neighbour table.

    Deliberately weaker than ARP and labelled as such: a host that drops ICMP
    still shows up in ``ip neigh`` after the ping, because the kernel had to
    resolve the address before it could send anything at all.
    """
    result: Dict[str, Any] = {"supported": False, "in_use": False, "mac": "", "error": ""}
    if not shutil.which("ping"):
        result["error"] = "ping not installed"
        return result
    result["supported"] = True
    code, _ = _run(["ping", "-n", "-c", "1", "-W", str(max(1, int(timeout))), target_ip], timeout=timeout + 2)
    if code == 0:
        result["in_use"] = True
    code, output = _run(["ip", "-4", "neigh", "show", target_ip])
    if code == 0:
        for line in output.splitlines():
            fields = line.split()
            if not fields or fields[0] != target_ip:
                continue
            if "lladdr" in fields:
                mac = fields[fields.index("lladdr") + 1]
                if "FAILED" not in line and "INCOMPLETE" not in line:
                    result["in_use"] = True
                    result["mac"] = mac
    return result


def check_address(interface: str, target_ip: str, attempts: int = 3) -> Dict[str, Any]:
    """Combined check, reporting which method actually produced the answer."""
    arp = arp_probe(interface, target_ip, attempts=attempts)
    if arp["supported"] and not arp["error"]:
        return {
            "address": target_ip,
            "free": not arp["in_use"],
            "method": "arp",
            "mac": arp["mac"],
            "detail": "",
        }
    ping = ping_probe(target_ip)
    if ping["supported"]:
        return {
            "address": target_ip,
            "free": not ping["in_use"],
            "method": "ping",
            "mac": ping["mac"],
            "detail": arp["error"] or "no raw socket",
        }
    return {
        "address": target_ip,
        "free": False,
        "method": "none",
        "mac": "",
        "detail": arp["error"] or ping["error"] or "no probe method available",
    }


# --------------------------------------------------------------------------
# Candidate generation
# --------------------------------------------------------------------------


def candidate_addresses(
    base: str,
    prefixlen: int,
    spec: str = "auto",
    exclude: Optional[List[str]] = None,
    limit: int = 32,
) -> List[str]:
    """Addresses worth probing, best first.

    ``auto`` walks **downwards from the top of the subnet**.  Routers hand out
    DHCP leases from the bottom or the middle far more often than from the last
    few addresses, so this is where a manually chosen address is least likely
    to be overrun - and it is the same advice the print-group documentation has
    always given, now applied automatically.
    """
    first, last = network_range(base, prefixlen)
    blocked = {ip_to_int(a) for a in (exclude or []) if a}
    blocked.add(ip_to_int(base))
    gateway = default_gateway()
    if gateway:
        try:
            blocked.add(ip_to_int(gateway))
        except OSError:
            pass

    window = parse_range(spec)
    if window:
        start, end = window
        start = max(start, first)
        end = min(end, last)
        order = range(start, end + 1)
    else:
        order = range(last, first - 1, -1)

    result: List[str] = []
    for value in order:
        if value in blocked:
            continue
        result.append(int_to_ip(value))
        if len(result) >= limit:
            break
    return result


# --------------------------------------------------------------------------
# Creating and removing aliases
# --------------------------------------------------------------------------


def add_alias(interface: str, address: str, prefixlen: int, index: int) -> Tuple[bool, str]:
    label = f"{interface}:{LABEL_PREFIX}{index}"
    code, output = _run(
        ["ip", "addr", "add", f"{address}/{prefixlen}", "dev", interface, "label", label]
    )
    if code == 0:
        log.info("Added IP alias %s/%s on %s (%s)", address, prefixlen, interface, label)
        return True, label
    if "File exists" in output:
        log.info("IP alias %s already present on %s", address, interface)
        return True, label
    log.warning("Cannot add %s/%s on %s: %s", address, prefixlen, interface, output)
    return False, output


def remove_alias(interface: str, address: str, prefixlen: int) -> Tuple[bool, str]:
    code, output = _run(["ip", "addr", "del", f"{address}/{prefixlen}", "dev", interface])
    if code == 0 or "Cannot assign requested address" in output:
        log.info("Removed IP alias %s/%s from %s", address, prefixlen, interface)
        return True, ""
    log.warning("Cannot remove %s/%s from %s: %s", address, prefixlen, interface, output)
    return False, output


# --------------------------------------------------------------------------
# The manager
# --------------------------------------------------------------------------


class AliasManager:
    """Owns the automatic assignment and keeps watching what it created.

    The manager never touches an address a human configured.  It only ever
    adds, re-adds or removes addresses that are recorded in its own state, and
    it only ever writes a printer's ``bind`` when that printer was left on
    ``0.0.0.0`` - the value that means "no fixed address chosen".
    """

    def __init__(
        self,
        settings: Optional[Dict[str, Any]] = None,
        on_change: Optional[Callable[[], None]] = None,
    ):
        self.settings = dict(DEFAULT_SETTINGS)
        self.settings.update(settings or {})
        self.on_change = on_change
        self.last_scan: List[Dict[str, Any]] = []
        #: The most recent proposal, so the web interface can show it again
        #: after a page reload instead of probing the network once more.
        self.last_plan: List[Dict[str, Any]] = []
        self.last_error = ""
        self.last_run = 0.0
        self.conflicts: List[Dict[str, Any]] = []
        self._lock = threading.RLock()
        self._monitor: Optional["_Monitor"] = None

    # -- state -----------------------------------------------------------

    def records(self) -> Dict[str, Any]:
        return dict(state.section(STATE_SECTION) or {})

    def _remember(self, address: str, entry: Optional[Dict[str, Any]]) -> None:
        data = state.load().setdefault(STATE_SECTION, {})
        if entry is None:
            data.pop(address, None)
        else:
            data[address] = entry
        state.save()

    # -- reading the situation -------------------------------------------

    def base(self) -> Optional[Dict[str, Any]]:
        return primary_address(str(self.settings.get("interface") or "auto"))

    def snapshot(self, printers: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
        base = self.base()
        present = {entry["address"]: entry for entry in list_addresses()}
        records = self.records()
        names = {p["id"]: p.get("name") or p["id"] for p in (printers or [])}
        aliases = []
        for address, entry in sorted(records.items()):
            printer_id = entry.get("printer", "")
            aliases.append(
                {
                    "address": address,
                    "interface": entry.get("interface", ""),
                    "prefixlen": entry.get("prefixlen", 24),
                    "printer": printer_id,
                    # The id is what the configuration keys on; the name is
                    # what the user gave the printer and recognises.
                    "printer_name": names.get(printer_id, printer_id),
                    "created": entry.get("created", 0),
                    "method": entry.get("method", ""),
                    "present": address in present,
                    "conflict": next(
                        (c for c in self.conflicts if c["address"] == address), None
                    ),
                }
            )
        needs = [p["id"] for p in self._printers_needing(printers or [])]
        return {
            "supported": HAVE_AF_PACKET,
            "probe": "arp" if HAVE_AF_PACKET else "ping",
            "settings": dict(self.settings),
            "interface": base["interface"] if base else "",
            "base_address": base["address"] if base else "",
            "prefixlen": base["prefixlen"] if base else 0,
            "gateway": default_gateway(),
            "aliases": aliases,
            "addresses": list_addresses(),
            "candidates": self.last_scan,
            "plan": self.last_plan,
            "conflicts": self.conflicts,
            "needs_address": needs,
            "last_error": self.last_error,
            "last_run": self.last_run,
        }

    # -- scanning ---------------------------------------------------------

    def scan(self, count: int = 0) -> Dict[str, Any]:
        """Probe candidate addresses and report which ones answered."""
        with self._lock:
            base = self.base()
            if not base:
                self.last_error = "no IPv4 address on this device"
                return {"ok": False, "error": self.last_error, "candidates": []}
            wanted = int(count or self.settings.get("candidates") or 6)
            attempts = int(self.settings.get("probe_attempts") or 3)
            taken = [entry["address"] for entry in list_addresses()]
            pool = candidate_addresses(
                base["address"],
                base["prefixlen"],
                str(self.settings.get("range") or "auto"),
                exclude=taken,
                limit=max(wanted * 4, 12),
            )
            found: List[Dict[str, Any]] = []
            checked = 0
            for address in pool:
                checked += 1
                result = check_address(base["interface"], address, attempts)
                found.append(result)
                if len([f for f in found if f["free"]]) >= wanted:
                    break
                if checked >= max(wanted * 4, 12):
                    break
            self.last_scan = found
            self.last_run = time.time()
            self.last_error = ""
            free = [f["address"] for f in found if f["free"]]
            log.info(
                "IP alias scan on %s/%s: %s checked, %s free",
                base["interface"],
                base["prefixlen"],
                len(found),
                len(free),
            )
            return {
                "ok": True,
                "interface": base["interface"],
                "prefixlen": base["prefixlen"],
                "candidates": found,
                "free": free,
            }

    # -- assignment -------------------------------------------------------

    @staticmethod
    def _printers_needing(printers: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Printers that are enabled and have no fixed address of their own."""
        return [
            printer
            for printer in printers
            if printer.get("enabled", True)
            and str(printer.get("bind") or "0.0.0.0") in ("", "0.0.0.0")
        ]

    def plan(
        self,
        printers: List[Dict[str, Any]],
        force: bool = False,
    ) -> Dict[str, Any]:
        """Work out which address each printer would get - and change nothing.

        Separated from ``apply`` because assigning an address is not a
        reversible little detail: it changes where the POS application has to
        point, and that has to be typed in by a human afterwards.  So the
        proposal is shown first, printer by printer, and only what was
        confirmed is carried out.

        ``force`` plans even when only one printer exists.  Without it, a
        single printer is left on ``0.0.0.0`` on purpose: it then answers on
        *every* address of the device, which needs no extra address at all.
        """
        with self._lock:
            base = self.base()
            if not base:
                self.last_error = "no IPv4 address on this device"
                return {"ok": False, "error": self.last_error, "proposals": []}

            enabled = [p for p in printers if p.get("enabled", True)]
            needing = self._printers_needing(printers)
            if not needing:
                return {"ok": True, "proposals": [], "note": "nothing to do"}
            if len(enabled) < 2 and not force:
                return {
                    "ok": True,
                    "proposals": [],
                    "note": "only one printer - a separate address is not needed",
                }

            attempts = int(self.settings.get("probe_attempts") or 3)
            taken = [entry["address"] for entry in list_addresses()]
            pool = candidate_addresses(
                base["address"],
                base["prefixlen"],
                str(self.settings.get("range") or "auto"),
                exclude=taken,
                limit=max(len(needing) * 6, 16),
            )
            proposals: List[Dict[str, Any]] = []
            checks: List[Dict[str, Any]] = []

            for printer in needing:
                chosen: Optional[Dict[str, Any]] = None
                error = ""
                while pool:
                    address = pool.pop(0)
                    result = check_address(base["interface"], address, attempts)
                    checks.append(result)
                    if result["method"] == "none":
                        error = result["detail"]
                        self.last_error = error
                        break
                    if result["free"]:
                        chosen = result
                        break
                proposals.append(
                    {
                        "printer": printer["id"],
                        "name": printer.get("name", printer["id"]),
                        "address": chosen["address"] if chosen else "",
                        "prefixlen": base["prefixlen"],
                        "interface": base["interface"],
                        "method": chosen["method"] if chosen else "",
                        "error": "" if chosen else (error or "no free address found"),
                    }
                )

            self.last_scan = checks or self.last_scan
            self.last_run = time.time()
            self.last_plan = proposals
            return {
                "ok": all(p["address"] for p in proposals),
                "proposals": proposals,
                "checks": checks,
                "interface": base["interface"],
                "prefixlen": base["prefixlen"],
            }

    def apply(
        self,
        printers: List[Dict[str, Any]],
        assignments: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Carry out a confirmed mapping of printer -> address.

        Every address is probed **again** here, even though the plan just
        probed it: between showing the proposal and the user pressing the
        button there is human time, which is exactly long enough for a phone
        to be switched on. An address may also have been typed in by hand.
        """
        with self._lock:
            base = self.base()
            if not base:
                self.last_error = "no IPv4 address on this device"
                return {"ok": False, "error": self.last_error, "assigned": []}

            by_id = {printer["id"]: printer for printer in printers}
            attempts = int(self.settings.get("probe_attempts") or 3)
            index = self._next_index()
            assigned: List[Dict[str, Any]] = []
            failures: List[Dict[str, Any]] = []
            existing = {entry["address"] for entry in list_addresses()}
            records = self.records()

            for wanted in assignments or []:
                printer_id = str(wanted.get("printer") or "")
                address = str(wanted.get("address") or "").strip()
                printer = by_id.get(printer_id)
                if printer is None:
                    failures.append({"printer": printer_id, "error": "unknown printer"})
                    continue
                if not address:
                    continue
                try:
                    ip_to_int(address)
                except OSError:
                    failures.append({"printer": printer_id, "error": f"'{address}' is not an IPv4 address"})
                    continue
                if not same_subnet(address, base["address"], base["prefixlen"]):
                    failures.append(
                        {
                            "printer": printer_id,
                            "error": f"{address} is not in {base['address']}/{base['prefixlen']}",
                        }
                    )
                    continue
                if address in existing and address not in records:
                    failures.append(
                        {"printer": printer_id, "error": f"{address} already belongs to this device"}
                    )
                    continue

                if address not in existing:
                    check = check_address(base["interface"], address, attempts)
                    if check["method"] == "none":
                        failures.append({"printer": printer_id, "error": check["detail"]})
                        continue
                    if not check["free"]:
                        failures.append(
                            {
                                "printer": printer_id,
                                "error": f"{address} answered from {check['mac'] or 'another device'}",
                            }
                        )
                        continue
                    ok, detail = add_alias(
                        base["interface"], address, base["prefixlen"], index
                    )
                    if not ok:
                        failures.append({"printer": printer_id, "error": detail})
                        continue
                    index += 1
                    method = check["method"]
                    label = detail
                else:
                    method = str((records.get(address) or {}).get("method") or "")
                    label = str((records.get(address) or {}).get("label") or "")

                self._remember(
                    address,
                    {
                        "interface": base["interface"],
                        "prefixlen": base["prefixlen"],
                        "printer": printer_id,
                        "created": time.time(),
                        "method": method,
                        "label": label,
                    },
                )
                printer["bind"] = address
                existing.add(address)
                assigned.append(
                    {
                        "printer": printer_id,
                        "name": printer.get("name", printer_id),
                        "address": address,
                        "prefixlen": base["prefixlen"],
                        "interface": base["interface"],
                        "method": method,
                    }
                )

            if assigned and self.on_change:
                try:
                    self.on_change()
                except Exception as exc:  # noqa: BLE001 - a callback must not break assignment
                    log.warning("IP alias callback failed: %s", exc)
            return {"ok": not failures, "assigned": assigned, "failed": failures}

    def assign(
        self,
        printers: List[Dict[str, Any]],
        force: bool = False,
    ) -> Dict[str, Any]:
        """Plan and immediately apply - the unattended path used at start-up."""
        planned = self.plan(printers, force=force)
        if not planned.get("proposals"):
            return {
                "ok": planned.get("ok", True),
                "assigned": [],
                "failed": [],
                "note": planned.get("note", ""),
                "error": planned.get("error", ""),
            }
        result = self.apply(
            printers,
            [
                {"printer": p["printer"], "address": p["address"]}
                for p in planned["proposals"]
                if p["address"]
            ],
        )
        result.setdefault("failed", []).extend(
            {"printer": p["printer"], "error": p["error"]}
            for p in planned["proposals"]
            if not p["address"]
        )
        result["ok"] = not result["failed"]
        result["checks"] = planned.get("checks") or []
        return result

    def _next_index(self) -> int:
        used = set()
        for entry in self.records().values():
            label = str(entry.get("label") or "")
            match = re.search(rf"{LABEL_PREFIX}(\d+)$", label)
            if match:
                used.add(int(match.group(1)))
        for entry in managed_addresses():
            match = re.search(rf"{LABEL_PREFIX}(\d+)$", entry.get("label") or "")
            if match:
                used.add(int(match.group(1)))
        index = 1
        while index in used:
            index += 1
        return index

    # -- start-up ---------------------------------------------------------

    def restore(self, printers: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Re-create the recorded aliases after a reboot.

        Each address is probed again first.  If somebody else answers, the
        address is *not* re-claimed - it is dropped from the record and the
        printer falls back to ``0.0.0.0`` so it keeps working while the web
        interface reports the conflict.  Silently re-adding a duplicate address
        would break both devices.
        """
        results: Dict[str, Any] = {"restored": [], "dropped": [], "kept": []}
        records = self.records()
        if not records:
            return results
        present = {entry["address"] for entry in list_addresses()}
        attempts = int(self.settings.get("probe_attempts") or 3)
        changed = False

        for address, entry in sorted(records.items()):
            interface = entry.get("interface") or ""
            prefixlen = int(entry.get("prefixlen") or 24)
            if address in present:
                results["kept"].append(address)
                continue
            if not interface:
                continue
            check = check_address(interface, address, attempts)
            if not check["free"] and check["method"] != "none":
                log.warning(
                    "Recorded alias %s is now used by %s - not re-claiming it",
                    address,
                    check["mac"] or "another device",
                )
                self.conflicts.append(
                    {
                        "address": address,
                        "mac": check["mac"],
                        "printer": entry.get("printer", ""),
                        "seen": time.time(),
                    }
                )
                self._remember(address, None)
                for printer in printers:
                    if printer.get("id") == entry.get("printer") and printer.get("bind") == address:
                        printer["bind"] = "0.0.0.0"
                        changed = True
                results["dropped"].append(address)
                continue
            ok, detail = add_alias(interface, address, prefixlen, self._next_index())
            if ok:
                entry["label"] = detail
                self._remember(address, entry)
                results["restored"].append(address)
            else:
                results["dropped"].append(address)
        if changed and self.on_change:
            try:
                self.on_change()
            except Exception as exc:  # noqa: BLE001
                log.warning("IP alias callback failed: %s", exc)
        return results

    # -- removal ----------------------------------------------------------

    def release(self, address: str, printers: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
        with self._lock:
            entry = self.records().get(address)
            if not entry:
                return {"ok": False, "error": "not a BonBridge alias"}
            ok, detail = remove_alias(
                entry.get("interface", ""), address, int(entry.get("prefixlen") or 24)
            )
            self._remember(address, None)
            self.conflicts = [c for c in self.conflicts if c["address"] != address]
            changed = False
            for printer in printers or []:
                if printer.get("bind") == address:
                    printer["bind"] = "0.0.0.0"
                    changed = True
            if changed and self.on_change:
                try:
                    self.on_change()
                except Exception as exc:  # noqa: BLE001
                    log.warning("IP alias callback failed: %s", exc)
            return {"ok": ok, "error": "" if ok else detail, "address": address}

    def release_all(self, printers: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
        removed = []
        for address in list(self.records().keys()):
            result = self.release(address, printers)
            if result.get("ok"):
                removed.append(address)
        return {"ok": True, "removed": removed}

    # -- ongoing conflict detection ---------------------------------------

    def check_conflicts(self) -> List[Dict[str, Any]]:
        """Probe our own aliases and report anyone else answering for them."""
        found: List[Dict[str, Any]] = []
        attempts = int(self.settings.get("probe_attempts") or 3)
        present = {entry["address"] for entry in list_addresses()}
        for address, entry in sorted(self.records().items()):
            interface = entry.get("interface") or ""
            if not interface:
                continue
            if address not in present:
                found.append(
                    {
                        "address": address,
                        "kind": "missing",
                        "mac": "",
                        "printer": entry.get("printer", ""),
                        "seen": time.time(),
                    }
                )
                continue
            probe = arp_probe(interface, address, attempts=attempts)
            if probe["supported"] and probe["in_use"] and probe["mac"]:
                found.append(
                    {
                        "address": address,
                        "kind": "duplicate",
                        "mac": probe["mac"],
                        "printer": entry.get("printer", ""),
                        "seen": time.time(),
                    }
                )
        self.conflicts = found
        return found

    def start_monitor(self) -> None:
        if not self.settings.get("monitor", True):
            return
        if not self.records():
            return
        if self._monitor is not None:
            return
        self._monitor = _Monitor(self, float(self.settings.get("monitor_interval") or 300.0))
        self._monitor.start()

    def stop(self) -> None:
        if self._monitor is not None:
            self._monitor.stop()
            self._monitor = None


class _Monitor(threading.Thread):
    """Re-probes the managed aliases at a slow, boring interval."""

    def __init__(self, manager: AliasManager, interval: float):
        super().__init__(name="ipalias-monitor", daemon=True)
        self.manager = manager
        self.interval = max(60.0, interval)
        self._stop_event = threading.Event()

    def run(self) -> None:
        # A first pass shortly after start, then on the configured interval.
        if self._stop_event.wait(20.0):
            return
        while not self._stop_event.is_set():
            try:
                conflicts = self.manager.check_conflicts()
                if conflicts:
                    log.warning("IP alias conflicts: %s", conflicts)
            except Exception as exc:  # noqa: BLE001 - a watchdog must not die
                log.debug("IP alias monitor: %s", exc)
            if self._stop_event.wait(self.interval):
                return

    def stop(self) -> None:
        self._stop_event.set()
