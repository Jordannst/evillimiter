import time
import socket
from netaddr import EUI, NotRegisteredError
from scapy.all import srp, Ether, ARP # pylint: disable=no-name-in-module
from concurrent.futures import ThreadPoolExecutor

from .host import Host
from evillimiter.console.io import IO
        

class HostScanner(object):
    def __init__(self, interface, iprange):
        self.interface = interface
        self.iprange = iprange
        self.timeout = 2       # time in s to wait for ARP responses

    @staticmethod
    def _get_vendor(mac):
        """
        Resolve device vendor/manufacturer from MAC OUI prefix.
        Uses netaddr's built-in IEEE OUI database.
        Returns empty string if vendor unknown.
        """
        try:
            return EUI(mac).oui.registration().org
        except (NotRegisteredError, IndexError, Exception):
            return ''

    def scan(self, iprange=None):
        """
        Broadcast ARP scan using srp() — sends all requests at once.
        ~10x faster than individual sr1() calls per IP.
        """
        iprange = self.iprange if iprange is None else iprange
        target_ips = [str(x) for x in iprange]

        IO.ok('scanning {} addresses...'.format(len(target_ips)))

        # single broadcast ARP sweep — all IPs scanned simultaneously
        packets = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target_ips)
        start_time = time.time()

        try:
            answered, _ = srp(packets, timeout=self.timeout, iface=self.interface, verbose=0)
        except KeyboardInterrupt:
            IO.ok('aborted.')
            return []

        elapsed = time.time() - start_time
        hosts = []

        for sent, received in answered:
            ip = received.psrc
            mac = received.hwsrc
            vendor = self._get_vendor(mac)

            # resolve hostname (non-blocking, fast timeout)
            name = ''
            try:
                host_info = socket.gethostbyaddr(ip)
                name = '' if host_info is None else host_info[0]
            except socket.herror:
                pass

            host = Host(ip, mac, name)
            host.vendor = vendor
            hosts.append(host)

        IO.ok('scan completed in {:.1f}s.'.format(elapsed))
        return hosts

    def scan_for_reconnects(self, hosts, iprange=None):
        """
        Broadcast ARP scan to detect hosts that reconnected with different IPs.
        """
        iprange = self.iprange if iprange is None else iprange
        target_ips = [str(x) for x in iprange]

        packets = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target_ips)

        try:
            answered, _ = srp(packets, timeout=self.timeout, iface=self.interface, verbose=0)
        except Exception:
            return {}

        scanned_hosts = []
        for sent, received in answered:
            ip = received.psrc
            mac = received.hwsrc
            scanned_hosts.append(Host(ip, mac, ''))

        reconnected_hosts = {}
        for host in hosts:
            for s_host in scanned_hosts:
                if host.mac == s_host.mac and host.ip != s_host.ip:
                    s_host.name = host.name
                    s_host.vendor = getattr(host, 'vendor', '')
                    reconnected_hosts[host] = s_host

        return reconnected_hosts