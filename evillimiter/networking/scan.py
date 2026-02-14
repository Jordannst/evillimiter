import sys
import time
import socket
import threading
from netaddr import EUI, NotRegisteredError
from scapy.all import srp, Ether, ARP # pylint: disable=no-name-in-module

from .host import Host
from evillimiter.console.io import IO
        

class HostScanner(object):
    _SPINNER = '⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'

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

    def _spinner_thread(self, total, stop_event):
        """Animated spinner shown while srp() scan is in progress."""
        i = 0
        while not stop_event.is_set():
            elapsed = time.time() - self._scan_start
            frame = self._SPINNER[i % len(self._SPINNER)]
            msg = '\r  {} scanning {} addresses... ({:.1f}s)'.format(frame, total, elapsed)
            sys.stdout.write(msg)
            sys.stdout.flush()
            i += 1
            stop_event.wait(0.1)
        # clear spinner line
        sys.stdout.write('\r' + ' ' * 60 + '\r')
        sys.stdout.flush()

    def scan(self, iprange=None):
        """
        Broadcast ARP scan using srp() — sends all requests at once.
        ~10x faster than individual sr1() calls per IP.
        """
        iprange = self.iprange if iprange is None else iprange
        target_ips = [str(x) for x in iprange]

        # single broadcast ARP sweep — all IPs scanned simultaneously
        packets = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target_ips)
        self._scan_start = time.time()

        # start spinner
        stop_event = threading.Event()
        spinner = threading.Thread(target=self._spinner_thread, args=(len(target_ips), stop_event), daemon=True)
        spinner.start()

        try:
            answered, _ = srp(packets, timeout=self.timeout, iface=self.interface, verbose=0)
        except KeyboardInterrupt:
            stop_event.set()
            spinner.join()
            IO.ok('aborted.')
            return []

        # stop spinner
        stop_event.set()
        spinner.join()

        elapsed = time.time() - self._scan_start
        hosts = []

        for sent, received in answered:
            ip = received.psrc
            mac = received.hwsrc
            vendor = self._get_vendor(mac)

            # resolve hostname
            name = ''
            try:
                host_info = socket.gethostbyaddr(ip)
                name = '' if host_info is None else host_info[0]
            except socket.herror:
                pass

            host = Host(ip, mac, name)
            host.vendor = vendor
            hosts.append(host)

        IO.ok('{} hosts discovered in {:.1f}s.'.format(len(hosts), elapsed))
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