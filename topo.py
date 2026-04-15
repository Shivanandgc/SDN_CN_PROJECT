#!/usr/bin/env python3
"""
Link Failure Detection and Recovery - Mininet Topology
Student: SHIVANAND | Roll: PES2UG24CS473 | Experiment: 36

Topology:
    h1 ── s1 ── s2 ── h2
           |    |
           s3 ──
"""

from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.topo import Topo
from mininet.log import setLogLevel, info
from mininet.cli import CLI
import time


class LinkFailureTopo(Topo):
    def build(self):
        h1 = self.addHost('h1', ip='10.0.0.1/24', mac='00:00:00:00:00:01')
        h2 = self.addHost('h2', ip='10.0.0.2/24', mac='00:00:00:00:00:02')

        s1 = self.addSwitch('s1', cls=OVSKernelSwitch,
                            protocols='OpenFlow13',
                            dpid='0000000000000001')
        s2 = self.addSwitch('s2', cls=OVSKernelSwitch,
                            protocols='OpenFlow13',
                            dpid='0000000000000002')
        s3 = self.addSwitch('s3', cls=OVSKernelSwitch,
                            protocols='OpenFlow13',
                            dpid='0000000000000003')

        self.addLink(h1, s1)
        self.addLink(s1, s2)
        self.addLink(s2, h2)
        self.addLink(s1, s3)
        self.addLink(s3, s2)


def run():
    setLogLevel('info')
    topo = LinkFailureTopo()
    net  = Mininet(
        topo=topo,
        controller=lambda name: RemoteController(
            name, ip='127.0.0.1', port=6633),
        switch=OVSKernelSwitch,
        autoSetMacs=False
    )

    net.start()

    # Disable IPv6 on hosts
    for host in net.hosts:
        host.cmd('sysctl -w net.ipv6.conf.all.disable_ipv6=1 > /dev/null 2>&1')
        host.cmd('sysctl -w net.ipv6.conf.default.disable_ipv6=1 > /dev/null 2>&1')

    info('\n*** Network started\n')
    info('*** Primary path : h1 -> s1 -> s2 -> h2\n')
    info('*** Backup  path : h1 -> s1 -> s3 -> s2 -> h2\n')

    info('\n*** Waiting 8s for controller to connect...\n')
    time.sleep(8)

    # Send ARP pings so controller learns host ports
    info('\n*** Sending warm-up pings so controller learns host ports...\n')
    h1, h2 = net.get('h1', 'h2')
    h1.cmd('arping -c 3 -I h1-eth0 10.0.0.2 > /dev/null 2>&1')
    h2.cmd('arping -c 3 -I h2-eth0 10.0.0.1 > /dev/null 2>&1')
    h1.cmd('ping -c 3 -W 2 10.0.0.2 > /dev/null 2>&1')
    time.sleep(4)

    # ── TEST 1 ─────────────────────────────────────────────────────────
    info('\n*** [TEST 1] Initial connectivity — PRIMARY path (s1 -> s2)\n')
    net.pingAll()
    time.sleep(2)

    # ── FAIL ───────────────────────────────────────────────────────────
    info('\n*** [FAIL] Bringing DOWN primary link: s1 <-> s2\n')
    net.configLinkStatus('s1', 's2', 'down')
    info('*** Waiting 8s for controller to install BACKUP flows...\n')
    time.sleep(8)

    # ── TEST 2 ─────────────────────────────────────────────────────────
    info('\n*** [TEST 2] Connectivity after failure — BACKUP path (s1->s3->s2)\n')
    net.pingAll()
    time.sleep(2)

    # ── RECOVER ────────────────────────────────────────────────────────
    info('\n*** [RECOVER] Restoring primary link: s1 <-> s2\n')
    net.configLinkStatus('s1', 's2', 'up')
    info('*** Waiting 5s for link to stabilise...\n')
    time.sleep(5)

    # ── TEST 3 ─────────────────────────────────────────────────────────
    info('\n*** [TEST 3] Connectivity after recovery\n')
    net.pingAll()

    info('\n*** Opening Mininet CLI — type "exit" to quit\n')
    CLI(net)
    net.stop()


if __name__ == '__main__':
    run()
