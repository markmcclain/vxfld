# vim: tabstop=4 shiftwidth=4 softtabstop=4
# Copyright 2014, 2015 Cumulus Networks, Inc. All rights reserved.
# Copyright (C) 2014 Metacloud Inc.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc.
# 51 Franklin Street, Fifth Floor
# Boston, MA  02110-1301, USA.
""" This module provides classes used by the VXLAN service node Daemon (vxsnd).
"""
import argparse
import atexit
import logging
from random import sample
import socket
import subprocess
import sys
import time

import dpkt
import eventlet
import eventlet.pools

from vxfld.common import config, service, utils
from vxfld.common.enums import NodeType
from vxfld.pkt import vxfld as VXFLD
from vxfld.pkt.vxlan import VXLAN

_NODE_NAME = 'vxsnd'
NODE_TYPE = NodeType.VXSND


class _Fdb(object):
    """ This class provies CRUD methods for the service node daemon's
    forwarding database.
    """
    NO_AGE = sys.maxint

    def __init__(self):
        # fdb[vni] = {addr1: ageout1, addr2: ageout2, ... }
        self.__data = {}

    def __iter__(self):
        return iter(self.__data)

    def add(self, vni, addr, ageout):
        """ Add this <vni, addr> to the fdb.  Just updates the ageout if tuple
        is already in the fdb.
        """
        vni_dict = self.__data.get(vni, dict())
        vni_dict[addr] = ageout
        self.__data[vni] = vni_dict

    def remove(self, vni, addr):
        """ Del the <vni, add> from the fdb.
        """
        if vni in self.__data:
            self.__data[vni].pop(addr, None)
            if not self.__data[vni]:
                del self.__data[vni]

    def get_addrs(self, vni):
        """ Returns all the IP addresses for a VNI in the FDB.
        """
        vni_dict = self.__data.get(vni, dict())
        return vni_dict.keys()

    def ageout(self):
        """ Ages out an IP address for an VNI. Removes the VNI from the
        FDB when all addresses have been aged out.
        """
        now = int(time.time())
        new_fdb = {}
        for vni, vni_dict in self.__data.iteritems():
            new_vni_dict = {
                addr: ageout for addr, ageout in vni_dict.iteritems()
                if now <= ageout or ageout == self.NO_AGE
            }
            if new_vni_dict:
                new_fdb[vni] = new_vni_dict
        self.__data = new_fdb

    def rel_holdtime(self):
        """ This returns a copy of the fdb with the hold times adjusted to
        be relative rather than absolute.  Used for display purposes.
        """
        now = int(time.time())
        adjusted = {}
        for vni in sorted(self.__data, key=self.__data.get):
            adjusted[vni] = {}
            fwdlist = self.__data[vni]
            for addr in sorted(fwdlist, key=fwdlist.get):
                if fwdlist[addr] == self.NO_AGE:
                    holdtime = 'STATIC'
                else:
                    holdtime = fwdlist[addr] - now
                adjusted[vni][addr] = holdtime
        return adjusted


class _Vxsnd(service.Vxfld):
    """ Main Class that provides methods used by Vxlan Service Node Daemon.
    """

    def __init__(self, conf):
        super(_Vxsnd, self).__init__(conf)
        # Addresses for receiving control traffic
        self.__vxfld_refresh_servers = {
            (ip_addr, self._conf.vxfld_port)
            for ip_addr, _ in self._conf.svcnode_peers
        }
        # Addresses for sending refresh messages
        if '0.0.0.0' in {self._conf.src_ip, self._conf.svcnode_ip}:
            self.__vxfld_addresses = {
                ('0.0.0.0', self._conf.vxfld_port)
            }
        else:
            self.__vxfld_addresses = {
                (self._conf.src_ip, self._conf.vxfld_port),
                (self._conf.svcnode_ip, self._conf.vxfld_port)
            }
        # Socket for inter-snd communication
        self.__isocketpool = eventlet.pools.Pool(max_size=1)
        # Socket for flooding
        if not self._conf.no_flood:
            self.__aton_cache = {}
            self.__fsocketpool = eventlet.pools.Pool(max_size=1)
        self.__fdb = _Fdb()

    def _run(self):
        """ Main method
        """
        self._conf.vxlan_listen_port = (
            self._conf.vxlan_listen_port or self._conf.vxlan_port
        )
        self._conf.vxlan_dest_port = (
            self._conf.vxlan_dest_port or self._conf.vxlan_port
        )

        # Install anycast address on lo and associated cleanup on exit
        if self._conf.install_svcnode_ip:
            if (self._conf.svcnode_ip ==
                    config.Config.CommonConfig.svcnode_ip.default):
                raise RuntimeError('Cannot install ANY addr on loopback IF')
            self.__add_ip_addr()
            atexit.register(self.__del_ip_addr)

        # open the sockets
        try:
            if self._conf.enable_vxlan_listen:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                # Set SO_RCVBUF
                # NOTE(cfb): Setting SO_RCVBUF results in the size being 2x the
                # bytes passed to the setsockopt call. As such we
                #             pass it as size/2.
                sock.setsockopt(socket.SOL_SOCKET,
                                socket.SO_RCVBUF,
                                self._conf.receive_queue / 2)
                sock.bind((self._conf.svcnode_ip,
                           self._conf.vxlan_listen_port))
                self._pool.spawn_n(self._serve, sock,
                                   self.__handle_vxlan_packet)
            if not self._conf.no_flood:
                # Don't create this if not flooding.  Then I can run non-root
                self.__fsocketpool.create = (
                    lambda: socket.socket(socket.AF_INET,
                                          socket.SOCK_RAW,
                                          socket.IPPROTO_RAW)
                )
            isock = None
            for ip_addr, port in self.__vxfld_addresses:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.bind((ip_addr, port))
                if isock is None or ip_addr == self._conf.src_ip:
                    isock = sock
                self._pool.spawn_n(self._serve, sock, self.__handle_vxfld_msg)
            if isock is not None:
                self.__isocketpool.create = lambda: isock
        except socket.error as ex:
            raise RuntimeError('opening receive and transmit sockets : %s' %
                               ex)

        # sync the fdb from peer snds
        self.__resync_fdb()

        # periodically ageout stale fdb entries
        next_ageout = 0
        while True:
            now = int(time.time())
            if now >= next_ageout:
                self.__fdb.ageout()
                next_ageout = now + self._conf.age_check
            eventlet.sleep(self._conf.age_check)

    def _process(self, msg):
        """ Returns result object and Exception.  Latter would be
        None if everything is good
        """
        ret = (None, RuntimeError('Unknown error'))
        try:
            if msg['fdb']:
                if msg['add']:
                    vni = int(msg['<vni>'])
                    ip_addr = msg['<ip>']
                    self._logger.info('MgmtServer: fdb set %s %s', vni,
                                      ip_addr)
                    try:
                        socket.inet_aton(ip_addr)
                        self.__fdb.add(vni, ip_addr, _Fdb.NO_AGE)
                        ret = (self.__fdb.rel_holdtime(), None)
                    except Exception as ex:  # pylint: disable=broad-except
                        self._logger.error('MgmtServer: unknown error %s',
                                           ex.message)
                        ret = (None, RuntimeError(ex.message))
                elif msg['del']:
                    vni = int(msg['<vni>'])
                    ip_addr = msg['<ip>']
                    self._logger.info('MgmtServer: fdb del %s %s', vni,
                                      ip_addr)
                    try:
                        self.__fdb.remove(vni, ip_addr)
                        ret = (self.__fdb.rel_holdtime(), None)
                    except Exception as ex:  # pylint: disable=broad-except
                        self._logger.error('MgmtServer: unknown error %s',
                                           ex.message)
                        ret = (None, RuntimeError(ex.message))
                else:
                    self._logger.info('MgmtServer: get fdb')
                    ret = (self.__fdb.rel_holdtime(), None)
            elif msg['get'] and msg['config']:
                if msg['<parameter>'] is not None:
                    parameter = msg['<parameter>']
                    self._logger.info('MgmtServer: get config %s', parameter)
                    parameters = self._conf.get_params()
                    if parameter in parameters:
                        value = parameters.get(parameter, None)
                        ret = ({parameter: value}, None)
                    else:
                        self._logger.error('MgmtServer: unknown parameter %s',
                                           parameter)
                        ret = (None, RuntimeError('Unknown parameter'))
                else:
                    self._logger.info('MgmtServer: get config')
                    ret = (self._conf.get_params(), None)
            elif msg['set'] and msg['config']:
                parameter = msg['<parameter>']
                if parameter in self._conf.get_params():
                    if self._conf.is_reloadable(parameter):
                        value = msg['<value>']
                        if (value is None and
                                not self._conf.is_nullable(parameter)):
                            self._logger.error('MgmtServer: %s cannot be None',
                                               parameter)
                            ret = (None, RuntimeError('Value cannot be None'))
                        else:
                            try:
                                # pylint: disable=broad-except
                                self._logger.info('MgmtServer: set config %s '
                                                  '= %s', parameter, value)
                                self._conf.set_param(parameter, value)
                                parameters = self._conf.get_params()
                                value = parameters.get(parameter, None)
                                ret = ({parameter: value}, None)
                            except Exception as ex:
                                self._logger.error('MgmtServer: unknown error '
                                                   '%s', ex.message)
                                ret = (None, RuntimeError(ex.message))
                    else:
                        self._logger.error('MgmtServer: %s is read-only',
                                           parameter)
                        ret = (None, RuntimeError('Read-Only Parameter'))
                else:
                    self._logger.error('MgmtServer: Unknown parameter %s',
                                       parameter)
                    ret = (None, RuntimeError('Unknown parameter'))
            elif msg['set'] and msg['debug']:
                if msg['on']:
                    try:
                        self._conf.set_param('debug', True)
                        self._logger.setLevel(
                            logging.getLevelName(logging.DEBUG))
                        self._logger.info('MgmtServer: set debug on')
                        ret = ({'debug': True, 'loglevel': 'DEBUG'}, None)
                    except Exception as ex:  # pylint: disable=broad-except
                        self._logger.error('MgmtServer: unknown error %s',
                                           ex.message)
                        ret = (None, RuntimeError(ex.message))
                elif msg['off']:
                    old_loglevel = self._conf.loglevel
                    try:
                        self._conf.set_param('debug', False)
                        self._logger.setLevel(old_loglevel)
                        self._logger.info('MgmtServer: set debug on')
                        ret = ({'debug': False, 'loglevel': old_loglevel},
                               None)
                    except Exception as ex:  # pylint: disable=broad-except
                        self._logger.error('MgmtServer: unknown error %s',
                                           ex.message)
                        ret = (None, RuntimeError(ex.message))
            elif msg['show']:
                op_dict = {
                    'local': self._conf.src_ip,
                    'anycast': self._conf.svcnode_ip,
                    'peers': [ip_addr
                              for ip_addr, _ in self._conf.svcnode_peers]
                }
                if msg['detail']:
                    op_dict.update({
                        'data_port': self._conf.vxlan_port,
                        'ctrl_port': self._conf.vxfld_port
                    })
                ret = (op_dict, None)
            else:
                ret = (None, RuntimeError('Unknown request'))
        except Exception as ex:  # pylint: disable=broad-except
            self._logger.error('MgmtServer: unknown error %s', ex.message)
            ret = (None, RuntimeError(ex.message))
        return ret

    def __resync_fdb(self):
        """ Resyncs FDB from proxy and/or refresh servers
        """
        targets = set()
        # First see if we need to sync from proxies
        if (self._conf.sync_from_proxy and
                self._conf.vxfld_proxy_servers):
            if (len(self._conf.vxfld_proxy_servers) <=
                    self._conf.sync_targets):
                targets.update(self._conf.vxfld_proxy_servers)
            else:
                targets.update(sample(self._conf.vxfld_proxy_servers,
                                      self._conf.sync_targets))
        needed = self._conf.sync_targets - len(targets)
        if needed > 0 and self.__vxfld_refresh_servers:
            possible = self.__vxfld_refresh_servers - self.__vxfld_addresses
            if len(possible) <= needed:
                targets.update(possible)
            else:
                targets.update(sample(possible, needed))
        if targets:
            self._logger.info('Requesting fdb sync from %s', targets)
            pkt = VXFLD.Packet()
            pkt.version = VXFLD.VERSION
            pkt.type = VXFLD.MsgType.REFRESH
            pkt.data = VXFLD.Refresh(holdtime=self._conf.holdtime,
                                     originator=False)
            pkt.data.response_type = VXFLD.ResponseType.ALL
            self.__send_to_peers(pkt, targets)

    def __handle_vxlan_packet(self, pkt, addr, proxy=True, learn=True):
        """ The entry point from the sock receive.
        """
        srcip, _ = addr
        try:
            vxlan_pkt = VXLAN(pkt)
        except Exception as ex:  # pylint: disable=broad-except
            self._logger.error('Unknown VXLAN packet received from %s: %s',
                               srcip, ex.message)
            return

        if not vxlan_pkt.i:
            return

        # Send messages to other proxies
        if proxy and self._conf.vxfld_proxy_servers:
            self.__send_vxfld_proxy(pkt, addr)

        fwd_list = self.__fdb.get_addrs(vxlan_pkt.vni)
        in_fdb = False
        if fwd_list:
            new_fwd_list = []
            for dstip in fwd_list:
                if dstip == srcip:
                    in_fdb = True
                    # Refresh our hold time.
                    self._logger.debug('Refreshing ip %s, vni %d from '
                                       'VXLAN pkt', srcip, vxlan_pkt.vni)
                    self.__fdb.add(vxlan_pkt.vni, srcip,
                                   int(time.time()) + self._conf.holdtime)
                    continue
                new_fwd_list.append(dstip)
            if not self._conf.no_flood:
                self.__flood_vxlan_packet(pkt, addr, vxlan_pkt.vni,
                                          new_fwd_list)

        if not in_fdb and learn:
            # Add this <vni, srcip> to the fdb and tell peers about it
            self._logger.info('Learning ip %s, vni %d from VXLAN pkt', srcip,
                              vxlan_pkt.vni)
            self.__fdb.add(vxlan_pkt.vni, srcip, int(time.time()) +
                           self._conf.holdtime)
            pkt = VXFLD.Packet()
            pkt.version = VXFLD.VERSION
            pkt.type = VXFLD.MsgType.REFRESH
            pkt.data = VXFLD.Refresh(holdtime=self._conf.holdtime,
                                     originator=False)
            pkt.data.add_vni_vteps({vxlan_pkt.vni: [srcip]})
            self.__send_to_peers(pkt, self.__vxfld_refresh_servers)

    def __flood_vxlan_packet(self, pkt, addr, vni, fwd_list):
        """Floods vxlan data packets to addresses in the fwdlist passed to this
        function.
        """
        srcip, srcport = addr
        udp_packet = dpkt.udp.UDP(sport=srcport,
                                  dport=self._conf.vxlan_dest_port,
                                  data=pkt)
        udp_packet.ulen = len(udp_packet)

        # Its quicker to replace the dstip for each VTEP rather than build
        # a new packet each time. As such start with a non-sensical dstip.
        ip_packet = dpkt.ip.IP(dst=socket.inet_aton(srcip),
                               src=socket.inet_aton(srcip),
                               ttl=64,
                               p=dpkt.ip.IP_PROTO_UDP,
                               data=udp_packet)
        ip_packet.len = len(ip_packet)
        with self.__fsocketpool.item() as fsock:
            for dstip in fwd_list:
                self._logger.debug('Sending vxlan pkt from %s to %s, vni %s',
                                   srcip, dstip, vni)
                # Set the dstip in the packet directly to avoid re-packing the
                # whole packet each time.
                if dstip in self.__aton_cache:
                    dst = self.__aton_cache[dstip]
                else:
                    dst = socket.inet_aton(dstip)
                    self.__aton_cache[dstip] = dst

                # This change ensures that the UDP checksum is always correct
                # useful for environments where TX offload isn't possible
                # TODO (markmcclain): reoptimize this later
                ip_packet.data.sum = 0
                ip_packet.dst = dst
                ip_packet_str = str(ip_packet)
                try:
                    fsock.sendto(ip_packet_str, (dstip, 0))
                except Exception as ex:  # pylint: disable=broad-except
                    self._logger.error('Error sending flood packet to rd: %s',
                                       type(ex))

    def __handle_vxfld_refresh(self, pkt, addr):
        """ Handle a membership refresh message.
        """
        srcip, _ = addr
        self._logger.debug('Refresh msg from %s: %s. Holdtime: %s', srcip,
                           pkt.data.vni_vteps, pkt.data.holdtime)
        ageout = int(time.time()) + pkt.data.holdtime
        response_type = pkt.data.response_type
        # Set the response type to None in the refresh message before
        # forwarding it on to peers
        pkt.data.response_type = VXFLD.ResponseType.NONE

        for vni, iplist in pkt.data.vni_vteps.iteritems():
            for ip_addr in iplist:
                if pkt.data.holdtime:
                    self.__fdb.add(vni, ip_addr, ageout)
                else:
                    # holdtime is 0 so delete from fdb
                    self.__fdb.remove(vni, ip_addr)

        if pkt.data.originator:
            if (self._conf.refresh_proxy_servers and
                    self._conf.vxfld_proxy_servers):
                # Send the packet to our proxy servers
                # Proxies may then re-forward so don't change originator
                self.__send_to_peers(pkt, self._conf.vxfld_proxy_servers)
            # Send on to all peers but set originator to 0 so that they do
            # not forward on
            pkt.data.originator = False
            self.__send_to_peers(pkt, self.__vxfld_refresh_servers)

        # Check to see if the originator wants a refresh
        if response_type:
            self.__send_refresh_pkt(pkt, addr, response_type)

    def __handle_vxfld_proxy(self, pkt, addr):
        """ Handle vxsnd to vxsnd proxy messages.
        """
        srcip, _ = addr
        self._logger.info('Proxy msg from %s', srcip)

        # Send messages to other proxies
        if pkt.data.ttl > 1:
            pkt.data.ttl -= 1
            pkt.data.add_proxy_ip(self._conf.proxy_id)
            if self._conf.vxfld_proxy_servers:
                # Check to see if should only proxy packets from our local area
                if self._conf.proxy_local_only:
                    if self._conf.area is not None:
                        if pkt.data.area == self._conf.area:
                            self._logger.debug('Forwarding pxy packet from '
                                               '%s, area %s', srcip,
                                               pkt.data.area)
                            self.__send_to_peers(
                                pkt, self._conf.vxfld_proxy_servers)
                    else:
                        self._logger.error('proxy_local_only requires option '
                                           '"area"')
                else:
                    self._logger.debug('Forwarding pxy packet from %s, area '
                                       '%s', srcip, pkt.data.area)
                    self.__send_to_peers(pkt, self._conf.vxfld_proxy_servers)

        # Flood messages to our local DB
        if self._conf.enable_flooding:
            # Only flood if the packet isn't local
            if self._conf.area is not None:
                if pkt.data.area != self._conf.area:
                    self.__handle_vxlan_packet(pkt.data.vxlan_pkt,
                                               (pkt.data.srcip,
                                                pkt.data.srcport),
                                               proxy=False,
                                               learn=False)
            else:
                self._logger.error('enable_flooding requires option "area"')

    def __send_vxfld_proxy(self, vxlan_pkt, addr):
        """ Generate a VXFLD Proxy packet and send it.
        """
        if self._conf.area is None:
            self._logger.error('Sending proxy packets requires config option '
                               '"area"')
            return
        srcip, srcport = addr
        pkt = VXFLD.Packet()
        pkt.version = VXFLD.VERSION
        pkt.type = VXFLD.MsgType.PROXY
        pkt.data = VXFLD.Proxy()
        pkt.data.srcport = srcport
        pkt.data.srcip = srcip
        pkt.data.area = self._conf.area
        pkt.data.add_proxy_ip(self._conf.proxy_id)
        pkt.data.vxlan_pkt = vxlan_pkt
        self._logger.debug('Sending proxy packet from %s', srcip)
        self.__send_to_peers(pkt, self._conf.vxfld_proxy_servers)

    def __handle_vxfld_msg(self, buf, addr):
        """ This is the entry function for the vxfld message.
        """
        srcip, _ = addr
        try:
            pkt = VXFLD.Packet(buf)
        except Exception as ex:  # pylint: disable=broad-except
            self._logger.error('Unknown VXFLD packet received from %s: %s',
                               srcip, ex.message)
            return
        if pkt.type == VXFLD.MsgType.REFRESH:
            self.__handle_vxfld_refresh(pkt, addr)
        elif pkt.type == VXFLD.MsgType.PROXY:
            self.__handle_vxfld_proxy(pkt, addr)
        else:
            self._logger.error('Unknown VXFLD packet type %s received from %s',
                               pkt.type, srcip)

    def __send_to_peers(self, pkt, servers):
        """ Sends a pkt to one or more servers.
        """
        with self.__isocketpool.item() as isock:
            for ip_addr, port in servers - self.__vxfld_addresses:
                if (pkt.type == VXFLD.MsgType.PROXY and
                        ip_addr in pkt.data.proxy_ips):
                    continue
                try:
                    isock.sendto(str(pkt), (ip_addr, port))
                except Exception:  # pylint: disable=broad-except
                    self._logger.exception('Error sending update to peer snd '
                                           '%s:%d', ip_addr, port)

    def __send_refresh_pkt(self, pkt, addr, response_type):
        """ Sends a VXLAN refresh packet to addr.
        """
        # pylint: disable=missing-docstring
        def send_pkt(pkt_in):
            with self.__isocketpool.item() as isock:
                try:
                    isock.sendto(str(pkt_in), addr)
                except Exception as ex:  # pylint: disable=broad-except
                    # Socket not ready, buffer overflow etc
                    self._logger.error('Error sending refresh reply: %s',
                                       type(ex))
        srcip, _ = addr
        if response_type == VXFLD.ResponseType.REQUESTED:
            vteps = pkt.data.vni_vteps
        elif response_type == VXFLD.ResponseType.ALL:
            self._logger.info('Sending refresh response(all) to %s', srcip)
            vteps = self.__fdb
        else:
            self._logger.error('Unknown response_type requested from %s',
                               srcip)
            return
        vxfld_pkt = refresh_pkt = None
        for vni in vteps:
            addrs = self.__fdb.get_addrs(vni)
            # Limit the refresh message to max_packet_size
            if (vxfld_pkt is None or
                    VXFLD.BASE_PKT_SIZE + len(vxfld_pkt) +
                    len(VXFLD.Refresh.vtep_to_str(vni, addrs)) >=
                    self._conf.max_packet_size):
                if vxfld_pkt is not None:
                    send_pkt(vxfld_pkt)
                vxfld_pkt = VXFLD.Packet(version=pkt.version,
                                         type=VXFLD.MsgType.REFRESH)
                refresh_pkt = (
                    VXFLD.Refresh(originator=False,
                                  holdtime=self._conf.holdtime,
                                  response_type=VXFLD.ResponseType.NONE)
                )
                vxfld_pkt.data = refresh_pkt
            refresh_pkt.add_vni_vteps({vni: addrs})
        if refresh_pkt is not None and refresh_pkt.vni_vteps:
            send_pkt(vxfld_pkt)

    def __add_ip_addr(self):
        """ Adds an IP address to the loopback interface.
        """
        try:
            self._logger.debug('Adding addr %s to loopback',
                               self._conf.svcnode_ip)
            cmd = '/bin/ip addr add %s/32 dev lo' % self._conf.svcnode_ip
            subprocess.check_output(cmd.split(), stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as ex:
            if ex.returncode == 2:
                self._logger.debug('Addr %s already installed',
                                   self._conf.svcnode_ip)
            else:
                # log warning and keep on trucking
                self._logger.warning('Failed to install addr %s on interface. '
                                     'out:%s', self._conf.svcnode_ip,
                                     ex.output, exc_info=True)

    def __del_ip_addr(self):
        """ Called by the exit handler to remove an IP address from the
        loopback interface.
        """
        try:
            self._logger.debug('Removing addr %s from loopback',
                               self._conf.svcnode_ip)
            cmd = '/bin/ip addr del %s/32 dev lo' % self._conf.svcnode_ip
            subprocess.check_output(cmd.split(), stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as ex:
            self._logger.warning('Failed to remove addr %s from interface. '
                                 'out:%s', self._conf.svcnode_ip,
                                 ex.output, exc_info=True)


def main():
    """ Main method
    """
    prsr = utils.common_parser(_NODE_NAME, NODE_TYPE)
    # For running non-sudo.  Disables bind to raw socket
    prsr.add_argument('-R', '--no-flood', action='store_true',
                      help='Turn off flooding')
    args = prsr.parse_args()
    conf = utils.load_configuration(args)
    vxsnd_inst = _Vxsnd(conf)
    return vxsnd_inst.run()
