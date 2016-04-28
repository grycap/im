# IM - Infrastructure Manager
# Copyright (C) 2011 - GRyCAP - Universitat Politecnica de Valencia
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import socket
from xmlobject import XMLObject


class EXTRA_ELEMENT(XMLObject):
    attributes = ['NAME', 'VAL']


class EXTRA_DATA(XMLObject):
    tuples_lists = {'EXTRA_ELEMENT': EXTRA_ELEMENT}


class METRIC(XMLObject):
    attributes = ['NAME', 'VAL', 'TYPE', 'UNITS',
                  'TN', 'TMAX', 'DMAX', 'SLOPE', 'SOURCE']
    tuples = {'EXTRA_DATA': EXTRA_DATA}


class HOST(XMLObject):
    attributes = ['NAME', 'IP', 'TN', 'REPORTED',
                  'TMAX', 'DMAX', 'LOCATION', 'GMOND_STARTED']
    tuples_lists = {'METRIC': METRIC}


class CLUSTER(XMLObject):
    attributes = ['NAME', 'LOCALTIME', 'OWNER', 'LATLONG', 'URL']
    tuples_lists = {'HOST': HOST}


class GRID(XMLObject):
    attributes = ['NAME', 'LOCALTIME', 'AUTHORITY']
    tuples_lists = {'CLUSTER': CLUSTER}


class GANGLIA_XML(XMLObject):
    attributes = ['VERSION', 'SOURCE']
    tuples_lists = {'GRID': GRID}


class ganglia_info:

    ganglia_port = 8651

    @staticmethod
    def update_ganglia_info(inf):
        port_open = False

        if not inf.vm_master:
            return (False, "VM master is None")
        master_ip = inf.vm_master.getPublicIP()
        if master_ip:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2)
                if(s.connect_ex((master_ip, ganglia_info.ganglia_port)) == 0):
                    port_open = True
            except Exception, ex:
                return (False, "Error connecting to ganglia: " + str(ex))
        else:
            return (False, "VM master without public IP")

        if not port_open:
            return (False, "Port " + str(ganglia_info.ganglia_port) + " from IP: " + str(master_ip) + " is closed")

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((master_ip, ganglia_info.ganglia_port))
            data = sock.recv(1024)
            str_data = ""
            while len(data):
                str_data += data
                data = sock.recv(1024)
            sock.close()

            data_lines = str_data.split('\n')
            data = ""
            found = False
            for line in data_lines:
                if found:
                    data += line
                elif line.strip().startswith('<GANGLIA_XML'):
                    found = True
                    data += line

            # logger.debug("Ganglia Info: " + data)
            xml_data = GANGLIA_XML(data)

            if len(data) == 0 or len(xml_data.GRID) == 0 or len(xml_data.GRID[0].CLUSTER) == 0:
                return (False, "No information available or with incorrect format")

            # De momento solo muestro una parte de la informacion
            # Estos son todos los que hay:
            # machine_type, disk_free, bytes_out, proc_total, gexec, pkts_in, cpu_nice, cpu_speed, boottime,
            # cpu_wio, os_name, load_one, os_release, disk_total, cpu_user, cpu_idle, swap_free, pkts_out,
            # mem_cached, load_five, cpu_num, load_fifteen, mem_free, cpu_system, proc_run, mem_total,
            # cpu_aidle, bytes_in, mem_buffers, mem_shared, swap_total, part_max_used
            for grid in xml_data.GRID:
                for cluster in grid.CLUSTER:
                    for host in cluster.HOST:
                        for vm in inf.get_vm_list():
                            if vm.hasIP(host.IP):
                                for metric in host.METRIC:
                                    if metric.NAME == 'disk_free':
                                        float_val = float(metric.VAL)
                                        vm.info.systems[0].setValue(
                                            "disk.0.free_size", float_val, metric.UNITS)
                                    if metric.NAME == 'cpu_idle':
                                        float_val = float(metric.VAL)
                                        vm.info.systems[0].setValue(
                                            "cpu.usage", int(100.0 - float_val))
                                    if metric.NAME == 'mem_free':
                                        float_val = float(metric.VAL)
                                        vm.info.systems[0].setValue(
                                            "memory.free", float_val, metric.UNITS)
                                    if metric.NAME == 'swap_free':
                                        float_val = float(metric.VAL)
                                        vm.info.systems[0].setValue(
                                            "swap.free", float_val, metric.UNITS)
                                    if metric.NAME == 'swap_total':
                                        float_val = float(metric.VAL)
                                        vm.info.systems[0].setValue(
                                            "swap", float_val, metric.UNITS)

        except Exception, ex:
            return (False, "Error getting ganglia information: " + str(ex))

        return (True, "")
