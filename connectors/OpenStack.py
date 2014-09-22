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

import boto.ec2
from connectors.EC2 import EC2CloudConnector, InstanceTypeInfo
from IM.uriparse import uriparse
from IM.radl.radl import Feature

class OpenStackCloudConnector(EC2CloudConnector):
    
    type = "OpenStack"
    # In case of using OpenStack set these details
    OPENSTACK_EC2_PATH="/services/Cloud"
    INSTANCE_TYPE = 'm1.tiny'


    def concreteSystem(self, radl_system, auth_data):
        if radl_system.getValue("disk.0.image.url"):
            url = uriparse(radl_system.getValue("disk.0.image.url"))
            protocol = url[0]
            protocol = url[0]
            src_host = url[1].split(':')[0]
            # TODO: check the port
            if protocol == "ost" and self.cloud.server == src_host:
                res_system = radl_system.clone()
                if res_system.getValue('disk.0.os.credentials.private_key'):
                    res_system.delValue('disk.0.os.credentials.password')
                
                instance_type = self.get_instance_type(res_system)

                res_system.addFeature(Feature("cpu.count", "=", instance_type.num_cpu * instance_type.cores_per_cpu), conflict="other", missing="other")
                res_system.addFeature(Feature("memory.size", "=", instance_type.mem, 'M'), conflict="other", missing="other")
                res_system.addFeature(Feature("disk.0.free_size", "=", instance_type.disks * instance_type.disk_space, 'G'), conflict="other", missing="other")
                res_system.addFeature(Feature("cpu.performance", "=", instance_type.cpu_perf, 'ECU'), conflict="other", missing="other")
                res_system.addFeature(Feature("price", "=", instance_type.price), conflict="me", missing="other")
                res_system.addFeature(Feature("virtual_system_type", "=", "ec2"), conflict="other", missing="other")
                
                res_system.addFeature(Feature("instance_type", "=", instance_type.name), conflict="other", missing="other")
                
                res_system.addFeature(Feature("provider.type", "=", self.type), conflict="other", missing="other")
                res_system.addFeature(Feature("provider.host", "=", self.cloud.server), conflict="other", missing="other")
                res_system.addFeature(Feature("provider.port", "=", self.cloud.port), conflict="other", missing="other")                
                    
                return [res_system]
            else:
                return []
        else:
            return [radl_system.clone()]

    # Get the EC2 connection object
    def get_connection(self, region_name, auth_data):
        conn = None
        try:
            auth = auth_data.getAuthInfo(OpenStackCloudConnector.type)
            if auth and 'username' in auth[0] and 'password' in auth[0]:            
                region = boto.ec2.regioninfo.RegionInfo(name="nova", endpoint=self.cloud.server)
                conn = boto.connect_ec2(aws_access_key_id=auth[0]['username'],
                          aws_secret_access_key=auth[0]['password'],
                          is_secure=False,
                          region=region,
                          port=self.cloud.port,
                          path=self.OPENSTACK_EC2_PATH)
            else:
                self.logger.error("Datos de autenticacion incorrectos")
        except Exception, e:
            print "Error getting the region " + region_name + ": "
            print e
            self.logger.error("Error getting the region " + region_name + ": ")
            self.logger.error(e)

        return conn
    
    def get_instace_type(self, radl):
        cpu = radl.getValue('cpu.count')
        arch = radl.getValue('cpu.arch')
        memory = radl.getValue('memory.size')

        instace_types = OpenStackInstanceTypes.get_all_instance_types()

        res = None
        for type in instace_types:
                # cogemos la de menor precio
                if res is None or (type.price <= res.price):
                        if arch in type.cpu_arch and type.cores_per_cpu * type.num_cpu >= cpu and type.mem >= memory:
                                res = type
        
        if res is None:
                self.logger.debug("Lanzaremos una instancia de tipo: " + self.INSTANCE_TYPE)
                return OpenStackInstanceTypes.get_instance_type_by_name(self.INSTANCE_TYPE)
        else:
                self.logger.debug("Lanzaremos una instancia de tipo: " + res.name)
                return res

class OpenStackInstanceTypes:
    @staticmethod
    def get_all_instance_types():
        list = []
        
        # A Definir con la plataforma concreta o sacarlo de algun modo (API propia o LibCloud)
        t1_micro = InstanceTypeInfo("m1.tiny", ["x86_64"], 1, 1, 512, 0, 0)
        list.append(t1_micro)
        
        return list

    @staticmethod
    def get_instance_type_by_name(name):
        for type in OpenStackInstanceTypes.get_all_instance_types():
            if type.name == name:
                return type
        return None