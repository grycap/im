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

from connectors.LibCloud import LibCloudCloudConnector
from libcloud.compute.types import Provider
from libcloud.compute.providers import get_driver
from IM.uriparse import uriparse

from IM.radl.radl import Feature

class OpenStackCloudConnector(LibCloudCloudConnector):
    """
    Cloud Launcher to OpenStack using LibCloud (Needs version 0.16.0 or higer version)
    """
    
    type = "OpenStack"
    """str with the name of the provider."""
    
    def get_driver(self, auth_data):
        """
        Get the driver from the auth data

        Arguments:
            - auth(Authentication): parsed authentication tokens.
        
        Returns: a :py:class:`libcloud.compute.base.NodeDriver` or None in case of error
        """
        auth = auth_data.getAuthInfo(self.type)
        
        if auth and 'username' in auth[0] and 'password' in auth[0] and 'tenant' in auth[0]:            
            parameters = {"auth_version":'2.0_password',
                          "auth_url":"http://" + self.cloud.server + ":" + str(self.cloud.port),
                          "auth_token":None,
                          "service_type":None,
                          "service_name":None,
                          "service_region":'regionOne',
                          "base_url":None}
            
            for param in parameters:
                if param in auth[0]:
                    parameters[param] = auth[0][param]
        else:
            self.logger.error("No correct auth data has been specified to OpenStack: username and password")
            return None
        
        cls = get_driver(Provider.OPENSTACK)
        driver = cls(auth[0]['username'], auth[0]['password'],
                     ex_tenant_name=auth[0]['tenant'], 
                     ex_force_auth_url=parameters["auth_url"],
                     ex_force_auth_version=parameters["auth_version"],
                     ex_force_service_region=parameters["service_region"],
                     ex_force_base_url=parameters["base_url"],
                     ex_force_service_name=parameters["service_name"],
                     ex_force_service_type=parameters["service_type"],
                     ex_force_auth_token=parameters["auth_token"])
        
        return driver
    
    def concreteSystem(self, radl_system, auth_data):
        if radl_system.getValue("disk.0.image.url"):
            url = uriparse(radl_system.getValue("disk.0.image.url"))
            protocol = url[0]
            src_host = url[1].split(':')[0]
            # TODO: check the port
            if protocol == "ost" and self.cloud.server == src_host:
                driver = self.get_driver(auth_data)
                
                res_system = radl_system.clone()
                instance_type = self.get_instance_type(driver.list_sizes(), res_system)
                
                res_system.addFeature(Feature("memory.size", "=", instance_type.ram, 'M'), conflict="other", missing="other")
                res_system.addFeature(Feature("disk.0.free_size", "=", instance_type.disk , 'G'), conflict="other", missing="other")
                res_system.addFeature(Feature("price", "=", instance_type.price), conflict="me", missing="other")
                
                res_system.addFeature(Feature("instance_type", "=", instance_type.name), conflict="other", missing="other")
                
                res_system.addFeature(Feature("provider.type", "=", self.type), conflict="other", missing="other")
                res_system.addFeature(Feature("provider.host", "=", self.cloud.server), conflict="other", missing="other")
                res_system.addFeature(Feature("provider.port", "=", self.cloud.port), conflict="other", missing="other")                
                    
                return [res_system]
            else:
                return []
        else:
            return [radl_system.clone()]
