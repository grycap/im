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

import os.path
import requests

from IM.config import Config
from radl.radl import Feature, system


class AppDBIS:
    """
    Get AppDBIS data
    """
    DOWNTIME_OUTCOME_VALUES = (ENDED, UPCOMMING, ONGOING) = ('ended', 'upcomming', 'ongoing')
    DEFAULT_APPDBIS_URL = "http://is.marie.hellasgrid.gr"
    REST_API_PATH = "/rest/cloud/computing"
    GRAPH_QL_PATH = "/graphql"

    def __init__(self, url=None, verify=False):
        self.verify = verify
        if url is not None:
            self.appdbis_url = url
        else:
            self.appdbis_url = self.DEFAULT_APPDBIS_URL

    def get_all_paged_results(self, url, limit=100):
        """
        Helper function to get paginated results
        """
        res = []
        total_count = 999999999
        skip = 0

        sep_char = "?"
        if "?" in url:
            sep_char = "&"

        while skip < total_count:
            surl = url + sep_char + "limit=%s&skip=%s" % (limit, skip)
            resp = requests.request("GET", surl, verify=self.verify)
            if resp.status_code == 200:
                data = resp.json()
                if data["totalCount"] < total_count:
                    total_count = data["totalCount"]
                res.extend(data["data"])
            else:
                return resp.status_code, resp.text

            skip += limit

        return 200, res

    def get_images_from_site(self, site):
        """
        Get the list of images of the specified site
        """
        name_filter = 'site.name::eq:"%s"' % site
        return self.get_image_list(image_filter=name_filter)

    def get_image_list(self, limit=100, image_filter=None):
        """
        Get the list of images from the REST API
        """
        url = self.appdbis_url + self.REST_API_PATH + "/images"
        if image_filter:
            url += "?filter=" + image_filter
        return self.get_all_paged_results(url, limit)

    def get_image(self, image_id):
        """
        Get the data of the specified image from the REST API
        """
        resp = requests.request("GET", self.appdbis_url + self.REST_API_PATH + "/images/%s" % image_id,
                                verify=self.verify)
        if resp.status_code == 200:
            return 200, resp.json()["data"]
        else:
            return resp.status_code, resp.text

    def get_endpoints_and_images(self, vo, app_name_filter, cpus, mem_in_mb):
        """
        Get the list of sites that supports an specific VO and has some templates
        with at least the specified cpus and mem. Also get the images of the specified VO
        and S.O. (distribution and version)
        """
        # GrapghQL Query
        graph_ql_req = """
        {
          siteCloudComputingEndpoints(filter: {
            templates: {
              CPU: {gt: %s},
              RAM: {gt: %s}
            },
            images: {
              entityName: {
                ilike: "%s"
              },
              shareVO:{
                ilike: "%s"
              }
            },
            isInProduction:true,
            beta:false,
            endpointServiceType: {
              eq: "org.openstack.nova"
            }
          }) {
            items {
              gocEndpointUrl,
              shares(filter: {
                VO:{
                  ilike: "%s"
                }
              }) {
                items {
                  totalVM,
                  maxVM,
                  runningVM,
                  suspendedVM,
                  VO
                }
              }
              serviceStatus{
                value,
                timestamp
              },
              serviceDowntimes {
                outcome,
                severity,
                endDate
              },
              site {
                name
              },
              images(filter: {
                entityName:{
                  ilike: "%s"
                },
                shareVO:{
                  ilike: "%s"
                }
              }) {
                totalCount,
                items {
                  share {
                    projectID,
                    VO
                  },
                  OSFamily,
                  OSName,
                  OSVersion,
                  OSPlatform,
                  entityName,
                  imageID
                }
              }
            }
          }
        }
        """ % (cpus, mem_in_mb, app_name_filter, vo, vo, app_name_filter, vo)

        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        graph_ql_req = '{"query": "%s"}' % graph_ql_req.replace(' ', '').replace('"', '\\"').replace('\n', '')

        resp = requests.request("POST", self.appdbis_url + self.GRAPH_QL_PATH, headers=headers,
                                data=graph_ql_req, verify=self.verify)

        if resp.status_code == 200:
            try:
                data = resp.json()["data"]["siteCloudComputingEndpoints"]["items"]
            except Exception:
                # in case of format not expected return only the text
                return resp.status_code, resp.text
        else:
            return resp.status_code, resp.text

        return 200, data

    def search_vm(self, radl_system):
        """
        Get a list of the most suitable VM according to the requirements
        expressed by the user.

        Args:

        - radl_system(system): system that AppDBIS will search compatible configurations.

        Return(None or list of system): available virtual machines
        """
        if radl_system.getValue("disk.0.image.url"):
            return []

        distribution = radl_system.getValue("disk.0.os.flavour")
        if not distribution:
            distribution = "*"
        version = radl_system.getValue("disk.0.os.version")
        if not version:
            version = "*"
        cpus = radl_system.getValue("cpu.count")
        if not cpus:
            cpus = Config.DEFAULT_VM_CPUS
        mem_in_mb = Config.DEFAULT_VM_MEMORY
        if radl_system.getFeature('memory.size'):
            mem_in_mb = radl_system.getFeature('memory.size').getValue('M')
        vo = radl_system.getValue("disk.0.os.image.vo")
        if not vo:
            vo = "*"
        name = radl_system.getValue("disk.0.os.image.name")
        if not name:
            name = ""

        app_name_filter = "*%s* [%s/%s/*]" % (name, distribution, version)
        code, res = self.get_endpoints_and_images(vo, app_name_filter, cpus, mem_in_mb)

        # Order res by maxVM - totalVM (free VMs)
        res = sorted(res, reverse =True,
                     key=lambda item: (item["shares"]["items"][0]["maxVM"] - item["shares"]["items"][0]["totalVM"] ))

        if code != 200:
            return None
        res_systems = []
        for site in res:
            url = site["gocEndpointUrl"]
            # Ignore sites in critical state
            if site["serviceStatus"]["value"] == "CRITICAL":
                continue

            if url.endswith("/"):
                url = url[0:-1]
            if url.endswith("v3"):
                url = url[0:-3]
            if url.endswith("v2.0"):
                url = url[0:-5]

            for image in site["images"]["items"]:
                res_systems.append(system(radl_system.name,
                                          [Feature("disk.0.image.url", "=", "%s/%s" % (url, image["imageID"])),
                                           Feature("disk.0.image.vo", "=", image["share"]["VO"])]))

        return res_systems
