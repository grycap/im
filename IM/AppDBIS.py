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

try:
    from urlparse import urlparse
except ImportError:
    from urllib.parse import urlparse
import requests
import re
import time

from radl.radl import Feature, system


class AppDBIS:
    """
    Get AppDBIS data
    """
    DOWNTIME_OUTCOME_VALUES = (ENDED, UPCOMMING, ONGOING) = ('ended', 'upcomming', 'ongoing')
    DEFAULT_APPDBIS_URL = "https://is.appdb.egi.eu"
    REST_API_PATH = "/rest/cloud/computing"
    GRAPH_QL_PATH = "/graphql"

    CACHE_TIMEOUT = 600
    SITES_CACHE = {}
    """Cache of sites info"""

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

    def _call_graphql(self, graph_ql_req):
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        graph_ql_q = '{"query": "%s"}' % graph_ql_req.replace(' ', '').replace('"', '\\"').replace('\n', '')

        resp = requests.request("POST", self.appdbis_url + self.GRAPH_QL_PATH, headers=headers,
                                data=graph_ql_q, verify=self.verify)

        if resp.status_code == 200:
            try:
                data = resp.json()["data"]["siteCloudComputingEndpoints"]["items"]
            except Exception:
                # in case of format not expected return only the text
                return resp.status_code, resp.text
        else:
            return resp.status_code, resp.text

        return 200, data

    def get_sites_supporting_vo(self, vo):
        """
        Get the list of sites that supports an specific VO.
        """
        if vo in AppDBIS.SITES_CACHE:
            res, data_time = AppDBIS.SITES_CACHE[vo]
            if time.time() - data_time > AppDBIS.CACHE_TIMEOUT:
                del AppDBIS.SITES_CACHE[vo]
            else:
                return 200, res

        # GrapghQL Query
        graph_ql_req = """
        {
          siteCloudComputingEndpoints(filter: {
            serviceStatus: {
              value: {ne: CRITICAL}
            },
            images: {
              shareVO:{
                eq: "%s"
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
                  eq: "%s"
                }
              }) {
                items {
                  totalVM,
                  maxVM,
                  projectID
                }
              }
              site {
                name
              }
            }
          }
        }
        """ % (vo, vo)

        code, data = self._call_graphql(graph_ql_req)

        if code == 200:
            res = []
            # Order res by maxVM - totalVM (free VMs)
            data = sorted(data, reverse=True,
                          key=lambda item: (item["shares"]["items"][0]["maxVM"] -
                                            item["shares"]["items"][0]["totalVM"]))
            for elem in data:
                endpoint = urlparse(elem["gocEndpointUrl"])
                res.append((elem["site"]["name"],
                            "%s://%s" % (endpoint[0], endpoint[1]),
                            elem["shares"]["items"][0]["projectID"]))
            AppDBIS.SITES_CACHE[vo] = (res, time.time())
            return code, res
        else:
            return code, data

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
            serviceStatus: {
              value: {ne: CRITICAL}
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

        return self._call_graphql(graph_ql_req)

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
            distribution = ".*"
        version = radl_system.getValue("disk.0.os.version")
        if not version:
            version = ".*"
        vo = radl_system.getValue("disk.0.os.image.vo")
        name = radl_system.getValue("disk.0.os.image.name")
        if not name:
            name = ""

        vo_filter = 'shareVO:"%s"' % vo if vo else None
        code, images = self.get_image_list(image_filter=vo_filter)

        if code != 200:
            return None

        res_systems = []
        for image in images:
            app_name_reg = ".*%s.* \[%s\/%s\/.*]" % (name.lower(), distribution.lower(), version)
            if not re.search(app_name_reg, image['entityName'].lower()):
                continue

            endpoint = urlparse(image["endpointID"])
            res_systems.append(system(radl_system.name,
                                      [Feature("disk.0.image.url", "=", "ost://%s/%s" % (endpoint[1],
                                                                                         image["imageID"])),
                                       Feature("disk.0.image.vo", "=", image["shareVO"])]))

        return res_systems

    def list_images(self, filters=None):
        """
        Get a list of images available on AppDBIS using IM URI format.

        Args:

          - filters(:py:class:`dict` of str objects): Pair key value to filter the list of images.
                                                     It is cloud provider specific.

        Returns: a list dicts with at least two fields "uri" and "name".
        """
        if not filters:
            filters = {}

        if "app" in filters:
            app = filters["app"]
        else:
            app = ""

        if "distribution" in filters:
            distribution = filters["distribution"]
        else:
            distribution = ".*"

        if "vo" in filters:
            vo = filters["vo"]
        else:
            vo = None

        if "version" in filters:
            version = filters["version"]
        else:
            version = ".*"

        vo_filter = 'shareVO:"%s"' % vo if vo else None
        code, images = self.get_image_list(image_filter=vo_filter)

        if code != 200:
            return None

        res = []
        for image in images:
            app_name_reg = ".*%s.* \[%s\/%s\/.*]" % (app.lower(), distribution.lower(), version)
            if not re.search(app_name_reg, image['entityName'].lower()):
                continue

            endpoint = urlparse(image["endpointID"])
            res.append({"uri": "ost://%s/%s" % (endpoint[1], image["imageID"]), "name": image['entityName']})

        if vo:
            code, sites = self.get_sites_supporting_vo(vo)
            if code == 200:
                ordered = []
                # order images using sites
                for name, endpoint, _ in sites:
                    site_host = urlparse(endpoint)[1]
                    for image in res:
                        if site_host in image['uri']:
                            image['name'] = "%s - %s" % (name, image['name'])
                            ordered.append(image)

                return ordered

        return res
