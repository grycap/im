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

import os
import requests
import xmltodict
try:
    from urlparse import urlparse
except ImportError:
    from urllib.parse import urlparse


class AppDB:
    """
    Get AppDB data
    """
    APPDB_URL = "https://appdb.egi.eu"

    @staticmethod
    def appdb_call(path):
        """
        Basic AppDB REST API call
        """
        resp = requests.request("GET", AppDB.APPDB_URL + path, verify=False)
        if resp.status_code == 200:
            resp.text.replace('\n', '')
            return xmltodict.parse(resp.text)
        else:
            return None

    @staticmethod
    def get_site_id(site_name, stype="occi"):
        """
        Get the site ID from the site name
        """
        data = AppDB.appdb_call('/rest/1.0/sites')
        if data:
            for site in data['appdb:appdb']['appdb:site']:
                if site_name.lower() == site['@name'].lower() and site['@infrastructure'] == "Production":
                    if isinstance(site['site:service'], list):
                        services = site['site:service']
                    else:
                        services = [site['site:service']]
                    for service in services:
                        if service['@type'] == stype:
                            return service['@id']
        else:
            return None

        return None

    @staticmethod
    def get_site_url(site_id, stype="occi"):
        """
        Get the site url from the site ID
        """
        data = AppDB.appdb_call('/rest/1.0/va_providers/%s' % site_id)
        site_url = None
        if data:
            if stype == "openstack":
                if 'provider:url' in data['appdb:appdb']['virtualization:provider']:
                    site_url = data['appdb:appdb']['virtualization:provider']['provider:url']
                    url = urlparse(site_url)
                    site_url = "%s://%s" % url[0:2]
            else:
                if 'provider:endpoint_url' in data['appdb:appdb']['virtualization:provider']:
                    site_url = data['appdb:appdb']['virtualization:provider']["provider:endpoint_url"]

        return site_url

    @staticmethod
    def get_image_id(site_id, image_name, vo_name):
        """
        Get the image ID from the site id, image and vo names
        """
        data = AppDB.appdb_call('/rest/1.0/va_providers/%s' % site_id)
        if data:
            if 'provider:image' in data['appdb:appdb']['virtualization:provider']:
                for image in data['appdb:appdb']['virtualization:provider']['provider:image']:
                    if (image['@archived'] == "false" and image['@appcname'] == image_name and
                            (not vo_name or image['@voname'] == vo_name)):
                        image_basename = os.path.basename(image['@va_provider_image_id'])
                        parts = image_basename.split("#")
                        if len(parts) > 1:
                            return parts[1]
                        else:
                            return image_basename

        return None

    @staticmethod
    def get_image_data(str_url, stype="occi"):
        """
        The url has this format: appdb://UPV-GRyCAP/egi.docker.ubuntu.16.04?fedcloud.egi.eu
        or this one appdb://UPV-GRyCAP/83d5e854-a128-5b1f-9457-d32e10a720a6:8135
        Get the Site url from the AppDB
        """
        url = urlparse(str_url)
        protocol = url[0]

        if protocol == "appdb":
            site_name = url[1]
            image_name = url[2][1:]
            vo_name = url[4]

            site_id = AppDB.get_site_id(site_name, stype)
            if not site_id:
                return None, None, "No site ID returned from EGI AppDB for site: %s." % site_name

            site_url = AppDB.get_site_url(site_id, stype)
            if not site_url:
                return None, None, "No site URL returned from EGI AppDB for site id: %s." % site_id

            if not vo_name and len(image_name) >= 37 and ":" in image_name:
                image_id = AppDB.get_image_id_from_uri(site_id, image_name)
                if not image_id:
                    return None, None, "No image ID returned from EGI AppDB for image: %s/%s." % (site_id,
                                                                                                  image_name)
            else:
                image_id = AppDB.get_image_id(site_id, image_name, vo_name)
                if not image_id:
                    return None, None, "No image ID returned from EGI AppDB for image: %s/%s/%s." % (site_id,
                                                                                                     image_name,
                                                                                                     vo_name)

            return site_url, image_id, ""

        return None, None, "Incorrect Protocol"

    @staticmethod
    def get_image_id_from_uri(site_id, image_mp_uri):
        """
        Get the image ID from the site id and image mp_uri
        """
        if not image_mp_uri.startswith("http"):
            image_mp_uri = "https://appdb.egi.eu/store/vo/image/%s/" % image_mp_uri

        data = AppDB.appdb_call('/rest/1.0/va_providers/%s' % site_id)
        if data:
            if 'provider:image' in data['appdb:appdb']['virtualization:provider']:
                for image in data['appdb:appdb']['virtualization:provider']['provider:image']:
                    if image['@mp_uri'] == image_mp_uri:
                        image_basename = os.path.basename(image['@va_provider_image_id'])
                        parts = image_basename.split("#")
                        if len(parts) > 1:
                            return parts[1]
                        else:
                            return image_basename

        return None
