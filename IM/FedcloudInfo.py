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
import re

try:
    from urlparse import urlparse
except ImportError:
    from urllib.parse import urlparse

from radl.radl import Feature, system


class FedcloudInfo:
    """
    Get FedCloud data
    """

    CLOUDINFO_URL = "https://is.cloud.egi.eu"

    @staticmethod
    def cloudinfo_call(path, params=None):
        """
        Basic Cloud info REST API call
        """
        data = None
        resp = requests.request("GET", FedcloudInfo.CLOUDINFO_URL + path, params=params)
        if resp.status_code == 200:
            data = resp.json()
        return data

    @staticmethod
    def get_site_url(site_name):
        """
        Get the site url from the site name
        """
        if not site_name:
            return None
        data = FedcloudInfo.cloudinfo_call(f"/site/{site_name}/")
        site_url = None
        if data:
            if data["url"].endswith("/"):
                data["url"] = data["url"][:-1]
            site_url = data["url"].rsplit("/", 1)[0]
        return site_url

    @staticmethod
    def get_image_id(site_name, image_name, vo_name):
        """
        Get the image ID from the site id, appdb image and vo names
        """
        images = []
        data = FedcloudInfo.cloudinfo_call(f"/site/{site_name}/{vo_name}/images")
        if data:
            for image in data:
                if image.get("appdb_id", "") == image_name:
                    try:
                        images.append((image["id"], image["version"]))
                    except KeyError:
                        continue
        image = None
        if len(images) == 1:
            # If there are only one, get it
            image = images[0][0]
        elif len(images) > 1:
            # if there are more than one, try to return last vmiversion
            images = sorted(images, key=lambda x: x[1], reverse=True)  # sort by version
            image = images[0][0]

        if image:
            parts = image.split("#")
            if len(parts) > 1:
                return parts[1]
            else:
                return image

        return None

    @staticmethod
    def _get_site_name(site_host):
        """
        Get the name if site.
        site may be the name itself or the site_url.
        """
        data = FedcloudInfo.cloudinfo_call("/sites/")
        if data:
            for site in data:
                if site["hostname"] == site_host:
                    return site["name"]
        else:
            return None

    @staticmethod
    def get_image_data(str_url, vo=None, site_host=None):
        """
        The url has this format: appdb://UPV-GRyCAP/egi.docker.ubuntu.16.04?fedcloud.egi.eu
        this format: appdb://egi.docker.ubuntu.16.04?fedcloud.egi.eu
        or this one appdb://UPV-GRyCAP/83d5e854-a128-5b1f-9457-d32e10a720a6:8135
        Get the Site url from the FedcloudInfo
        """
        url = urlparse(str_url)
        protocol = url[0]

        if protocol == "appdb":
            if url[2]:
                site_name = url[1]
                image_name = url[2][1:]
            else:
                site_name = FedcloudInfo._get_site_name(site_host)
                image_name = url[1]
            vo_name = url[4]

            if not site_name:
                return (
                    None,
                    None,
                    "No site name returned from EGI FedcloudInfo for site host: %s."
                    % site_host,
                )
            site_url = FedcloudInfo.get_site_url(site_name)
            if not site_url:
                return (
                    None,
                    None,
                    "No site URL returned from EGI FedcloudInfo for site: %s."
                    % site_name,
                )

            if not vo_name and len(image_name) >= 37 and ":" in image_name:
                image_id = FedcloudInfo.get_image_id_from_uri(site_name, image_name)
                if not image_id:
                    return (
                        None,
                        None,
                        "No image ID returned from EGI FedcloudInfo for image: %s/%s."
                        % (site_name, image_name),
                    )
            else:
                if not vo_name:
                    vo_name = vo
                image_id = FedcloudInfo.get_image_id(site_name, image_name, vo_name)
                if not image_id:
                    return (
                        None,
                        None,
                        "No image ID returned from EGI FedcloudInfo for image: %s/%s/%s."
                        % (site_name, image_name, vo_name),
                    )

            return site_url, image_id, ""

        return None, None, "Incorrect Protocol"

    @staticmethod
    def get_image_id_from_uri(site_name, image_mp_uri):
        """
        Get the image ID from the site id and image mp_uri
        """
        if not image_mp_uri.startswith("http"):
            image_mp_uri = f"https://appdb.egi.eu/store/vo/image/{image_mp_uri}/"

        data = FedcloudInfo.cloudinfo_call(f"/site/{site_name}/images")
        if data:
            for image in data:
                if image["mpuri"] == image_mp_uri:
                    image_basename = os.path.basename(image["id"])
                    parts = image_basename.split("#")
                    if len(parts) > 1:
                        return parts[1]
                    else:
                        return image_basename
        return None

    @staticmethod
    def get_project_ids(site_name):
        projects = {}
        data = FedcloudInfo.cloudinfo_call(f"/site/{site_name}/projects")
        if data:
            projects = {p["name"]: p["id"] for p in data}
        return projects

    @staticmethod
    def get_sites_supporting_vo(vo_name=None):
        res = []
        data = FedcloudInfo.cloudinfo_call("/sites/", params={"vo_name": vo_name})
        if data:
            for site in data:
                vo_info = FedcloudInfo.cloudinfo_call(f"/sites/{site['name']}/{vo_name}/project")
                if vo_info:
                    if site["url"].endswith("/"):
                        site["url"] = site["url"][:-1]
                    site["url"] = site["url"].rsplit("/", 1)[0]
                    site.update({"project_id": vo_info["id"]})
                    res.append(site)
        return res

    @staticmethod
    def list_images(filters=None, do_order=True):
        """
        Get a list of images available using IM URI format.

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

        params = {}
        if vo:
            params.update({"vo_name": vo})
        images = FedcloudInfo.cloudinfo_call("/images", params)
        if not images:
            return None

        res = []
        for image in images:
            app_name_reg = r".*%s.* \[%s\/%s\/.*]" % (
                app.lower(),
                distribution.lower(),
                version,
            )
            if not re.search(app_name_reg, image["name"].lower()):
                continue

            endpoint = urlparse(image["endpointID"])
            res.append(
                {
                    "uri": "ost://%s/%s" % (endpoint[1], image["imageID"]),
                    "name": image["name"],
                    "vo": image["vo"],
                }
            )
        if vo and do_order:
            sites = FedcloudInfo.get_sites_supporting_vo(vo)
            if sites:
                ordered = []
                # order images using sites
                for site in sites:
                    site_host = urlparse(site["url"])[1]
                    for image in res:
                        if site_host in image["uri"]:
                            image["name"] = "%s - %s" % (site["name"], image["name"])
                            ordered.append(image)

                return ordered
        return res

    @staticmethod
    def search_vm(radl_system):
        """
        Get a list of the most suitable VM according to the requirements
        expressed by the user.

        Args:

        - radl_system(system): system that AppDBIS will search compatible configurations.

        Return(None or list of system): available virtual machines
        """

        filters = {}
        if radl_system.getValue("disk.0.image.url"):
            return []

        distribution = radl_system.getValue("disk.0.os.flavour")
        if distribution:
            filters["distribution"] = distribution
        version = radl_system.getValue("disk.0.os.version")
        if version:
            filters["version"] = version
        vo = radl_system.getValue("disk.0.os.image.vo")
        if vo:
            filters["vo"] = vo
        name = radl_system.getValue("disk.0.os.image.name")
        if name:
            filters["app"] = name

        res_systems = []
        for image in FedcloudInfo.list_images(filters, do_order=False):
            res_systems.append(
                system(
                    radl_system.name,
                    [
                        Feature("disk.0.image.url", "=", image["uri"]),
                        Feature("disk.0.image.vo", "=", image["vo"]),
                    ],
                )
            )

        return res_systems
