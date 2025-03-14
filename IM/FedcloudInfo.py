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

try:
    from urlparse import urlparse
except ImportError:
    from urllib.parse import urlparse


class FedcloudInfo:
    """
    Get FedCloud data
    """

    CLOUDINFO_URL = "https://is.ops.fedcloud.eu"

    @staticmethod
    def cloudinfo_call(path):
        """
        Basic Cloud info REST API call
        """
        data = None
        resp = requests.request("GET", FedcloudInfo.CLOUDINFO_URL + path)
        if resp.status_code == 200:
            data = resp.json()
        return data

    @staticmethod
    def get_site_id(site_name):
        """
        Get the site ID from the site name
        """
        data = FedcloudInfo.cloudinfo_call(f"/sites/?site_name={site_name}")
        if data:
            return data[0]["id"]
        else:
            return None

        return None

    @staticmethod
    def get_site_url(site_id):
        """
        Get the site url from the site ID
        """
        if not site_id:
            return None
        data = FedcloudInfo.cloudinfo_call(f"/site/{site_id}/")
        site_url = None
        if data:
            site_url = data["url"]
        return site_url

    @staticmethod
    def get_image_id(site_id, image_name, vo_name):
        """
        Get the image ID from the site id, image and vo names
        """
        images = []
        data = FedcloudInfo.cloudinfo_call("/site/{site_id}/{vo_name}/images")
        if data:
            for image in data:
                if image.get("name", "") == image_name:
                    try:
                        images.append(image["id"], image["version"])
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
    def get_image_data(str_url, vo=None, site=None):
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
                site_name = FedcloudInfo._get_site_name(site)
                image_name = url[1]
            vo_name = url[4]

            if not site_name:
                return (
                    None,
                    None,
                    "No site name returned from EGI FedcloudInfo for site host: %s."
                    % site,
                )

            site_id = FedcloudInfo.get_site_id(site_name)
            if not site_id:
                return (
                    None,
                    None,
                    "No site ID returned from EGI FedcloudInfo for site: %s."
                    % site_name,
                )

            site_url = FedcloudInfo.get_site_url(site_id)
            if not site_url:
                return (
                    None,
                    None,
                    "No site URL returned from EGI FedcloudInfo for site id: %s."
                    % site_id,
                )

            if not vo_name and len(image_name) >= 37 and ":" in image_name:
                image_id = FedcloudInfo.get_image_id_from_uri(site_id, image_name)
                if not image_id:
                    return (
                        None,
                        None,
                        "No image ID returned from EGI FedcloudInfo for image: %s/%s."
                        % (site_id, image_name),
                    )
            else:
                if not vo_name:
                    vo_name = vo
                image_id = FedcloudInfo.get_image_id(site_id, image_name, vo_name)
                if not image_id:
                    return (
                        None,
                        None,
                        "No image ID returned from EGI FedcloudInfo for image: %s/%s/%s."
                        % (site_id, image_name, vo_name),
                    )

            return site_url, image_id, ""

        return None, None, "Incorrect Protocol"

    @staticmethod
    def get_image_id_from_uri(site_id, image_mp_uri):
        """
        Get the image ID from the site id and image mp_uri
        """
        if not image_mp_uri.startswith("http"):
            image_mp_uri = f"https://appdb.egi.eu/store/vo/image/{image_mp_uri}/"

        data = FedcloudInfo.cloudinfo_call(f"/site/{site_id}/images")
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
    def get_project_ids(site_id):
        projects = {}
        # Until it is on the prod instance use the Devel one

        data = FedcloudInfo.cloudinfo_call(f"/site/{site_id}/projects")
        if data:
            projects = {p["name"]: p["id"] for p in data}
        return projects
