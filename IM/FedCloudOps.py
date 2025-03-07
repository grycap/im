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

import yaml
import requests
try:
    from urlparse import urlparse
except ImportError:
    from urllib.parse import urlparse


class GitHubRepository():
    """
    Get data from a GitHub repository
    """

    def __init__(self, repository_url):
        url = urlparse(repository_url[:-1] if repository_url.endswith("/") else repository_url)
        if "githubusercontent.com" in url.netloc:
            self.owner = url.path.split("/")[1]
            self.repo = url.path.split("/")[2]
            self.branch = url.path.split("/")[3]
            self.path = "/".join(url.path.split("/")[4:])
        elif "github.com" in url.netloc:
            self.owner = url.path.split("/")[1]
            self.repo = url.path.split("/")[2]
            self.branch = url.path.split("/")[4]
            self.path = "/".join(url.path.split("/")[5:])
        else:
            raise ValueError("Invalid GitHub repository URL")

    def get(self, element, timeout=10):
        """ Get the content of a file from the repository """
        url = f"https://raw.githubusercontent.com/{self.owner}/{self.repo}/{self.branch}/{self.path}/{element}"
        response = requests.get(url, timeout=timeout)
        return response.text


class FedCloudOps:
    """
    Get Project IDs info from the FedCloudOps repository
    """
    REPO_URL = "https://github.com/EGI-Federation/fedcloud-catchall-operations/blob/main/sites"

    @staticmethod
    def get_project_ids(site_name):
        """ Get the mapping between VO names and project IDs for a site """
        projects = {}
        try:
            repo = GitHubRepository(FedCloudOps.REPO_URL)
            site_info = yaml.safe_load(repo.get(f"{site_name}.yaml"))
            projects = {vo["name"]: vo["auth"]["project_id"] for vo in site_info["vos"]}
        except Exception:
            print(f"Error getting project IDs for site {site_name}")
        return projects
