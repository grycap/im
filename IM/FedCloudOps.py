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
        self.repository_url = repository_url[:-1] if repository_url.endswith("/") else repository_url

    def _getRepoDetails(self):
        url = urlparse(self.repository_url)
        if "githubusercontent.com" in self.repository_url:
            owner = url.path.split("/")[1]
            repo = url.path.split("/")[2]
            branch = url.path.split("/")[3]
            path = "/".join(url.path.split("/")[4:])
        elif "github.com" in self.repository_url:
            owner = url.path.split("/")[1]
            repo = url.path.split("/")[2]
            branch = url.path.split("/")[4]
            path = "/".join(url.path.split("/")[5:])
        return owner, repo, branch, path

    def get(self, element, timeout=10):
        owner, repo, branch, _ = self._getRepoDetails()
        url = "https://raw.githubusercontent.com/%s/%s/%s/%s" % (owner, repo, branch, element)
        response = requests.get(url, timeout=timeout)
        return response.text


class FedCloudOps:
    """
    Get Project IDs info from the FedCloudOps repository
    """
    REPO_URL = "https://github.com/EGI-Federation/fedcloud-catchall-operations/blob/main/"

    @staticmethod
    def get_project_ids(site_name):
        projects = {}
        try:
            repo = GitHubRepository(FedCloudOps.REPO_URL)
            site_info = yaml.safe_load(repo.get(f"sites/{site_name}.yaml"))
            projects = {vo["name"]: vo["auth"]["project_id"] for vo in site_info["vos"]}
        except Exception:
            print(f"Error getting project IDs for site {site_name}")
        return projects
