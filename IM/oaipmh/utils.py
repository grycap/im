#
# IM - Infrastructure Manager
# Copyright (C) 2024 - GRyCAP - Universitat Politecnica de Valencia
#
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
import requests_cache
from urllib.parse import urlparse


class Repository():

    def __init__(self, repository_url):
        self.cache_session = requests_cache.CachedSession('oai_cache', cache_control=True, expire_after=3600)
        self.repository_url = repository_url[:-1] if repository_url.endswith("/") else repository_url

    def list(self):
        raise NotImplementedError

    def get(self, element):
        raise NotImplementedError

    def get_by_path(self, path):
        raise NotImplementedError

    @staticmethod
    def create(repository_url):
        if "github.com" or "githubusercontent.com" in repository_url:
            return GitHubRepository(repository_url)
        else:
            return Repository(repository_url)


class GitHubRepository(Repository):

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
        else:
            raise Exception("Invalid repository type.")
        return owner, repo, branch, path

    def list(self):
        owner, repo, branch, path = self._getRepoDetails()
        url = "https://api.github.com/repos/%s/%s/git/trees/%s?recursive=1" % (owner, repo, branch)
        response = self.cache_session.get(url)
        response.raise_for_status()
        res = [elem for elem in response.json()["tree"] if elem["type"] == "blob" and elem["path"].startswith(path)]
        return dict(zip([elem['path'][len(path) + 1:] for elem in res], res))

    def get(self, element):
        return self.get_by_path(element['path']).text

    def get_by_path(self, path, details=False):
        owner, repo, branch, _ = self._getRepoDetails()
        if details:
            url = "https://api.github.com/repos/%s/%s/contents/%s?ref=%s" % (owner, repo, path, branch)
        else:
            url = "https://raw.githubusercontent.com/%s/%s/%s/%s" % (owner, repo, branch, path)
        response = self.cache_session.get(url)
        return response

    def get_by_sha(self, sha):
        owner, repo, _, _ = self._getRepoDetails()
        url = 'https://api.github.com/repos/%s/%s/git/blobs/%s' % (owner, repo, sha)
        response = self.cache_session.get(url)
        return response
