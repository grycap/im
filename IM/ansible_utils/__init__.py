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
import copy

__all__ = ['ansible_launcher', 'ansible_executor_v2']


def merge_recipes(yaml1, yaml2):
    """
    Merge two ansible recipes yaml docs

    Arguments:
       - yaml1(str): string with the first YAML
       - yaml1(str): string with the second YAML
    Returns: The merged YAML. In case of errors, it concatenates both strings
    """
    yamlo1o = {}
    try:
        yamlo1o = yaml.safe_load(yaml1)[0]
        if not isinstance(yamlo1o, dict):
            yamlo1o = {}
    except Exception as ex:
        raise Exception("Error parsing YAML: " + yaml1 + "\n. Error: %s" % str(ex))

    yamlo2s = {}
    try:
        yamlo2s = yaml.safe_load(yaml2)
        if not isinstance(yamlo2s, list) or any([not isinstance(d, dict) for d in yamlo2s]):
            yamlo2s = {}
    except Exception as ex:
        raise Exception("Error parsing YAML: " + yaml2 + "\n. Error: %s" % str(ex))

    if not yamlo2s and not yamlo1o:
        return ""

    result = []
    for yamlo2 in yamlo2s:
        yamlo1 = copy.deepcopy(yamlo1o)
        all_keys = []
        all_keys.extend(yamlo1.keys())
        all_keys.extend(yamlo2.keys())
        all_keys = set(all_keys)

        for key in all_keys:
            if key in yamlo1 and yamlo1[key]:
                if key in yamlo2 and yamlo2[key]:
                    if isinstance(yamlo1[key], dict):
                        yamlo1[key].update(yamlo2[key])
                    elif isinstance(yamlo1[key], list):
                        yamlo1[key].extend(yamlo2[key])
                    else:
                        # Both use have the same key with merge in a lists
                        v1 = yamlo1[key]
                        v2 = yamlo2[key]
                        yamlo1[key] = [v1, v2]
            elif key in yamlo2 and yamlo2[key]:
                yamlo1[key] = yamlo2[key]
        result.append(yamlo1)

    return yaml.safe_dump(result, default_flow_style=False, explicit_start=True, width=256)
