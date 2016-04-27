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
""" Class to connect with the VMRC server """
from SOAPpy import SOAPProxy
from HTTPHeaderTransport import HTTPHeaderTransport
from radl.radl import Feature, system, FeaturesApp, SoftFeatures


class VMRC:
    """ Class to connect with the VMRC server """
    # define the namespace
    namespace = 'http://ws.vmrc.grycap.org/'
    server = None

    def __init__(self, url, user=None, passwd=None):
        if user is None:
            self.server = SOAPProxy(url)
        else:
            self.server = SOAPProxy(url, transport=HTTPHeaderTransport)
            self.server.transport.headers = {'Username': user,
                                             'Password': passwd}

        # if you want to see the SOAP message exchanged
        # uncomment the two following lines
        # self.server.config.dumpSOAPOut = 1
        # self.server.config.dumpSOAPIn = 1
        # self.server.config.dumpHeadersOut = 1

    @staticmethod
    def _toRADLSystem(vmi):

        # Pass common features
        VMRC_RADL_MAP = {
            'hypervisor': ('virtual_system_type', str),
            'diskSize': ('disk.0.size', int),
            'arch': ('cpu.arch', str),
            'location': ('disk.0.image.url', str),
            'name': ('disk.0.image.name', str),
            'userLogin': ('disk.0.os.credentials.username', str),
            'userPassword': ('disk.0.os.credentials.password', str)
        }
        fs = [Feature(VMRC_RADL_MAP[prop][0], "=", VMRC_RADL_MAP[prop][1](getattr(vmi, prop)))
              for prop in VMRC_RADL_MAP if hasattr(vmi, prop) and getattr(vmi, prop)]
        fs.extend([Feature("disk.0.os." + prop, "=", getattr(vmi.os, prop))
                   for prop in ['name', "flavour", "version"]])

        if not hasattr(vmi, 'applications'):
            return system("", fs)

        # vmi.applications can store the attributes of a single application
        # or can be a list of objects.
        if vmi.applications and isinstance(vmi.applications[0], str):
            apps = [vmi.applications]
        else:
            apps = vmi.applications

        for app in apps:
            OS_VMRC_RADL_PROPS = ["name", "version", "path"]
            fs.append(Feature("disk.0.applications", "contains", FeaturesApp(
                [Feature(prop, "=", getattr(app, prop))
                    for prop in OS_VMRC_RADL_PROPS] +
                [Feature("preinstalled", "=", "yes")])))
        return system("", fs)

    def list_vm(self):
        """Get a list of all the VM registered in the catalog."""

        try:
            vmrc_res = self.server._ns(self.namespace).list()
        except Exception:
            return None

        if len(vmrc_res) > 0:
            if isinstance(vmrc_res, list):
                return [VMRC._toRADLSystem(vmi) for vmi in vmrc_res]
            else:
                return [VMRC._toRADLSystem(vmrc_res)]
        else:
            return []

    def search_vm(self, radl_system):
        """
        Get a list of the most suitable VM according to the requirements
        expressed by the user.

        Args:

        - radl_system(system): system that VMRC will search compatible configurations.

        Return(None or list of system): available virtual machines
        """

        # If an images is already set, VMRC service is not asked
        if radl_system.getValue("disk.0.image.url"):
            return []

        vmi_desc_str_val = VMRC._generateVMRC(radl_system.features).strip()
        try:
            vmrc_res = self.server._ns(self.namespace).search(
                vmiDescStr=vmi_desc_str_val)
        except Exception:
            return []

        if len(vmrc_res) > 0:
            if isinstance(vmrc_res, list):
                return [VMRC._toRADLSystem(vmi) for vmi in vmrc_res]
            else:
                return [VMRC._toRADLSystem(vmrc_res)]
        else:
            return []

    @staticmethod
    def _generateVMRC(features):
        """
        Generate a VMRC request from a list of ``system`` features.

        A VMRC request shows slightly different format than RADL::

           system.hypervisor = vmware
           cpu.arch = i686
           disk.os.name = Linux
           disk.os.flavour = Ubuntu
           soft 25 disk.os.version >= 11.15
           disk.applications contains (name = com.java, version >= 1.6)
           soft 5 disk.applications contains (name = net.nbcr.opal, version > 2.0)

        As example shows, VMRC requests cannot represent group of soft features and
        soft features inside other soft features. For that, these characteristics are
        forbidden in the passed list of features.

        Args:
        - features(list of Feature): features to convert.

        Return(str): string with the request.
        """

        HARD = "HARD"

        def default(prop):
            return lambda f, soft: (soft, "%s %s %s" % (prop, f.operator, f.getValue()))

        def app(f, soft):
            return (1 if f.value.getValue('preinstalled') != "yes" and soft == HARD else soft,
                    "disk.applications contains (%s )" % ",".join([
                        s for _, s in walk(f.value.features, False, HARD)]))

        RADL_VMRC_MAP = {
            'virtual_system_type': default('system.hypervisor'),
            'cpu.arch': default('cpu.arch'),
            'disk.0.size': default('disk.size'),
            'disk.0.os.name': default('disk.os.name'),
            'disk.0.os.flavour': default('disk.os.flavour'),
            'disk.0.os.version': default('disk.os.version'),
            'disk.0.image.name': default('system.name'),
            'disk.0.applications': app,
            'name': default('name'),
            'version': default('version')
        }

        def walk(fs, noSofts, soft):
            # First process simple features in fs.
            for f in fs:
                if isinstance(f, Feature) and f.prop in RADL_VMRC_MAP:
                    yield RADL_VMRC_MAP[f.prop](f, soft)

            # Next check soft features.
            for fs0 in [list(walk(f.features, True, f.soft)) for f in fs if isinstance(f, SoftFeatures)]:
                if noSofts and len(fs0) > 0:
                    raise Exception(
                        "Not allowed soft features inside soft features.")
                if len(fs0) > 1:
                    raise Exception(
                        "Not allowed soft feature groups with more than one feature.")
                for f in fs0:
                    yield f

        return "\n".join([("%s" if soft == HARD else "soft %s %%s" % soft) % prop
                          for soft, prop in walk(features, False, HARD)])
