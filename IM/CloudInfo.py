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

import sys
from datetime import datetime, timedelta
from connectors import *
	
# Clase que representa un site cloud
class CloudInfo:
	
	def __init__(self):
		self.id = None
		self.type = ""
		self.server = ""
		self.port = -1
		self.score = 1
		self.vm_launches = []
		self.vm_fails = []
		self.vm_boot_times = {}

	# Devolvemos la clase adecuada para el proveedor cloud del tipo self.type
	def getCloudConnector(self):
		if len(self.type) > 15 or "." in self.type:
			raise Exception("Not valid cloud provider.")
		try:
			return getattr(sys.modules['connectors.' + self.type], self.type + "CloudConnector")(self)
		except:
			raise Exception("Cloud provider not supported: %s" % self.type)

	def __str__(self):
		res = ""

		if self.id:
			res += "id = " + self.id + ", "
		res += "type = " + self.type + ", "
		if self.server:
			res += "server = " + self.server + ", "
		if self.port != -1:
			res += "port = " + str(self.port) + ", "

		return res

	def getMeanBootTime(self):
		if len(self.vm_boot_times) > 0:
			total_time = timedelta(0)
			for vm_id, boot_time in self.vm_boot_times.iteritems():
				total_time += boot_time
			
			total_time /= len(self.vm_boot_times)
			
			return total_time
		else:
			return timedelta(0)

	def setVMBootTime(self, vm_id, time):
		if not self.vm_boot_times.has_key(vm_id):
			self.vm_boot_times[vm_id] = time
		
		return self.vm_boot_times[vm_id]

	def addVMLaunch(self):
		self.vm_launches.append(datetime.now())
		
	def addVMFail(self):
		self.vm_fails.append(datetime.now())
		
	def getErrorPct(self, delay = 3600):
		diff = timedelta(seconds = delay)
		now = datetime.now()
		fails = 0.0
		for fail_t in self.vm_fails:
			if (now - fail_t) < diff:
				fails += 1.0
		launches = 0.0
		for launch_t in self.vm_launches:
			if (now - launch_t) < diff:
				launches += 1.0
		
		if (launches == 0.0):
			return 0.0
		else:
			return fails/launches

	def getScore(self):
		err = int(100.0 * self.getErrorPct())
		res = (self.getMeanBootTime() * (100 - err)) / 100
		score = res.days * 24 * 60 * 60 + res.seconds + self.score
		#return score
		# Esto lo desactivamos
		return 1

	# Devuelve el listado de clouds
	@staticmethod
	def get_cloud_list(auth_data):
		res = []

		for i, auth in enumerate(auth_data.auth_list):
			if auth['type'] not in ['InfrastructureManager','VMRC']:
				cloud_item = CloudInfo()
				cloud_item.type = auth['type']
				if 'id' in auth.keys() and auth['id']:
					cloud_item.id = auth['id']
				else:
					#We need an ID, so generate one
					cloud_item.id = cloud_item.type + str(i)
				try:
					if (auth['host'] != None):
						cloud_item.server = auth['host'].split(":")[0]
						cloud_item.port = int(auth['host'].split(":")[1])
				except:
					pass

				res.append(cloud_item)

		return res
