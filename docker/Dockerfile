# Dockerfile to create a container with the IM service
FROM ubuntu:14.04
MAINTAINER Miguel Caballer <micafer1@upv.es>
LABEL version="1.3.2"
LABEL description="Container image to run the IM service. (http://www.grycap.upv.es/im)"
EXPOSE 8899
RUN apt-get update && apt-get install -y gcc python-dev python-pip python-soappy openssh-client sshpass
RUN pip install IM
RUN pip uninstall -y SOAPpy
COPY ansible.cfg /etc/ansible/ansible.cfg
# Solve a bug in gce.py driver in libcloud 0.17
COPY gce.py /usr/local/lib/python2.7/dist-packages/libcloud/compute/drivers/gce.py
CMD im_service.py
