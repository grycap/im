# Dockerfile to create a container with the IM service
FROM ubuntu:14.04
MAINTAINER Miguel Caballer <micafer1@upv.es>
LABEL version="1.4.3"
LABEL description="Container image to run the IM service. (http://www.grycap.upv.es/im)"
EXPOSE 8899
RUN apt-get update && apt-get install -y gcc python-dev python-pip python-soappy openssh-client sshpass
RUN pip install IM
RUN pip uninstall -y SOAPpy
COPY ansible.cfg /etc/ansible/ansible.cfg
CMD im_service.py
