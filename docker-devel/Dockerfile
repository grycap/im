# Dockerfile to create a container with the IM service
FROM grycap/jenkins:ubuntu16.04-im
MAINTAINER Miguel Caballer <micafer1@upv.es>
LABEL version="1.5.5"
LABEL description="Container image to run the IM service. (http://www.grycap.upv.es/im)"

EXPOSE 8899 8800

# Install pip optional libraries
RUN pip install MySQL-python msrest msrestazure azure-common azure-mgmt-storage azure-mgmt-compute azure-mgmt-network azure-mgmt-resource azure-mgmt-dns
# Install im - 'devel' branch
RUN cd tmp \
 && git clone -b devel https://github.com/grycap/im.git \
 && cd im \
 && pip install /tmp/im

COPY ansible.cfg /etc/ansible/ansible.cfg

CMD im_service.py
