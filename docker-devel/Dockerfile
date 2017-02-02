# Dockerfile to create a container with the IM service
FROM grycap/jenkins:ubuntu16.04-im
MAINTAINER Miguel Caballer <micafer1@upv.es>
LABEL version="1.5.1"
LABEL description="Container image to run the IM service with TOSCA support. (http://www.grycap.upv.es/im)"

# Install tosca-parser
RUN cd tmp \
 && git clone --recursive https://github.com/indigo-dc/tosca-parser.git \
 && cd tosca-parser \
 && pip install /tmp/tosca-parser

# Install pip optional libraries
RUN pip install MySQL-python msrest msrestazure azure-common azure-mgmt-storage azure-mgmt-compute azure-mgmt-network azure-mgmt-resource
# Install im indigo tosca fork branch 'devel'
RUN cd tmp \
 && git clone --branch devel --recursive https://github.com/indigo-dc/im.git \
 && cd im \
 && pip install /tmp/im
COPY ansible.cfg /etc/ansible/ansible.cfg

# Turn on the REST services
RUN sed -i "/ACTIVATE_REST =.*/c\ACTIVATE_REST=True" /etc/im/im.cfg

# Expose the IM ports
EXPOSE 8899 8800

# Launch the service at the beginning of the container
CMD im_service.py
