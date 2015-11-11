# Dockerfile to create a container with the IM service and TOSCA support
FROM ubuntu:14.04
MAINTAINER Miguel Caballer <micafer1@upv.es>
LABEL version="1.3.2"
LABEL description="Container image to run the IM service with TOSCA support. (http://www.grycap.upv.es/im)"

EXPOSE 8899

# Update and install all the neccesary packages
RUN apt-get update && apt-get install -y \
    gcc \
    python-dev \
    python-pip \
    python-soappy \
    python-pbr \
    python-dateutil \
    openssh-client \
    sshpass \
    git \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

# Install tosca-parser
RUN cd tmp \
 && git clone https://github.com/indigo-dc/tosca-parser.git \
 && cd tosca-parser \
 && python setup.py install

# Install im - 'tosca' branch
RUN cd tmp \
 && git clone -b tosca https://github.com/grycap/im.git \
 && cd im \
 && python setup.py install
COPY ansible.cfg /etc/ansible/ansible.cfg

# Turn on the REST services
RUN sed -i "/ACTIVATE_REST =.*/c\ACTIVATE_REST=True" /etc/im/im.cfg

CMD im_service.py
