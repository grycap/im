# Dockerfile to create a container with the IM service
FROM ubuntu:14.04
MAINTAINER Miguel Caballer <micafer1@upv.es>
LABEL version="1.4.2"
LABEL description="Container image to run the IM service. (http://www.grycap.upv.es/im)"

EXPOSE 8899

RUN apt-get update && apt-get install -y \
    gcc \
    python-dev \
    python-pip \
    python-soappy \
    python-dateutil \
    python-pbr \
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

# Install im - 'devel' branch
RUN cd tmp \
 && git clone -b devel https://github.com/grycap/im.git \
 && cd im \
 && python setup.py install

# Turn on the REST services
RUN sed -i "/ACTIVATE_REST =.*/c\ACTIVATE_REST=True" /etc/im/im.cfg

COPY ansible.cfg /etc/ansible/ansible.cfg

CMD im_service.py
