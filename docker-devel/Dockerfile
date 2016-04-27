# Dockerfile to create a container with the IM service
FROM grycapjenkins/im-base
MAINTAINER Miguel Caballer <micafer1@upv.es>
LABEL version="1.4.4"
LABEL description="Container image to run the IM service with TOSCA support. (http://www.grycap.upv.es/im)"

# Install tosca-parser
RUN cd tmp \
 && git clone --recursive https://github.com/indigo-dc/tosca-parser.git \
 && cd tosca-parser \
 && python setup.py install

# Install im indigo tosca fork branch 'devel'
RUN cd tmp \
 && git clone --branch devel --recursive https://github.com/indigo-dc/im.git \
 && cd im \
 && python setup.py install
COPY ansible.cfg /etc/ansible/ansible.cfg

# Turn on the REST services
RUN sed -i "/ACTIVATE_REST =.*/c\ACTIVATE_REST=True" /etc/im/im.cfg

# Expose the IM ports
EXPOSE 8899 8800

# Launch the service at the beginning of the container
CMD im_service.py
