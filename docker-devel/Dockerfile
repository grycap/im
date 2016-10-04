# Dockerfile to create a container with the IM service
FROM grycap/jenkins:ubuntu14.04-im
MAINTAINER Miguel Caballer <micafer1@upv.es>
LABEL version="1.4.8"
LABEL description="Container image to run the IM service. (http://www.grycap.upv.es/im)"

EXPOSE 8899 8800

# Add unresolved LibCloud dependency
RUN pip install backports.ssl_match_hostname

# Install im - 'devel' branch
RUN cd tmp \
 && git clone -b devel https://github.com/grycap/im.git \
 && cd im \
 && pip install /tmp/im

# Turn on the REST services
RUN sed -i "/ACTIVATE_REST =.*/c\ACTIVATE_REST=True" /etc/im/im.cfg

COPY ansible.cfg /etc/ansible/ansible.cfg

CMD im_service.py
