from ubuntu:16.04

RUN echo "deb [trusted=yes] http://ppa.launchpad.net/adiscon/v8-stable/ubuntu xenial main" >> /etc/apt/sources.list.d/rsyslog.list
RUN apt-get update && apt-get install --no-install-recommends -y rsyslog && apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* && rm -rf ~/.cache/

COPY rsyslog.conf /etc/rsyslog.conf

EXPOSE 514 514/udp

ENTRYPOINT [ "rsyslogd", "-n" ]

