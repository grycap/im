#!/bin/sh

distribution_id() {
    RETVAL=""
    if [ -z "${RETVAL}" -a -e "/etc/os-release" ]; then
        . /etc/os-release
        RETVAL="${ID}"
    fi

    if [ -z "${RETVAL}" -a -e "/etc/centos-release" ]; then
        RETVAL="centos"
    fi

    if [ -z "${RETVAL}" -a -e "/etc/fedora-release" ]; then
        RETVAL="fedora"
    fi

    if [ -z "${RETVAL}" -a -e "/etc/redhat-release" ]; then
        RELEASE_OUT=$(head -n1 /etc/redhat-release)
        case "${RELEASE_OUT}" in
            Red\ Hat\ Enterprise\ Linux*)
                RETVAL="rhel"
                ;;
            CentOS*)
                RETVAL="centos"
                ;;
            Fedora*)
                RETVAL="fedora"
                ;;
        esac
    fi

    if [ -z "${RETVAL}" ]; then
        RETVAL="unknown"
    fi

    echo ${RETVAL}
}

distribution_major_version() {
	if [ -f /etc/lsb-release ]; then
		. /etc/lsb-release
		echo ${DISTRIB_RELEASE} | sed -e 's|\([0-9]\+\)\([0-9.]*\).*|\1|'
	else
	    for RELEASE_FILE in /etc/system-release \
	                        /etc/centos-release \
	                        /etc/fedora-release \
	                        /etc/redhat-release
	    do
	        if [ -e "${RELEASE_FILE}" ]; then
	            RELEASE_VERSION=$(head -n1 ${RELEASE_FILE})
	            break
	        fi
	    done
	    echo ${RELEASE_VERSION} | sed -e 's|\(.\+\) release \([0-9]\+\)\([0-9.]*\).*|\2|'
	fi
}

SSH2_PYHTON_VERSION=0.18.0_1_ge5fdd3e
SSH2_PYHTON_URL=http://ftpgrycap.i3m.upv.es/ssh2-python

if [ $(which ansible-playbook) ]; then
    echo "Ansible installed. Do not install."
else
    echo "Ansible not installed. Installing ..."
    DISTRO=$(distribution_id)
    case $DISTRO in
        debian)
            echo "deb http://ppa.launchpad.net/ansible/ansible/ubuntu trusty main" >> /etc/apt/sources.list
            apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 93C4A3FD7BB9C367
            apt-get update
            apt-get -y install wget ansible
            wget $SSH2_PYHTON_URL/python-ssh2-python-$SSH2_PYHTON_VERSION-1.debian8.x86_64.rpm
            dpkg -i python-ssh2-python-0.18.0_1_ge5fdd3e-1.debian8.x86_64.rpm
            apt install -f -y
            ;;
        ubuntu)
            apt-get -y install software-properties-common
            apt-add-repository -y ppa:ansible/ansible
            apt-get update
            apt-get -y install wget ansible
            wget $SSH2_PYHTON_URL/python-ssh2-python-$SSH2_PYHTON_VERSION-1.ubuntu$(distribution_major_version).x86_64.rpm
            dpkg -i python-ssh2-python-0.18.0_1_ge5fdd3e-1.ubuntu$(distribution_major_version).x86_64.rpm
            apt install -f -y
            ;;
        rhel)
            yum install -y http://dl.fedoraproject.org/pub/epel/epel-release-latest-$(distribution_major_version).noarch.rpm
            yum install -y wget ansible
            yum install -y $SSH2_PYHTON_URL/python-ssh2-python-$SSH2_PYHTON_VERSION-1.el7.x86_64.rpm
            ;;
        centos)
            yum install -y epel-release wget
            yum install -y ansible
            yum install -y $SSH2_PYHTON_URL/python-ssh2-python-$SSH2_PYHTON_VERSION-1.el7.x86_64.rpm
            ;;
        fedora)
            yum install -y wget ansible python2-rpm yum
            yum install -y $SSH2_PYHTON_URL/python-ssh2-python-$SSH2_PYHTON_VERSION-1.fc$(distribution_major_version).x86_64.rpm
            ;;
    	*)
            echo "Unsupported distribution: $DISTRO"
            ;;
    esac
fi

# Create the config file
cat > /etc/ansible/ansible.cfg <<EOL
[defaults]
transport  = smart
host_key_checking = False
nocolor = 1
become_user = root
become_method = sudo
fact_caching = jsonfile
fact_caching_connection = /var/tmp/facts_cache
fact_caching_timeout = 86400
gathering = smart
[paramiko_connection]
record_host_keys=False
[ssh_connection]
pipelining = True
EOL

if [ $(which ansible-playbook) ]; then
	echo '{"OK" : true}' > $1
else
	echo '{"OK" : false}' > $1
fi

chmod 666 $1