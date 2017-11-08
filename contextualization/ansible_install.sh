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
	if [ -e "/etc/lsb-release" ]; then
		RELEASE_VERSION=$(cat /etc/lsb-release | grep DISTRIB_RELEASE | sed 's/DISTRIB_RELEASE=//' | sed 's/\([^0-9]*\)\.[0-9]*/\1/')
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
    fi
    echo ${RELEASE_VERSION} | sed -e 's|\(.\+\) release \([0-9]\+\)\([0-9.]*\).*|\2|'
}

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
            ;;
        ubuntu)
            apt-get update
            apt-get -y install software-properties-common wget sudo
            apt-add-repository -y ppa:ansible/ansible
            wget -q -O - http://repo.indigo-datacloud.eu/repository/RPM-GPG-KEY-indigodc | sudo apt-key add -
            case $(distribution_major_version) in
                14)
                    wget http://repo.indigo-datacloud.eu/repository/indigo/1/ubuntu/dists/trusty/main/binary-amd64/indigodc-release_1.0.0-1_amd64.deb
                    dpkg -i indigodc-release_1.0.0-1_amd64.deb
                    ;;
                16)
                    wget http://repo.indigo-datacloud.eu/repository/indigo/2/ubuntu/dists/xenial/main/binary-amd64/indigodc-release_2.0.0-1_amd64.deb
                    dpkg -i indigodc-release_2.0.0-1_amd64.deb
                    ;;
            esac
            apt-get update
            apt-get -y install ansible
            ;;
        rhel)
            yum install -y http://dl.fedoraproject.org/pub/epel/epel-release-latest-$(distribution_major_version).noarch.rpm
            yum install -y wget ansible
            ;;
        centos)
            yum install -y epel-release wget
            yum install -y http://repo.indigo-datacloud.eu/repository/indigo/2/centos7/x86_64/base/indigodc-release-2.0.0-1.el7.centos.noarch.rpm
            yum install -y ansible
            ;;
        fedora)
            yum install -y wget ansible python2-rpm yum
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
