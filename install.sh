#!/bin/bash

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
}

ansible_installed=`type -p ansible-playbook`

if [ x${ansible_installed}x != "xx" ]
then
    echo "Ansible installed. Do not install."
else
    echo "Ansible not installed. Installing ..."
    DISTRO=$(distribution_id)
    case $DISTRO in
        debian)
            apt-get update
            apt-get -y install gnupg wget
            echo "deb http://ppa.launchpad.net/ansible/ansible/ubuntu trusty main" >> /etc/apt/sources.list
            apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 93C4A3FD7BB9C367
            apt-get update
            apt-get -y install ansible
            ;;
        ubuntu)
            apt-get update
            apt-get -y install software-properties-common
            apt-add-repository -y ppa:ansible/ansible
            apt-get update
            apt-get -y install wget ansible
            ;;
        rhel)
            yum install -y http://dl.fedoraproject.org/pub/epel/epel-release-latest-$(distribution_major_version).noarch.rpm
            yum install -y wget ansible
            ;;
        centos)
            yum install -y epel-release wget
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

if [ -f "ansible_install.yaml" ]
then
	echo "ansible_install.yaml file present. Do not download."
else
	echo "Downloading ansible_install.yaml file from github."
	wget http://raw.githubusercontent.com/grycap/im/master/ansible_install.yaml
fi

echo "Call Ansible playbook to install the IM."
ansible-playbook ansible_install.yaml
