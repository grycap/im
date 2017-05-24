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


case $(distribution_id) in
    ubuntu)
        apt-get -y install software-properties-common
        apt-add-repository -y ppa:ansible/ansible
        apt-get update
        apt-get -y install wget ansible
        ;;
    rhel|centos|ol)
        case $(distribution_major_version) in
            6)
                yum install -y http://dl.fedoraproject.org/pub/epel/epel-release-latest-6.noarch.rpm
                ;;
            7)
                yum install -y http://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm
                ;;
        esac
        yum install -y wget ansible
        ;;
    fedora)
        yum install -y wget ansible
        ;;
esac

if [ -f "ansible_install.yaml" ]; then
	echo "ansible_install.yaml file present. Do not download."
else
	echo "Downloading ansible_install.yaml file."
	wget http://raw.githubusercontent.com/grycap/im/devel/ansible_install.yaml
fi


ansible-playbook ansible_install.yaml
