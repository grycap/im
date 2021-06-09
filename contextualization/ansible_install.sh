#!/bin/sh

ANSIBLE_VERSION="2.9.21"

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

if [ $(which ansible-playbook) ]; then
    echo "Ansible installed. Do not install."
else
    echo "Ansible not installed. Installing ..."
    DISTRO=$(distribution_id)
    case $DISTRO in
        debian)
            apt install -y --no-install-recommends python3 python3-pip wget python3-setuptools sshpass openssh-client unzip
            ;;
        ubuntu)
            apt update
            if [ "$(distribution_major_version)" == "14"]
            then
                ls /usr/bin/python3.5 && rm -f /usr/bin/python3 && ln -s /usr/bin/python3.5 /usr/bin/python3
                apt install -y --no-install-recommends python3.5 wget gcc python3.5-dev libffi-dev libssl-dev python3-pip wget python3-setuptools sshpass openssh-client unzip
                rm -f /usr/bin/pip3
                ln -s /usr/local/bin/pip3.5 /usr/bin/pip3
                pip3 install cryptography==2.9.2
                pip3 install urllib3 ndg-httpsclient pyasn1
            else
                apt install -y --no-install-recommends python3 python3-pip wget python3-setuptools sshpass openssh-client unzip
            fi
            ;;
        rhel)
            yum install -y epel-release wget
            yum install -y python3 libselinux-python3 python3-pip python3-setuptools sshpass openssh-clients
            ;;
        centos)
            yum install -y epel-release wget
            yum install -y python3 libselinux-python3 python3-pip python3-setuptools sshpass openssh-clients
            ;;
        fedora)
            yum install -y wget python3 libselinux-python3 python3-pip python3-setuptools sshpass openssh-clients

            ;;
    	*)
            echo "Unsupported distribution: $DISTRO"
            ;;
    esac

    pip3 install "pip>=9.0.3"
    pip3 install -U setuptools
    pip3 install pyOpenSSL pyyaml jmespath scp
    pip3 install ansible==$ANSIBLE_VERSION
fi

# Create the config file
mkdir /etc/ansible
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
interpreter_python = /usr/bin/python3
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
