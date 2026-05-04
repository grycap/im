#!/bin/sh

ANSIBLE_VERSION="9.5.1"

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

if [ -f /var/tmp/.mamba/envs/ansible/bin/ansible ]; then
    echo "Ansible installed. Do not install."
else
    echo "Ansible not installed. Installing ..."
    DISTRO=$(distribution_id)
    case $DISTRO in
        debian)
            apt install -y --no-install-recommends python3 wget sshpass openssh-client unzip
            ;;
        ubuntu)
            apt update
            apt install -y --no-install-recommends python3 wget sshpass openssh-client unzip
            ;;
        rhel)
            yum install -y epel-release wget
            yum install -y python3 libselinux-python3 sshpass openssh-clients
            ;;
        centos)
            yum install -y epel-release wget
            yum install -y python3 libselinux-python3 sshpass openssh-clients
            ;;
        fedora)
            yum install -y wget python3 libselinux-python3 sshpass openssh-clients

            ;;
    	*)
            echo "Unsupported distribution: $DISTRO"
            ;;
    esac

    mkdir -p /var/tmp/.mamba/bin/
    ls /var/tmp/.mamba/bin/micromamba || wget https://github.com/mamba-org/micromamba-releases/releases/latest/download/micromamba-linux-64 -O /var/tmp/.mamba/bin/micromamba
    chmod +x /var/tmp/.mamba/bin/micromamba
    ls /var/tmp/.mamba/envs/ansible || /var/tmp/.mamba/bin/micromamba create -y -n ansible -r /var/tmp/.mamba python=3.12 ansible=${ANSIBLE_VERSION} paramiko psutil pyyaml jmespath scp pywinrm

fi

# Create the config file
ls /etc/ansible || mkdir /etc/ansible
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
roles_path = /etc/ansible/roles
collections_path = /etc/ansible
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
