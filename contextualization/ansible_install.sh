#!/bin/sh

ANSIBLE_VERSION="4.10.0"

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

# Create a symbolic link to python3 in case of not venv created
ls /var/tmp/.ansible/bin/ || mkdir -p /var/tmp/.ansible/bin/
ls /var/tmp/.ansible/bin/python3 || ln -s /usr/bin/python3 /var/tmp/.ansible/bin/python3

if [ $(which ansible-playbook) ]; then
    echo "Ansible installed. Do not install."
else
    echo "Ansible not installed. Installing ..."
    DISTRO=$(distribution_id)
    case $DISTRO in
        debian)
            apt install -y --no-install-recommends python3 python3-pip python3-psutil wget python3-setuptools sshpass openssh-client unzip
            ;;
        ubuntu)
            apt update
            apt install -y --no-install-recommends python3 python3-pip python3-psutil wget python3-setuptools sshpass openssh-client unzip
            ;;
        rhel)
            yum install -y epel-release wget
            yum install -y python3 libselinux-python3 python3-pip python3-setuptools python3-psutil sshpass openssh-clients
            ;;
        centos)
            yum install -y epel-release wget
            yum install -y python3 libselinux-python3 python3-pippython3-setuptools python3-psutil sshpass openssh-clients
            ;;
        fedora)
            yum install -y wget python3 libselinux-python3 python3-pip python3-psutil python3-setuptools sshpass openssh-clients

            ;;
    	*)
            echo "Unsupported distribution: $DISTRO"
            ;;
    esac

    pip3 install "pip>=20.0"
    pip3 install -U "setuptools<66.0"
    pip3 install "pyOpenSSL>20.0,<22.1.0" "cryptography>37.0.0,<39.0.0" pyyaml jmespath scp "paramiko>=2.9.5" packaging --prefer-binary
    pip3 install ansible==$ANSIBLE_VERSION --prefer-binary
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
collections_paths = /etc/ansible
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
