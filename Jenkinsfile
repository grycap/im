#!/usr/bin/groovy

@Library(['github.com/indigo-dc/jenkins-pipeline-library']) _

pipeline {
    agent {
        label 'python'
    }

    environment {
        dockerhub_repo = "indigodatacloud/im"
        pip_test_reqs = '''bandit
pep8
nose
nosexcover
'''
        pip_reqs = '''paramiko
radl
mock
scp
PyYAML
netaddr
ansible
boto
apache-libcloud
backports.ssl_match_hostname
-egit+https://github.com/indigo-dc/tosca-parser@master#egg=tosca-parser
bottle
suds
msrest
msrestazure
azure-common
azure-mgmt-storage
azure-mgmt-compute
azure-mgmt-network
azure-mgmt-resource
azure-mgmt-dns
azure-storage
pywinrm
MySQL-python
pyVmomi'''
        tox_envs = """
[testenv:pep8]
commands = pep8 --max-line-length=120 --ignore=E402 --exclude=doc,.tox .
[testenv:unit]
commands = nosetests --with-xcoverage --xcoverage-file=coverage_unit.xml --cover-package IM --all-modules --exe test/unit
[testenv:functional]
commands = nosetests -vv --all-modules --exe test/functional
[testenv:bandit]
commands = bandit -r IM -f html -o bandit.html"""
    }

    stages {
        stage('Code fetching') {
            steps {
                checkout scm
            }
        }

        stage('Environment setup') {
            steps {
                PipRequirements(pip_test_reqs, 'test-requirements.txt')
                PipRequirements(pip_reqs, 'requirements.txt')
                ToxConfig(tox_envs)
            }
            post {
                always {
                    archiveArtifacts artifacts: '*requirements.txt,*tox*.ini'
                }
            }
        }

        stage('Style analysis') {
            steps {
                ToxEnvRun('pep8')
            }
            post {
                always {
                    WarningsReport('Pep8')
                }
            }
        }

        stage('Unit testing coverage') {
            steps {
                ToxEnvRun('unit')
            }
            post {
                success {
                    CoberturaReport()
                }
            }
        }

        stage('Functional testing') {
            steps {
                ToxEnvRun('functional')
            }
        }

        stage('Security scanner') {
            steps {
                script {
                    try {
                        ToxEnvRun('bandit')
                    }
                    catch(e) {
                        currentBuild.result = 'UNSTABLE'
                    }
                }
            }
            post {
                always {
                    HTMLReport('', 'bandit.html', 'Bandit report')
                }
            }
        }

        stage('Metrics gathering') {
            agent {
                label 'sloc'
            }
            steps {
                checkout scm
                SLOCRun()
            }
            post {
                success {
                    SLOCPublish()
                }
            }
        }
