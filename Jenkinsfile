#!/usr/bin/groovy

@Library(['github.com/indigo-dc/jenkins-pipeline-library']) _

pipeline {
    agent {
        label 'python'
    }

    environment {
        dockerhub_repo = "indigodatacloud/im"
        dockerhub_image_id = ""
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
pyVmomi
pymongo
defusedxml'''
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
                        // FIXME: Temporarily ignore bandit exit status
                        currentBuild.result = 'SUCCESS'
                    }
                }
            }
            post {
                always {
                    HTMLReport('', 'bandit.html', 'Bandit report')
                }
            }
        }

        stage('Dependency check') {
            agent {
                label 'docker-build'
            }
            steps {
                checkout scm
                OWASPDependencyCheckRun("$WORKSPACE/im/IM", project="im")
            }
            post {
                always {
                    OWASPDependencyCheckPublish()
                    HTMLReport('im', 'dependency-check-report.html', 'OWASP Dependency Report')
                    deleteDir()
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

        stage('DockerHub delivery') {
            when {
                anyOf {
                    branch 'master'
                    buildingTag()
                }
            }
            agent {
                label 'docker-build'
            }
            steps {
                checkout scm
                script {
                    dockerhub_image_id = DockerBuild(
                        dockerhub_repo,
                        env.BRANCH_NAME,
                        "docker-devel")
                }
            }
            post {
                success {
                    DockerPush(dockerhub_image_id)
                }
                failure {
                    DockerClean()
                }
                always {
                    cleanWs()
                }
            }
        }

        stage('Notifications') {
            when {
                buildingTag()
            }
	    steps {
                JiraIssueNotification(
                    'DEEP',
                    'DPM',
                    '10204',
                    "[preview-testbed] New InfrastructureManager version ${env.BRANCH_NAME} available",
                    "Check new artifacts at:\n\t- Docker image: [${dockerhub_image_id}:${env.BRANCH_NAME}|https://hub.docker.com/r/${dockerhub_image_id}/tags/]",
                    ['wp3', 'preview-testbed', "IM-${env.BRANCH_NAME}"],
		    'Task',
                    'mariojmdavid',
                    ['wgcastell',
                     'vkozlov',
                     'dlugo',
                     'keiichiito',
                     'laralloret',
                     'ignacioheredia']
                )
            }
        }
    }
}
