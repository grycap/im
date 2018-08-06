pipeline {
    agent {
        label 'python'
    }
    
    stages {
        stage('Fetch code') {
            steps {
                checkout scm
            }
        }
        
        stage('Generate configuration files') {
            steps {
                echo 'Generating test-requirements.txt file..'
                writeFile file: 'test-requirements.txt', text: '''bandit
pep8
nose
nosexcover
'''
                echo 'Generating requirements.txt file..'
                writeFile file: 'requirements.txt', text: '''paramiko
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
                echo 'Generating tox.ini file..'
                writeFile file: 'tox.ini', text: '''[tox]
envlist = py27
[testenv]
usedevelop = True
install_command = pip install -U {opts} {packages}
setenv =
   VIRTUAL_ENV={envdir}
deps = -r{toxinidir}/test-requirements.txt
       -r{toxinidir}/requirements.txt
[testenv:pep8]
commands = pep8 --max-line-length=120 --ignore=E402 --exclude=doc,.tox .
[testenv:unit]
commands = nosetests --with-xcoverage --xcoverage-file=coverage_unit.xml --cover-package IM --all-modules --exe test/unit
[testenv:functional]
commands = nosetests -vv --all-modules --exe test/functional
[testenv:bandit]
commands = bandit -r IM -f html -o bandit/index.html'''
            }
        }
        
        stage('Style Analysis') {
            steps {
                echo 'Running pep8..'
                sh 'tox -e pep8'
            }
            post {
                always {
                    warnings canComputeNew: false,
                             canResolveRelativePaths: false,
                             categoriesPattern: '',
                             consoleParsers: [[parserName: 'Pep8']],
                             defaultEncoding: '',
                             excludePattern: '',
                             healthy: '',
                             includePattern: '',
                             messagesPattern: '',
                             unHealthy: ''
                }
            }
        } // code style stage
        
        stage('Unit tests') {
            steps {
                sh 'tox -e unit'
            }
            post {
                success {
                    cobertura autoUpdateHealth: false,
                              autoUpdateStability: false,
                              coberturaReportFile: '**/coverage_unit.xml',
                              conditionalCoverageTargets: '70, 0, 0',
                              failUnhealthy: false,
                              failUnstable: false,
                              lineCoverageTargets: '80, 0, 0',
                              maxNumberOfBuilds: 0,
                              methodCoverageTargets: '80, 0, 0',
                              onlyStable: false,
                              sourceEncoding: 'ASCII',
                              zoomCoverageChart: false
                }
            }
        } // unit testing stage
        
        stage('Functional tests') {
            steps {
                sh 'tox -e functional'
            }
        } // functional testing stage
        
        stage('Security scanner') {
            steps {
                script {
                    try {
                        sh 'mkdir bandit' // otherwise report does not show up
                        sh 'tox -e bandit'
                    }
                    catch(e) {
                        // Mark build as UNSTABLE (instead of FAILURE) until
                        // Bandit warnings are resolved
                        currentBuild.result = 'UNSTABLE'
                    }
                }
            }
            post {
                always {
                    publishHTML([allowMissing: false,
                                 alwaysLinkToLastBuild: false,
                                 keepAll: true,
                                 reportDir: 'bandit',
                                 reportFiles: 'index.html',
                                 reportName: 'Bandit report',
                                 reportTitles: ''])
                }
            }
        } // security stage
    } // stages
} // pipeline
