# IM Service plugin for nagios

This probe contacts an IM REST API endpoint and checks the service is up and running,
and return OK, CRITICAL or WARNING accordingly. It also return ``mean_response_time``
as part of the performnce data.

## Usage

```sh
$ probeim.py -h
usage: probeim.py [-h] [-u URL] [-t TOKEN] [-f LOG_FILE] [-l LOG_LEVEL]

Monitorize IM operations.

optional arguments:
  -h, --help            show this help message and exit
  -u URL, --url URL     URL of the IM REST API endpoint
  -t TOKEN, --token TOKEN
                        OIDC access token
  -f LOG_FILE, --log_file LOG_FILE
                        Path to the log file
  -l LOG_LEVEL, --log_level LOG_LEVEL
                        Set the log level
```

## Generate ARGO RPM package

To generate the RPM package for the ARGO monitoring system:

```sh
$ rpmbuild -ba probeim.spec
```