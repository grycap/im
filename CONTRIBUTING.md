# Contributing

Contributions are welcome, and they are greatly appreciated!
When contributing to this repository, please first discuss the change you wish
to make via issue, email, or any other method with the owners of this
repository before making a change.

Please note we have a [code of conduct](CODE_OF_CONDUCT.md), please follow it
in all your interactions with the project.

## Reporting bugs

Report bugs at <https://github.com/grycap/im/issues>

If you are reporting a bug, please include:

* Your operating system name and version.
* Any details about your local setup that might be helpful in troubleshooting.
* If you can, provide detailed steps to reproduce the bug.
* If you don't have steps to reproduce the bug, just note your observations in
  as much detail as you can. Questions to start a discussion about the issue
  are welcome.

### Submit Feedback

The best way to send feedback is to file an issue at the follwing URL:

<https://github.com/grycap/im/issues>

If you are proposing a feature:

* Explain in detail how it would work.
* Keep the scope as narrow as possible, to make it easier to implement.
* Remember that this is a volunteer-driven project, and that contributions
  are welcome :)

## Pull Request Process

You are welcome to open Pull Requests for either fixing a bug, adding a new
feature, contributing to the documentation, etc.

* The Pull Request should include tests.
* For testing we use tox tool, update tox.ini file correspondingly.
* The Pull Request should work for Python 3.6 and above.
* Increase the version numbers in any examples files and the README.md to
  the new version that this Pull Request would represent. The versioning
  scheme we use is [SemVer](http://semver.org/).
* If the Pull Request adds functionality, the docs should be updated. Put your
  new functionality into a function with a docstring
  ([Sphinx docstring format](https://sphinx-rtd-tutorial.readthedocs.io/en/latest/docstrings.html)),
  and add the feature in the appropriate place in sphinx docs (`docs/source` directory).
* Update the README.md with details of changes to the interface, this includes
  new environment variables, exposed ports, useful file locations and
  container parameters.

## Coding Standards

* PEP8 with line length of 120 characters.
* Write new code in Python 3
* [Sphinx docstring format](https://sphinx-rtd-tutorial.readthedocs.io/en/latest/docstrings.html)