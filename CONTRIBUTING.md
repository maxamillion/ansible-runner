# Ansible Runner Contributing Guidelines

Hi there! We're excited to have you as a contributor.

If you have questions about this document or anything not covered here? Come chat with us `#ansible-awx` on irc.freenode.net

## Things to know prior to submitting code

- All code and doc submissions are done through pull requests against the `devel` branch.
- Take care to make sure no merge commits are in the submission, and use `git rebase` vs `git merge` for this reason.
- We ask all of our community members and contributors to adhere to the [Ansible code of conduct](http://docs.ansible.com/ansible/latest/community/code_of_conduct.html). If you have questions, or need assistance, please reach out to our community team at [codeofconduct@ansible.com](mailto:codeofconduct@ansible.com)   

## Setting up your development environment

Ansible Runner development is powered by [Poetry](https://python-poetry.org/), make sure you have it [installed](https://python-poetry.org/docs/#installation) and then:

```bash
(host)$ poetry install
```

This will automatically setup the development environment under a virtualenv, which you can then switch to with:

```bash
(host)$ poetry shell
```

## Linting and Unit Tests

`tox` is used to run linters (`flake8` and `yamllint`) and unit tests on both Python 2 and 3. It uses poetry to bootstrap these two environments.

## A note about setup.py

In this repository you will find a [`setup.py` file](https://docs.python.org/3/installing/index.html#installing-index),
this file should never be touched by hand. There is a python script located at
`packaging/poetry-gen-setup.py` which will generate the `setup.py`. If in the
event you need to add or alter the `pyproject.toml` file along with your
changes, please generate a new `setup.py` and include it in your pull request.
This allows the Ansible Runner codebase to be compatible with build and release
systems that do not yet support [Poetry](https://python-poetry.org/).
