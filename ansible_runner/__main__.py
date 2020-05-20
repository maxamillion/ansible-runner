#
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
#
import ast
import pkg_resources
import threading
import traceback
import argparse
import logging
import signal
import sys
import errno
import json
import stat
import os
import shutil
import textwrap

from contextlib import contextmanager
from uuid import uuid4

from yaml import safe_load

from ansible_runner import run
from ansible_runner import output
from ansible_runner.utils import dump_artifact, Bunch
from ansible_runner.runner import Runner
from ansible_runner.exceptions import AnsibleRunnerException

if sys.version_info >= (3, 0):
    from ansible_runner.receptor_plugin import receptor_import
else:
    receptor_import = False

VERSION = pkg_resources.require("ansible_runner")[0].version

DEFAULT_ROLES_PATH = os.getenv('ANSIBLE_ROLES_PATH', None)
DEFAULT_RUNNER_BINARY = os.getenv('RUNNER_BINARY', None)
DEFAULT_RUNNER_PLAYBOOK = os.getenv('RUNNER_PLAYBOOK', None)
DEFAULT_RUNNER_ROLE = os.getenv('RUNNER_ROLE', None)
DEFAULT_RUNNER_MODULE = os.getenv('RUNNER_MODULE', None)
DEFAULT_UUID = uuid4()

DEFAULT_CLI_ARGS = {
    "positional_args": (
        (
            ('private_data_dir',),
            dict(
                help="base directory cotnaining the ansible-runner metadata "
                     "(project, inventory, env, etc)"
            ),
        ),
    ),
    "misc_args": (
        (
            ('--version',),
            dict(
                action='version',
                version=VERSION
            ),
        ),
    ),
    "mutually_exclusive_group": (
        (
            ("-p", "--playbook",),
            dict(
                default=DEFAULT_RUNNER_PLAYBOOK,
                help="invoke an Ansible playbook from the ansible-runner project "
                     "(See Ansible Playbook Options below)"
            ),
        ),
        (
            ("-m", "--module",),
            dict(
                default=DEFAULT_RUNNER_MODULE,
                help="invoke an Ansible module directly without a playbook "
                     "(See Ansible Module Options below)"
            ),
        ),
        (
            ("-r", "--role",),
            dict(
                default=DEFAULT_RUNNER_ROLE,
                help="invoke an Ansible role directly without a playbook "
                     "(See Ansible Role Options below)"
            ),
        ),
    ),
    "ansible_group": (
        (
            ("--limit",),
            dict(
                help="matches Ansible's ```--limit``` parameter to further constrain "
                     "the inventory to be used (default=None)"
            ),
        ),
        (
            ("--cmdline",),
            dict(
                help="command line options to pass to ansible-playbook at "
                     "execution time (default=None)"
            ),
        ),
        (
            ("--hosts",),
            dict(
                help="define the set of hosts to execute against (default=None) "
                     "Note: this parameter only works with -m or -r"
            ),
        ),
        (
            ("--forks",),
            dict(
                help="matches Ansible's ```--forks``` parameter to set the number "
                     "of conconurent processes (default=None)"
            ),
        ),
    ),
    "runner_group": (
        # ansible-runner options
        (
            ("--debug",),
            dict(
                action="store_true",
                help="enable ansible-runner debug output logging (default=False)"
            ),
        ),
        (
            ("--logfile",),
            dict(
                help="log output messages to a file (default=None)"
            ),
        ),
        (
            ("-b", "--binary",),
            dict(
                default=DEFAULT_RUNNER_BINARY,
                help="specifies the full path pointing to the Ansible binaries "
                     "(default={})".format(DEFAULT_RUNNER_BINARY)
            ),
        ),
        (
            ("-i", "--ident",),
            dict(
                default=DEFAULT_UUID,
                help="an identifier that will be used when generating the artifacts "
                     "directory and can be used to uniquely identify a playbook run "
                     "(default={})".format(DEFAULT_UUID)
            ),
        ),
        (
            ("--rotate-artifacts",),
            dict(
                default=0,
                type=int,
                help="automatically clean up old artifact directories after a given "
                     "number have been created (default=0, disabled)"
            ),
        ),
        (
            ("--artifact-dir",),
            dict(
                help="optional path for the artifact root directory "
                     "(default=<private_data_dir>/artifacts)"
            ),
        ),
        (
            ("--project-dir",),
            dict(
                help="optional path for the location of the playbook content directory "
                     "(default=<private_data_dir/project)"
            ),
        ),
        (
            ("--inventory",),
            dict(
                help="optional path for the location of the inventory content directory "
                     "(default=<private_data_dir>/inventory)"
            ),
        ),
        (
            ("-j", "--json",),
            dict(
                action="store_true",
                help="output the JSON event structure to stdout instead of "
                     "Ansible output (default=False)"
            ),
        ),
        (
            ("--omit-event-data",),
            dict(
                action="store_true",
                help="Omits including extra event data in the callback payloads "
                     "or the Runner payload data files "
                     "(status and stdout still included)"
            ),
        ),
        (
            ("--only-failed-event-data",),
            dict(
                action="store_true",
                help="Only adds extra event data for failed tasks in the callback "
                     "payloads or the Runner payload data files "
                     "(status and stdout still included for other events)"
            ),
        ),
        (
            ("-q", "--quiet",),
            dict(
                action="store_true",
                help="disable all messages sent to stdout/stderr (default=False)"
            ),
        ),
        (
            ("-v",),
            dict(
                action="count",
                help="increase the verbosity with multiple v's (up to 5) of the "
                     "ansible-playbook output (default=None)"
            ),
        ),
        (
            ('--exec-env',), # FIXME FIXME - this should probably be a reasonable default
            dict(
                dest='container_image',
                default='execenv',
                help="Container image name containing an Ansible Execution Environment"
            ),
        ),
        (
            ('--container-runtime',),
            dict(
                dest='container_runtime',
                default='podman',
                help="OCI Compliant container runtime to use. Examples: podman, docker"
            ),
        ),

        # Receptor options
        (
            ("--via-receptor",),
            dict(
                default=None,
                help="Run the job on a Receptor node rather than locally"
            ),
        ),
        (
            ("--receptor-peer",),
            dict(
                default=None,
                help="peer connection to use to reach the Receptor network"
            ),
        ),
        (
            ("--receptor-node-id",),
            dict(
                default=None,
                help="Receptor node-id to use for the local node"
            ),
        )
    ),
    "roles_group": (
        (
            ("--roles-path",),
            dict(
                default=DEFAULT_ROLES_PATH,
                help="path used to locate the role to be executed (default=None)"
            ),
        ),
        (
            ("--role-vars",),
            dict(
                help="set of variables to be passed to the role at run time in the "
                      "form of 'key1=value1 key2=value2 keyN=valueN'(default=None)"
            ),
        ),
        (
            ("--role-skip-facts",),
            dict(
                action="store_true",
                default=False,
                help="disable fact collection when the role is executed (default=False)"
            ),
        )
    ),
    "playbook_group": (
        (
            ("--process-isolation",),
            dict(
                dest="process_isolation",
                action="store_true",
                help="limits what directories on the filesystem the playbook run "
                     "has access to, defaults to /tmp (default=False)"
            ),
        ),
        (
            ("--process-isolation-executable",),
            dict(
                dest="process_isolation_executable",
                default="bwrap",
                help="process isolation executable that will be used. (default=bwrap)"
            )
        ),
        (
            ("--process-isolation-path",),
            dict(
                dest="process_isolation_path",
                default="/tmp",
                help="path that an isolated playbook run will use for staging. "
                     "(default=/tmp)"
            )
        ),
        (
            ("--process-isolation-hide-paths",),
            dict(
                dest="process_isolation_hide_paths",
                nargs='*',
                help="list of paths on the system that should be hidden from the "
                      "playbook run (default=None)"
            )
        ),
        (
            ("--process-isolation-show-paths",),
            dict(
                dest="process_isolation_show_paths",
                nargs='*',
                help="list of paths on the system that should be exposed to the "
                     "playbook run (default=None)"
            )
        ),
        (
            ("--process-isolation-ro-paths",),
            dict(
                dest="process_isolation_ro_paths",
                nargs='*',
                help="list of paths on the system that should be exposed to the "
                     "playbook run as read-only (default=None)"
            )
        ),
        (
            ("--directory-isolation-base-path",),
            dict(
                dest="directory_isolation_base_path",
                help="copies the project directory to a location in this directory "
                     "to prevent multiple simultaneous executions from conflicting "
                     "(default=None)"
            )
        ),
        (
            ("--resource-profiling",),
            dict(
                dest='resource_profiling',
                action="store_true",
                help="Records resource utilization during playbook execution"
            )
        ),
        (
            ("--resource-profiling-base-cgroup",),
            dict(
                dest='resource_profiling_base_cgroup',
                default="ansible-runner",
                help="Top-level cgroup used to collect information on resource utilization. Defaults to ansible-runner"
            )
        ),
        (
            ("--resource-profiling-cpu-poll-interval",),
            dict(
                dest='resource_profiling_cpu_poll_interval',
                default=0.25,
                help="Interval (in seconds) between CPU polling for determining CPU usage. Defaults to 0.25"
            )
        ),
        (
            ("--resource-profiling-memory-poll-interval",),
            dict(
                dest='resource_profiling_memory_poll_interval',
                default=0.25,
                help="Interval (in seconds) between memory polling for determining memory usage. Defaults to 0.25"
            )
        ),
        (
            ("--resource-profiling-pid-poll-interval",),
            dict(
                dest='resource_profiling_pid_poll_interval',
                default=0.25,
                help="Interval (in seconds) between polling PID count for determining number of processes used. Defaults to 0.25"
            )
        ),
        (
            ("--resource-profiling-results-dir",),
            dict(
                dest='resource_profiling_results_dir',
                help="Directory where profiling data files should be saved. Defaults to None (profiling_data folder under private data dir is used in this case)."
            )
        )
    ),
    "modules_group": (
        (
            ("-a", "--args",),
            dict(
                dest='module_args',
                help="set of arguments to be passed to the module at run time in the "
                     "form of 'key1=value1 key2=value2 keyN=valueN'(default=None)"
            )
        ),
    )
}

logger = logging.getLogger('ansible-runner')


@contextmanager
def role_manager(vargs):
    if vargs.get('role'):
        role = {'name': vargs.get('role')}
        if vargs.get('role_vars'):
            role_vars = {}
            for item in vargs['role_vars'].split():
                key, value = item.split('=')
                try:
                    role_vars[key] = ast.literal_eval(value)
                except Exception:
                    role_vars[key] = value
            role['vars'] = role_vars

        kwargs = Bunch(**vargs)
        kwargs.update(private_data_dir=vargs.get('private_data_dir'),
                      json_mode=vargs.get('json'),
                      ignore_logging=False,
                      project_dir=vargs.get('project_dir'),
                      rotate_artifacts=vargs.get('rotate_artifacts'))

        if vargs.get('artifact_dir'):
            kwargs.artifact_dir = vargs.get('artifact_dir')

        if vargs.get('project_dir'):
            project_path = kwargs.project_dir = vargs.get('project_dir')
        else:
            project_path = os.path.join(vargs.get('private_data_dir'), 'project')

        project_exists = os.path.exists(project_path)

        env_path = os.path.join(vargs.get('private_data_dir'), 'env')
        env_exists = os.path.exists(env_path)

        envvars_path = os.path.join(vargs.get('private_data_dir'), 'env/envvars')
        envvars_exists = os.path.exists(envvars_path)

        if vargs.get('cmdline'):
            kwargs.cmdline = vargs.get('cmdline')

        playbook = None
        tmpvars = None

        play = [{'hosts': vargs.get('hosts') if vargs.get('hosts') is not None else "all",
                 'gather_facts': not vargs.get('role_skip_facts'),
                 'roles': [role]}]

        filename = str(uuid4().hex)

        playbook = dump_artifact(json.dumps(play), project_path, filename)
        kwargs.playbook = playbook
        output.debug('using playbook file %s' % playbook)

        if vargs.get('inventory'):
            inventory_file = os.path.join(vargs.get('private_data_dir'), 'inventory', vargs.get('inventory'))
            if not os.path.exists(inventory_file):
                raise AnsibleRunnerException('location specified by --inventory does not exist')
            kwargs.inventory = inventory_file
            output.debug('using inventory file %s' % inventory_file)

        roles_path = vargs.get('roles_path') or os.path.join(vargs.get('private_data_dir'), 'roles')
        roles_path = os.path.abspath(roles_path)
        output.debug('setting ANSIBLE_ROLES_PATH to %s' % roles_path)

        envvars = {}
        if envvars_exists:
            with open(envvars_path, 'rb') as f:
                tmpvars = f.read()
                new_envvars = safe_load(tmpvars)
                if new_envvars:
                    envvars = new_envvars

        envvars['ANSIBLE_ROLES_PATH'] = roles_path
        kwargs.envvars = envvars
    else:
        kwargs = vargs

    yield kwargs

    if vargs.get('role'):
        if not project_exists and os.path.exists(project_path):
            logger.debug('removing dynamically generated project folder')
            shutil.rmtree(project_path)
        elif playbook and os.path.isfile(playbook):
            logger.debug('removing dynamically generated playbook')
            os.remove(playbook)

        # if a previous envvars existed in the private_data_dir,
        # restore the original file contents
        if tmpvars:
            with open(envvars_path, 'wb') as f:
                f.write(tmpvars)
        elif not envvars_exists and os.path.exists(envvars_path):
            logger.debug('removing dynamically generated envvars folder')
            os.remove(envvars_path)

        # since ansible-runner created the env folder, remove it
        if not env_exists and os.path.exists(env_path):
            logger.debug('removing dynamically generated env folder')
            shutil.rmtree(env_path)


def print_common_usage():
    print(textwrap.dedent("""
        These are common Ansible Runner commands:

            execute a playbook contained in an ansible-runner directory:

                ansible-runner run /tmp/private -p playbook.yml
                ansible-runner start /tmp/private -p playbook.yml
                ansible-runner stop /tmp/private
                ansible-runner is-alive /tmp/private

            directly execute ansible primitives:

                ansible-runner run . -r role_name --hosts myhost
                ansible-runner run . -m command -a "ls -l" --hosts myhost

            run ansible execution environments:

                ansible-runner adhoc myhosts -m ping
                ansible-runner playbook my_playbook.yml

        `ansible-runner --help` list of optional command line arguments
    """))


def add_args_to_parser(parser, args):
    """
    Traverse a tuple of argments to add to a parser

    :param parser: Instance of a parser, subparser, or argument group
    :type sys_args: argparse.ArgumentParser

    :param args: Tuple of tuples, format ((arg1, arg2), {'kwarg1':'val1'},)
    :type sys_args: tuple

    :returns: None
    """
    for arg in args:
        parser.add_argument(*arg[0], **arg[1])


def main(sys_args=None):
    """Main entry point for ansible-runner executable

    When the ```ansible-runner``` command is executed, this function
    is the main entry point that is called and executed.

    :param sys_args: List of arguments to be parsed by the parser
    :type sys_args: list

    :returns: an instance of SystemExit
    :rtype: SystemExit
    """

    parser = argparse.ArgumentParser(
        prog='ansible-runner',
        description="Use 'ansible-runner' (with no arguments) to see basic usage"
    )
    subparser = parser.add_subparsers(
        help="Command to invoke",
        dest='command',
        description="COMMAND PRIVATE_DATA_DIR [ARGS]"
    )


    # positional options
    run_subparser = subparser.add_parser(
        'run',
        help="Run ansible-runner in the foreground"
    )
    add_args_to_parser(run_subparser, DEFAULT_CLI_ARGS['positional_args'])
    start_subparser = subparser.add_parser(
        'start',
        help="Start an ansible-runner process in the background"
    )
    add_args_to_parser(start_subparser, DEFAULT_CLI_ARGS['positional_args'])
    stop_subparser = subparser.add_parser(
        'stop',
        help="Stop an ansible-runner process that's running in the background"
    )
    add_args_to_parser(stop_subparser, DEFAULT_CLI_ARGS['positional_args'])
    isalive_subparser = subparser.add_parser(
        'is-alive',
        help="Check if a an ansible-runner process in the background is still running."
    )
    add_args_to_parser(isalive_subparser, DEFAULT_CLI_ARGS['positional_args'])


    # adhoc command exec
    adhoc_subparser = subparser.add_parser(
        'adhoc',
        help="Run ansible adhoc commands in an Execution Environment"
    )
    adhoc_subparser.add_argument(
        "cmdline",
        nargs=argparse.REMAINDER,
        help="command line options to pass to ansible at execution time"
    )
    adhoc_subparser.add_argument(
        "--private-data-dir",
        help="base directory cotnaining the ansible-runner metadata "
             "(project, inventory, env, etc)",
        default='.'
    )

    # adhoc command exec
    playbook_subparser = subparser.add_parser(
        'playbook',
        help="Run ansible-playbook commands in an Execution Environment"
    )
    playbook_subparser.add_argument(
        "cmdline",
        nargs=argparse.REMAINDER,
        help="command line options to pass to ansible at execution time"
    )
    playbook_subparser.add_argument(
        "--private-data-dir",
        help="base directory cotnaining the ansible-runner metadata "
             "(project, inventory, env, etc)",
        default='.'
    )

    # misc args
    add_args_to_parser(run_subparser, DEFAULT_CLI_ARGS['misc_args'])
    add_args_to_parser(start_subparser, DEFAULT_CLI_ARGS['misc_args'])
    add_args_to_parser(stop_subparser, DEFAULT_CLI_ARGS['misc_args'])
    add_args_to_parser(isalive_subparser, DEFAULT_CLI_ARGS['misc_args'])
    add_args_to_parser(adhoc_subparser, DEFAULT_CLI_ARGS['misc_args'])

    # runner group
    ansible_runner_group_options = (
        "Ansible Runner Options",
        "configuration options for controlling the ansible-runner "
        "runtime environment.",
    )
    run_runner_group = run_subparser.add_argument_group(*ansible_runner_group_options)
    start_runner_group = start_subparser.add_argument_group(*ansible_runner_group_options)
    stop_runner_group = stop_subparser.add_argument_group(*ansible_runner_group_options)
    isalive_runner_group = isalive_subparser.add_argument_group(*ansible_runner_group_options)
    adhoc_runner_group = adhoc_subparser.add_argument_group(*ansible_runner_group_options)
    playbook_runner_group = playbook_subparser.add_argument_group(*ansible_runner_group_options)
    add_args_to_parser(run_runner_group, DEFAULT_CLI_ARGS['runner_group'])
    add_args_to_parser(start_runner_group, DEFAULT_CLI_ARGS['runner_group'])
    add_args_to_parser(stop_runner_group, DEFAULT_CLI_ARGS['runner_group'])
    add_args_to_parser(isalive_runner_group, DEFAULT_CLI_ARGS['runner_group'])
    add_args_to_parser(adhoc_runner_group, DEFAULT_CLI_ARGS['runner_group'])
    add_args_to_parser(playbook_runner_group, DEFAULT_CLI_ARGS['runner_group'])

    # mutually exclusive group
    run_mutually_exclusive_group = run_subparser.add_mutually_exclusive_group()
    start_mutually_exclusive_group = start_subparser.add_mutually_exclusive_group()
    stop_mutually_exclusive_group = stop_subparser.add_mutually_exclusive_group()
    isalive_mutually_exclusive_group = isalive_subparser.add_mutually_exclusive_group()
    add_args_to_parser(run_mutually_exclusive_group, DEFAULT_CLI_ARGS['mutually_exclusive_group'])
    add_args_to_parser(start_mutually_exclusive_group, DEFAULT_CLI_ARGS['mutually_exclusive_group'])
    add_args_to_parser(stop_mutually_exclusive_group, DEFAULT_CLI_ARGS['mutually_exclusive_group'])
    add_args_to_parser(isalive_mutually_exclusive_group, DEFAULT_CLI_ARGS['mutually_exclusive_group'])

    # ansible options
    ansible_options = (
        "Ansible Options",
        "control the ansible[-playbook] execution environment",
    )
    run_ansible_group = run_subparser.add_argument_group(*ansible_options)
    start_ansible_group = start_subparser.add_argument_group(*ansible_options)
    stop_ansible_group = stop_subparser.add_argument_group(*ansible_options)
    isalive_ansible_group = isalive_subparser.add_argument_group(*ansible_options)
    add_args_to_parser(run_ansible_group, DEFAULT_CLI_ARGS['ansible_group'])
    add_args_to_parser(start_ansible_group, DEFAULT_CLI_ARGS['ansible_group'])
    add_args_to_parser(stop_ansible_group, DEFAULT_CLI_ARGS['ansible_group'])
    add_args_to_parser(isalive_ansible_group, DEFAULT_CLI_ARGS['ansible_group'])


    # roles group
    roles_group_options = (
        "Ansible Role Options",
        "configuration options for directly executing Ansible roles",
    )
    run_roles_group = run_subparser.add_argument_group(*roles_group_options)
    start_roles_group = start_subparser.add_argument_group(*roles_group_options)
    stop_roles_group = stop_subparser.add_argument_group(*roles_group_options)
    isalive_roles_group = isalive_subparser.add_argument_group(*roles_group_options)
    add_args_to_parser(run_roles_group, DEFAULT_CLI_ARGS['roles_group'])
    add_args_to_parser(start_roles_group, DEFAULT_CLI_ARGS['roles_group'])
    add_args_to_parser(stop_roles_group, DEFAULT_CLI_ARGS['roles_group'])
    add_args_to_parser(isalive_roles_group, DEFAULT_CLI_ARGS['roles_group'])

    # modules groups

    modules_group_options = (
            "Ansible Module Options",
            "configuration options for directly executing Ansible modules",
    )
    run_modules_group = run_subparser.add_argument_group(*modules_group_options)
    start_modules_group = start_subparser.add_argument_group(*modules_group_options)
    stop_modules_group = stop_subparser.add_argument_group(*modules_group_options)
    isalive_modules_group = isalive_subparser.add_argument_group(*modules_group_options)
    adhoc_modules_group = adhoc_subparser.add_argument_group(*modules_group_options)
    add_args_to_parser(run_modules_group, DEFAULT_CLI_ARGS['modules_group'])
    add_args_to_parser(start_modules_group, DEFAULT_CLI_ARGS['modules_group'])
    add_args_to_parser(stop_modules_group, DEFAULT_CLI_ARGS['modules_group'])
    add_args_to_parser(isalive_modules_group, DEFAULT_CLI_ARGS['modules_group'])
    add_args_to_parser(adhoc_modules_group, DEFAULT_CLI_ARGS['modules_group'])

    # playbook options
    playbook_group_options = (
        "Ansible Playbook Options",
        "configuation options for executing Ansible playbooks",
    )
    run_playbook_group = run_subparser.add_argument_group(*playbook_group_options)
    start_playbook_group = start_subparser.add_argument_group(*playbook_group_options)
    stop_playbook_group = stop_subparser.add_argument_group(*playbook_group_options)
    isalive_playbook_group = isalive_subparser.add_argument_group(*playbook_group_options)
    add_args_to_parser(run_playbook_group, DEFAULT_CLI_ARGS['playbook_group'])
    add_args_to_parser(start_playbook_group, DEFAULT_CLI_ARGS['playbook_group'])
    add_args_to_parser(stop_playbook_group, DEFAULT_CLI_ARGS['playbook_group'])
    add_args_to_parser(isalive_playbook_group, DEFAULT_CLI_ARGS['playbook_group'])

    if len(sys.argv) == 1:
        parser.print_usage()
        print_common_usage()
        parser.exit(status=0)

    args = parser.parse_args(sys_args)
    vargs = vars(args)

    # FIXME - Probably a more elegant way to handle this.
    # set some state about CLI Exec Env 
    cli_execenv = None
    containerized = False

    if vargs.get('command') in ('adhoc', 'playbook'):
        containerized = True
        cli_execenv = vargs.get('command')


    if vargs.get('command') in ('start', 'run'):
        if vargs.get('hosts') and not (vargs.get('module') or vargs.get('role')):
            parser.exit(status=1, message="The --hosts option can only be used with -m or -r\n")
        if not (vargs.get('module') or vargs.get('role')) and not vargs.get('playbook'):
            parser.exit(status=1, message="The -p option must be specified when not using -m or -r\n")

    if vargs.get('via_receptor') and not receptor_import:
        parser.exit(status=1, message="The --via-receptor option requires Receptor to be installed.\n")

    if vargs.get('via_receptor') and vargs.get('command') != 'run':
        parser.exit(status=1, message="Only the 'run' command is supported via Receptor.\n")

    output.configure()

    # enable or disable debug mode
    output.set_debug('enable' if vargs.get('debug') else 'disable')

    # set the output logfile
    if ('logfile' in args) and vargs.get('logfile'):
        output.set_logfile(vargs.get('logfile'))

    output.debug('starting debug logging')

    # get the absolute path for start since it is a daemon
    vargs['private_data_dir'] = os.path.abspath(vargs.get('private_data_dir'))

    pidfile = os.path.join(vargs.get('private_data_dir'), 'pid')

    try:
        os.makedirs(vargs.get('private_data_dir'), mode=0o700)
    except OSError as exc:
        if exc.errno == errno.EEXIST and os.path.isdir(vargs.get('private_data_dir')):
            pass
        else:
            raise

    stderr_path = None
    context = None
    if vargs.get('command') not in ('run', 'adhoc', 'playbook'):
        stderr_path = os.path.join(vargs.get('private_data_dir'), 'daemon.log')
        if not os.path.exists(stderr_path):
            os.close(os.open(stderr_path, os.O_CREAT, stat.S_IRUSR | stat.S_IWUSR))

    if vargs.get('command') in ('start', 'run', 'adhoc', 'playbook'):

        if vargs.get('command') == 'start':
            import daemon
            from daemon.pidfile import TimeoutPIDLockFile
            context = daemon.DaemonContext(pidfile=TimeoutPIDLockFile(pidfile))
        else:
            context = threading.Lock()

        with context:
            with role_manager(vargs) as vargs:
                run_options = dict(private_data_dir=vargs.get('private_data_dir'),
                                   ident=vargs.get('ident'),
                                   binary=vargs.get('binary'),
                                   playbook=vargs.get('playbook'),
                                   module=vargs.get('module'),
                                   module_args=vargs.get('module_args'),
                                   host_pattern=vargs.get('hosts'),
                                   verbosity=vargs.get('v'),
                                   quiet=vargs.get('quiet'),
                                   rotate_artifacts=vargs.get('rotate_artifacts'),
                                   ignore_logging=False,
                                   json_mode=vargs.get('json'),
                                   omit_event_data=vargs.get('omit_event_data'),
                                   only_failed_event_data=vargs.get('only_failed_event_data'),
                                   inventory=vargs.get('inventory'),
                                   forks=vargs.get('forks'),
                                   project_dir=vargs.get('project_dir'),
                                   artifact_dir=vargs.get('artifact_dir'),
                                   roles_path=[vargs.get('roles_path')] if vargs.get('roles_path') else None,
                                   process_isolation=vargs.get('process_isolation'),
                                   process_isolation_executable=vargs.get('process_isolation_executable'),
                                   process_isolation_path=vargs.get('process_isolation_path'),
                                   process_isolation_hide_paths=vargs.get('process_isolation_hide_paths'),
                                   process_isolation_show_paths=vargs.get('process_isolation_show_paths'),
                                   process_isolation_ro_paths=vargs.get('process_isolation_ro_paths'),
                                   directory_isolation_base_path=vargs.get('directory_isolation_base_path'),
                                   resource_profiling=vargs.get('resource_profiling'),
                                   resource_profiling_base_cgroup=vargs.get('resource_profiling_base_cgroup'),
                                   resource_profiling_cpu_poll_interval=vargs.get('resource_profiling_cpu_poll_interval'),
                                   resource_profiling_memory_poll_interval=vargs.get('resource_profiling_memory_poll_interval'),
                                   resource_profiling_pid_poll_interval=vargs.get('resource_profiling_pid_poll_interval'),
                                   resource_profiling_results_dir=vargs.get('resource_profiling_results_dir'),
                                   limit=vargs.get('limit'),
                                   via_receptor=vargs.get('via_receptor'),
                                   receptor_peer=vargs.get('receptor_peer'),
                                   receptor_node_id=vargs.get('receptor_node_id'),
                                   containerized=containerized,
                                   container_runtime=vargs.get('container_runtime'),
                                   container_image=vargs.get('container_image'),
                                   cli_execenv=cli_execenv
                                   )
                if vargs.get('cmdline'):
                    run_options['cmdline'] = vargs.get('cmdline')

                try:
                    res = run(**run_options)
                except Exception:
                    exc = traceback.format_exc()
                    if stderr_path:
                        open(stderr_path, 'w+').write(exc)
                    else:
                        sys.stderr.write(exc)
                    return 1
            return(res.rc)

    try:
        with open(pidfile, 'r') as f:
            pid = int(f.readline())
    except IOError:
        return(1)

    if vargs.get('command') == 'stop':
        Runner.handle_termination(pid, pidfile=pidfile)
        return (0)

    elif vargs.get('command') == 'is-alive':
        try:
            os.kill(pid, signal.SIG_DFL)
            return(0)
        except OSError:
            return(1)
