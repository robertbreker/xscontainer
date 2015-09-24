from xscontainer import api_helper
from xscontainer import util
from xscontainer.util import log

import os
import paramiko
import paramiko.rsakey
import socket
import StringIO
import sys
import time

IDRSAFILENAME = '/opt/xensource/packages/files/xscontainer/xscontainer-idrsa'


class SshException(util.XSContainerException):
    pass


class VmHostKeyException(SshException):
    pass


class AuthenticationException(SshException):
    pass


def ensure_idrsa(session):
    neednewfile = False
    if os.path.exists(IDRSAFILENAME):
        mtime = os.path.getmtime(IDRSAFILENAME)
        if time.time() - mtime > 60:
            neednewfile = True
    else:
        neednewfile = True
    if neednewfile:
        util.write_file(IDRSAFILENAME,
                        api_helper.get_idrsa_secret_private(session))


class MyHostKeyPolicy(paramiko.MissingHostKeyPolicy):

    _session = None
    _vm_uuid = None

    def __init__(self, session, vm_uuid):
        self._session = session
        self._vm_uuid = vm_uuid

    def missing_host_key(self, client, hostname, key):
        hostkey = key.get_base64()
        remembered_hostkey = api_helper.get_ssh_hostkey(self._session,
                                                        self._vm_uuid)
        if remembered_hostkey:
            # We have a key on record
            if hostkey == remembered_hostkey:
                # all good - continue
                return
            else:
                # bad - throw error because of mismatch
                message = ("Key for VM %s does not match the known public key."
                           % (self._vm_uuid))
                log.error(message)
                raise VmHostKeyException(message)
        else:
            # we don't have key on record. Let's remember this one for next
            # time
            log.debug("No public key on record found for %s. Will remember."
                      % hostkey)
            api_helper.set_ssh_hostkey(self._session, self._vm_uuid, hostkey)
            # all good - continue
            return


class SshLikeTcpClient:
    asocket = None

    def __init__(self, host, port):
        self.asocket = socket.socket()
        self.asocket.connect((host, port))

    def close(self):
        if self.asocket:
            self.asocket.close()
            self.asocket = None

    def __del__(self):
        self.close()

    def exec_command(self, command):
        ahandle = SshLikeFileHandle(self.asocket.fileno())
        return (ahandle, ahandle, ahandle)


class SshLikeChannel:
    afileno = None

    def __init__(self, fileno):
        self.afileno = fileno

    def shutdown_write(self):
        pass

    def recv_exit_status(self):
        return 0

    def fileno(self):
        return self.afileno


class SshLikeFileHandle:
    afileno = None
    channel = None

    def __init__(self, fileno):
        self.afileno = fileno
        self.channel = SshLikeChannel(fileno)

    def read(self, length):
        return os.read(self.afileno, length)

    def write(self, data):
        os.write(self.afileno, data)
        log.info("write %s" % data)


def prepare_ssh_client(session, vmuuid):
    username = api_helper.get_vm_xscontainer_username(session, vmuuid)
    host = api_helper.get_suitable_vm_ip(session, vmuuid)
    log.info("prepare_ssh_client for vm %s via %s" % (vmuuid, host))
    # Hack: Let's try unencrypted first
    try:
        return SshLikeTcpClient(host, 2375)
    except:
        # fall back to SSH
        pass
    ensure_idrsa(session)
    client = paramiko.SSHClient()
    pkey = paramiko.rsakey.RSAKey.from_private_key(
        StringIO.StringIO(api_helper.get_idrsa_secret_private(session)))
    client.get_host_keys().clear()
    client.set_missing_host_key_policy(MyHostKeyPolicy(session, vmuuid))
    try:
        client.connect(host, port=22, username=username, pkey=pkey,
                       look_for_keys=False)
    except SshException:
        # This exception is already improved - leave it as it is
        raise
    except paramiko.AuthenticationException, exception:
        message = ("prepare_ssh_client failed to authenticate with private key"
                   " on VM %s" % (vmuuid))
        log.info(message)
        raise AuthenticationException(message)
    except (paramiko.SSHException, socket.error), exception:
        # reraise as SshException
        raise SshException("prepare_ssh_client: %s" % exception,
                           (sys.exc_info()[2]))
    return client


def execute_ssh(session, vmuuid, cmd, stdin_input=None):
    # The heavy weight is docker ps with plenty of containers.
    # Assume 283 bytes per container.
    # 300KB should be enough for 1085 containers.
    max_read_size = 300 * 1024
    client = None
    try:
        try:
            client = prepare_ssh_client(session, vmuuid)
            if isinstance(cmd, list):
                cmd = ' '.join(cmd)
            stripped_stdin_input = stdin_input
            if stripped_stdin_input:
                stripped_stdin_input = stripped_stdin_input.strip()
            log.info("execute_ssh will run '%s' with stdin '%s' on vm %s"
                     % (cmd, stripped_stdin_input, vmuuid))
            stdin, stdout, _ = client.exec_command(cmd)
            if stdin_input:
                stdin.write(stdin_input)
                stdin.channel.shutdown_write()
            output = stdout.read(max_read_size)
            if stdout.read(1) != "":
                raise SshException("too much data was returned when executing"
                                   "'%s'" % (cmd))
            returncode = stdout.channel.recv_exit_status()
            if returncode != 0:
                log.info("execute_ssh '%s' on vm %s exited with rc %d: Stdout:"
                         " %s" % (cmd, vmuuid, returncode, stdout))
                raise SshException("Returncode for '%s' is not 0" % cmd)
            return output
        except SshException:
            # This exception is already improved - leave it as it is
            raise
        except Exception, exception:
            # reraise as SshException
            raise SshException("execute_ssh: %s" % exception,
                               (sys.exc_info()[2]))
    finally:
        if client:
            client.close()
