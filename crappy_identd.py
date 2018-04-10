#!/usr/bin/env python

"""
crappy_identd.py -- An ident server designed to artifically inflate my
                 -- IRC client's eliteness.
  by Daniel Roberson @dmfroberson             November - December/2017
"""

# TODO:
# - daemonize

import argparse
import os
import re
import pwd
import sys
import time
import socket
import syslog
import uuid
import yaml


def is_valid_port(port):
    """ is_valid_port() -- Determines if a number is a valid value for a TCP/IP port.

    Args:
        port (int) - Port number.

    Returns:
        True if port is a valid port number.
        False if port is not a valid port number.
    """
    if port > 0 and port <= 65535:
        return True

    return False


def get_uid_from_port(source_ip, port):
    """ get_uid_from_port() -- Maps UID to port number via /proc/net/tcp.

    Args:
        source_ip(str) - Source IP of the request
        port (int)     - Local port number

    Returns:
        UID as an int of the owner of the specified port.
        None if no match was found.
    """
    if ':' in source_ip:
        target = "/proc/net/tcp6"
    else:
        target = "/proc/net/tcp"
    with open(target) as proc_net_tcp:
        for line in proc_net_tcp:
            try:
                lport = line.split()[1]
                lport = lport.split(":")[1]
                lport = int(lport, 16)
            except IndexError:
                continue

            if port == lport:
                # State 0A is listening. Do not disclose this.
                if line.split()[3] == "0A":
                    return None

                return int(line.split()[7])

    return None


def identd_response(source_ip, data, mapping):
    """ identd_response() -- Parse ident request. Return appropriate response.

        Args:
            source_ip (str) - Client IP.
            data (str)      - Client's request.
            mapping (dict)  - User-defined overrides per IP/DNS/User.

        Returns:
            String containing the response.
    """
    if re.match(r"(\d+).*,.*(\d+)", data) is None:
        # Doesn't match "lport , lport" format
        response = "%s : ERROR : INVALID-PORT" % data
        return response

    # Make sure ports are sane
    lport, rport = data.split(",")

    lport = int(re.sub(r"\D", "", lport))
    rport = int(re.sub(r"\D", "", rport))

    if not is_valid_port(lport) or not is_valid_port(rport):
        response = "%s : ERROR : INVALID-PORT" % data
        return response

    username = ""

    if args.lie:
        username = uuid.uuid4().get_hex()[0:7]
    elif mapping:
        if source_ip in mapping['ip']:
            username = mapping['ip'][source_ip]
        else:
            try:
                # Check whether the IP has a reverse DNS entry
                source_host = socket.gethostbyaddr(source_ip)[0]
                if source_host in mapping['host']:
                    username = mapping['host'][source_host]
            except socket.herror as e:
                pass
    # If we got a username like that we're done here
    if username:
        return "%s : USERID : UNIX : %s" % (data, username)

    # Figure out which user is using lport
    uid = get_uid_from_port(source_ip, lport)

    if uid is None:
        response = "%s : ERROR : NO-USER" % data
        return response

    try:
        username = pwd.getpwuid(uid).pw_name
    except KeyError:
        response = "%s : ERROR : NO-USER" % data
        return response

    # See if user has a .fakeid
    fakeid = os.path.join(pwd.getpwuid(uid).pw_dir, args.idfile)
    if os.path.isfile(fakeid) and not os.path.islink(fakeid):
        try:
            with open(fakeid) as fake_id_file:
                for line in fake_id_file:
                    # Skip comments
                    if line[:1] == "#":
                        continue

                    # *nix username regex, but allow UPPERCASE as well because IRC
                    if re.match(r"[a-zA-Z_][a-zA-Z0-9_-]*[$]?", line.rstrip()):
                        username = line.rstrip()
                        break
        except IOError as err:
            pass
    elif args.fake:
        if username in mapping['user']:
            username = mapping['user'][username]

    # Return the actual username if no fakeid was found.
    response = "%s : USERID : UNIX : %s" % (data, username)
    return response


def drop_privileges(username):
    """ drop_privileges() -- setuid()/setgid() to something other than root.

    Args:
        username (str) - Username to attempt to setuid() to.

    Returns:
        Nothing.
    """
    # Check if this is even running as root in the first place
    if os.getuid() != 0:
        return

    uid = pwd.getpwnam(username).pw_uid
    gid = pwd.getpwnam(username).pw_gid

    # Always setgid() before setuid()
    os.setgroups([])
    os.setgid(gid)
    os.setuid(uid)


def output_message(message, timestamp=True, use_syslog=True):
    """ output_message() -- Deal with outputting messages; logging, stdout,
                         -- all that stuff.

    Args:
        message (str)     - Message to output.

        timestamp (bool)  - Whether or not to add a timestamp to the message.
                            Default: True.

        use_syslog (bool) - Whether or not to use syslog facilities.
                            Default: True.

    Returns:
        Nothing.
    """
    if use_syslog:
        syslog.syslog(message)

    if timestamp:
        print("%s %s" % (time.strftime("%b %d %H:%M:%S"), message))
    else:
        print(message)


def main(args):
    """ main() -- Entry point of the program.

    Args:
        args    - Arguments as supplied on commandline via argparse.

    Returns:
        Nothing.
    """
    if args.mapping:
        with open(args.mapping, "r") as file:
            try:
                mapping = yaml.safe_load(file)
            except yaml.YAMLError as e:
                output_message("error while loading yml mapping: %s" % e)
                sys.exit(os.EX_DATAERR)
        # Initialize mapping with empty defaults if missing in YAML
        if 'ip' not in mapping:
            mapping['ip'] = {}
        if 'host' not in mapping:
            mapping['host'] = {}
        if 'user' not in mapping:
            mapping['user'] = {}
    else:
        mapping = None

    try:
        sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    except socket.error as message:
        output_message("unable to create socket: %s" % message)
        sys.exit(os.EX_USAGE)

    try:
        sock.bind(("::", 113))
    except socket.error as message:
        output_message("unable to bind socket: %s" % message)
        sys.exit(os.EX_USAGE)

    try:
        sock.listen(5)
    except socket.error as message:
        output_message("unable to listen: %s" % message)
        sys.exit(os.EX_USAGE)

    drop_privileges(args.user)

    syslog.openlog(logoption=syslog.LOG_PID, facility=syslog.LOG_AUTH)
    output_message("server started.")

    while True:
        client, addr = sock.accept()
        try:
            data = client.recv(1024).decode('ascii')
        #except socket.error as message:
        except:
            output_message("receive error from %s: %s" % (addr[0], message))
            continue

        source_ip = addr[0]
        if source_ip.startswith('::ffff:'):
            # IPv4 addresses look like ::ffff:127.0.0.1
            source_ip = source_ip.replace('::ffff:', '')

        output_message("request from %s: %s" % (source_ip, data.rstrip()))

        response = identd_response(source_ip, data.rstrip(), mapping)
        output_message("reply to %s: %s" % (source_ip, response))

        client.send("{}\r\n".format(response).encode('ascii'))
        client.close()


if __name__ == "__main__":
    try:
        parser = argparse.ArgumentParser("crappy identd")
        parser.add_argument("-u",
                            "--user",
                            help="run as the specified user",
                            default="nobody")
        parser.add_argument("-m",
                            "--mapping",
                            help="path to mapping.yml containing overrides",
                            default=None)
        parser.add_argument("-l",
                            "--lie",
                            help="don't check for port/user association",
                            action="store_true",
                            default=False)
        parser.add_argument("-i",
                            "--idfile",
                            help="name of the id file in users homedir",
                            default=".fakeid")
        parser.add_argument("-f",
                            "--fake",
                            help="return fake username from mapping if no idfile can be found",
                            action="store_true",
                            default="False")
        args = parser.parse_args()
        main(args)
    except KeyboardInterrupt:
        output_message("caught SIGINT. Exiting.")
        sys.exit(os.EX_USAGE)

