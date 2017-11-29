#!/usr/bin/env python

"""
crappy_identd.py -- An ident server designed to artifically inflate my
                 -- IRC client's eliteness.
  by Daniel Roberson @dmfroberson                        November/2017
"""

# TODO:
# - daemonize
# - ability to lie by default (dont actually check port, just return a value)
# - real user:fake user mappings config file (in case of unreadable home dir)
# - detect enumeration attempts: X attempts in Y seconds from Z address...
# - error checking for bind, listen, socket, ...

import os
import re
import pwd
import sys
import time
import socket
import syslog


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


def get_uid_from_port(port):
    """ get_uid_from_port() -- Maps UID to port number via /proc/net/tcp.

    Args:
        port (int) - Local port number

    Returns:
        UID as an int of the owner of the specified port.
        None if no match was found.
    """
    with open("/proc/net/tcp") as proc_net_tcp:
        for line in proc_net_tcp:
            try:
                lport = line.split()[1]
                lport = lport.split(":")[1]
                lport = int(lport, 16)
            except IndexError:
                continue

            if port == lport:
                return int(line.split()[7])

    return None


def identd_response(data):
    """ identd_response() -- Parse ident request. Return appropriate response.

        Args:
            data (str) - Client's request.

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

    # Figure out which user is using lport
    uid = get_uid_from_port(lport)

    if uid is None:
        response = "%s : ERROR : NO-USER" % data
        return response

    try:
        username = pwd.getpwuid(uid).pw_name
    except KeyError:
        response = "%s : ERROR : NO-USER" % data
        return response

    # See if user has a .fakeid
    fakeid = os.path.join(pwd.getpwuid(uid).pw_dir, ".fakeid")
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

    # No fakeid, so return the actual username.
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
        print time.strftime("%b %d %H:%M:%S"), message
    else:
        print message


def main():
    """ main() -- Entry point of the program.

    Args:
        None.

    Returns:
        Nothing.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("0.0.0.0", 113))
    sock.listen(5)

    drop_privileges("nobody")

    syslog.openlog(logoption=syslog.LOG_PID, facility=syslog.LOG_AUTH)
    output_message("server started.")

    while True:
        client, addr = sock.accept()
        data = client.recv(1024)
        output_message("request from %s: %s" % (addr[0], data.rstrip()))

        response = identd_response(data.rstrip())
        output_message("reply to %s: %s" % (addr[0], response))

        client.send("%s\r\n" % response)
        client.close()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        output_message("caught SIGINT. Exiting.")
        sys.exit(os.EX_USAGE)

