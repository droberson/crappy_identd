# CRAPPY IDENT SERVER

I wrote this to get rid of the ~ on my username on IRC and to have the ability
to lie about my actual username.

Simply place a file containing your desired username in ~/.fakeid to lie about
your username.

### Dependencies:
For the handling of the yaml mapping `PyYAML` is required.

You can for example use `pip install PyYAML` to install it.

### Mappings:
You have the ability to override on a per-IP, per-Host or per-Username basis.

Per-IP means, if the IP the request originates from matches a key in the `ip`
hash we'll always return the corresponding value. There is no check if that
IP matches a connection that we opened.

If there is no match by IP we'll do a reverse DNS lookup to see if there's a
hostname associated with it. If there is a hostname and it matches a key in
the `host` hash we'll return the corresponding value. Again, no checking of
whether or not we initiated the connection.

It is also possible to specify a username override. If the user that opened
the connection is `root` we'll not tell the other side about that, instead
we'll tell them the ID is `toor`. This only works for connections we actively
initiated to get the port <-> username mapping.

Example mapping:
```yaml
ip:
  127.0.0.1: internal
host:
  irc.efnet.org: reverse
user:
  root: toor
```

### Notes:
This identd supports Python 2.7 (tested) as well as Python 3.5 (tested).

Other versions of Python 3 are likely to work aswell as there is not a lot of
code that might be incompatible between both versions.

### Usage:
```bash
usage: crappy_identd.py [-h] [-u USER] [-m MAPPING] [-l] [-i IDFILE] [-f]

optional arguments:
  -h, --help            show this help message and exit
  -u USER, --user USER  run as the specified user
  -m MAPPING, --mapping MAPPING
                        path to mapping.yml with ip/host/user overrides
  -l, --lie             don't check for port/user association
  -i IDFILE, --idfile IDFILE
                        name of the id file in users homedir (default: .fakeid)
  -f, --fake            return fake username from mapping if no idfile can be found

```
