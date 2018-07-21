# h3c

A command line tool for H3C 802.1X authentication

## Usage

```sh
Usage: h3c [options]

-h, --help          This help text
-u, --username      Username
-p, --password      Password
-i, --interface     Network interface (Default: en0)
-m, --method        EAP-MD5 CHAP Method [md5 / xor] (Default: md5)
-c, --color         Enable colorized output
```

For example:

```sh
# ./h3c -u user -p pass -i en0 -m md5 -c
```

If there's no password provided with the CLI, the program will prompt for the password.

## TODO

- Implement daemon method
- Implement MD5-Challenge (XOR)
- Implement H3C-Challenge
- Port to Linux (Ubuntu 18.04 LTS) platform
- Port to OpenWrt 18.06 platform

## Special Thanks

- [SYSU H3C Client](https://github.com/zonyitoo/sysuh3c)
- [h3c](https://github.com/renbaoke/h3c)
- [Alexander Peslya](http://openwall.info/wiki/people/solar/software/public-domain-source-code/md5)
