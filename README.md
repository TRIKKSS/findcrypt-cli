# FINDCRYPT - CLI

## Installation

```
git clone https://github.com/TRIKKSS/findcrypt-cli.git
cd findcrypt-cli
python3 -m pip install -r requirements.txt
```

## Usage

```
python3 findcrypt.py [options] <file>
```
```
positional arguments:
  file            file to parse

options:
  -h, --help      show this help message and exit
  -o, --offsets   print offsets of values found.
  -f, --function  search for cryptographic functions (only ELF)
```

## Examples

```
python3 findcrypt.py -o ../Downloads/firmware.bin        2 ↵
[~] parsing ../Downloads/firmware.bin
[+] CRC32_poly_Constant found
offsets : { 0x15174 }
[+] SHA256_Constants found
offsets : { 0x3c60, 0x3c6c, 0x3c78, 0x3c80, 0x3c88, 0x3c90, 0x3c64, 0x3c98 }
[+] SHA512_Constants found
offsets : { 0x14544, 0x1454c, 0x14554, 0x1455c, 0x14540 }
```

```
python3 findcrypt.py -fo ../ctf/elf.bin
[~] parsing ../ctf/elf.bin
[~] searching for cryptographic functions ...
  MD5_Final
  MD5_Update
  MD5_Init
```