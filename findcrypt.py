import yara
import sys
import argparse
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import (
    SymbolTableSection, SymbolTableIndexSection
)
from elftools.common.exceptions import ELFError

"""
todo: 
	search for a list of cryptographic function to add more functions
"""

def get_symbols(filename):
	functions = []
	try:
		with open(filename, 'rb') as f:
			elf = ELFFile(f)
			symbol_tables = [(idx, s) for idx, s in enumerate(elf.iter_sections()) if isinstance(s, SymbolTableSection)]
			for section_index, section in symbol_tables:
				for nsym, symbol in enumerate(section.iter_symbols()):
					# print(symbol.name)
					functions.append(symbol.name)
	except ELFError as e:
		print(f"[-] ELF error : {e}")
		sys.exit(1)
	return functions


def search_cryptographic_func(filename):
	func_names = open("data/crypto_func_name.txt", "r").read().split("\n")
	syms = get_symbols(filename)
	print("[~] searching for cryptographic functions ...")
	for i in syms:
		for u in func_names:
			# print(f"{i.lower()} : {u}")
			if u in i.lower():
				print(f"  {i}")


def parse_file(filename, print_offsets=False):
	print(f"[~] parsing {filename}")
	rules = yara.compile("data/findcrypt3.rules")
	matches = rules.match(filepath=filename)

	for match in matches:
		print(f"[+] {match} found")
		if print_offsets:
			print(f"offsets : {{ {', '.join([hex(values.instances[0].offset) for values in match.strings])} }}")

if __name__ == "__main__":
	argparser = argparse.ArgumentParser( usage='%(prog)s [options] <file>', prog=f"python3 {sys.argv[0]}")
	argparser.add_argument('file', nargs='?', default=None, help='file to parse')
	argparser.add_argument('-o', '--offsets', action='store_true', help='print offsets of values found.')
	argparser.add_argument('-f', '--function', action='store_true', help='search for cryptographic functions (only ELF)')

	args = argparser.parse_args()

	if not args.file:
		argparser.print_help()
		sys.exit(0)

	parse_file(args.file, print_offsets=args.offsets)
	if args.function:
		search_cryptographic_func(args.file)