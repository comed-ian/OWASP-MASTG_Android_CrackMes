#Deobfuscates strings in the OWASP-MASTG Android UnCrackable Level 4 Crackme
#Performs computations in functions .datadiv_decode16323044921667855934, 
#.datadiv_decode12289074223533035339
#that obfuscate strings through logical operations.
#@comedian
#@deobfuscation
#@keybinding
#@menupath 
#@toolbar 

from ghidra import *
from ghidra.program.model.listing import CodeUnit

def get_bytes(address, size):
	return bytes(map(lambda b: b & 0xff, getBytes(address, size)))

def deobfuscate(bs, first, second, third):
	if third == None: third = 0
	s = ''
	for b in bs: s += chr(((b ^ 0xff) & first | b & second) ^ third)
	return s

strings = [
	# .datadiv_decode16323044921667855934
	{"address": 0x02b4128, "length": 0x08, "first": 100, "second": 0x9b, "third": 0x2a},
	{"address": 0x02b4130, "length": 0x13, "first": 0xb6, "second": 0x49, "third": None},
	{"address": 0x02b4143, "length": 0x08, "first": 0x34, "second": 0xcb, "third": 0x98},
	{"address": 0x02b414b, "length": 0x02, "first": 0x31, "second": 0xce, "third": 0xd7},
	{"address": 0x02b414d, "length": 0x12, "first": 200, "second": 0x37, "third": None},
	{"address": 0x02b415f, "length": 0x0a, "first": 0x01, "second": 0xfe, "third": 0x86},
	{"address": 0x02b4169, "length": 0x11, "first": 0x1f, "second": 0xe0, "third": 0x61},
	{"address": 0x02b417a, "length": 0x0e, "first": 0xd8, "second": 0x27, "third": None},
	{"address": 0x02b4188, "length": 0x0a, "first": 0x21, "second": 0xde, "third": None},
	{"address": 0x02b4192, "length": 0x02, "first": 0x77, "second": 0x88, "third": 0xe2},
	{"address": 0x02b4194, "length": 0x03, "first": 0x75, "second": 0x8a, "third": 0xee},
	{"address": 0x02b4197, "length": 0x10, "first": 0xba, "second": 0x45, "third": None},
	{"address": 0x02b41a7, "length": 0x1a, "first": 0x0a, "second": 0xf5, "third": 0xb3},
	{"address": 0x02b41c1, "length": 0x0c, "first": 0xb1, "second": 0x4e, "third": None},
	{"address": 0x02b41cd, "length": 0x06, "first": 0xbf, "second": 0x40, "third": None},
	{"address": 0x02b41d3, "length": 0x19, "first": 0xbd, "second": 0x42, "third": 0xd2},
	{"address": 0x02b41ec, "length": 0x20, "first": 0x50, "second": 0xaf, "third": None},
	{"address": 0x02b420c, "length": 0x15, "first": 0x60, "second": 0x9f, "third": None},
	{"address": 0x02b4221, "length": 0x16, "first": 0xfa, "second": 0x05, "third": None},
	{"address": 0x02b4237, "length": 0x17, "first": 0x5b, "second": 0xa4, "third": None},
	{"address": 0x02b424e, "length": 0x1e, "first": 0x69, "second": 0x96, "third": 0x17},
	{"address": 0x02b426c, "length": 0x15, "first": 0xaa, "second": 0x55, "third": 0x1c},
	{"address": 0x02b4281, "length": 0x25, "first": 0x42, "second": 0xbd, "third": None},
	{"address": 0x02b42a6, "length": 0x1d, "first": 0x04, "second": 0xfb, "third": 0x9a},
	{"address": 0x02b42c3, "length": 0x16, "first": 0x88, "second": 0x77, "third": 0x9c},
	{"address": 0x02b42d9, "length": 0x1a, "first": 0x06, "second": 0xf9, "third": 0x32},
	{"address": 0x02b42f3, "length": 0x26, "first": 0x80, "second": 0x7f, "third": 0x11},
	{"address": 0x02b4319, "length": 0x10, "first": 0x09, "second": 0xf6, "third": None},
	{"address": 0x02b4329, "length": 0x17, "first": 0xf9, "second": 0x06, "third": None},
	{"address": 0x02b4340, "length": 0x04, "first": 0x70, "second": 0x8f, "third": None},
	{"address": 0x02b4344, "length": 0x0b, "first": 0xf5, "second": 0x0a, "third": 0xe3},
	{"address": 0x02b434f, "length": 0x09, "first": 99, "second": 0x9c, "third": 0xeb},
	{"address": 0x02b4358, "length": 0x09, "first": 0x3a, "second": 0xc5, "third": 0x81},
	{"address": 0x02b4361, "length": 0x07, "first": 0xa2, "second": 0x5d, "third": None},
	{"address": 0x02b4368, "length": 0x11, "first": 0x70, "second": 0x8f, "third": None},
	{"address": 0x02b4379, "length": 0x0f, "first": 0xfe, "second": 0x01, "third": None},
	{"address": 0x02b4388, "length": 0x13, "first": 0xb8, "second": 0x47, "third": None},
	{"address": 0x02b439b, "length": 0x14, "first": 0xa9, "second": 0x56, "third": 0x74},
	{"address": 0x02b43af, "length": 0x09, "first": 0x0b, "second": 0xf4, "third": 0xe9},
	{"address": 0x02b43b8, "length": 0x0b, "first": 0xa2, "second": 0x5d, "third": 0x12},
	{"address": 0x02b43c3, "length": 0x0f, "first": 0xcb, "second": 0x34, "third": 0x50},
	{"address": 0x02b43d2, "length": 0x14, "first": 0xbe, "second": 0x41, "third": None},
	{"address": 0x02b43e6, "length": 0x18, "first": 0x19, "second": 0xe6, "third": 0xbb},
	{"address": 0x02b43fe, "length": 0x13, "first": 0xd4, "second": 0x2b, "third": None},
	{"address": 0x02b4411, "length": 0x1c, "first": 0x58, "second": 0xa7, "third": None},
	{"address": 0x02b442d, "length": 0x10, "first": 0x83, "second": 0x7c, "third": None},
	{"address": 0x02b443d, "length": 0x0a, "first": 0xb4, "second": 0x4b, "third": None},
	{"address": 0x02b443d, "length": 0x0a, "first": 0xb4, "second": 0x4b, "third": None},
	{"address": 0x02b4450, "length": 0x08, "first": 0x8f, "second": 0x70, "third": 0xc0},
	{"address": 0x02b4458, "length": 0x08, "first": 0xfd, "second": 0x02, "third": 0x08},
	{"address": 0x02b4460, "length": 0x0c, "first": 0x83, "second": 0x7c, "third": 0x88},
	{"address": 0x02b446c, "length": 0x0d, "first": 0x79, "second": 0x86, "third": 0x96},
	{"address": 0x02b4479, "length": 0x0d, "first": 0xc1, "second": 0x3e, "third": 0xa8},
	{"address": 0x02b4486, "length": 0x0c, "first": 0x95, "second": 0x6a, "third": 0x2c},
	{"address": 0x02b4492, "length": 0x06, "first": 0xb5, "second": 0x4a, "third": 0xbf},
	{"address": 0x02b4498, "length": 0x05, "first": 0x90, "second": 0x6f, "third": None},

	# .datadiv_decode12289074223533035339
	{"address": 0x02b449d, "length": 0x02, "first": 0x2d, "second": 0xd2, "third": 0x57},

]

for s in strings:
	data = getBytes(toAddr(s["address"]), s["length"])
	do = deobfuscate(data, s["first"], s["second"], s["third"]).encode()
	print(do)
	# add comment at address and each xref for easy reference
	cu = currentProgram.getListing().getCodeUnitAt(toAddr(s["address"]))
	cu.getComment(CodeUnit.EOL_COMMENT)
	cu.setComment(CodeUnit.EOL_COMMENT, do)
	for ref in getReferencesTo(toAddr(s["address"])):
		cu = currentProgram.getListing().getCodeUnitAt(ref.getFromAddress())
		if cu == None: continue
		cu.getComment(CodeUnit.EOL_COMMENT)
		cu.setComment(CodeUnit.EOL_COMMENT, do)
