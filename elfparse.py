#!/usr/bin/env python3
import argparse
import json
import struct
import sys
import os
import re
import curses
from collections import defaultdict, Counter

# ============================================================
# ELF 常量定义
# ============================================================

# ELF Identification
EI_MAG0 = 0
EI_MAG1 = 1
EI_MAG2 = 2
EI_MAG3 = 3
EI_CLASS = 4
EI_DATA = 5
EI_VERSION = 6
EI_OSABI = 7
EI_ABIVERSION = 8
EI_PAD = 9
EI_NIDENT = 16

ELFMAG0 = 0x7f
ELFMAG1 = ord('E')
ELFMAG2 = ord('L')
ELFMAG3 = ord('F')

ELFCLASSNONE = 0
ELFCLASS32 = 1
ELFCLASS64 = 2

ELFDATANONE = 0
ELFDATA2LSB = 1
ELFDATA2MSB = 2

# OS ABI
ELFOSABI = {
    0: "ELFOSABI_NONE/SYSV",
    1: "ELFOSABI_HPUX",
    2: "ELFOSABI_NETBSD",
    3: "ELFOSABI_LINUX",
    6: "ELFOSABI_SOLARIS",
    9: "ELFOSABI_FREEBSD",
    12: "ELFOSABI_OPENBSD",
    64: "ELFOSABI_ARM_AEABI",
    97: "ELFOSABI_ARM",
    255: "ELFOSABI_STANDALONE",
}

# ELF Type
ET_NONE = 0
ET_REL = 1
ET_EXEC = 2
ET_DYN = 3
ET_CORE = 4

ET_TYPES = {
    ET_NONE: "ET_NONE (No file type)",
    ET_REL: "ET_REL (Relocatable file)",
    ET_EXEC: "ET_EXEC (Executable file)",
    ET_DYN: "ET_DYN (Shared object file)",
    ET_CORE: "ET_CORE (Core file)",
}

# Machine Architecture
EM = {
    0: "EM_NONE",
    2: "EM_SPARC",
    3: "EM_386 (Intel 80386)",
    40: "EM_ARM",
    50: "EM_IA_64",
    62: "EM_X86_64 (AMD x86-64)",
    183: "EM_AARCH64 (ARM 64-bit)",
    243: "EM_RISCV",
}

# Program Header Types
PT = {
    0: "PT_NULL",
    1: "PT_LOAD",
    2: "PT_DYNAMIC",
    3: "PT_INTERP",
    4: "PT_NOTE",
    5: "PT_SHLIB",
    6: "PT_PHDR",
    7: "PT_TLS",
    0x6474e550: "PT_GNU_EH_FRAME",
    0x6474e551: "PT_GNU_STACK",
    0x6474e552: "PT_GNU_RELRO",
    0x6474e553: "PT_GNU_PROPERTY",
}

PF_X = 1
PF_W = 2
PF_R = 4

# Section Types
SHT = {
    0: "SHT_NULL",
    1: "SHT_PROGBITS",
    2: "SHT_SYMTAB",
    3: "SHT_STRTAB",
    4: "SHT_RELA",
    5: "SHT_HASH",
    6: "SHT_DYNAMIC",
    7: "SHT_NOTE",
    8: "SHT_NOBITS",
    9: "SHT_REL",
    10: "SHT_SHLIB",
    11: "SHT_DYNSYM",
    14: "SHT_INIT_ARRAY",
    15: "SHT_FINI_ARRAY",
    16: "SHT_PREINIT_ARRAY",
    17: "SHT_GROUP",
    18: "SHT_SYMTAB_SHNDX",
    0x6ffffff5: "SHT_GNU_ATTRIBUTES",
    0x6ffffff6: "SHT_GNU_HASH",
    0x6ffffffb: "SHT_GNU_VERDEF",
    0x6ffffffc: "SHT_GNU_VERNEED",
    0x6ffffffd: "SHT_GNU_VERSYM",
}

SHN = {
    0: "SHN_UNDEF",
    0xfff1: "SHN_ABS",
    0xfff2: "SHN_COMMON",
    0xffff: "SHN_XINDEX",
}

# Symbol Binding
STB = {
    0: "LOCAL",
    1: "GLOBAL",
    2: "WEAK",
    13: "LOOS",
    14: "HIOS",
    15: "LOPROC",
    16: "HIPROC",
}

# Symbol Type
STT = {
    0: "NOTYPE",
    1: "OBJECT",
    2: "FUNC",
    3: "SECTION",
    4: "FILE",
    5: "COMMON",
    6: "TLS",
    10: "LOOS",
    12: "HIOS",
    13: "LOPROC",
    15: "HIPROC",
}

# X86_64 Relocation Types
R_X86_64 = {
    0: "R_X86_64_NONE",
    1: "R_X86_64_64",
    2: "R_X86_64_PC32",
    3: "R_X86_64_GOT32",
    4: "R_X86_64_PLT32",
    5: "R_X86_64_COPY",
    6: "R_X86_64_GLOB_DAT",
    7: "R_X86_64_JUMP_SLOT",
    8: "R_X86_64_RELATIVE",
    9: "R_X86_64_GOTPCREL",
    10: "R_X86_64_32",
    11: "R_X86_64_32S",
    12: "R_X86_64_16",
    13: "R_X86_64_PC16",
    14: "R_X86_64_8",
    15: "R_X86_64_PC8",
    16: "R_X86_64_DTPMOD64",
    17: "R_X86_64_DTPOFF64",
    18: "R_X86_64_TPOFF64",
    19: "R_X86_64_TLSGD",
    20: "R_X86_64_TLSLD",
    21: "R_X86_64_DTPOFF32",
    22: "R_X86_64_GOTTPOFF",
    23: "R_X86_64_TPOFF32",
    24: "R_X86_64_PC64",
    25: "R_X86_64_GOTOFF64",
    26: "R_X86_64_GOTPC32",
    32: "R_X86_64_SIZE32",
    33: "R_X86_64_SIZE64",
}

# AArch64 Relocation Types
R_AARCH64 = {
    0: "R_AARCH64_NONE",
    257: "R_AARCH64_ABS64",
    258: "R_AARCH64_ABS32",
    259: "R_AARCH64_ABS16",
    260: "R_AARCH64_PREL64",
    261: "R_AARCH64_PREL32",
    262: "R_AARCH64_PREL16",
    263: "R_AARCH64_MOVW_UABS_G0",
    264: "R_AARCH64_MOVW_UABS_G0_NC",
    265: "R_AARCH64_MOVW_UABS_G1",
    266: "R_AARCH64_MOVW_UABS_G1_NC",
    267: "R_AARCH64_MOVW_UABS_G2",
    268: "R_AARCH64_MOVW_UABS_G2_NC",
    269: "R_AARCH64_MOVW_UABS_G3",
    270: "R_AARCH64_MOVW_SABS_G0",
    271: "R_AARCH64_MOVW_SABS_G1",
    272: "R_AARCH64_MOVW_SABS_G2",
    273: "R_AARCH64_LD_PREL_LO19",
    274: "R_AARCH64_ADR_PREL_LO21",
    275: "R_AARCH64_ADR_PREL_PG_HI21",
    276: "R_AARCH64_ADR_PREL_PG_HI21_NC",
    277: "R_AARCH64_ADD_ABS_LO12_NC",
    278: "R_AARCH64_LDST8_ABS_LO12_NC",
    279: "R_AARCH64_TSTBR14",
    280: "R_AARCH64_CONDBR19",
    281: "R_AARCH64_JUMP26",
    282: "R_AARCH64_CALL26",
    283: "R_AARCH64_LDST16_ABS_LO12_NC",
    284: "R_AARCH64_LDST32_ABS_LO12_NC",
    285: "R_AARCH64_LDST64_ABS_LO12_NC",
    286: "R_AARCH64_LDST128_ABS_LO12_NC",
    1024: "R_AARCH64_COPY",
    1025: "R_AARCH64_GLOB_DAT",
    1026: "R_AARCH64_JUMP_SLOT",
    1027: "R_AARCH64_RELATIVE",
    1028: "R_AARCH64_TLS_DTPREL64",
    1029: "R_AARCH64_TLS_DTPMOD64",
    1030: "R_AARCH64_TLS_TPREL64",
    1031: "R_AARCH64_TLSDESC",
    1032: "R_AARCH64_IRELATIVE",
}

# Dynamic Tags
DT = {
    0: "DT_NULL",
    1: "DT_NEEDED",
    2: "DT_PLTRELSZ",
    3: "DT_PLTGOT",
    4: "DT_HASH",
    5: "DT_STRTAB",
    6: "DT_SYMTAB",
    7: "DT_RELA",
    8: "DT_RELASZ",
    9: "DT_RELAENT",
    10: "DT_STRSZ",
    11: "DT_SYMENT",
    12: "DT_INIT",
    13: "DT_FINI",
    14: "DT_SONAME",
    15: "DT_RPATH",
    16: "DT_SYMBOLIC",
    17: "DT_REL",
    18: "DT_RELSZ",
    19: "DT_RELENT",
    20: "DT_PLTREL",
    21: "DT_DEBUG",
    22: "DT_TEXTREL",
    23: "DT_JMPREL",
    24: "DT_BIND_NOW",
    25: "DT_INIT_ARRAY",
    26: "DT_FINI_ARRAY",
    27: "DT_INIT_ARRAYSZ",
    28: "DT_FINI_ARRAYSZ",
    29: "DT_RUNPATH",
    30: "DT_FLAGS",
    32: "DT_ENCODING",
    33: "DT_PREINIT_ARRAY",
    34: "DT_PREINIT_ARRAYSZ",
    35: "DT_SYMTAB_SHNDX",
    0x6ffffd00: "DT_VALRNGLO",
    0x6ffffef5: "DT_GNU_HASH",
    0x6ffffff0: "DT_VERSYM",
    0x6ffffff9: "DT_RELACOUNT",
    0x6ffffffa: "DT_RELCOUNT",
    0x6ffffffb: "DT_FLAGS_1",
    0x6ffffffc: "DT_VERDEF",
    0x6ffffffd: "DT_VERDEFNUM",
    0x6ffffffe: "DT_VERNEED",
    0x6fffffff: "DT_VERNEEDNUM",
    0x7ffffffd: "DT_AUXILIARY",
    0x7fffffff: "DT_FILTER",
}

# DT_FLAGS values
DF_ORIGIN = 0x1
DF_SYMBOLIC = 0x2
DF_TEXTREL = 0x4
DF_BIND_NOW = 0x8
DF_STATIC_TLS = 0x10

DT_FLAGS_BITS = {
    DF_ORIGIN: "DF_ORIGIN",
    DF_SYMBOLIC: "DF_SYMBOLIC",
    DF_TEXTREL: "DF_TEXTREL",
    DF_BIND_NOW: "DF_BIND_NOW",
    DF_STATIC_TLS: "DF_STATIC_TLS",
}

# DT_FLAGS_1 values
DF_1_NOW = 0x1
DF_1_GLOBAL = 0x2
DF_1_GROUP = 0x4
DF_1_NODELETE = 0x8
DF_1_LOADFLTR = 0x10
DF_1_INITFIRST = 0x20
DF_1_NOOPEN = 0x40
DF_1_ORIGIN = 0x80
DF_1_DIRECT = 0x100
DF_1_TRANS = 0x200
DF_1_INTERPOSE = 0x400
DF_1_NODEFLIB = 0x800
DF_1_NODUMP = 0x1000
DF_1_CONFALT = 0x2000
DF_1_ENDFILTEE = 0x4000
DF_1_DISPRELDNE = 0x8000
DF_1_DISPRELPND = 0x10000
DF_1_NODIRECT = 0x20000
DF_1_IGNMULDEF = 0x40000
DF_1_NOKSYMS = 0x80000
DF_1_NOHDR = 0x100000
DF_1_EDITED = 0x200000
DF_1_NORELOC = 0x400000
DF_1_SYMINTPOSE = 0x800000
DF_1_GLOBAUDIT = 0x1000000
DF_1_SINGLETON = 0x2000000
DF_1_PIE = 0x08000000

DT_FLAGS_1_BITS = {
    DF_1_NOW: "DF_1_NOW",
    DF_1_GLOBAL: "DF_1_GLOBAL",
    DF_1_GROUP: "DF_1_GROUP",
    DF_1_NODELETE: "DF_1_NODELETE",
    DF_1_LOADFLTR: "DF_1_LOADFLTR",
    DF_1_INITFIRST: "DF_1_INITFIRST",
    DF_1_NOOPEN: "DF_1_NOOPEN",
    DF_1_ORIGIN: "DF_1_ORIGIN",
    DF_1_DIRECT: "DF_1_DIRECT",
    DF_1_INTERPOSE: "DF_1_INTERPOSE",
    DF_1_NODEFLIB: "DF_1_NODEFLIB",
    DF_1_NODUMP: "DF_1_NODUMP",
    DF_1_PIE: "DF_1_PIE",
}

# Common Linux library paths
COMMON_LIB_PATHS = [
    "/lib", "/lib64", "/usr/lib", "/usr/lib64",
    "/lib/x86_64-linux-gnu", "/usr/lib/x86_64-linux-gnu",
    "/lib/aarch64-linux-gnu", "/usr/lib/aarch64-linux-gnu",
    "/usr/local/lib", "/opt/lib",
]

# GNU Version structures
VERNEED_HASH_OFFSET = 0
VERNEED_FLAGS_OFFSET = 4
VERNEED_VERSION_OFFSET = 6
VERNEED_NEXT_OFFSET = 8
VERNEED_CNT_OFFSET = 10
VERNEED_AUX_OFFSET = 12
VERNEED_NAME_OFFSET = 16
VERNEED_SIZE = 20

VERNAUX_HASH_OFFSET = 0
VERNAUX_HALF_OFFSET = 4
VERNAUX_NAME_OFFSET = 6
VERNAUX_NEXT_OFFSET = 8
VERNAUX_SIZE = 12

# ANSI Color codes
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    DIM = '\033[2m'

def color_enabled():
    return sys.stdout.isatty()

def cgreen(text):
    return (Colors.OKGREEN + text + Colors.ENDC) if color_enabled() else text

def cred(text):
    return (Colors.FAIL + text + Colors.ENDC) if color_enabled() else text

def cyellow(text):
    return (Colors.WARNING + text + Colors.ENDC) if color_enabled() else text

def cblue(text):
    return (Colors.OKBLUE + text + Colors.ENDC) if color_enabled() else text

def ccyan(text):
    return (Colors.OKCYAN + text + Colors.ENDC) if color_enabled() else text

def cbold(text):
    return (Colors.BOLD + text + Colors.ENDC) if color_enabled() else text

# ============================================================
# ELF 解析器核心类
# ============================================================

class ELFParserError(Exception):
    pass


class ELFParser:
    def __init__(self, filepath):
        self.filepath = filepath
        with open(filepath, 'rb') as f:
            self.data = f.read()
        self.offset = 0
        self.size = len(self.data)

        self.elf_class = None
        self.endian = None
        self.elf_header = None
        self.program_headers = []
        self.section_headers = []
        self.section_names = {}
        self.symtab = []
        self.dynsym = []
        self.relocations = []
        self.dynamic_entries = []
        self.version_syms = []
        self.version_needs = []
        self.version_map = {}

        self._parse()

    # --------------------------------------------------------
    # 基础读取方法
    # --------------------------------------------------------

    def _unpack(self, fmt, offset=None):
        if offset is None:
            offset = self.offset
            self.offset += struct.calcsize(fmt)
        if offset + struct.calcsize(fmt) > self.size:
            raise ELFParserError("Unexpected end of file")
        endian_prefix = '<' if self.endian == ELFDATA2LSB else '>'
        return struct.unpack_from(endian_prefix + fmt, self.data, offset)

    def _read_bytes(self, n, offset=None):
        if offset is None:
            offset = self.offset
            self.offset += n
        if offset + n > self.size:
            raise ELFParserError("Unexpected end of file")
        return self.data[offset:offset + n]

    def _read_cstring(self, offset, max_len=4096):
        end = self.data.find(b'\x00', offset, offset + max_len)
        if end == -1:
            end = min(offset + max_len, self.size)
        return self.data[offset:end].decode('utf-8', errors='replace')

    # --------------------------------------------------------
    # ELF Identification
    # --------------------------------------------------------

    def _parse_ident(self):
        e_ident = self._read_bytes(EI_NIDENT)
        if e_ident[EI_MAG0] != ELFMAG0 or \
           e_ident[EI_MAG1] != ELFMAG1 or \
           e_ident[EI_MAG2] != ELFMAG2 or \
           e_ident[EI_MAG3] != ELFMAG3:
            raise ELFParserError("Not a valid ELF file (bad magic)")

        self.elf_class = e_ident[EI_CLASS]
        if self.elf_class not in (ELFCLASS32, ELFCLASS64):
            raise ELFParserError(f"Unknown ELF class: {self.elf_class}")

        self.endian = e_ident[EI_DATA]
        if self.endian not in (ELFDATA2LSB, ELFDATA2MSB):
            raise ELFParserError(f"Unknown ELF data encoding: {self.endian}")

        return e_ident

    # --------------------------------------------------------
    # ELF Header
    # --------------------------------------------------------

    def _parse_elf_header(self):
        e_ident = self._parse_ident()

        if self.elf_class == ELFCLASS64:
            # Elf64_Ehdr
            (e_type, e_machine, e_version, e_entry, e_phoff, e_shoff,
             e_flags, e_ehsize, e_phentsize, e_phnum, e_shentsize,
             e_shnum, e_shstrndx) = self._unpack('HHIQQQIHHHHHH')
            header_size = 64
        else:
            # Elf32_Ehdr
            (e_type, e_machine, e_version, e_entry, e_phoff, e_shoff,
             e_flags, e_ehsize, e_phentsize, e_phnum, e_shentsize,
             e_shnum, e_shstrndx) = self._unpack('HHIIIIIHHHHHH')
            header_size = 52

        self.elf_header = {
            'e_ident': list(e_ident),
            'e_ident_magic': '0x' + ''.join(f'{b:02x}' for b in e_ident[:4]),
            'e_class': self.elf_class,
            'e_class_str': 'ELF32' if self.elf_class == ELFCLASS32 else 'ELF64',
            'e_data': self.endian,
            'e_data_str': 'Little Endian (2\'s complement)' if self.endian == ELFDATA2LSB else 'Big Endian (2\'s complement)',
            'e_version': e_ident[EI_VERSION],
            'e_osabi': e_ident[EI_OSABI],
            'e_osabi_str': ELFOSABI.get(e_ident[EI_OSABI], f"Unknown ({e_ident[EI_OSABI]})"),
            'e_abiversion': e_ident[EI_ABIVERSION],
            'e_type': e_type,
            'e_type_str': ET_TYPES.get(e_type, f"Unknown ({e_type})"),
            'e_machine': e_machine,
            'e_machine_str': EM.get(e_machine, f"Unknown ({e_machine})"),
            'e_version_full': e_version,
            'e_entry': hex(e_entry),
            'e_entry_int': e_entry,
            'e_phoff': hex(e_phoff),
            'e_phoff_int': e_phoff,
            'e_shoff': hex(e_shoff),
            'e_shoff_int': e_shoff,
            'e_flags': e_flags,
            'e_ehsize': e_ehsize,
            'e_phentsize': e_phentsize,
            'e_phnum': e_phnum,
            'e_shentsize': e_shentsize,
            'e_shnum': e_shnum,
            'e_shstrndx': e_shstrndx,
        }
        return self.elf_header

    # --------------------------------------------------------
    # Program Headers
    # --------------------------------------------------------

    def _parse_program_headers(self):
        phoff = self.elf_header['e_phoff_int']
        phentsize = self.elf_header['e_phentsize']
        phnum = self.elf_header['e_phnum']

        if phoff == 0 or phnum == 0:
            return

        for i in range(phnum):
            off = phoff + i * phentsize
            if self.elf_class == ELFCLASS64:
                # Elf64_Phdr
                (p_type, p_flags, p_offset, p_vaddr, p_paddr,
                 p_filesz, p_memsz, p_align) = self._unpack('IIQQQQQQ', off)
            else:
                # Elf32_Phdr
                (p_type, p_offset, p_vaddr, p_paddr, p_filesz,
                 p_memsz, p_flags, p_align) = self._unpack('IIIIIIII', off)

            flags_str = ''
            if p_flags & PF_R:
                flags_str += 'R'
            else:
                flags_str += '-'
            if p_flags & PF_W:
                flags_str += 'W'
            else:
                flags_str += '-'
            if p_flags & PF_X:
                flags_str += 'E'
            else:
                flags_str += '-'

            interp_str = ''
            if p_type == 3 and p_filesz > 0:
                try:
                    interp_str = self.data[p_offset:p_offset + p_filesz].rstrip(b'\x00').decode('utf-8', errors='replace')
                except Exception:
                    pass

            self.program_headers.append({
                'index': i,
                'p_type': p_type,
                'p_type_str': PT.get(p_type, f"Unknown (0x{p_type:x})"),
                'p_flags': p_flags,
                'p_flags_str': flags_str,
                'p_offset': hex(p_offset),
                'p_offset_int': p_offset,
                'p_vaddr': hex(p_vaddr),
                'p_vaddr_int': p_vaddr,
                'p_paddr': hex(p_paddr),
                'p_paddr_int': p_paddr,
                'p_filesz': p_filesz,
                'p_memsz': p_memsz,
                'p_align': p_align,
                'interp': interp_str,
            })

    # --------------------------------------------------------
    # Section Headers
    # --------------------------------------------------------

    def _parse_section_headers(self):
        shoff = self.elf_header['e_shoff_int']
        shentsize = self.elf_header['e_shentsize']
        shnum = self.elf_header['e_shnum']
        shstrndx = self.elf_header['e_shstrndx']

        if shoff == 0 or shnum == 0:
            return

        raw_sections = []
        for i in range(shnum):
            off = shoff + i * shentsize
            if self.elf_class == ELFCLASS64:
                # Elf64_Shdr
                (sh_name, sh_type, sh_flags, sh_addr, sh_offset,
                 sh_size, sh_link, sh_info, sh_addralign,
                 sh_entsize) = self._unpack('IIQQQQIIQQ', off)
            else:
                # Elf32_Shdr
                (sh_name, sh_type, sh_flags, sh_addr, sh_offset,
                 sh_size, sh_link, sh_info, sh_addralign,
                 sh_entsize) = self._unpack('IIIIIIIIII', off)

            raw_sections.append({
                'index': i,
                'sh_name': sh_name,
                'sh_type': sh_type,
                'sh_type_str': SHT.get(sh_type, f"Unknown (0x{sh_type:x})"),
                'sh_flags': sh_flags,
                'sh_addr': hex(sh_addr),
                'sh_addr_int': sh_addr,
                'sh_offset': hex(sh_offset),
                'sh_offset_int': sh_offset,
                'sh_size': sh_size,
                'sh_link': sh_link,
                'sh_info': sh_info,
                'sh_addralign': sh_addralign,
                'sh_entsize': sh_entsize,
            })

        # 解析节区名称字符串表
        shstrtab_off = 0
        shstrtab_size = 0
        if shstrndx < len(raw_sections):
            shstrtab_off = raw_sections[shstrndx]['sh_offset_int']
            shstrtab_size = raw_sections[shstrndx]['sh_size']

        for sec in raw_sections:
            name_off = sec['sh_name']
            if shstrtab_off > 0 and name_off < shstrtab_size:
                end = self.data.find(b'\x00', shstrtab_off + name_off, shstrtab_off + shstrtab_size)
                if end != -1:
                    sec['sh_name_str'] = self.data[shstrtab_off + name_off:end].decode('utf-8', errors='replace')
                else:
                    sec['sh_name_str'] = ''
            else:
                sec['sh_name_str'] = ''

            # 十六进制预览（前64字节）
            hex_preview = ''
            ascii_preview = ''
            data_offset = sec['sh_offset_int']
            data_size = min(sec['sh_size'], 64)
            if sec['sh_type'] != 8 and data_size > 0 and data_offset + data_size <= self.size:
                raw = self.data[data_offset:data_offset + data_size]
                hex_bytes = []
                ascii_chars = []
                for j, b in enumerate(raw):
                    hex_bytes.append(f'{b:02x}')
                    if 32 <= b < 127:
                        ascii_chars.append(chr(b))
                    else:
                        ascii_chars.append('.')
                hex_preview = ' '.join(hex_bytes)
                ascii_preview = ''.join(ascii_chars)
            sec['hex_preview'] = hex_preview
            sec['ascii_preview'] = ascii_preview
            sec['preview_size'] = data_size

        self.section_headers = raw_sections
        for sec in self.section_headers:
            if sec['sh_name_str']:
                self.section_names[sec['sh_name_str']] = sec['index']

    # --------------------------------------------------------
    # 符号表解析
    # --------------------------------------------------------

    def _parse_symtab_section(self, sec_idx, linked_sec_idx):
        syms = []
        sec = self.section_headers[sec_idx]
        entsize = sec['sh_entsize']
        size = sec['sh_size']
        if entsize == 0:
            return syms

        num_entries = size // entsize
        data_off = sec['sh_offset_int']

        # 获取关联的字符串表
        strtab_off = 0
        strtab_size = 0
        if linked_sec_idx < len(self.section_headers):
            str_sec = self.section_headers[linked_sec_idx]
            strtab_off = str_sec['sh_offset_int']
            strtab_size = str_sec['sh_size']

        for i in range(num_entries):
            entry_off = data_off + i * entsize
            if self.elf_class == ELFCLASS64:
                # Elf64_Sym
                (st_name, st_info, st_other, st_shndx, st_value,
                 st_size) = self._unpack('IBBHQQ', entry_off)
            else:
                # Elf32_Sym
                (st_name, st_value, st_size, st_info, st_other,
                 st_shndx) = self._unpack('IIIBBH', entry_off)

            st_bind = (st_info >> 4) & 0xf
            st_type = st_info & 0xf

            # 解析符号名
            name = ''
            if st_name > 0 and strtab_off > 0 and st_name < strtab_size:
                end = self.data.find(b'\x00', strtab_off + st_name, strtab_off + strtab_size)
                if end != -1:
                    name = self.data[strtab_off + st_name:end].decode('utf-8', errors='replace')

            shndx_str = SHN.get(st_shndx, None)
            if shndx_str is None:
                if 0 <= st_shndx < len(self.section_headers):
                    shndx_str = self.section_headers[st_shndx]['sh_name_str'] or f"section[{st_shndx}]"
                else:
                    shndx_str = str(st_shndx)

            syms.append({
                'index': i,
                'st_name': st_name,
                'st_name_str': name,
                'st_value': hex(st_value),
                'st_value_int': st_value,
                'st_size': st_size,
                'st_info': st_info,
                'st_bind': st_bind,
                'st_bind_str': STB.get(st_bind, f"Unknown ({st_bind})"),
                'st_type': st_type,
                'st_type_str': STT.get(st_type, f"Unknown ({st_type})"),
                'st_other': st_other,
                'st_shndx': st_shndx,
                'st_shndx_str': shndx_str,
            })
        return syms

    def _parse_symbols(self):
        for idx, sec in enumerate(self.section_headers):
            name = sec['sh_name_str']
            if name == '.symtab' and sec['sh_type'] == 2:
                self.symtab = self._parse_symtab_section(idx, sec['sh_link'])
            elif name == '.dynsym' and sec['sh_type'] == 11:
                self.dynsym = self._parse_symtab_section(idx, sec['sh_link'])

    # --------------------------------------------------------
    # 重定位解析
    # --------------------------------------------------------

    def _parse_relocation_section(self, sec_idx):
        rels = []
        sec = self.section_headers[sec_idx]
        entsize = sec['sh_entsize']
        size = sec['sh_size']
        if entsize == 0:
            return rels

        num_entries = size // entsize
        data_off = sec['sh_offset_int']
        is_rela = sec['sh_type'] == 4
        sh_name = sec['sh_name_str']

        # 获取关联的符号表
        symtab = []
        link = sec['sh_link']
        if 0 <= link < len(self.section_headers):
            link_name = self.section_headers[link]['sh_name_str']
            if link_name == '.symtab':
                symtab = self.symtab
            elif link_name == '.dynsym':
                symtab = self.dynsym

        machine = self.elf_header['e_machine']
        reloc_table = R_X86_64 if machine == 62 else (R_AARCH64 if machine == 183 else {})

        for i in range(num_entries):
            entry_off = data_off + i * entsize

            if self.elf_class == ELFCLASS64:
                if is_rela:
                    # Elf64_Rela
                    (r_offset, r_info, r_addend) = self._unpack('QQq', entry_off)
                else:
                    # Elf64_Rel
                    (r_offset, r_info) = self._unpack('QQ', entry_off)
                    r_addend = 0
                r_sym = (r_info >> 32) & 0xffffffff
                r_type = r_info & 0xffffffff
            else:
                if is_rela:
                    # Elf32_Rela
                    (r_offset, r_info, r_addend) = self._unpack('IIi', entry_off)
                else:
                    # Elf32_Rel
                    (r_offset, r_info) = self._unpack('II', entry_off)
                    r_addend = 0
                r_sym = (r_info >> 8) & 0xffffff
                r_type = r_info & 0xff

            sym_name = ''
            if 0 <= r_sym < len(symtab):
                sym_name = symtab[r_sym]['st_name_str']

            reloc_type_str = reloc_table.get(r_type, f"Unknown (0x{r_type:x})")

            rels.append({
                'index': i,
                'section': sh_name,
                'r_offset': hex(r_offset),
                'r_offset_int': r_offset,
                'r_info': r_info,
                'r_sym': r_sym,
                'r_type': r_type,
                'r_type_str': reloc_type_str,
                'r_addend': r_addend,
                'symbol_name': sym_name,
            })
        return rels

    def _parse_relocations(self):
        for idx, sec in enumerate(self.section_headers):
            if sec['sh_type'] in (4, 9):
                self.relocations.extend(self._parse_relocation_section(idx))

    # --------------------------------------------------------
    # 动态段解析
    # --------------------------------------------------------

    def _get_dynstr_string(self, offset):
        dynstr_idx = self.section_names.get('.dynstr', None)
        if dynstr_idx is None:
            return ''
        dynstr_sec = self.section_headers[dynstr_idx]
        strtab_off = dynstr_sec['sh_offset_int']
        strtab_size = dynstr_sec['sh_size']
        if offset >= strtab_size:
            return ''
        end = self.data.find(b'\x00', strtab_off + offset, strtab_off + strtab_size)
        if end == -1:
            end = strtab_off + strtab_size
        return self.data[strtab_off + offset:end].decode('utf-8', errors='replace')

    def _parse_dynamic(self):
        dynamic_idx = self.section_names.get('.dynamic', None)
        if dynamic_idx is None:
            return

        sec = self.section_headers[dynamic_idx]
        entsize = sec['sh_entsize']
        size = sec['sh_size']
        if entsize == 0:
            entsize = 16 if self.elf_class == ELFCLASS64 else 8

        num_entries = size // entsize
        data_off = sec['sh_offset_int']

        string_tags = {1, 14, 15, 29}

        for i in range(num_entries):
            entry_off = data_off + i * entsize
            if self.elf_class == ELFCLASS64:
                (d_tag, d_val) = self._unpack('QQ', entry_off)
            else:
                (d_tag, d_val) = self._unpack('II', entry_off)

            if d_tag == 0:
                break

            tag_str = DT.get(d_tag, f"Unknown (0x{d_tag:x})")
            val_str = ''

            if d_tag in string_tags:
                val_str = self._get_dynstr_string(d_val)
            elif d_tag == 30:
                flags = []
                for bit, name in DT_FLAGS_BITS.items():
                    if d_val & bit:
                        flags.append(name)
                val_str = ' | '.join(flags) if flags else f"0x{d_val:x}"
            elif d_tag == 0x6ffffffb:
                flags = []
                for bit, name in DT_FLAGS_1_BITS.items():
                    if isinstance(bit, int) and d_val & bit:
                        flags.append(name)
                val_str = ' | '.join(flags) if flags else f"0x{d_val:x}"
            else:
                val_str = f"0x{d_val:x}"

            self.dynamic_entries.append({
                'index': i,
                'd_tag': d_tag,
                'd_tag_str': tag_str,
                'd_val': d_val,
                'd_val_str': val_str,
            })

    # --------------------------------------------------------
    # 版本信息解析
    # --------------------------------------------------------

    def _parse_version_info(self):
        versym_idx = self.section_names.get('.gnu.version', None)
        verneed_idx = self.section_names.get('.gnu.version_r', None)

        if versym_idx is not None and len(self.dynsym) > 0:
            sec = self.section_headers[versym_idx]
            data_off = sec['sh_offset_int']
            num_syms = len(self.dynsym)
            for i in range(min(num_syms, sec['sh_size'] // 2)):
                (ver_idx,) = self._unpack('H', data_off + i * 2)
                self.version_syms.append({
                    'sym_index': i,
                    'ver_idx': ver_idx,
                    'is_local': (ver_idx == 0),
                    'is_global': (ver_idx == 1),
                })

        if verneed_idx is not None:
            dynstr_idx = self.section_names.get('.dynstr', None)
            dynstr_off = 0
            dynstr_size = 0
            if dynstr_idx is not None:
                dynstr_off = self.section_headers[dynstr_idx]['sh_offset_int']
                dynstr_size = self.section_headers[dynstr_idx]['sh_size']

            sec = self.section_headers[verneed_idx]
            data_off = sec['sh_offset_int']
            data_end = data_off + sec['sh_size']
            base = data_off

            while data_off < data_end:
                (vn_file, vn_flags, vn_ver, vn_cnt, vn_aux, vn_next) = self._unpack('IHHHHH', data_off)

                file_name = ''
                if dynstr_off > 0 and vn_file < dynstr_size:
                    end = self.data.find(b'\x00', dynstr_off + vn_file, dynstr_off + dynstr_size)
                    if end != -1:
                        file_name = self.data[dynstr_off + vn_file:end].decode('utf-8', errors='replace')

                aux_off = base + vn_aux
                auxes = []
                for j in range(vn_cnt):
                    if aux_off >= data_end:
                        break
                    (vna_hash, vna_flags, vna_other, vna_name, vna_next) = self._unpack('IHHHH', aux_off)

                    ver_name = ''
                    if dynstr_off > 0 and vna_name < dynstr_size:
                        end = self.data.find(b'\x00', dynstr_off + vna_name, dynstr_off + dynstr_size)
                        if end != -1:
                            ver_name = self.data[dynstr_off + vna_name:end].decode('utf-8', errors='replace')

                    ver_idx = vna_other
                    auxes.append({
                        'hash': hex(vna_hash),
                        'flags': vna_flags,
                        'ver_idx': ver_idx,
                        'version': ver_name,
                    })

                    if vna_next == 0:
                        break
                    aux_off += vna_next

                self.version_needs.append({
                    'file': file_name,
                    'flags': vn_flags,
                    'version_entries': auxes,
                })

                if vn_next == 0:
                    break
                data_off += vn_next

            for sym_ver in self.version_syms:
                ver_idx = sym_ver['ver_idx']
                if ver_idx == 0:
                    self.version_map[sym_ver['sym_index']] = 'local'
                elif ver_idx == 1:
                    self.version_map[sym_ver['sym_index']] = 'global'
                else:
                    for vn in self.version_needs:
                        for aux in vn['version_entries']:
                            if aux['ver_idx'] == ver_idx:
                                self.version_map[sym_ver['sym_index']] = f"{vn['file']}@{aux['version']}"

    # --------------------------------------------------------
    # 安全特性检测
    # --------------------------------------------------------

    def check_security(self):
        result = {}

        has_gnu_relro = False
        has_bind_now = False
        for ph in self.program_headers:
            if ph['p_type'] == 0x6474e552:
                has_gnu_relro = True
                break

        for de in self.dynamic_entries:
            if de['d_tag'] == 24:
                has_bind_now = True
            if de['d_tag'] == 0x6ffffffb:
                if de['d_val'] & DF_1_NOW:
                    has_bind_now = True

        if has_gnu_relro and has_bind_now:
            result['RELRO'] = ('Full RELRO', True)
        elif has_gnu_relro:
            result['RELRO'] = ('Partial RELRO', True)
        else:
            result['RELRO'] = ('No RELRO', False)

        has_canary = False
        all_syms = self.symtab + self.dynsym
        for sym in all_syms:
            if sym['st_name_str'] == '__stack_chk_fail':
                has_canary = True
                break
        result['Stack Canary'] = ('Enabled' if has_canary else 'Disabled', has_canary)

        is_pie = False
        if self.elf_header['e_type'] == ET_DYN:
            has_soname = any(de['d_tag'] == 14 for de in self.dynamic_entries)
            if not has_soname:
                is_pie = True
        result['PIE'] = ('Enabled' if is_pie else 'Disabled', is_pie)

        has_nx = True
        for ph in self.program_headers:
            if ph['p_type'] == 0x6474e551:
                if ph['p_flags'] & PF_X:
                    has_nx = False
                break
        result['NX'] = ('Enabled' if has_nx else 'Disabled', has_nx)

        has_fortify = False
        fortify_funcs = set()
        for sym in all_syms:
            name = sym['st_name_str']
            if name.endswith('_chk') and name.startswith('__'):
                has_fortify = True
                fortify_funcs.add(name)
        result['FORTIFY'] = ('Enabled (' + ', '.join(sorted(fortify_funcs)) + ')' if has_fortify else 'Disabled', has_fortify)

        return result

    # --------------------------------------------------------
    # 控制流图生成
    # --------------------------------------------------------

    def _get_section_data(self, sec_name):
        idx = self.section_names.get(sec_name, None)
        if idx is None:
            return b'', 0
        sec = self.section_headers[idx]
        off = sec['sh_offset_int']
        sz = sec['sh_size']
        if sz == 0:
            return b'', sec['sh_addr_int']
        return self.data[off:off + sz], sec['sh_addr_int']

    def disassemble_cfg(self):
        text_data, text_base = self._get_section_data('.text')
        if not text_data:
            return [], {}, []

        instructions = []
        i = 0
        size = len(text_data)

        while i < size:
            byte = text_data[i]
            instr = {
                'offset': i,
                'addr': text_base + i,
                'bytes': [byte],
                'mnemonic': 'db',
                'size': 1,
                'is_branch': False,
                'branch_type': None,
                'target': None,
                'is_call': False,
                'is_ret': False,
            }

            if byte == 0x90:
                instr['mnemonic'] = 'nop'
            elif byte == 0xc3:
                instr['mnemonic'] = 'ret'
                instr['is_ret'] = True
                instr['is_branch'] = True
                instr['branch_type'] = 'ret'
            elif byte == 0xe8 and i + 5 <= size:
                instr['mnemonic'] = 'call'
                instr['size'] = 5
                instr['bytes'] = list(text_data[i:i+5])
                (disp,) = struct.unpack_from('<i', text_data, i + 1)
                instr['target'] = text_base + i + 5 + disp
                instr['is_branch'] = True
                instr['is_call'] = True
                instr['branch_type'] = 'call'
            elif byte == 0xe9 and i + 5 <= size:
                instr['mnemonic'] = 'jmp'
                instr['size'] = 5
                instr['bytes'] = list(text_data[i:i+5])
                (disp,) = struct.unpack_from('<i', text_data, i + 1)
                instr['target'] = text_base + i + 5 + disp
                instr['is_branch'] = True
                instr['branch_type'] = 'unconditional'
            elif (byte & 0xf0) == 0x70 and i + 2 <= size:
                cond_map = {
                    0x70: 'jo', 0x71: 'jno', 0x72: 'jb', 0x73: 'jnb',
                    0x74: 'je', 0x75: 'jne', 0x76: 'jbe', 0x77: 'jnbe',
                    0x78: 'js', 0x79: 'jns', 0x7a: 'jp', 0x7b: 'jnp',
                    0x7c: 'jl', 0x7d: 'jnl', 0x7e: 'jle', 0x7f: 'jnle',
                }
                instr['mnemonic'] = cond_map.get(byte, 'jcc')
                instr['size'] = 2
                instr['bytes'] = list(text_data[i:i+2])
                (disp,) = struct.unpack_from('<b', text_data, i + 1)
                instr['target'] = text_base + i + 2 + disp
                instr['is_branch'] = True
                instr['branch_type'] = 'conditional'
            elif byte == 0x0f and i + 2 <= size:
                byte2 = text_data[i + 1]
                if (byte2 & 0xf0) == 0x80 and i + 6 <= size:
                    cond_map2 = {
                        0x80: 'jo', 0x81: 'jno', 0x82: 'jb', 0x83: 'jnb',
                        0x84: 'je', 0x85: 'jne', 0x86: 'jbe', 0x87: 'jnbe',
                        0x88: 'js', 0x89: 'jns', 0x8a: 'jp', 0x8b: 'jnp',
                        0x8c: 'jl', 0x8d: 'jnl', 0x8e: 'jle', 0x8f: 'jnle',
                    }
                    instr['mnemonic'] = cond_map2.get(byte2, 'jcc')
                    instr['size'] = 6
                    instr['bytes'] = list(text_data[i:i+6])
                    (disp,) = struct.unpack_from('<i', text_data, i + 2)
                    instr['target'] = text_base + i + 6 + disp
                    instr['is_branch'] = True
                    instr['branch_type'] = 'conditional'
                else:
                    instr['size'] = self._guess_instr_size(text_data, i)
                    if instr['size'] == 0:
                        instr['size'] = 1
                    instr['bytes'] = list(text_data[i:i+instr['size']])
            else:
                instr['size'] = self._guess_instr_size(text_data, i)
                if instr['size'] == 0:
                    instr['size'] = 1
                instr['bytes'] = list(text_data[i:i+instr['size']])

            instructions.append(instr)
            i += instr['size']

        branch_targets = set()
        leader_addr = {instructions[0]['addr']} if instructions else set()

        for instr in instructions:
            if instr['is_branch']:
                if instr['target'] is not None:
                    branch_targets.add(instr['target'])
                    leader_addr.add(instr['target'])
                if instr['branch_type'] in ('conditional', 'call'):
                    next_idx = instructions.index(instr) + 1
                    if next_idx < len(instructions):
                        leader_addr.add(instructions[next_idx]['addr'])

        leader_list = sorted(leader_addr)
        addr_to_block = {}
        blocks = []

        block_id = 0
        for li, leader in enumerate(leader_list):
            end_addr = leader_list[li + 1] if li + 1 < len(leader_list) else (text_base + size)
            block_instrs = [ins for ins in instructions if leader <= ins['addr'] < end_addr]
            if block_instrs:
                block = {
                    'id': block_id,
                    'start': leader,
                    'end': block_instrs[-1]['addr'] + block_instrs[-1]['size'],
                    'instructions': block_instrs,
                    'num_instrs': len(block_instrs),
                    'successors': [],
                }
                blocks.append(block)
                addr_to_block[leader] = block_id
                block_id += 1

        for block in blocks:
            last_instr = block['instructions'][-1]
            if last_instr['is_branch']:
                if last_instr['target'] is not None and last_instr['target'] in addr_to_block:
                    succ_id = addr_to_block[last_instr['target']]
                    edge_type = last_instr['branch_type']
                    block['successors'].append((succ_id, edge_type))
                if last_instr['branch_type'] in ('conditional', 'call'):
                    fallthrough_addr = block['end']
                    if fallthrough_addr in addr_to_block:
                        succ_id = addr_to_block[fallthrough_addr]
                        edge_type = 'fallthrough' if last_instr['branch_type'] == 'conditional' else 'call-fallthrough'
                        block['successors'].append((succ_id, edge_type))
            else:
                fallthrough_addr = block['end']
                if fallthrough_addr in addr_to_block:
                    succ_id = addr_to_block[fallthrough_addr]
                    block['successors'].append((succ_id, 'fallthrough'))

        func_entries = []
        for sym in self.symtab + self.dynsym:
            if sym['st_type'] == 2:
                func_entries.append({
                    'name': sym['st_name_str'] or f'func_{sym["st_value"]}',
                    'addr': sym['st_value_int'],
                    'size': sym['st_size'],
                })
        func_entries.sort(key=lambda x: x['addr'])

        return blocks, addr_to_block, func_entries

    def _guess_instr_size(self, data, offset):
        size = 1
        if offset >= len(data):
            return 1
        b = data[offset]

        if b in (0x48, 0x4c, 0x4d, 0x49, 0x44, 0x45, 0x46, 0x47):
            if offset + 1 < len(data):
                b2 = data[offset + 1]
                if b2 in (0x89, 0x8b, 0x8d, 0x83, 0x81, 0x3b, 0x39, 0x85, 0x8a):
                    size = 3
                    if offset + 2 < len(data):
                        modrm = data[offset + 2]
                        mod = (modrm >> 6) & 3
                        rm = modrm & 7
                        if mod == 0 and rm == 5:
                            size = 7
                        elif mod == 0 and rm == 4:
                            size = 4
                        elif mod == 2:
                            size += 4
                        elif mod == 1:
                            size += 1
                elif b2 in (0xc7, 0xc1):
                    size = 7
                elif b2 in (0x55, 0x5d, 0x50, 0x58, 0x53, 0x5b, 0x52, 0x5a, 0x51, 0x59):
                    size = 2
                elif b2 in (0xec, 0xe4, 0xe5, 0xc9, 0xcc, 0xc3):
                    size = 2
                elif b2 == 0xff:
                    size = 3
                else:
                    size = 2
            else:
                size = 1
        elif b in (0x55, 0x5d, 0x50, 0x58, 0x53, 0x5b, 0x52, 0x5a, 0x51, 0x59, 0x54, 0x5c, 0x56, 0x5e, 0x57, 0x5f):
            size = 1
        elif b in (0x89, 0x8b, 0x8d, 0x3b, 0x39, 0x85, 0x8a):
            size = 2
            if offset + 1 < len(data):
                modrm = data[offset + 1]
                mod = (modrm >> 6) & 3
                rm = modrm & 7
                if mod == 0 and rm == 5:
                    size = 6
                elif mod == 0 and rm == 4:
                    size = 3
                elif mod == 2:
                    size += 4
                elif mod == 1:
                    size += 1
        elif b in (0xc7, 0xc1):
            size = 6
        elif b in (0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf):
            size = 5
        elif b in (0x83, 0x81):
            size = 3
            if offset + 1 < len(data):
                modrm = data[offset + 1]
                mod = (modrm >> 6) & 3
                rm = modrm & 7
                if mod == 0 and rm == 5:
                    size = 7 if b == 0x81 else 4
                elif mod == 0 and rm == 4:
                    size = 4
                elif mod == 2:
                    size += 4
                elif mod == 1:
                    size += 1
        elif b == 0xff:
            size = 2
            if offset + 1 < len(data):
                modrm = data[offset + 1]
                reg = (modrm >> 3) & 7
                if reg in (2, 3):
                    size = 2
        elif b in (0x01, 0x03, 0x08, 0x0a, 0x29, 0x2b, 0x31, 0x33, 0x88, 0x8c, 0x8e):
            size = 2
        elif b in (0x66, 0xf2, 0xf3):
            size = 2
        elif b in (0xc9, 0xcc, 0xc2, 0xca, 0xcf):
            size = 1 if b in (0xc9, 0xcc, 0xcf) else (3 if b in (0xc2, 0xca) else 1)
        elif b in (0xf4, 0xfb, 0xf5, 0xfc, 0xf8, 0xf9, 0xfa, 0xf7):
            if b == 0xf7 and offset + 1 < len(data):
                size = 3
            else:
                size = 1
        else:
            size = 1

        return max(1, min(size, 15))

    # --------------------------------------------------------
    # 主解析流程
    # --------------------------------------------------------

    def _parse(self):
        self._parse_elf_header()
        self._parse_program_headers()
        self._parse_section_headers()
        self._parse_symbols()
        self._parse_relocations()
        self._parse_dynamic()
        self._parse_version_info()

    # --------------------------------------------------------
    # 字符串提取
    # --------------------------------------------------------

    def extract_strings(self, encoding='utf-8', min_len=4, target_sections=None):
        results = []
        sections_to_scan = []

        for sec in self.section_headers:
            name = sec['sh_name_str']
            if target_sections:
                if name in target_sections:
                    sections_to_scan.append(sec)
            else:
                if name in ('.rodata', '.strtab', '.dynstr', '.shstrtab', '.data'):
                    sections_to_scan.append(sec)

        encodings = self._parse_encoding(encoding)

        for sec in sections_to_scan:
            if sec['sh_type'] == 8:
                continue
            data_offset = sec['sh_offset_int']
            data_size = sec['sh_size']
            if data_size == 0 or data_offset + data_size > self.size:
                continue

            raw = self.data[data_offset:data_offset + data_size]

            for enc_name, enc_bytes in encodings:
                try:
                    decoded = raw.decode(enc_name, errors='ignore')
                    self._find_printable_strings(
                        decoded, enc_name, enc_bytes,
                        data_offset, sec['sh_name_str'], min_len, results
                    )
                except Exception:
                    continue

        return results

    def _parse_encoding(self, encoding):
        enc_lower = encoding.lower()
        if enc_lower == 'ascii':
            return [('ascii', 1)]
        elif enc_lower == 'utf-16':
            return [('utf-16-le', 2), ('utf-16-be', 2)]
        else:
            return [('utf-8', 1), ('ascii', 1)]

    def _find_printable_strings(self, text, enc_name, enc_bytes, base_offset, sec_name, min_len, results):
        if enc_bytes == 1:
            current = []
            current_start = 0
            for i, ch in enumerate(text):
                if ch.isprintable() and ch != '\x00':
                    if not current:
                        current_start = i
                    current.append(ch)
                else:
                    if len(current) >= min_len:
                        s = ''.join(current)
                        results.append({
                            'section': sec_name,
                            'offset': hex(base_offset + current_start),
                            'offset_int': base_offset + current_start,
                            'encoding': enc_name,
                            'string': s,
                        })
                    current = []
            if len(current) >= min_len:
                s = ''.join(current)
                results.append({
                    'section': sec_name,
                    'offset': hex(base_offset + current_start),
                    'offset_int': base_offset + current_start,
                    'encoding': enc_name,
                    'string': s,
                })
        else:
            import re as _re
            pattern = _re.compile(r'[\u0020-\u007E\u4E00-\u9FFF\u3000-\u303F\uFF00-\uFFEF]{' + str(min_len) + r',}')
            for m in pattern.finditer(text):
                results.append({
                    'section': sec_name,
                    'offset': hex(base_offset + m.start() * enc_bytes),
                    'offset_int': base_offset + m.start() * enc_bytes,
                    'encoding': enc_name,
                    'string': m.group(),
                })

    # --------------------------------------------------------
    # 工具方法
    # --------------------------------------------------------

    def get_section_size_stats(self):
        total_file_size = self.size
        stats = []
        total_section_size = 0
        for sec in self.section_headers:
            total_section_size += sec['sh_size']

        for sec in self.section_headers:
            pct_file = (sec['sh_size'] / total_file_size * 100) if total_file_size > 0 else 0
            pct_section = (sec['sh_size'] / total_section_size * 100) if total_section_size > 0 else 0
            stats.append({
                'name': sec['sh_name_str'] or f"[{sec['index']}]",
                'size': sec['sh_size'],
                'pct_file': pct_file,
                'pct_section': pct_section,
                'type': sec['sh_type_str'],
            })
        stats.sort(key=lambda x: x['size'], reverse=True)
        return {
            'total_file_size': total_file_size,
            'total_section_size': total_section_size,
            'sections': stats,
        }

    def search_symbols(self, pattern, table='all'):
        results = []
        tables = []
        if table in ('all', 'symtab'):
            tables.append(('.symtab', self.symtab))
        if table in ('all', 'dynsym'):
            tables.append(('.dynsym', self.dynsym))

        try:
            regex = re.compile(pattern, re.IGNORECASE)
        except re.error:
            regex = re.compile(re.escape(pattern), re.IGNORECASE)

        for tname, syms in tables:
            for sym in syms:
                if regex.search(sym['st_name_str']):
                    results.append({'table': tname, **sym})
        return results

    def to_dict(self):
        return {
            'filepath': self.filepath,
            'file_size': self.size,
            'elf_header': self.elf_header,
            'program_headers': self.program_headers,
            'section_headers': self.section_headers,
            'symtab': self.symtab,
            'dynsym': self.dynsym,
            'relocations': self.relocations,
            'dynamic_entries': self.dynamic_entries,
            'version_needs': self.version_needs,
            'version_syms': self.version_syms,
        }


# ============================================================
# 差异对比
# ============================================================

def diff_elf(elf1: ELFParser, elf2: ELFParser):
    result = {
        'header_diff': {},
        'sections': {'added': [], 'removed': [], 'modified': []},
        'symbols': {'added': [], 'removed': [], 'modified': []},
    }

    # Header comparison
    keys_to_compare = ['e_class_str', 'e_data_str', 'e_type_str', 'e_machine_str', 'e_entry']
    for k in keys_to_compare:
        v1 = elf1.elf_header.get(k)
        v2 = elf2.elf_header.get(k)
        if v1 != v2:
            result['header_diff'][k] = {'file1': v1, 'file2': v2}

    # Sections comparison
    secs1 = {s['sh_name_str']: s for s in elf1.section_headers if s['sh_name_str']}
    secs2 = {s['sh_name_str']: s for s in elf2.section_headers if s['sh_name_str']}

    all_sec_names = set(secs1.keys()) | set(secs2.keys())
    for name in sorted(all_sec_names):
        if name not in secs1:
            result['sections']['added'].append(name)
        elif name not in secs2:
            result['sections']['removed'].append(name)
        else:
            s1, s2 = secs1[name], secs2[name]
            changes = {}
            for attr in ('sh_size', 'sh_type_str', 'sh_addr_int'):
                if s1.get(attr) != s2.get(attr):
                    changes[attr] = {'file1': s1.get(attr), 'file2': s2.get(attr)}
            if changes:
                result['sections']['modified'].append({'name': name, 'changes': changes})

    # Symbols comparison (.symtab)
    def get_sym_names(syms):
        return {s['st_name_str']: s for s in syms if s['st_name_str']}

    syms1 = get_sym_names(elf1.symtab)
    syms2 = get_sym_names(elf2.symtab)
    all_sym_names = set(syms1.keys()) | set(syms2.keys())

    for name in sorted(all_sym_names):
        if name not in syms1:
            result['symbols']['added'].append(name)
        elif name not in syms2:
            result['symbols']['removed'].append(name)
        else:
            s1, s2 = syms1[name], syms2[name]
            changes = {}
            for attr in ('st_bind_str', 'st_type_str', 'st_size', 'st_value_int'):
                if s1.get(attr) != s2.get(attr):
                    changes[attr] = {'file1': s1.get(attr), 'file2': s2.get(attr)}
            if changes:
                result['symbols']['modified'].append({'name': name, 'changes': changes})

    return result


# ============================================================
# 显示/格式化函数
# ============================================================

def print_section(title):
    bar = '=' * 70
    print(f"\n{bar}")
    print(f"  {title}")
    print(bar)


def print_elf_header(elf: ELFParser):
    print_section("ELF Header")
    h = elf.elf_header
    print(f"  Magic:                             {h['e_ident_magic']}")
    print(f"  Class:                             {h['e_class_str']}")
    print(f"  Data:                              {h['e_data_str']}")
    print(f"  Version:                           {h['e_version']} (current)")
    print(f"  OS/ABI:                            {h['e_osabi_str']}")
    print(f"  ABI Version:                       {h['e_abiversion']}")
    print(f"  Type:                              {h['e_type_str']}")
    print(f"  Machine:                           {h['e_machine_str']}")
    print(f"  Version:                           0x{h['e_version_full']:x}")
    print(f"  Entry point address:               {h['e_entry']}")
    print(f"  Start of program headers:          {h['e_phoff']} (bytes into file)")
    print(f"  Start of section headers:          {h['e_shoff']} (bytes into file)")
    print(f"  Flags:                             0x{h['e_flags']:x}")
    print(f"  Size of this header:               {h['e_ehsize']} (bytes)")
    print(f"  Size of program headers:           {h['e_phentsize']} (bytes)")
    print(f"  Number of program headers:         {h['e_phnum']}")
    print(f"  Size of section headers:           {h['e_shentsize']} (bytes)")
    print(f"  Number of section headers:         {h['e_shnum']}")
    print(f"  Section header string table index: {h['e_shstrndx']}")


def print_program_headers(elf: ELFParser):
    print_section("Program Headers")
    if not elf.program_headers:
        print("  (No program headers)")
        return

    # Table format
    hdr_fmt = "  {:<3} {:<18} {:>8} {:>10} {:>10} {:>8} {:>8} {:>5} {:>8}"
    row_fmt = "  [{:<2}] {:<18} {:>8} {:>10} {:>10} {:>8} {:>8} {:>5} {:>8}"
    print(hdr_fmt.format('Nr', 'Type', 'Offset', 'VirtAddr', 'PhysAddr',
                         'FileSiz', 'MemSiz', 'Flags', 'Align'))
    for ph in elf.program_headers:
        print(row_fmt.format(
            ph['index'],
            ph['p_type_str'].replace('PT_', '') if ph['p_type_str'].startswith('PT_') else ph['p_type_str'],
            ph['p_offset'], ph['p_vaddr'], ph['p_paddr'],
            hex(ph['p_filesz']), hex(ph['p_memsz']),
            ph['p_flags_str'], hex(ph['p_align'])
        ))
        if ph['interp']:
            print(f"         [Requesting program interpreter: {ph['interp']}]")


def print_sections(elf: ELFParser):
    print_section("Section Headers")
    if not elf.section_headers:
        print("  (No section headers)")
        return

    print("  [Nr] Name              Type            Address          Off    Size   ES Flg Lk Inf Al")
    fmt = "  [{:>2}] {:<17} {:<15} {:>16} {:>6} {:>6} {:>3} {:>3} {:>2} {:>3} {:>2}"
    for sec in elf.section_headers:
        name = sec['sh_name_str'][:17] if sec['sh_name_str'] else ''
        flags = ''
        sh_flags = sec['sh_flags']
        if sh_flags & 0x1: flags += 'W'
        if sh_flags & 0x2: flags += 'A'
        if sh_flags & 0x4: flags += 'X'
        if sh_flags & 0x10: flags += 'M'
        if sh_flags & 0x20: flags += 'S'
        if sh_flags & 0x40: flags += 'I'
        if sh_flags & 0x80: flags += 'L'
        if sh_flags & 0x100: flags += 'G'
        if sh_flags & 0x200: flags += 'T'
        if sh_flags & 0x40000000: flags += 'O'
        print(fmt.format(
            sec['index'], name,
            sec['sh_type_str'].replace('SHT_', '') if sec['sh_type_str'].startswith('SHT_') else sec['sh_type_str'][:15],
            sec['sh_addr'],
            f"{sec['sh_offset_int']:06x}",
            f"{sec['sh_size']:06x}",
            f"{sec['sh_entsize']:02x}",
            flags if flags else '',
            sec['sh_link'], sec['sh_info'], sec['sh_addralign']
        ))

    # 十六进制预览
    print_section("Section Hex Preview (first 64 bytes)")
    for sec in elf.section_headers:
        if not sec['hex_preview'] and not sec['sh_name_str']:
            continue
        name = sec['sh_name_str'] or f"section[{sec['index']}]"
        print(f"\n  [{sec['index']}] {name} ({sec['preview_size']} bytes):")
        hex_str = sec['hex_preview']
        ascii_str = sec['ascii_preview']
        # 每行16字节
        hex_bytes = hex_str.split()
        for line_idx in range(0, len(hex_bytes), 16):
            hex_line = hex_bytes[line_idx:line_idx + 16]
            padded = ' '.join(hex_line + ['  '] * (16 - len(hex_line)))
            ascii_line = ascii_str[line_idx:line_idx + 16].ljust(16)
            offset = sec['sh_offset_int'] + line_idx
            print(f"    {offset:08x}  {padded}  |{ascii_line}|")

    # 大小占比统计
    stats = elf.get_section_size_stats()
    print_section("Section Size Distribution")
    print(f"  Total file size:    {stats['total_file_size']} bytes ({stats['total_file_size']/1024:.2f} KB)")
    print(f"  Total sections:     {stats['total_section_size']} bytes ({stats['total_section_size']/1024:.2f} KB)")
    print()
    print(f"  {'Name':<20} {'Size':>10} {'% File':>8} {'% Sections':>10}  Bar")
    for s in stats['sections']:
        if s['size'] == 0:
            continue
        bar_len = int(s['pct_section'] / 5)
        bar = '█' * bar_len
        print(f"  {s['name']:<20} {s['size']:>10} {s['pct_file']:>7.2f}% {s['pct_section']:>9.2f}%  {bar}")


def _get_symbol_version(elf, sym_index, is_dynsym):
    if not is_dynsym:
        return ''
    ver = elf.version_map.get(sym_index, '')
    if ver and ver not in ('local', 'global'):
        return f" [{ver}]"
    return ''


def _group_and_print_symbols(elf, syms, title, is_dynsym=False):
    print_section(title)
    if not syms:
        print("  (No symbols)")
        return

    groups = defaultdict(list)
    for sym in syms:
        groups[sym['st_type_str']].append(sym)

    for type_str in sorted(groups.keys()):
        group = groups[type_str]
        print(f"\n  -- Symbol Type: {type_str} ({len(group)} symbols) --")
        print(f"  {'Num':>5} {'Value':>18} {'Size':>8} {'Bind':>8} {'Type':>8} {'Ndx':>10}  Name")
        for sym in group:
            ver_str = _get_symbol_version(elf, sym['index'], is_dynsym)
            print(f"  {sym['index']:>5} {sym['st_value']:>18} {sym['st_size']:>8} "
                  f"{sym['st_bind_str']:>8} {sym['st_type_str']:>8} {sym['st_shndx_str']:>10}  "
                  f"{sym['st_name_str']}{cyellow(ver_str)}")


def print_symbols(elf: ELFParser, search=None):
    if search:
        found = elf.search_symbols(search)
        print_section(f"Symbol Search Results (pattern: '{search}')")
        if not found:
            print(f"  No symbols matching '{search}' found.")
            return
        print(f"  Found {len(found)} matching symbols.\n")
        print(f"  {'Table':>8} {'Num':>5} {'Value':>18} {'Size':>8} {'Bind':>8} {'Type':>8} {'Ndx':>10}  Name")
        for sym in found:
            is_dyn = (sym['table'] == '.dynsym')
            ver_str = _get_symbol_version(elf, sym['index'], is_dyn)
            print(f"  {sym['table']:>8} {sym['index']:>5} {sym['st_value']:>18} {sym['st_size']:>8} "
                  f"{sym['st_bind_str']:>8} {sym['st_type_str']:>8} {sym['st_shndx_str']:>10}  "
                  f"{sym['st_name_str']}{cyellow(ver_str)}")
        return

    _group_and_print_symbols(elf, elf.symtab, "Symbol Table (.symtab)", is_dynsym=False)
    _group_and_print_symbols(elf, elf.dynsym, "Dynamic Symbol Table (.dynsym)", is_dynsym=True)


def print_relocations(elf: ELFParser):
    print_section("Relocation Entries")
    if not elf.relocations:
        print("  (No relocation entries)")
        return

    by_section = defaultdict(list)
    for rel in elf.relocations:
        by_section[rel['section']].append(rel)

    type_counter = Counter()
    for rel in elf.relocations:
        type_counter[rel['r_type_str']] += 1

    for sec_name in sorted(by_section.keys()):
        rels = by_section[sec_name]
        print(f"\n  Section: {sec_name} ({len(rels)} entries)")
        print(f"  {'Offset':>18} {'Type':<28} {'Sym':>5} {'Addend':>12}  Symbol Name")
        for rel in rels:
            addend = f"{rel['r_addend']:+d}" if rel['r_addend'] != 0 else ''
            print(f"  {rel['r_offset']:>18} {rel['r_type_str']:<28} {rel['r_sym']:>5} {addend:>12}  {rel['symbol_name']}")

    print_section("Relocation Type Distribution")
    total = sum(type_counter.values())
    for rtype, count in type_counter.most_common():
        pct = count / total * 100 if total > 0 else 0
        bar = '█' * int(pct / 5)
        print(f"  {rtype:<30} {count:>6}  {pct:>6.2f}%  {bar}")


def print_strings(results):
    print_section("Extracted Strings")
    if not results:
        print("  (No strings found)")
        return

    by_section = defaultdict(list)
    for s in results:
        by_section[s['section']].append(s)

    total = len(results)
    print(f"  Found {total} strings (length >= 4):\n")

    for sec in sorted(by_section.keys()):
        strs = by_section[sec]
        print(f"  -- From section {sec} ({len(strs)} strings) --")
        print(f"  {'Offset':>12} {'Enc':<8}  String")
        for s in strs:
            printable = s['string'].replace('\t', '\\t').replace('\n', '\\n')
            print(f"  {s['offset']:>12} {s['encoding']:<8}  \"{printable}\"")


def print_diff(diff_result, file1, file2):
    print_section(f"ELF Diff: {os.path.basename(file1)} vs {os.path.basename(file2)}")

    if diff_result['header_diff']:
        print("\n  Header Differences:")
        for k, v in diff_result['header_diff'].items():
            print(f"    {k}:")
            print(f"      {os.path.basename(file1)}: {v['file1']}")
            print(f"      {os.path.basename(file2)}: {v['file2']}")
    else:
        print("\n  Headers: No differences.")

    def _print_list(title, items, prefix='    '):
        print(f"\n  {title} ({len(items)}):")
        if items:
            for item in items:
                print(f"{prefix}{item}")
        else:
            print(f"{prefix}(none)")

    _print_list("Added Sections", diff_result['sections']['added'])
    _print_list("Removed Sections", diff_result['sections']['removed'])
    if diff_result['sections']['modified']:
        print(f"\n  Modified Sections ({len(diff_result['sections']['modified'])}):")
        for m in diff_result['sections']['modified']:
            print(f"    {m['name']}:")
            for attr, vals in m['changes'].items():
                print(f"      {attr}: {vals['file1']} -> {vals['file2']}")
    else:
        print(f"\n  Modified Sections (0): (none)")

    _print_list("Added Symbols", diff_result['symbols']['added'])
    _print_list("Removed Symbols", diff_result['symbols']['removed'])
    if diff_result['symbols']['modified']:
        print(f"\n  Modified Symbols ({len(diff_result['symbols']['modified'])}):")
        for m in diff_result['symbols']['modified'][:50]:
            changes_str = ', '.join(f"{k}: {v['file1']}->{v['file2']}" for k, v in m['changes'].items())
            print(f"    {m['name']}: {changes_str}")
        if len(diff_result['symbols']['modified']) > 50:
            print(f"    ... and {len(diff_result['symbols']['modified']) - 50} more")
    else:
        print(f"\n  Modified Symbols (0): (none)")


# ============================================================
# 动态段深度解析显示
# ============================================================

def _check_lib_exists(libname):
    for path in COMMON_LIB_PATHS:
        full = os.path.join(path, libname)
        if os.path.exists(full):
            return True, full
    return False, None


def print_dynamic(elf: ELFParser):
    print_section("Dynamic Section (.dynamic) Deep Analysis")
    if not elf.dynamic_entries:
        print("  (No dynamic section)")
        return

    needed = []
    paths = []
    init_funcs = []
    misc = []

    for de in elf.dynamic_entries:
        tag = de['d_tag']
        if tag == 1:
            needed.append(de)
        elif tag in (15, 29):
            paths.append(de)
        elif tag in (12, 13, 25, 26, 33):
            init_funcs.append(de)
        else:
            misc.append(de)

    print_section("1. Shared Library Dependencies (DT_NEEDED)")
    if needed:
        print(f"  {'Library':<40} {'Status':<25} {'Found At'}")
        for de in needed:
            lib = de['d_val_str'] or f"offset_{de['d_val']}"
            exists, found_at = _check_lib_exists(lib)
            status = cgreen("EXISTS in common paths") if exists else cred("NOT FOUND in common paths")
            found = found_at if exists else ''
            print(f"  {lib:<40} {status:<25} {found}")
        print(f"\n  Total dependencies: {len(needed)}")
    else:
        print("  (No dependencies)")

    print_section("2. Library Search Paths (RPATH/RUNPATH)")
    if paths:
        for de in paths:
            tag_str = de['d_tag_str']
            val = de['d_val_str'] or hex(de['d_val'])
            print(f"  {tag_str:<20} = {ccyan(val)}")
    else:
        print("  (No RPATH/RUNPATH configured)")

    print_section("3. Initialization / Finalization Functions")
    if init_funcs:
        print(f"  {'Tag':<20} {'Address':>18}  {'Note'}")
        for de in init_funcs:
            tag = de['d_tag']
            note = ''
            if tag == 12:
                note = 'Legacy init function'
            elif tag == 13:
                note = 'Legacy fini function'
            elif tag == 25:
                note = 'Init array (see .init_array)'
            elif tag == 26:
                note = 'Fini array (see .fini_array)'
            elif tag == 33:
                note = 'Pre-init array'
            print(f"  {de['d_tag_str']:<20} {de['d_val_str']:>18}  {note}")
    else:
        print("  (No init/fini functions)")

    print_section("4. Other Dynamic Entries")
    if misc:
        print(f"  {'Nr':>4} {'Tag':<22} {'Value / String'}")
        for i, de in enumerate(misc):
            print(f"  [{i:>2}] {de['d_tag_str']:<22} {de['d_val_str']}")
    else:
        print("  (None)")


# ============================================================
# 安全特性检测显示
# ============================================================

def print_security(elf: ELFParser):
    print_section("ELF Security Hardening Features")
    sec = elf.check_security()

    col_w = 18
    status_w = 22
    desc_w = 30

    header = f"  {'Feature':<{col_w}} {'Status':<{status_w}} {'Description'}"
    print(header)
    print(f"  {'-'*col_w} {'-'*status_w} {'-'*desc_w}")

    items = [
        ('RELRO', sec['RELRO'], 'GNU Relocation Read-Only'),
        ('Stack Canary', sec['Stack Canary'], 'Stack smashing protection'),
        ('PIE', sec['PIE'], 'Position Independent Executable'),
        ('NX', sec['NX'], 'Non-Executable stack (DEP)'),
        ('FORTIFY', sec['FORTIFY'], 'Source fortification (_chk variants)'),
    ]

    for name, (status_text, enabled), desc in items:
        if enabled:
            status = cgreen(f"[✓] {status_text}")
        else:
            status = cred(f"[✗] {status_text}")
        print(f"  {name:<{col_w}} {status:<{status_w + 10}} {desc}")

    score = sum(1 for _, (_, e), _ in items if e)
    print(f"\n  Security Score: {score}/{len(items)} features enabled")


# ============================================================
# 控制流图生成显示
# ============================================================

def _edge_color(edge_type):
    colors = {
        'conditional': 'blue',
        'unconditional': 'red',
        'call': 'darkgreen',
        'fallthrough': 'gray',
        'call-fallthrough': 'green',
        'ret': 'purple',
    }
    return colors.get(edge_type, 'black')


def generate_cfg_dot(blocks, func_entries, output_path):
    lines = ['digraph CFG {']
    lines.append('    node [shape=box, style=filled, fillcolor="#f0f0f0", fontname="monospace"];')
    lines.append('    edge [fontname="monospace", fontsize=10];')
    lines.append('    rankdir=TB;')
    lines.append('')

    func_addr_to_name = {}
    for f in func_entries:
        func_addr_to_name[f['addr']] = f['name']

    lines.append('    // Function entry point clusters')
    for fi, func in enumerate(func_entries):
        func_blocks = []
        for blk in blocks:
            if blk['start'] == func['addr'] or (fi + 1 < len(func_entries) and func['addr'] <= blk['start'] < func_entries[fi + 1]['addr']):
                func_blocks.append(blk)
            elif fi + 1 >= len(func_entries) and blk['start'] >= func['addr']:
                func_blocks.append(blk)
        if func_blocks:
            lines.append(f'    subgraph cluster_func_{fi} {{')
            lines.append(f'        label="{func["name"]} @ {hex(func["addr"])}";')
            lines.append(f'        style=dashed;')
            for blk in func_blocks:
                label = f"BB{blk['id']}\\nStart: {hex(blk['start'])}\\nInstrs: {blk['num_instrs']}"
                lines.append(f'        bb{blk["id"]} [label="{label}"];')
            lines.append(f'    }}')
            lines.append('')

    standalone = [b for b in blocks if b['start'] not in func_addr_to_name]
    if standalone:
        lines.append('    // Standalone basic blocks')
        for blk in standalone:
            label = f"BB{blk['id']}\\nStart: {hex(blk['start'])}\\nInstrs: {blk['num_instrs']}"
            lines.append(f'    bb{blk["id"]} [label="{label}"];')
        lines.append('')

    lines.append('    // Control flow edges')
    for blk in blocks:
        for (succ_id, edge_type) in blk['successors']:
            color = _edge_color(edge_type)
            lines.append(f'    bb{blk["id"]} -> bb{succ_id} [label="{edge_type}", color="{color}"];')

    lines.append('}')

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))
    return len(lines)


def print_cfg(elf: ELFParser, output_path=None):
    print_section("Control Flow Graph (CFG) Analysis")
    blocks, addr_to_block, func_entries = elf.disassemble_cfg()

    if not blocks:
        print("  (No .text section or empty - CFG not available)")
        return

    print(f"  Total basic blocks: {len(blocks)}")
    total_edges = sum(len(b['successors']) for b in blocks)
    print(f"  Total CFG edges:    {total_edges}")
    print()

    print_section("Basic Blocks")
    print(f"  {'ID':>4} {'Start Addr':>18} {'End Addr':>18} {'Instrs':>7}  Successors")
    for blk in blocks:
        succs = []
        for (sid, etype) in blk['successors']:
            succs.append(f"BB{sid}({etype})")
        succ_str = ', '.join(succs) if succs else '(none)'
        print(f"  {blk['id']:>4} {hex(blk['start']):>18} {hex(blk['end']):>18} {blk['num_instrs']:>7}  {succ_str}")

    print_section("Function Entry Points")
    if func_entries:
        print(f"  {'Name':<30} {'Address':>18} {'Size':>10}  Block")
        for func in func_entries:
            bid = addr_to_block.get(func['addr'], 'N/A')
            print(f"  {func['name']:<30} {hex(func['addr']):>18} {func['size']:>10}  BB{bid}")
    else:
        print("  (No FUNC type symbols found)")

    base = os.path.splitext(os.path.basename(elf.filepath))[0]
    if output_path is None:
        output_path = f"{base}_cfg.dot"

    num_lines = generate_cfg_dot(blocks, func_entries, output_path)
    print_section("DOT Output")
    print(f"  [+] CFG written to: {output_path} ({num_lines} lines)")
    print(f"  Render with: dot -Tpng {output_path} -o {base}_cfg.png")


# ============================================================
# 版本信息显示
# ============================================================

def _parse_glibc_version(ver_str):
    m = re.match(r'GLIBC_(\d+)\.(\d+)', ver_str)
    if m:
        return (int(m.group(1)), int(m.group(2)))
    m2 = re.match(r'GLIBC_(\d+)\.(\d+)\.(\d+)', ver_str)
    if m2:
        return (int(m2.group(1)), int(m2.group(2)), int(m2.group(3)))
    return None


def print_versions(elf: ELFParser):
    print_section("GNU Symbol Version Information")

    if not elf.version_needs:
        print("  (No .gnu.version_r section - no versioned dependencies)")
    else:
        print(f"  Total versioned libraries: {len(elf.version_needs)}")
        print()

        all_glibc_versions = []

        for vn in elf.version_needs:
            lib_name = vn['file'] or '(unknown)'
            print_section(f"Library: {ccyan(lib_name)}")

            version_syms_map = defaultdict(list)
            for sym_idx, ver_label in elf.version_map.items():
                if ver_label.startswith(lib_name + '@'):
                    ver = ver_label.split('@', 1)[1]
                    sym_name = elf.dynsym[sym_idx]['st_name_str'] if sym_idx < len(elf.dynsym) else f'sym_{sym_idx}'
                    version_syms_map[ver].append(sym_name)

            for aux in vn['version_entries']:
                ver = aux['version']
                glibc_ver = _parse_glibc_version(ver)
                if glibc_ver:
                    all_glibc_versions.append((glibc_ver, ver))

                syms = version_syms_map.get(ver, [])
                print(f"  Version: {cbold(ver)}  (idx={aux['ver_idx']}, hash={aux['hash']})")
                if syms:
                    print(f"    Symbols using this version ({len(syms)}):")
                    for s in syms:
                        print(f"      • {s}")
                else:
                    print(f"    (No symbols directly reference this version)")
                print()

        if all_glibc_versions:
            all_glibc_versions.sort(key=lambda x: x[0])
            min_ver = all_glibc_versions[0]
            max_ver = all_glibc_versions[-1]
            print_section("GLIBC Version Summary")
            print(f"  Minimum required GLIBC: {cgreen(min_ver[1])}  {tuple(min_ver[0])}")
            print(f"  Maximum referenced GLIBC: {cyellow(max_ver[1])}  {tuple(max_ver[0])}")
            print(f"  All GLIBC versions referenced:")
            for _, v in all_glibc_versions:
                print(f"    • {v}")

    if elf.version_syms:
        print_section("Dynamic Symbol → Version Mapping")
        printed = 0
        for sv in elf.version_syms:
            idx = sv['sym_index']
            if idx >= len(elf.dynsym):
                continue
            sym_name = elf.dynsym[idx]['st_name_str']
            if not sym_name:
                continue
            ver = elf.version_map.get(idx, '')
            if ver and ver not in ('local', 'global'):
                print(f"  {sym_name:<30} → {cyellow(ver)}")
                printed += 1
        if printed == 0:
            print("  (No version-tagged dynamic symbols)")


# ============================================================
# 交互式浏览模式 (TUI)
# ============================================================

class ELFBrowser:
    def __init__(self, elf: ELFParser):
        self.elf = elf
        self.left_items = []
        self.expanded = set()
        self.item_map = {}
        self.left_scroll = 0
        self.right_scroll = 0
        self.left_cursor = 0
        self.focus = 'left'
        self.search_pattern = None
        self.search_matches = set()
        self.search_cur_match = 0
        self._build_tree()

    def _build_tree(self):
        self.left_items = []
        self.item_map = {}
        idx = 0

        self.left_items.append(('root_header', 'ELF File', idx))
        self.item_map[idx] = {'type': 'header', 'title': 'ELF Header', 'collapsible': True}
        idx += 1

        self.left_items.append(('root_sections', f'Sections ({len(self.elf.section_headers)})', idx))
        self.item_map[idx] = {'type': 'sections_root', 'title': 'Sections', 'collapsible': True}
        idx += 1
        for i, sec in enumerate(self.elf.section_headers):
            name = sec['sh_name_str'] or f'section[{i}]'
            self.left_items.append(('section', f'  [{i}] {name}', idx))
            self.item_map[idx] = {'type': 'section', 'index': i, 'collapsible': False}
            idx += 1

        self.left_items.append(('root_segments', f'Program Headers ({len(self.elf.program_headers)})', idx))
        self.item_map[idx] = {'type': 'segments_root', 'title': 'Program Headers', 'collapsible': True}
        idx += 1
        for i, ph in enumerate(self.elf.program_headers):
            self.left_items.append(('segment', f'  [{i}] {ph["p_type_str"]}', idx))
            self.item_map[idx] = {'type': 'segment', 'index': i, 'collapsible': False}
            idx += 1

        self.left_items.append(('root_symtab', f'Symbol Table (.symtab: {len(self.elf.symtab)})', idx))
        self.item_map[idx] = {'type': 'symtab_root', 'title': '.symtab', 'collapsible': True}
        idx += 1
        sym_preview = self.elf.symtab[:50]
        for i, sym in enumerate(sym_preview):
            name = sym['st_name_str'] or '(no name)'
            self.left_items.append(('symtab_sym', f'  [{i}] {name}', idx))
            self.item_map[idx] = {'type': 'symtab_sym', 'index': i, 'collapsible': False}
            idx += 1
        if len(self.elf.symtab) > 50:
            self.left_items.append(('symtab_more', f'  ... ({len(self.elf.symtab) - 50} more)', idx))
            self.item_map[idx] = {'type': 'placeholder', 'collapsible': False}
            idx += 1

        self.left_items.append(('root_dynsym', f'Dynamic Symbols (.dynsym: {len(self.elf.dynsym)})', idx))
        self.item_map[idx] = {'type': 'dynsym_root', 'title': '.dynsym', 'collapsible': True}
        idx += 1
        dyn_preview = self.elf.dynsym[:50]
        for i, sym in enumerate(dyn_preview):
            name = sym['st_name_str'] or '(no name)'
            self.left_items.append(('dynsym_sym', f'  [{i}] {name}', idx))
            self.item_map[idx] = {'type': 'dynsym_sym', 'index': i, 'collapsible': False}
            idx += 1
        if len(self.elf.dynsym) > 50:
            self.left_items.append(('dynsym_more', f'  ... ({len(self.elf.dynsym) - 50} more)', idx))
            self.item_map[idx] = {'type': 'placeholder', 'collapsible': False}
            idx += 1

    def _get_visible_items(self):
        visible = []
        expand_state = {
            'root_header': True,
            'root_sections': True,
            'root_segments': False,
            'root_symtab': False,
            'root_dynsym': False,
        }
        for key, _ in self.expanded:
            expand_state[key] = True
            if key in ('root_segments', 'root_symtab', 'root_dynsym'):
                pass

        skip_until = None
        for i, (item_key, display, idx) in enumerate(self.left_items):
            if skip_until and item_key != skip_until and not item_key.startswith(skip_until.split('_')[0] if '_' in skip_until else ''):
                skip_until = None

            if item_key in ('root_sections', 'root_segments', 'root_symtab', 'root_dynsym', 'root_header'):
                is_section_child = item_key.startswith('section') if item_key != 'root_sections' else False
                visible.append((item_key, display, idx, 'root'))
                if item_key == 'root_header' and expand_state.get('root_header', True):
                    pass
                elif item_key == 'root_sections' and not expand_state.get('root_sections', True):
                    skip_until = 'segment'
                elif item_key == 'root_segments' and not expand_state.get('root_segments', False):
                    skip_until = 'symtab'
                elif item_key == 'root_symtab' and not expand_state.get('root_symtab', False):
                    skip_until = 'dynsym'
                elif item_key == 'root_dynsym' and not expand_state.get('root_dynsym', False):
                    skip_until = 'END'
            else:
                if skip_until == 'END':
                    continue
                if skip_until and not item_key.startswith(skip_until.split('_')[0] if '_' in skip_until and skip_until != 'segment' else skip_until):
                    continue
                if skip_until == 'segment' and item_key.startswith('root'):
                    skip_until = None
                if skip_until == 'symtab' and item_key.startswith('root'):
                    skip_until = None
                if skip_until == 'dynsym' and item_key.startswith('root'):
                    skip_until = None
                is_child = item_key.startswith('section') or item_key.startswith('segment') or \
                           item_key.startswith('symtab_sym') or item_key.startswith('dynsym_sym') or \
                           item_key.endswith('_more')
                visible.append((item_key, display, idx, 'child' if is_child else 'root'))

        filtered = []
        in_hidden = False
        for item_key, display, idx, level in visible:
            if item_key == 'root_sections' and not expand_state.get('root_sections', True):
                in_hidden = True
                filtered.append((item_key, display, idx, level))
                continue
            if item_key == 'root_segments':
                in_hidden = False
            if in_hidden and item_key.startswith('section'):
                continue

            if item_key == 'root_segments' and not expand_state.get('root_segments', False):
                in_hidden = True
                filtered.append((item_key, display, idx, level))
                continue
            if in_hidden and item_key.startswith('segment'):
                continue
            if item_key == 'root_symtab':
                in_hidden = False

            if item_key == 'root_symtab' and not expand_state.get('root_symtab', False):
                in_hidden = True
                filtered.append((item_key, display, idx, level))
                continue
            if in_hidden and (item_key.startswith('symtab_') or item_key.endswith('_more') and 'symtab' in display.lower()):
                continue
            if item_key == 'root_dynsym':
                in_hidden = False

            if item_key == 'root_dynsym' and not expand_state.get('root_dynsym', False):
                in_hidden = True
                filtered.append((item_key, display, idx, level))
                continue
            if in_hidden and item_key.startswith('dynsym_'):
                continue

            filtered.append((item_key, display, idx, level))

        return filtered

    def _get_item_detail(self, item_key, item_idx):
        info = self.item_map.get(item_idx)
        if not info:
            return ['(No details)']

        t = info['type']
        lines = []

        if t == 'header':
            h = self.elf.elf_header
            lines = [
                cbold("=== ELF Header ==="),
                f"  Magic:       {h['e_ident_magic']}",
                f"  Class:       {h['e_class_str']}",
                f"  Data:        {h['e_data_str']}",
                f"  OS/ABI:      {h['e_osabi_str']}",
                f"  Type:        {h['e_type_str']}",
                f"  Machine:     {h['e_machine_str']}",
                f"  Entry:       {h['e_entry']}",
                f"  File size:   {self.elf.size} bytes",
                f"  Sections:    {len(self.elf.section_headers)}",
                f"  Segments:    {len(self.elf.program_headers)}",
            ]
        elif t == 'section':
            i = info['index']
            sec = self.elf.section_headers[i]
            lines = [cbold(f"=== Section [{i}]: {sec['sh_name_str'] or '(no name)'} ===")]
            lines.append(f"  Type:        {sec['sh_type_str']}")
            lines.append(f"  Address:     {sec['sh_addr']}")
            lines.append(f"  Offset:      {sec['sh_offset']}")
            lines.append(f"  Size:        {sec['sh_size']} bytes")
            lines.append(f"  Link:        {sec['sh_link']}")
            lines.append(f"  Info:        {sec['sh_info']}")
            lines.append(f"  Alignment:   {sec['sh_addralign']}")
            lines.append(f"  Entry size:  {sec['sh_entsize']}")
            if sec['hex_preview']:
                lines.append('')
                lines.append(cbold("  Hex Preview (first 64 bytes):"))
                hex_bytes = sec['hex_preview'].split()
                for li in range(0, len(hex_bytes), 16):
                    hl = hex_bytes[li:li + 16]
                    padded = ' '.join(hl + ['  '] * (16 - len(hl)))
                    ascii_str = sec['ascii_preview'][li:li + 16].ljust(16)
                    off = sec['sh_offset_int'] + li
                    lines.append(f"    {off:08x}  {padded}  |{ascii_str}|")
        elif t == 'segment':
            i = info['index']
            ph = self.elf.program_headers[i]
            lines = [cbold(f"=== Program Header [{i}]: {ph['p_type_str']} ===")]
            lines.append(f"  Offset:      {ph['p_offset']}")
            lines.append(f"  VirtAddr:    {ph['p_vaddr']}")
            lines.append(f"  PhysAddr:    {ph['p_paddr']}")
            lines.append(f"  FileSiz:     {hex(ph['p_filesz'])}")
            lines.append(f"  MemSiz:      {hex(ph['p_memsz'])}")
            lines.append(f"  Flags:       {ph['p_flags_str']}")
            lines.append(f"  Alignment:   {hex(ph['p_align'])}")
            if ph['interp']:
                lines.append(f"  Interpreter: {ph['interp']}")
        elif t == 'symtab_sym' or t == 'dynsym_sym':
            i = info['index']
            symtab = self.elf.symtab if t == 'symtab_sym' else self.elf.dynsym
            if i < len(symtab):
                sym = symtab[i]
                ver_str = ''
                if t == 'dynsym_sym':
                    v = self.elf.version_map.get(i, '')
                    if v and v not in ('local', 'global'):
                        ver_str = f" [{v}]"
                lines = [cbold(f"=== Symbol [{i}]: {sym['st_name_str'] or '(no name)'}{cyellow(ver_str)} ===")]
                lines.append(f"  Value:       {sym['st_value']}")
                lines.append(f"  Size:        {sym['st_size']} bytes")
                lines.append(f"  Binding:     {sym['st_bind_str']}")
                lines.append(f"  Type:        {sym['st_type_str']}")
                lines.append(f"  Section:     {sym['st_shndx_str']}")
            else:
                lines = ['(Symbol index out of range)']
        elif t == 'sections_root' or t == 'segments_root' or t == 'symtab_root' or t == 'dynsym_root':
            title = info['title']
            lines = [cbold(f"=== {title} ===")]
            if t == 'sections_root':
                lines.append(f"  Count: {len(self.elf.section_headers)}")
                lines.append(f"  Total size: {sum(s['sh_size'] for s in self.elf.section_headers)} bytes")
                lines.append("  Select a child section in the left panel for details.")
            elif t == 'segments_root':
                lines.append(f"  Count: {len(self.elf.program_headers)}")
                lines.append("  Select a child segment in the left panel for details.")
            elif t == 'symtab_root':
                lines.append(f"  Count: {len(self.elf.symtab)}")
                lines.append("  Select a child symbol in the left panel for details.")
            elif t == 'dynsym_root':
                lines.append(f"  Count: {len(self.elf.dynsym)}")
                lines.append("  Select a child symbol in the left panel for details.")
        else:
            lines = ['(No details available)']

        return lines

    def _get_file_offset_at_cursor(self):
        visible = self._get_visible_items()
        if self.left_cursor >= len(visible):
            return 0
        item_key, display, idx, level = visible[self.left_cursor]
        info = self.item_map.get(idx)
        if not info:
            return 0
        t = info['type']
        if t == 'section':
            return self.elf.section_headers[info['index']]['sh_offset_int']
        elif t == 'segment':
            return self.elf.program_headers[info['index']]['p_offset_int']
        return 0

    def _run_search(self, pattern):
        if not pattern:
            self.search_pattern = None
            self.search_matches = set()
            return
        self.search_pattern = pattern.lower()
        self.search_matches = set()
        try:
            regex = re.compile(pattern, re.IGNORECASE)
        except re.error:
            regex = re.compile(re.escape(pattern), re.IGNORECASE)

        visible = self._get_visible_items()
        for i, (item_key, display, idx, level) in enumerate(visible):
            txt = display.lower()
            if regex.search(txt):
                self.search_matches.add(i)

            info = self.item_map.get(idx)
            if info and info['type'] in ('section', 'segment', 'symtab_sym', 'dynsym_sym'):
                details = self._get_item_detail(item_key, idx)
                for dline in details:
                    if regex.search(dline.lower()):
                        self.search_matches.add(i)
                        break

        self.search_cur_match = 0
        if self.search_matches:
            sorted_matches = sorted(self.search_matches)
            if self.left_cursor in sorted_matches:
                self.search_cur_match = sorted_matches.index(self.left_cursor)
            else:
                self.left_cursor = sorted_matches[0]
                self.search_cur_match = 0

    def run(self, stdscr):
        curses.curs_set(0)
        stdscr.keypad(1)

        while True:
            max_y, max_x = stdscr.getmaxyx()
            status_h = 2
            left_w = max_x // 3
            right_w = max_x - left_w - 1
            content_h = max_y - status_h - 1

            if content_h < 5 or left_w < 20:
                stdscr.clear()
                stdscr.addstr(0, 0, "Terminal too small!")
                stdscr.refresh()
                stdscr.getch()
                continue

            stdscr.erase()

            visible = self._get_visible_items()
            if self.left_cursor >= len(visible):
                self.left_cursor = max(0, len(visible) - 1)
            if self.left_cursor < 0:
                self.left_cursor = 0

            if self.left_cursor < self.left_scroll:
                self.left_scroll = self.left_cursor
            if self.left_cursor >= self.left_scroll + content_h:
                self.left_scroll = self.left_cursor - content_h + 1

            cur_item_key = None
            cur_item_idx = None
            if visible:
                cur_item_key, _, cur_item_idx, _ = visible[self.left_cursor]

            for i in range(content_h):
                vis_idx = self.left_scroll + i
                if vis_idx >= len(visible):
                    break
                item_key, display, idx, level = visible[vis_idx]

                attr = 0
                is_match = vis_idx in self.search_matches
                is_current = (vis_idx == self.left_cursor and self.focus == 'left')
                if is_current:
                    attr = curses.A_REVERSE
                if is_match and not is_current:
                    attr |= curses.A_BOLD
                if is_match and is_current:
                    attr = curses.A_BOLD | curses.A_REVERSE

                info = self.item_map.get(idx)
                prefix = ' '
                if info and info.get('collapsible'):
                    is_exp = True
                    if item_key == 'root_segments':
                        is_exp = ('root_segments',) in self.expanded
                    elif item_key == 'root_symtab':
                        is_exp = ('root_symtab',) in self.expanded
                    elif item_key == 'root_dynsym':
                        is_exp = ('root_dynsym',) in self.expanded
                    elif item_key == 'root_sections':
                        is_exp = ('root_sections',) not in self.expanded
                    elif item_key == 'root_header':
                        is_exp = True
                    prefix = '▼ ' if is_exp else '▶ '

                try:
                    disp = prefix + display
                    disp = disp[:left_w - 1]
                    stdscr.addstr(i, 0, disp.ljust(left_w), attr)
                except curses.error:
                    pass

            for i in range(content_h):
                try:
                    stdscr.addch(i, left_w, curses.ACS_VLINE)
                except curses.error:
                    pass

            detail_lines = []
            if cur_item_key is not None and cur_item_idx is not None:
                detail_lines = self._get_item_detail(cur_item_key, cur_item_idx)

            if self.right_scroll >= len(detail_lines):
                self.right_scroll = max(0, len(detail_lines) - content_h)
            if self.right_scroll < 0:
                self.right_scroll = 0

            for i in range(content_h):
                line_idx = self.right_scroll + i
                if line_idx >= len(detail_lines):
                    break
                line = detail_lines[line_idx]
                line_stripped = re.sub(r'\x1b\[[0-9;]*m', '', line)
                line_stripped = line_stripped[:right_w - 2]
                attr = 0
                if self.focus == 'right':
                    attr = 0
                try:
                    stdscr.addstr(i, left_w + 2, line_stripped, attr)
                except curses.error:
                    pass

            try:
                stdscr.hline(content_h, 0, curses.ACS_HLINE, max_x)
            except curses.error:
                pass

            filename = os.path.basename(self.elf.filepath)
            offset = self._get_file_offset_at_cursor()
            status_line1 = f" File: {filename} | Size: {self.elf.size} bytes | Cursor offset: 0x{offset:x} ({offset})"
            status_line2 = f" [↑/↓] Navigate | [←/→] Tab switch | [Enter] Expand/Collapse | [/] Search | [n] Next match | [q] Quit "
            if self.focus == 'left':
                status_line2 += "| Focus: LEFT PANEL "
            else:
                status_line2 += "| Focus: RIGHT PANEL "
            if self.search_pattern:
                matches = sorted(self.search_matches)
                cur = ''
                if self.left_cursor in matches:
                    cur = f" {matches.index(self.left_cursor) + 1}/{len(matches)}"
                status_line2 += f"| Search: '{self.search_pattern}'{cur} "

            try:
                status1 = status_line1[:max_x - 1]
                stdscr.addstr(content_h + 1, 0, status1.ljust(max_x), curses.A_REVERSE)
                status2 = status_line2[:max_x - 1]
                if max_y > content_h + 2:
                    stdscr.addstr(content_h + 2, 0, status2.ljust(max_x), curses.A_DIM)
            except curses.error:
                pass

            stdscr.refresh()
            key = stdscr.getch()

            if key == ord('q') or key == 27:
                break
            elif key == ord('\t') or key == curses.KEY_RIGHT or key == curses.KEY_LEFT:
                if key == curses.KEY_RIGHT:
                    self.focus = 'right'
                elif key == curses.KEY_LEFT:
                    self.focus = 'left'
                else:
                    self.focus = 'right' if self.focus == 'left' else 'left'
            elif key == curses.KEY_UP:
                if self.focus == 'left' and visible:
                    self.left_cursor = max(0, self.left_cursor - 1)
                elif self.focus == 'right':
                    self.right_scroll = max(0, self.right_scroll - 1)
            elif key == curses.KEY_DOWN:
                if self.focus == 'left' and visible:
                    self.left_cursor = min(len(visible) - 1, self.left_cursor + 1)
                elif self.focus == 'right':
                    self.right_scroll = min(max(0, len(detail_lines) - content_h), self.right_scroll + 1)
            elif key == curses.KEY_PPAGE:
                if self.focus == 'left':
                    self.left_cursor = max(0, self.left_cursor - content_h)
                else:
                    self.right_scroll = max(0, self.right_scroll - content_h)
            elif key == curses.KEY_NPAGE:
                if self.focus == 'left' and visible:
                    self.left_cursor = min(len(visible) - 1, self.left_cursor + content_h)
                else:
                    self.right_scroll = min(max(0, len(detail_lines) - content_h), self.right_scroll + content_h)
            elif key == curses.KEY_HOME:
                if self.focus == 'left':
                    self.left_cursor = 0
                else:
                    self.right_scroll = 0
            elif key == curses.KEY_END:
                if self.focus == 'left' and visible:
                    self.left_cursor = len(visible) - 1
                else:
                    self.right_scroll = max(0, len(detail_lines) - content_h)
            elif key == ord('\n') or key == curses.KEY_ENTER:
                if visible and self.focus == 'left':
                    item_key, _, idx, _ = visible[self.left_cursor]
                    info = self.item_map.get(idx)
                    if info and info.get('collapsible') and item_key.startswith('root_'):
                        ek = (item_key,)
                        if item_key == 'root_header':
                            continue
                        if ek in self.expanded:
                            self.expanded.discard(ek)
                        else:
                            self.expanded.add(ek)
            elif key == ord('/'):
                curses.echo()
                curses.curs_set(1)
                try:
                    prompt = "Search: "
                    if max_y > 0:
                        stdscr.addstr(max_y - 1, 0, prompt.ljust(max_x), curses.A_REVERSE)
                    stdscr.refresh()
                    search_buf = ""
                    while True:
                        ch = stdscr.getch(max_y - 1, len(prompt) + len(search_buf))
                        if ch == 27:
                            curses.noecho()
                            curses.curs_set(0)
                            search_buf = ""
                            break
                        elif ch in (curses.KEY_ENTER, ord('\n'), 13):
                            curses.noecho()
                            curses.curs_set(0)
                            break
                        elif ch in (curses.KEY_BACKSPACE, 127, 8):
                            search_buf = search_buf[:-1]
                            clr = " " * (max_x - len(prompt) - len(search_buf) - 1)
                            stdscr.addstr(max_y - 1, len(prompt), search_buf + clr)
                            stdscr.move(max_y - 1, len(prompt) + len(search_buf))
                        elif 32 <= ch < 127 and len(prompt) + len(search_buf) < max_x - 1:
                            search_buf += chr(ch)
                            stdscr.addch(max_y - 1, len(prompt) + len(search_buf) - 1, ch)
                    self._run_search(search_buf.strip())
                except curses.error:
                    curses.noecho()
                    curses.curs_set(0)
            elif key == ord('n') or key == ord('N'):
                if self.search_matches:
                    matches = sorted(self.search_matches)
                    if matches:
                        cur_pos = self.left_cursor
                        if key == ord('n'):
                            try:
                                ci = matches.index(cur_pos)
                                self.left_cursor = matches[(ci + 1) % len(matches)]
                            except ValueError:
                                self.left_cursor = matches[0]
                        else:
                            try:
                                ci = matches.index(cur_pos)
                                self.left_cursor = matches[(ci - 1) % len(matches)]
                            except ValueError:
                                self.left_cursor = matches[-1]


def run_browse(elf: ELFParser):
    print(f"Launching interactive browser for: {elf.filepath}")
    print(f"Terminal: {os.environ.get('TERM', 'unknown')}")
    try:
        browser = ELFBrowser(elf)
        curses.wrapper(browser.run)
    except curses.error as e:
        print(f"Error initializing curses: {e}")
        print("Make sure you're running in a terminal with proper TERM setting.")
    except KeyboardInterrupt:
        pass
    print("\nExited browser.")


def generate_text_report(elf: ELFParser) -> str:
    import io
    old_stdout = sys.stdout
    sys.stdout = buf = io.StringIO()
    try:
        print(f"ELF Analysis Report for: {elf.filepath}")
        print(f"Generated by elfparse.py")
        print(f"File size: {elf.size} bytes")
        print_elf_header(elf)
        print_program_headers(elf)
        print_sections(elf)
        print_symbols(elf)
        print_relocations(elf)
        strings = elf.extract_strings()
        print_strings(strings)
    finally:
        sys.stdout = old_stdout
    return buf.getvalue()


# ============================================================
# CLI 入口
# ============================================================

def cmd_info(args):
    elf = ELFParser(args.binary)
    print_elf_header(elf)
    print_program_headers(elf)
    print_relocations(elf)

    if args.export_json:
        with open(args.export_json, 'w', encoding='utf-8') as f:
            json.dump(elf.to_dict(), f, indent=2, ensure_ascii=False)
        print(f"\n[+] Exported JSON to: {args.export_json}")

    if args.export_report:
        report = generate_text_report(elf)
        with open(args.export_report, 'w', encoding='utf-8') as f:
            f.write(report)
        print(f"\n[+] Exported report to: {args.export_report}")


def cmd_sections(args):
    elf = ELFParser(args.binary)
    print_sections(elf)


def cmd_symbols(args):
    elf = ELFParser(args.binary)
    print_symbols(elf, search=args.search)


def cmd_relocs(args):
    elf = ELFParser(args.binary)
    print_relocations(elf)


def cmd_strings(args):
    elf = ELFParser(args.binary)
    target = None
    if args.sections:
        target = [s.strip() for s in args.sections.split(',')]
    results = elf.extract_strings(encoding=args.encoding, min_len=args.min_len, target_sections=target)
    print_strings(results)


def cmd_diff(args):
    elf1 = ELFParser(args.bin1)
    elf2 = ELFParser(args.bin2)
    result = diff_elf(elf1, elf2)
    print_diff(result, args.bin1, args.bin2)

    if args.export_json:
        with open(args.export_json, 'w', encoding='utf-8') as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        print(f"\n[+] Exported diff JSON to: {args.export_json}")


def cmd_export(args):
    elf = ELFParser(args.binary)
    if args.json:
        with open(args.output, 'w', encoding='utf-8') as f:
            json.dump(elf.to_dict(), f, indent=2, ensure_ascii=False)
        print(f"[+] JSON exported to: {args.output}")
    else:
        report = generate_text_report(elf)
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write(report)
        print(f"[+] Report exported to: {args.output}")


def cmd_dynamic(args):
    elf = ELFParser(args.binary)
    print_dynamic(elf)


def cmd_cfg(args):
    elf = ELFParser(args.binary)
    output = args.output if hasattr(args, 'output') else None
    print_cfg(elf, output_path=output)


def cmd_security(args):
    elf = ELFParser(args.binary)
    print_security(elf)


def cmd_versions(args):
    elf = ELFParser(args.binary)
    print_versions(elf)


def cmd_browse(args):
    elf = ELFParser(args.binary)
    run_browse(elf)


def main():
    parser = argparse.ArgumentParser(
        prog='elfparse.py',
        description='ELF (Executable and Linkable Format) File Parser - Pure Python implementation without pyelftools',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python elfparse.py info hello_elf              Show header + program headers
  python elfparse.py sections hello_elf          Show section headers + hex preview
  python elfparse.py symbols hello_elf           Show symbol tables (grouped by type)
  python elfparse.py symbols hello_elf --search main  Search symbols by name
  python elfparse.py strings hello_elf           Extract printable strings
  python elfparse.py strings hello_elf --encoding utf-16
  python elfparse.py diff hello_elf dyn_elf      Compare two ELF files
  python elfparse.py export hello_elf --json -o out.json
  python elfparse.py dynamic dyn_elf             Deep parse .dynamic section
  python elfparse.py cfg hello_elf -o cfg.dot    Generate CFG in DOT format
  python elfparse.py security hello_elf          Check security hardening features
  python elfparse.py versions dyn_elf            Show GNU symbol version info
  python elfparse.py browse hello_elf            Interactive TUI browser
        """
    )
    subparsers = parser.add_subparsers(dest='command', required=True)

    # info subcommand
    p_info = subparsers.add_parser('info', help='Parse ELF header, program headers, and relocation info')
    p_info.add_argument('binary', help='ELF binary file path')
    p_info.add_argument('--export-json', help='Export full parse result to JSON file')
    p_info.add_argument('--export-report', help='Export readable text report')
    p_info.set_defaults(func=cmd_info)

    # sections subcommand
    p_sec = subparsers.add_parser('sections', help='Parse section headers with hex preview and size stats')
    p_sec.add_argument('binary', help='ELF binary file path')
    p_sec.set_defaults(func=cmd_sections)

    # symbols subcommand
    p_sym = subparsers.add_parser('symbols', help='Parse .symtab and .dynsym symbol tables (with version tags)')
    p_sym.add_argument('binary', help='ELF binary file path')
    p_sym.add_argument('--search', help='Fuzzy search symbol names (regex supported)')
    p_sym.set_defaults(func=cmd_symbols)

    # relocs subcommand
    p_rel = subparsers.add_parser('relocs', help='Parse relocation entries (.rel/.rela)')
    p_rel.add_argument('binary', help='ELF binary file path')
    p_rel.set_defaults(func=cmd_relocs)

    # strings subcommand
    p_str = subparsers.add_parser('strings', help='Extract printable strings from sections')
    p_str.add_argument('binary', help='ELF binary file path')
    p_str.add_argument('--encoding', default='utf-8', choices=['utf-8', 'ascii', 'utf-16'],
                       help='String encoding (default: utf-8)')
    p_str.add_argument('--min-len', type=int, default=4, help='Minimum string length (default: 4)')
    p_str.add_argument('--sections', help='Comma-separated section names to scan (default: .rodata,.strtab,.dynstr,.shstrtab,.data)')
    p_str.set_defaults(func=cmd_strings)

    # diff subcommand
    p_diff = subparsers.add_parser('diff', help='Compare two ELF files for structural differences')
    p_diff.add_argument('bin1', help='First ELF binary')
    p_diff.add_argument('bin2', help='Second ELF binary')
    p_diff.add_argument('--export-json', help='Export diff result to JSON')
    p_diff.set_defaults(func=cmd_diff)

    # export subcommand
    p_exp = subparsers.add_parser('export', help='Export parse results to JSON or text report')
    p_exp.add_argument('binary', help='ELF binary file path')
    p_exp.add_argument('-o', '--output', required=True, help='Output file path')
    p_exp.add_argument('--json', action='store_true', help='Export as JSON (default: text report)')
    p_exp.set_defaults(func=cmd_export)

    # dynamic subcommand
    p_dyn = subparsers.add_parser('dynamic', help='Deep parse .dynamic section (DT_NEEDED, paths, init funcs, etc.)')
    p_dyn.add_argument('binary', help='ELF binary file path')
    p_dyn.set_defaults(func=cmd_dynamic)

    # cfg subcommand
    p_cfg = subparsers.add_parser('cfg', help='Generate control flow graph (CFG) in DOT format from .text')
    p_cfg.add_argument('binary', help='ELF binary file path')
    p_cfg.add_argument('-o', '--output', help='Output DOT file path (default: <name>_cfg.dot)')
    p_cfg.set_defaults(func=cmd_cfg)

    # security subcommand
    p_sec2 = subparsers.add_parser('security', help='Check ELF security hardening features (RELRO/Canary/PIE/NX/FORTIFY)')
    p_sec2.add_argument('binary', help='ELF binary file path')
    p_sec2.set_defaults(func=cmd_security)

    # versions subcommand
    p_ver = subparsers.add_parser('versions', help='Parse .gnu.version and .gnu.version_r for symbol version info')
    p_ver.add_argument('binary', help='ELF binary file path')
    p_ver.set_defaults(func=cmd_versions)

    # browse subcommand
    p_br = subparsers.add_parser('browse', help='Interactive TUI browser for ELF structure')
    p_br.add_argument('binary', help='ELF binary file path')
    p_br.set_defaults(func=cmd_browse)

    args = parser.parse_args()
    try:
        args.func(args)
    except ELFParserError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except FileNotFoundError as e:
        print(f"Error: File not found: {e.filename}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
