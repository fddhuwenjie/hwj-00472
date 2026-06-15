#!/usr/bin/env python3
import argparse
import json
import struct
import sys
import os
import re
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
    # 主解析流程
    # --------------------------------------------------------

    def _parse(self):
        self._parse_elf_header()
        self._parse_program_headers()
        self._parse_section_headers()
        self._parse_symbols()
        self._parse_relocations()

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


def _group_and_print_symbols(syms, title):
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
            print(f"  {sym['index']:>5} {sym['st_value']:>18} {sym['st_size']:>8} "
                  f"{sym['st_bind_str']:>8} {sym['st_type_str']:>8} {sym['st_shndx_str']:>10}  "
                  f"{sym['st_name_str']}")


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
            print(f"  {sym['table']:>8} {sym['index']:>5} {sym['st_value']:>18} {sym['st_size']:>8} "
                  f"{sym['st_bind_str']:>8} {sym['st_type_str']:>8} {sym['st_shndx_str']:>10}  "
                  f"{sym['st_name_str']}")
        return

    _group_and_print_symbols(elf.symtab, "Symbol Table (.symtab)")
    _group_and_print_symbols(elf.dynsym, "Dynamic Symbol Table (.dynsym)")


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
    p_sym = subparsers.add_parser('symbols', help='Parse .symtab and .dynsym symbol tables')
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
