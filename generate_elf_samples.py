#!/usr/bin/env python3
import struct
import os

def create_hello_elf64(output_path):
    """构造一个最小化的ELF64 x86_64可执行文件示例，包含完整的节区和符号结构。"""

    endian = '<'

    # --- 内容准备 ---
    # .interp 内容
    interp = b'/lib64/ld-linux-x86-64.so.2\x00'

    # .rodata 内容（包含字符串）
    rodata = (
        b'Hello, ELF World!\x00'
        b'result=%d global=%d\n\x00'
        b'Copyright 2024 ELF Parser Demo\x00'
        b'https://example.com/elf-demo\x00'
        b'version 1.0.0-release\x00'
        b'BuildID: abc123def4567890\x00'
        b'Loaded successfully\x00'
        b'Initializing runtime environment\x00'
    )

    # .text 伪机器码（x86_64）
    text = bytes([
        0x55, 0x48, 0x89, 0xe5,
        0x48, 0x83, 0xec, 0x10,
        0xc7, 0x45, 0xfc, 0x0a, 0x00, 0x00, 0x00,
        0xc7, 0x45, 0xf8, 0x14, 0x00, 0x00, 0x00,
        0x8b, 0x55, 0xfc,
        0x8b, 0x45, 0xf8,
        0x01, 0xd0,
        0x89, 0x45, 0xf4,
        0x48, 0x8b, 0x15, 0x00, 0x00, 0x00, 0x00,
        0x48, 0x8d, 0x3d, 0x00, 0x00, 0x00, 0x00,
        0xe8, 0x00, 0x00, 0x00, 0x00,
        0xc9, 0xc3,
        0x55, 0x48, 0x89, 0xe5,
        0x89, 0x7d, 0xfc,
        0x89, 0x75, 0xf8,
        0x8b, 0x45, 0xfc,
        0x03, 0x45, 0xf8,
        0x5d, 0xc3,
    ])

    # .data 初始化数据
    data = struct.pack('<i', 42)  # global_var = 42

    # .bss 大小（未初始化数据）
    bss_size = 256

    # .note.ABI-tag
    note = struct.pack('<III', 4, 16, 1) + b'GNU\x00' + struct.pack('<IIII', 0, 0, 0, 3)

    # --- 符号准备 ---
    # .strtab 字符串表
    strtab_strings = [
        b'',
        b'hello.c\x00',
        b'global_var\x00',
        b'msg\x00',
        b'main\x00',
        b'add\x00',
        b'printf\x00',
        b'_start\x00',
        b'__bss_start\x00',
        b'_end\x00',
        b'_GLOBAL_OFFSET_TABLE_\x00',
        b'__libc_csu_init\x00',
        b'__libc_start_main\x00',
    ]

    # .dynstr 动态字符串表
    dynstr_strings = [
        b'',
        b'printf\x00',
        b'__libc_start_main\x00',
        b'libc.so.6\x00',
        b'GLIBC_2.2.5\x00',
    ]

    def build_strtab(strings):
        offsets = {}
        data = b''
        for s in strings:
            offsets[s.rstrip(b'\x00')] = len(data)
            data += s
        return data, offsets

    strtab_data, strtab_offsets = build_strtab(strtab_strings)
    dynstr_data, dynstr_offsets = build_strtab(dynstr_strings)

    # --- 节区名称表 .shstrtab ---
    shstrtab_entries = [
        b'',
        b'.symtab\x00',
        b'.strtab\x00',
        b'.shstrtab\x00',
        b'.interp\x00',
        b'.note.ABI-tag\x00',
        b'.hash\x00',
        b'.dynsym\x00',
        b'.dynstr\x00',
        b'.rela.dyn\x00',
        b'.rela.plt\x00',
        b'.rodata\x00',
        b'.text\x00',
        b'.data\x00',
        b'.bss\x00',
        b'.comment\x00',
        b'.dynamic\x00',
    ]
    shstrtab_data, shstrtab_offsets = build_strtab(shstrtab_entries)

    # --- 节区名称索引辅助 ---
    def sh_name(s):
        return shstrtab_offsets[s.encode() if isinstance(s, str) else s.rstrip(b'\x00')]

    # ============================================================
    # 布局规划
    # ============================================================
    # 我们按顺序放置各个部分：
    # [0x0000] ELF Header (64 bytes)
    # [0x0040] Program Headers (8 * 56 = 448 bytes)
    # [0x0200] .interp
    # [0x0240] .note.ABI-tag
    # [0x0280] .hash (placeholder)
    # [0x0300] .dynsym
    # [0x0400] .dynstr
    # [0x0500] .rela.dyn
    # [0x0600] .rela.plt
    # [0x0700] .rodata
    # [0x0800] .text
    # [0x0900] .data
    # [0x0A00] .comment
    # [0x0A80] .dynamic
    # [0x0C00] .symtab
    # [0x0E00] .strtab
    # [0x1000] .shstrtab
    # [0x1100] Section Headers (17 * 64 = 1088 bytes)
    # ============================================================

    # 各节区的偏移和大小
    sections_layout = [
        # (name, offset, size, type, flags, addr, link, info, align, entsize)
        (b'\x00', 0, 0, 0, 0, 0, 0, 0, 0, 0),  # SHT_NULL [0]
        (b'.interp\x00', 0x200, len(interp), 1, 0x2, 0x400200, 0, 0, 1, 0),  # [1]
        (b'.note.ABI-tag\x00', 0x240, len(note), 7, 0x2, 0x400240, 0, 0, 4, 0),  # [2]
        (b'.hash\x00', 0x280, 64, 5, 0x2, 0x400280, 7, 0, 8, 4),  # [3]
        (b'.dynsym\x00', 0x300, 24*8, 11, 0x2, 0x400300, 5, 1, 8, 24),  # [4]
        (b'.dynstr\x00', 0x400, len(dynstr_data), 3, 0x2, 0x400400, 0, 0, 1, 0),  # [5]
        (b'.rela.dyn\x00', 0x500, 2*24, 4, 0x2, 0x400500, 4, 0, 8, 24),  # [6]
        (b'.rela.plt\x00', 0x600, 2*24, 4, 0x2, 0x400600, 4, 12, 8, 24),  # [7]
        (b'.rodata\x00', 0x700, len(rodata), 1, 0x2, 0x400700, 0, 0, 8, 0),  # [8]
        (b'.text\x00', 0x800, len(text), 1, 0x6, 0x400800, 0, 0, 16, 0),  # [9]
        (b'.data\x00', 0x900, len(data), 1, 0x3, 0x600900, 0, 0, 8, 0),  # [10]
        (b'.bss\x00', 0x900 + len(data), bss_size, 8, 0x3, 0x600910, 0, 0, 16, 0),  # [11]
        (b'.comment\x00', 0xA00, 50, 1, 0x30, 0, 0, 0, 1, 0),  # [12]
        (b'.dynamic\x00', 0xA80, 20*16, 6, 0x3, 0x600A80, 5, 0, 8, 16),  # [13]
        (b'.symtab\x00', 0xC00, 12*24, 2, 0, 0, 15, 6, 8, 24),  # [14] sh_link=.strtab[15], sh_info=first non-local idx=6
        (b'.strtab\x00', 0xE00, len(strtab_data), 3, 0, 0, 0, 0, 1, 0),  # [15]
        (b'.shstrtab\x00', 0x1000, len(shstrtab_data), 3, 0, 0, 0, 0, 1, 0),  # [16]
    ]

    # .shstrtab 的索引
    SHSTRTAB_IDX = 16
    SYMTAB_IDX = 14
    STRTAB_IDX = 15
    DYNSYM_IDX = 4
    DYNSTR_IDX = 5
    TEXT_IDX = 9
    DATA_IDX = 10
    RODATA_IDX = 8
    BSS_IDX = 11
    COMMENT_IDX = 12

    section_header_offset = 0x1100

    # ============================================================
    # 构建 ELF Header
    # ============================================================
    e_ident = bytes([
        0x7f, 0x45, 0x4c, 0x46,  # Magic: .ELF
        0x02,  # EI_CLASS: ELFCLASS64
        0x01,  # EI_DATA: ELFDATA2LSB
        0x01,  # EI_VERSION
        0x00,  # EI_OSABI: SYSV
        0x00,  # EI_ABIVERSION
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # Padding (7 bytes to make 16 total)
    ])

    e_type = 2  # ET_EXEC
    e_machine = 62  # EM_X86_64
    e_version = 1
    e_entry = 0x400800  # entry point in .text
    e_phoff = 0x40
    e_shoff = section_header_offset
    e_flags = 0
    e_ehsize = 64
    e_phentsize = 56
    e_phnum = 8
    e_shentsize = 64
    e_shnum = len(sections_layout)
    e_shstrndx = SHSTRTAB_IDX

    elf_header = e_ident + struct.pack(endian + 'HHIQQQIHHHHHH',
        e_type, e_machine, e_version, e_entry, e_phoff, e_shoff,
        e_flags, e_ehsize, e_phentsize, e_phnum, e_shentsize,
        e_shnum, e_shstrndx)

    # ============================================================
    # 构建 Program Headers
    # ============================================================
    program_headers = b''

    # PT_PHDR
    program_headers += struct.pack(endian + 'IIQQQQQQ',
        6,  # p_type: PT_PHDR
        0x5,  # p_flags: R+E
        0x40,  # p_offset
        0x400040,  # p_vaddr
        0x400040,  # p_paddr
        e_phentsize * e_phnum,  # p_filesz
        e_phentsize * e_phnum,  # p_memsz
        8  # p_align
    )

    # PT_INTERP
    program_headers += struct.pack(endian + 'IIQQQQQQ',
        3,  # PT_INTERP
        0x4,  # R
        0x200,  # offset
        0x400200,  # vaddr
        0x400200,  # paddr
        len(interp),  # filesz
        len(interp),  # memsz
        1  # align
    )

    # PT_LOAD (seg1: header + rodata)
    program_headers += struct.pack(endian + 'IIQQQQQQ',
        1,  # PT_LOAD
        0x5,  # R+E
        0x0,  # offset
        0x400000,  # vaddr
        0x400000,  # paddr
        0x700 + len(rodata) + len(text),  # filesz
        0x700 + len(rodata) + len(text),  # memsz
        0x1000  # align (2MB would be 0x200000)
    )

    # PT_LOAD (seg2: data + bss)
    program_headers += struct.pack(endian + 'IIQQQQQQ',
        1,  # PT_LOAD
        0x6,  # R+W
        0x900,  # offset
        0x600900,  # vaddr
        0x600900,  # paddr
        0x180,  # filesz (data + comment + dynamic)
        0x200 + bss_size,  # memsz
        0x1000  # align
    )

    # PT_DYNAMIC
    program_headers += struct.pack(endian + 'IIQQQQQQ',
        2,  # PT_DYNAMIC
        0x6,  # R+W
        0xA80,  # offset
        0x600A80,  # vaddr
        0x600A80,  # paddr
        20*16,  # filesz
        20*16,  # memsz
        8  # align
    )

    # PT_NOTE
    program_headers += struct.pack(endian + 'IIQQQQQQ',
        4,  # PT_NOTE
        0x4,  # R
        0x240,  # offset
        0x400240,  # vaddr
        0x400240,  # paddr
        len(note),  # filesz
        len(note),  # memsz
        4  # align
    )

    # PT_GNU_EH_FRAME
    program_headers += struct.pack(endian + 'IIQQQQQQ',
        0x6474e550,  # PT_GNU_EH_FRAME
        0x4,  # R
        0x700,  # offset (use .rodata start)
        0x400700,  # vaddr
        0x400700,  # paddr
        0x40,  # filesz
        0x40,  # memsz
        4  # align
    )

    # PT_GNU_STACK
    program_headers += struct.pack(endian + 'IIQQQQQQ',
        0x6474e551,  # PT_GNU_STACK
        0x6,  # R+W
        0x0,  # offset
        0x0,  # vaddr
        0x0,  # paddr
        0x0,  # filesz
        0x0,  # memsz
        0x10  # align
    )

    # ============================================================
    # 构建 .dynsym (Elf64_Sym * 8)
    # ============================================================
    dynsym = b''

    def make_elf64_sym(st_name, st_info, st_other, st_shndx, st_value, st_size):
        return struct.pack(endian + 'IBBHQQ',
            st_name, st_info, st_other, st_shndx, st_value, st_size)

    # [0] NULL
    dynsym += make_elf64_sym(0, 0, 0, 0, 0, 0)

    # [1] printf (GLOBAL FUNC UNDEF)
    st_info = (1 << 4) | 2  # GLOBAL | FUNC
    dynsym += make_elf64_sym(dynstr_offsets[b'printf'], st_info, 0, 0, 0, 0)

    # [2] __libc_start_main
    dynsym += make_elf64_sym(dynstr_offsets[b'__libc_start_main'], st_info, 0, 0, 0, 0)

    # [3] main (GLOBAL FUNC in .text)
    dynsym += make_elf64_sym(0, st_info, 0, TEXT_IDX, 0x400810, 40)

    # [4] global_var (GLOBAL OBJECT in .data)
    st_info_obj = (1 << 4) | 1
    dynsym += make_elf64_sym(0, st_info_obj, 0, DATA_IDX, 0x600900, 4)

    # [5] msg (GLOBAL OBJECT in .rodata)
    dynsym += make_elf64_sym(0, st_info_obj, 0, RODATA_IDX, 0x400700, 18)

    # [6] add (LOCAL FUNC)
    st_info_local = (0 << 4) | 2
    dynsym += make_elf64_sym(0, st_info_local, 0, TEXT_IDX, 0x400840, 20)

    # [7] _start (GLOBAL FUNC)
    dynsym += make_elf64_sym(0, st_info, 0, TEXT_IDX, 0x400800, 16)

    # ============================================================
    # 构建 .rela.dyn
    # ============================================================
    rela_dyn = b''

    def make_elf64_rela(r_offset, r_info, r_addend):
        return struct.pack(endian + 'QQq', r_offset, r_info, r_addend)

    # R_X86_64_GLOB_DAT for printf
    r_info = (1 << 32) | 6  # sym 1, type R_X86_64_GLOB_DAT
    rela_dyn += make_elf64_rela(0x600900, r_info, 0)

    # R_X86_64_COPY for global_var reference
    r_info = (4 << 32) | 5  # sym 4, type R_X86_64_COPY
    rela_dyn += make_elf64_rela(0x600904, r_info, 0)

    # ============================================================
    # 构建 .rela.plt
    # ============================================================
    rela_plt = b''

    # R_X86_64_JUMP_SLOT for printf
    r_info = (1 << 32) | 7  # sym 1, type R_X86_64_JUMP_SLOT
    rela_plt += make_elf64_rela(0x600908, r_info, 0)

    # R_X86_64_JUMP_SLOT for __libc_start_main
    r_info = (2 << 32) | 7  # sym 2, type R_X86_64_JUMP_SLOT
    rela_plt += make_elf64_rela(0x600910, r_info, 0)

    # ============================================================
    # 构建 .symtab
    # ============================================================
    symtab = b''

    # [0] NULL
    symtab += make_elf64_sym(0, 0, 0, 0, 0, 0)

    # [1] FILE: hello.c (LOCAL)
    st_info_file = (0 << 4) | 4  # LOCAL FILE
    symtab += make_elf64_sym(strtab_offsets[b'hello.c'], st_info_file, 0, 0xfff1, 0, 0)

    # [2] SECTION: .text
    st_info_sec = (0 << 4) | 3  # LOCAL SECTION
    symtab += make_elf64_sym(0, st_info_sec, 0, TEXT_IDX, 0, 0)

    # [3] SECTION: .data
    symtab += make_elf64_sym(0, st_info_sec, 0, DATA_IDX, 0, 0)

    # [4] SECTION: .bss
    symtab += make_elf64_sym(0, st_info_sec, 0, BSS_IDX, 0, 0)

    # [5] LOCAL FUNC: add
    symtab += make_elf64_sym(strtab_offsets[b'add'], st_info_local, 0, TEXT_IDX, 0x400840, 20)

    # [6] GLOBAL OBJECT: global_var
    symtab += make_elf64_sym(strtab_offsets[b'global_var'], st_info_obj, 0, DATA_IDX, 0x600900, 4)

    # [7] GLOBAL OBJECT: msg
    symtab += make_elf64_sym(strtab_offsets[b'msg'], st_info_obj, 0, RODATA_IDX, 0x400700, 18)

    # [8] GLOBAL FUNC: main
    st_info_global_func = (1 << 4) | 2
    symtab += make_elf64_sym(strtab_offsets[b'main'], st_info_global_func, 0, TEXT_IDX, 0x400810, 40)

    # [9] GLOBAL FUNC: printf (UNDEF)
    symtab += make_elf64_sym(strtab_offsets[b'printf'], st_info_global_func, 0, 0, 0, 0)

    # [10] GLOBAL NOTYPE: __bss_start
    st_info_global_notype = (1 << 4) | 0
    symtab += make_elf64_sym(strtab_offsets[b'__bss_start'], st_info_global_notype, 0, BSS_IDX, 0x600910, 0)

    # [11] GLOBAL FUNC: _start
    symtab += make_elf64_sym(strtab_offsets[b'_start'], st_info_global_func, 0, TEXT_IDX, 0x400800, 16)

    # ============================================================
    # 构建 .dynamic
    # ============================================================
    dynamic = b''

    def make_dyn64(d_tag, d_val):
        return struct.pack(endian + 'QQ', d_tag, d_val)

    # DT_NEEDED libc.so.6
    dynamic += make_dyn64(1, dynstr_offsets[b'libc.so.6'])
    # DT_PLTRELSZ
    dynamic += make_dyn64(2, 2 * 24)
    # DT_PLTGOT
    dynamic += make_dyn64(3, 0x6008f8)
    # DT_HASH
    dynamic += make_dyn64(4, 0x400280)
    # DT_STRTAB
    dynamic += make_dyn64(5, 0x400400)
    # DT_SYMTAB
    dynamic += make_dyn64(6, 0x400300)
    # DT_STRSZ
    dynamic += make_dyn64(10, len(dynstr_data))
    # DT_SYMENT
    dynamic += make_dyn64(11, 24)
    # DT_RELA
    dynamic += make_dyn64(7, 0x400500)
    # DT_RELASZ
    dynamic += make_dyn64(8, 2 * 24)
    # DT_RELAENT
    dynamic += make_dyn64(9, 24)
    # DT_PLTREL
    dynamic += make_dyn64(20, 7)  # DT_RELA
    # DT_JMPREL
    dynamic += make_dyn64(23, 0x400600)
    # DT_VERSYM
    dynamic += make_dyn64(0x6ffffff0, 0x400480)
    # DT_VERNEE
    dynamic += make_dyn64(0x6ffffffe, 0x4004b0)
    # DT_VERNEENUM
    dynamic += make_dyn64(0x6fffffff, 2)
    # DT_NULL
    dynamic += make_dyn64(0, 0)
    # padding zeros
    dynamic += b'\x00' * 32

    # ============================================================
    # 构建 .comment
    # ============================================================
    comment = b'GCC: (GNU) 11.3.0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

    # ============================================================
    # 构建 .hash (placeholder)
    # ============================================================
    hash_section = bytes(64)

    # ============================================================
    # 构建 Section Headers
    # ============================================================
    section_headers = b''

    def make_elf64_shdr(sh_name, sh_type, sh_flags, sh_addr, sh_offset,
                        sh_size, sh_link, sh_info, sh_addralign, sh_entsize):
        return struct.pack(endian + 'IIQQQQIIQQ',
            sh_name, sh_type, sh_flags, sh_addr, sh_offset,
            sh_size, sh_link, sh_info, sh_addralign, sh_entsize)

    for (name, offset, size, stype, flags, addr, link, info, align, entsize) in sections_layout:
        name_bytes = name if isinstance(name, bytes) else name.encode()
        name_key = name_bytes.rstrip(b'\x00')
        nm = shstrtab_offsets[name_key] if name_key else 0
        section_headers += make_elf64_shdr(
            nm, stype, flags, addr, offset,
            size, link, info, align, entsize
        )

    # ============================================================
    # 组装完整的ELF文件
    # ============================================================
    blob = b''
    blob += elf_header.ljust(0x40, b'\x00')
    blob += program_headers.ljust(0x200 - 0x40, b'\x00')
    blob += interp.ljust(0x240 - 0x200, b'\x00')
    blob += note.ljust(0x280 - 0x240, b'\x00')
    blob += hash_section.ljust(0x300 - 0x280, b'\x00')
    blob += dynsym.ljust(0x400 - 0x300, b'\x00')
    blob += dynstr_data.ljust(0x500 - 0x400, b'\x00')
    blob += rela_dyn.ljust(0x600 - 0x500, b'\x00')
    blob += rela_plt.ljust(0x700 - 0x600, b'\x00')
    blob += rodata.ljust(0x800 - 0x700, b'\x00')
    blob += text.ljust(0x900 - 0x800, b'\x00')
    blob += data.ljust(0xA00 - 0x900, b'\x00')
    blob += comment.ljust(0xA80 - 0xA00, b'\x00')
    blob += dynamic.ljust(0xC00 - 0xA80, b'\x00')
    blob += symtab.ljust(0xE00 - 0xC00, b'\x00')
    blob += strtab_data.ljust(0x1000 - 0xE00, b'\x00')
    blob += shstrtab_data.ljust(0x1100 - 0x1000, b'\x00')
    blob += section_headers

    with open(output_path, 'wb') as f:
        f.write(blob)

    print(f"Created {output_path} ({len(blob)} bytes)")


def create_dynamic_elf64(output_path):
    """构造第二个ELF示例（包含更多动态链接、重定位和不同节区的共享库风格）。"""

    endian = '<'

    # .interp
    interp = b'/lib/ld-linux-aarch64.so.1\x00'

    # .rodata
    rodata = (
        b'Static linking test: %d + %d = %d\n\x00'
        b'Dynamic linking: libm loaded successfully\n\x00'
        b'Dynamic linking note: libm not loaded\n\x00'
        b'Dynamic string test: argc=%d\n\x00'
        b'math_operations_v2\x00'
        b'Copyright 2024 Dynamic Demo\x00'
        b'Author: ELF Team <elf@example.com>\n\x00'
        b'Environment: Linux x86_64 glibc 2.35\x00'
        b'Compile flags: -O2 -fPIC -Wall\x00'
    )

    # .text
    text = bytes([
        0x55, 0x48, 0x89, 0xe5, 0x48, 0x83, 0xec, 0x20,
        0x89, 0x7d, 0xec, 0x89, 0x75, 0xe8, 0x8b, 0x55, 0xec,
        0x8b, 0x45, 0xe8, 0x01, 0xd0, 0x48, 0x83, 0xc4, 0x20,
        0x5d, 0xc3, 0x55, 0x48, 0x89, 0xe5, 0x48, 0x83, 0xec, 0x40,
        0x89, 0x7d, 0xfc, 0x48, 0x89, 0x75, 0xf0, 0xc7, 0x45, 0xf8,
        0x0f, 0xc7, 0x45, 0xf4, 0x1b, 0x8b, 0x55, 0xf8, 0x8b, 0x45,
        0xf4, 0x89, 0xd6, 0x89, 0xc7, 0xe8, 0x00, 0x00, 0x00, 0x00,
        0x48, 0x8d, 0x3d, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8b, 0x55,
        0xf8, 0x8b, 0x4d, 0xf4, 0x48, 0x89, 0xc1, 0xb8, 0x00, 0x00,
        0x00, 0x00, 0xe8, 0x00, 0x00, 0x00, 0x00, 0x48, 0x83, 0xc4,
        0x40, 0x5d, 0xc3,
    ])

    # .data
    data = (
        struct.pack('<I', 0xc0ffee) +
        struct.pack('<I', 0xdeadbeef) +
        b'initialized_data_block_v2' + b'\x00' * 16
    )

    # .bss
    bss_size = 512

    # .fini_array 和 .init_array
    init_array = struct.pack('<Q', 0x401200)
    fini_array = struct.pack('<Q', 0x401240)

    # .note
    note = struct.pack('<III', 4, 20, 1) + b'GNU\x00' + struct.pack('<IIIII', 2, 35, 0, 0, 0)

    # 字符串表
    strtab_strings = [
        b'',
        b'dynamic_test.c\x00',
        b'static_add\x00',
        b'main\x00',
        b'dlopen\x00',
        b'dlerror\x00',
        b'dlclose\x00',
        b'malloc\x00',
        b'snprintf\x00',
        b'printf\x00',
        b'free\x00',
        b'handle\x00',
        b'dyn_add\x00',
        b'__bss_start__\x00',
        b'_edata\x00',
        b'_end\x00',
        b'__init_array_start\x00',
        b'__fini_array_start\x00',
        b'math_operate\x00',
        b'do_computation\x00',
        b'_GLOBAL_OFFSET_TABLE_\x00',
    ]
    dynstr_strings = [
        b'',
        b'dlopen\x00',
        b'dlerror\x00',
        b'dlclose\x00',
        b'malloc\x00',
        b'snprintf\x00',
        b'printf\x00',
        b'free\x00',
        b'libdl.so.2\x00',
        b'libc.so.6\x00',
        b'GLIBC_2.34\x00',
        b'GLIBC_2.2.5\x00',
    ]

    def build_strtab(strings):
        offsets = {}
        data = b''
        for s in strings:
            offsets[s.rstrip(b'\x00')] = len(data)
            data += s
        return data, offsets

    strtab_data, strtab_offsets = build_strtab(strtab_strings)
    dynstr_data, dynstr_offsets = build_strtab(dynstr_strings)

    # .shstrtab
    shstrtab_entries = [
        b'',
        b'.interp\x00',
        b'.note.gnu.build-id\x00',
        b'.hash\x00',
        b'.dynsym\x00',
        b'.dynstr\x00',
        b'.gnu.version\x00',
        b'.gnu.version_r\x00',
        b'.rela.dyn\x00',
        b'.rela.plt\x00',
        b'.init\x00',
        b'.plt\x00',
        b'.text\x00',
        b'.fini\x00',
        b'.rodata\x00',
        b'.eh_frame\x00',
        b'.init_array\x00',
        b'.fini_array\x00',
        b'.data.rel.ro\x00',
        b'.dynamic\x00',
        b'.got\x00',
        b'.data\x00',
        b'.bss\x00',
        b'.comment\x00',
        b'.symtab\x00',
        b'.strtab\x00',
        b'.shstrtab\x00',
    ]
    shstrtab_data, shstrtab_offsets = build_strtab(shstrtab_entries)

    def sh_name(s):
        key = s.encode() if isinstance(s, str) else s.rstrip(b'\x00')
        return shstrtab_offsets[key] if key else 0

    # --- 节区布局 ---
    sections_layout = [
        # name, offset, size, type, flags, addr, link, info, align, entsize
        (b'\x00', 0, 0, 0, 0, 0, 0, 0, 0, 0),  # 0
        (b'.interp\x00', 0x318, len(interp), 1, 0x2, 0x400318, 0, 0, 1, 0),  # 1
        (b'.note.gnu.build-id\x00', 0x338, len(note), 7, 0x2, 0x400338, 0, 0, 4, 0),  # 2
        (b'.hash\x00', 0x380, 128, 5, 0x2, 0x400380, 4, 0, 8, 4),  # 3
        (b'.dynsym\x00', 0x400, 48*10, 11, 0x2, 0x400400, 5, 1, 8, 24),  # 4
        (b'.dynstr\x00', 0x700, len(dynstr_data), 3, 0x2, 0x400700, 0, 0, 1, 0),  # 5
        (b'.gnu.version\x00', 0x800, 10*2, 0x6fffffff, 0x2, 0x400800, 4, 0, 2, 2),  # 6
        (b'.gnu.version_r\x00', 0x820, 64, 0x6ffffffe, 0x2, 0x400820, 5, 2, 8, 0),  # 7
        (b'.rela.dyn\x00', 0x900, 3*24, 4, 0x2, 0x400900, 4, 0, 8, 24),  # 8
        (b'.rela.plt\x00', 0xA00, 4*24, 4, 0x42, 0x400A00, 4, 12, 8, 24),  # 9
        (b'.init\x00', 0xB00, 28, 1, 0x6, 0x400B00, 0, 0, 4, 0),  # 10
        (b'.plt\x00', 0xB20, 80, 1, 0x6, 0x400B20, 0, 0, 16, 0),  # 11
        (b'.text\x00', 0xC00, len(text), 1, 0x6, 0x400C00, 0, 0, 16, 0),  # 12
        (b'.fini\x00', 0xD00, 13, 1, 0x6, 0x400D00, 0, 0, 4, 0),  # 13
        (b'.rodata\x00', 0xE00, len(rodata), 1, 0x2, 0x400E00, 0, 0, 8, 0),  # 14
        (b'.eh_frame\x00', 0x1000, 128, 1, 0x2, 0x401000, 0, 0, 8, 0),  # 15
        (b'.init_array\x00', 0x1200, 8, 14, 0x3, 0x601200, 0, 0, 8, 0),  # 16
        (b'.fini_array\x00', 0x1208, 8, 15, 0x3, 0x601208, 0, 0, 8, 0),  # 17
        (b'.data.rel.ro\x00', 0x1210, 128, 1, 0x3, 0x601210, 0, 0, 16, 0),  # 18
        (b'.dynamic\x00', 0x1300, 24*16, 6, 0x3, 0x601300, 5, 0, 8, 16),  # 19
        (b'.got\x00', 0x1480, 128, 1, 0x3, 0x601480, 0, 0, 8, 0),  # 20
        (b'.data\x00', 0x1500, len(data), 1, 0x3, 0x601500, 0, 0, 16, 0),  # 21
        (b'.bss\x00', 0x1500 + len(data), bss_size, 8, 0x3, 0x601600, 0, 0, 32, 0),  # 22
        (b'.comment\x00', 0x1600, 40, 1, 0x30, 0, 0, 0, 1, 0),  # 23
        (b'.symtab\x00', 0x1700, 24*21, 2, 0, 0, 25, 20, 8, 24),  # 24
        (b'.strtab\x00', 0x1A00, len(strtab_data), 3, 0, 0, 0, 0, 1, 0),  # 25
        (b'.shstrtab\x00', 0x1C00, len(shstrtab_data), 3, 0, 0, 0, 0, 1, 0),  # 26
    ]

    SHSTRTAB_IDX = 26
    SYMTAB_IDX = 24
    STRTAB_IDX = 25
    DYNSYM_IDX = 4
    DYNSTR_IDX = 5
    TEXT_IDX = 12
    DATA_IDX = 21
    RODATA_IDX = 14
    BSS_IDX = 22
    section_header_offset = 0x1E00

    # --- ELF Header ---
    e_ident = bytes([
        0x7f, 0x45, 0x4c, 0x46,
        0x02, 0x01, 0x01, 0x03,  # Class=64, LSB, V1, Linux OSABI
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ])
    e_type = 3  # ET_DYN (shared object / PIE executable)
    e_machine = 183  # EM_AARCH64
    e_version = 1
    e_entry = 0x400C00
    e_phoff = 0x40
    e_shoff = section_header_offset
    e_flags = 0
    e_ehsize = 64
    e_phentsize = 56
    e_phnum = 9
    e_shentsize = 64
    e_shnum = len(sections_layout)
    e_shstrndx = SHSTRTAB_IDX

    elf_header = e_ident + struct.pack(endian + 'HHIQQQIHHHHHH',
        e_type, e_machine, e_version, e_entry, e_phoff, e_shoff,
        e_flags, e_ehsize, e_phentsize, e_phnum, e_shentsize,
        e_shnum, e_shstrndx)

    # --- Program Headers ---
    def mkph(p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align):
        return struct.pack(endian + 'IIQQQQQQ',
            p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align)

    phs = b''
    phs += mkph(6, 5, 0x40, 0x400040, 0x400040, 9*56, 9*56, 8)
    phs += mkph(3, 4, 0x318, 0x400318, 0x400318, len(interp), len(interp), 1)
    phs += mkph(4, 4, 0x338, 0x400338, 0x400338, len(note), len(note), 4)
    phs += mkph(1, 5, 0x0, 0x400000, 0x400000, 0x1000 + 128, 0x1000 + 128, 0x1000)
    phs += mkph(1, 6, 0x1200, 0x601200, 0x601200, 0x400, 0x400 + bss_size, 0x1000)
    phs += mkph(2, 6, 0x1300, 0x601300, 0x601300, 24*16, 24*16, 8)
    phs += mkph(0x6474e550, 4, 0x1000, 0x401000, 0x401000, 128, 128, 4)
    phs += mkph(0x6474e551, 6, 0, 0, 0, 0, 0, 0x10)
    phs += mkph(0x6474e552, 4, 0x1200, 0x601200, 0x601200, 128, 128, 1)

    # --- Dynsym ---
    def mksym(n, info, other, shndx, val, sz):
        return struct.pack(endian + 'IBBHQQ', n, info, other, shndx, val, sz)

    st_global_func = (1 << 4) | 2
    st_global_obj = (1 << 4) | 1
    st_local_func = (0 << 4) | 2

    dynsym = b''
    dynsym += mksym(0, 0, 0, 0, 0, 0)  # NULL
    dynsym += mksym(dynstr_offsets[b'dlopen'], st_global_func, 0, 0, 0, 0)
    dynsym += mksym(dynstr_offsets[b'dlerror'], st_global_func, 0, 0, 0, 0)
    dynsym += mksym(dynstr_offsets[b'dlclose'], st_global_func, 0, 0, 0, 0)
    dynsym += mksym(dynstr_offsets[b'malloc'], st_global_func, 0, 0, 0, 0)
    dynsym += mksym(dynstr_offsets[b'snprintf'], st_global_func, 0, 0, 0, 0)
    dynsym += mksym(dynstr_offsets[b'printf'], st_global_func, 0, 0, 0, 0)
    dynsym += mksym(dynstr_offsets[b'free'], st_global_func, 0, 0, 0, 0)
    dynsym += mksym(strtab_offsets[b'static_add'], st_local_func, 0, TEXT_IDX, 0x400C00, 20)
    dynsym += mksym(strtab_offsets[b'main'], st_global_func, 0, TEXT_IDX, 0x400C20, 70)

    # --- Relocations ---
    def mkrela(off, info, add):
        return struct.pack(endian + 'QQq', off, info, add)

    rela_dyn = b''
    rela_dyn += mkrela(0x601500, (1 << 32) | 1025, 0)  # R_AARCH64_GLOB_DAT dlopen
    rela_dyn += mkrela(0x601508, (2 << 32) | 1025, 0)  # dlerror
    rela_dyn += mkrela(0x601510, (8 << 32) | 1027, 0)  # R_AARCH64_RELATIVE static_add

    rela_plt = b''
    rela_plt += mkrela(0x601480, (1 << 32) | 1026, 0)  # JUMP_SLOT dlopen
    rela_plt += mkrela(0x601488, (4 << 32) | 1026, 0)  # malloc
    rela_plt += mkrela(0x601490, (5 << 32) | 1026, 0)  # snprintf
    rela_plt += mkrela(0x601498, (6 << 32) | 1026, 0)  # printf

    # --- Symtab ---
    symtab = b''
    symtab += mksym(0, 0, 0, 0, 0, 0)
    symtab += mksym(strtab_offsets[b'dynamic_test.c'], (0 << 4) | 4, 0, 0xfff1, 0, 0)  # FILE
    symtab += mksym(0, (0 << 4) | 3, 0, TEXT_IDX, 0, 0)  # SECTION .text
    symtab += mksym(0, (0 << 4) | 3, 0, RODATA_IDX, 0, 0)  # SECTION .rodata
    symtab += mksym(0, (0 << 4) | 3, 0, DATA_IDX, 0, 0)  # SECTION .data
    symtab += mksym(0, (0 << 4) | 3, 0, BSS_IDX, 0, 0)  # SECTION .bss
    symtab += mksym(strtab_offsets[b'static_add'], st_local_func, 0, TEXT_IDX, 0x400C00, 20)
    symtab += mksym(strtab_offsets[b'math_operate'], st_local_func, 0, TEXT_IDX, 0x400C14, 12)
    symtab += mksym(strtab_offsets[b'main'], st_global_func, 0, TEXT_IDX, 0x400C20, 70)
    symtab += mksym(strtab_offsets[b'dlopen'], st_global_func, 0, 0, 0, 0)
    symtab += mksym(strtab_offsets[b'dlerror'], st_global_func, 0, 0, 0, 0)
    symtab += mksym(strtab_offsets[b'dlclose'], st_global_func, 0, 0, 0, 0)
    symtab += mksym(strtab_offsets[b'malloc'], st_global_func, 0, 0, 0, 0)
    symtab += mksym(strtab_offsets[b'snprintf'], st_global_func, 0, 0, 0, 0)
    symtab += mksym(strtab_offsets[b'printf'], st_global_func, 0, 0, 0, 0)
    symtab += mksym(strtab_offsets[b'free'], st_global_func, 0, 0, 0, 0)
    symtab += mksym(strtab_offsets[b'__bss_start__'], (1 << 4), 0, BSS_IDX, 0x601600, 0)
    symtab += mksym(strtab_offsets[b'_edata'], (1 << 4), 0, BSS_IDX, 0x601600, 0)
    symtab += mksym(strtab_offsets[b'_end'], (1 << 4), 0, BSS_IDX, 0x601600 + bss_size, 0)
    symtab += mksym(strtab_offsets[b'do_computation'], st_global_func, 0, TEXT_IDX, 0x400C32, 50)
    symtab += mksym(strtab_offsets[b'_GLOBAL_OFFSET_TABLE_'], (1 << 4), 0, 0xfff1, 0, 0)

    # --- .dynamic ---
    def mkdyn(tag, val):
        return struct.pack(endian + 'QQ', tag, val)

    dynamic = b''
    dynamic += mkdyn(1, dynstr_offsets[b'libdl.so.2'])
    dynamic += mkdyn(1, dynstr_offsets[b'libc.so.6'])
    dynamic += mkdyn(2, 4 * 24)
    dynamic += mkdyn(3, 0x601470)
    dynamic += mkdyn(4, 0x400380)
    dynamic += mkdyn(5, 0x400700)
    dynamic += mkdyn(6, 0x400400)
    dynamic += mkdyn(10, len(dynstr_data))
    dynamic += mkdyn(11, 24)
    dynamic += mkdyn(7, 0x400900)
    dynamic += mkdyn(8, 3 * 24)
    dynamic += mkdyn(9, 24)
    dynamic += mkdyn(20, 7)
    dynamic += mkdyn(23, 0x400A00)
    dynamic += mkdyn(15, 0)
    dynamic += mkdyn(0, 0)
    dynamic += b'\x00' * (24*16 - 16*16)

    # --- .gnu.version ---
    gnu_version = b''
    for _ in range(10):
        gnu_version += struct.pack(endian + 'H', 0)

    # --- .gnu.version_r ---
    gnu_version_r = struct.pack(endian + 'HHI', 1, 2, 0x10)
    gnu_version_r += struct.pack(endian + 'HHI', dynstr_offsets[b'GLIBC_2.34'], 0x8001, 0)
    gnu_version_r += b'\x00' * 32

    # --- .comment ---
    comment = b'GCC: (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0\x00\x00\x00'

    # --- .hash ---
    hash_section = bytes(128)

    # --- .init / .plt / .fini / .eh_frame placeholders ---
    init_sec = bytes(28)
    plt_sec = bytes(80)
    fini_sec = bytes(13)
    eh_frame = bytes(128)
    data_rel_ro = bytes(128)
    got_sec = bytes(128)

    # --- Section Headers ---
    def mkshdr(nm, stype, flags, addr, off, sz, link, info, align, entsize):
        return struct.pack(endian + 'IIQQQQIIQQ',
            nm, stype, flags, addr, off, sz, link, info, align, entsize)

    shdrs = b''
    for (name, offset, size, stype, flags, addr, link, info, align, entsize) in sections_layout:
        nm = sh_name(name)
        shdrs += mkshdr(nm, stype, flags, addr, offset, size, link, info, align, entsize)

    # --- 组装 ---
    blob = b''
    blob += elf_header.ljust(0x40, b'\x00')
    blob += phs.ljust(0x318 - 0x40, b'\x00')
    blob += interp.ljust(0x338 - 0x318, b'\x00')
    blob += note.ljust(0x380 - 0x338, b'\x00')
    blob += hash_section.ljust(0x400 - 0x380, b'\x00')
    blob += dynsym.ljust(0x700 - 0x400, b'\x00')
    blob += dynstr_data.ljust(0x800 - 0x700, b'\x00')
    blob += gnu_version.ljust(0x820 - 0x800, b'\x00')
    blob += gnu_version_r.ljust(0x900 - 0x820, b'\x00')
    blob += rela_dyn.ljust(0xA00 - 0x900, b'\x00')
    blob += rela_plt.ljust(0xB00 - 0xA00, b'\x00')
    blob += init_sec.ljust(0xB20 - 0xB00, b'\x00')
    blob += plt_sec.ljust(0xC00 - 0xB20, b'\x00')
    blob += text.ljust(0xD00 - 0xC00, b'\x00')
    blob += fini_sec.ljust(0xE00 - 0xD00, b'\x00')
    blob += rodata.ljust(0x1000 - 0xE00, b'\x00')
    blob += eh_frame.ljust(0x1200 - 0x1000, b'\x00')
    blob += init_array.ljust(0x1208 - 0x1200, b'\x00')
    blob += fini_array.ljust(0x1210 - 0x1208, b'\x00')
    blob += data_rel_ro.ljust(0x1300 - 0x1210, b'\x00')
    blob += dynamic.ljust(0x1480 - 0x1300, b'\x00')
    blob += got_sec.ljust(0x1500 - 0x1480, b'\x00')
    blob += data.ljust(0x1600 - 0x1500, b'\x00')
    blob += comment.ljust(0x1700 - 0x1600, b'\x00')
    blob += symtab.ljust(0x1A00 - 0x1700, b'\x00')
    blob += strtab_data.ljust(0x1C00 - 0x1A00, b'\x00')
    blob += shstrtab_data.ljust(0x1E00 - 0x1C00, b'\x00')
    blob += shdrs

    with open(output_path, 'wb') as f:
        f.write(blob)

    print(f"Created {output_path} ({len(blob)} bytes)")


if __name__ == '__main__':
    base = os.path.dirname(os.path.abspath(__file__))
    create_hello_elf64(os.path.join(base, 'hello_elf'))
    create_dynamic_elf64(os.path.join(base, 'dyn_elf'))
    print("\nExample ELF files generated successfully.")
