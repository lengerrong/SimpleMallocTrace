// Copyright (c) 2006, Google Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
//     * Redistributions in binary form must reproduce the above
// copyright notice, this list of conditions and the following disclaimer
// in the documentation and/or other materials provided with the
// distribution.
//     * Neither the name of Google Inc. nor the names of its
// contributors may be used to endorse or promote products derived from
// this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
// Author: Satoru Takabayashi
// Stack-footprint reduction work done by Raksit Ashok
//
// Implementation note:
//
// We don't use heaps but only use stacks.  We want to reduce the
// stack consumption so that the symbolizer can run on small stacks.
//
// Here are some numbers collected with GCC 4.1.0 on x86:
// - sizeof(Elf32_Sym)  = 16
// - sizeof(Elf32_Shdr) = 40
// - sizeof(Elf64_Sym)  = 24
// - sizeof(Elf64_Shdr) = 64
//
// This implementation is intended to be async-signal-safe but uses
// some functions which are not guaranteed to be so, such as memchr()
// and memmove().  We assume they are async-signal-safe.
//
// Additional header can be specified by the GLOG_BUILD_CONFIG_INCLUDE
// macro to add platform specific defines (e.g. OS_OPENBSD).

#include "Symbolize.h"

#include "Demangle.h"

#include <dlfcn.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <limits>
#include <limits.h>
#include <link.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

namespace WTF {

#define NO_INTR(fn)   do {} while ((fn) < 0 && errno == EINTR)

static int AssertFail() {
  abort();
  return 0;  // Should not reach.
}

#define SAFE_ASSERT(expr) ((expr) ? 0 : AssertFail())

char *itoa_r(intptr_t i, char *buf, size_t sz, int base, size_t padding) {
  // Make sure we can write at least one NUL byte.
  size_t n = 1;
  if (n > sz)
    return NULL;

  if (base < 2 || base > 16) {
    buf[0] = '\000';
    return NULL;
  }

  char *start = buf;

  uintptr_t j = i;

  // Handle negative numbers (only for base 10).
  if (i < 0 && base == 10) {
    j = -i;

    // Make sure we can write the '-' character.
    if (++n > sz) {
      buf[0] = '\000';
      return NULL;
    }
    *start++ = '-';
  }

  // Loop until we have converted the entire number. Output at least one
  // character (i.e. '0').
  char *ptr = start;
  do {
    // Make sure there is still enough space left in our output buffer.
    if (++n > sz) {
      buf[0] = '\000';
      return NULL;
    }

    // Output the next digit.
    *ptr++ = "0123456789abcdef"[j % base];
    j /= base;

    if (padding > 0)
      padding--;
  } while (j > 0 || padding > 0);

  // Terminate the output with a NUL character.
  *ptr = '\000';

  // Conversion to ASCII actually resulted in the digits being in reverse
  // order. We can't easily generate them in forward order, as we can't tell
  // the number of characters needed until we are done converting.
  // So, now, we reverse the string (except for the possible "-" sign).
  while (--ptr > start) {
    char ch = *ptr;
    *ptr = *start;
    *start++ = ch;
  }
  return buf;
}

void SafeAppendString(const char* source, char* dest, int dest_size) {
  int dest_string_length = strlen(dest);
  SAFE_ASSERT(dest_string_length < dest_size);
  dest += dest_string_length;
  dest_size -= dest_string_length;
  strncpy(dest, source, dest_size);
  // Making sure |dest| is always null-terminated.
  dest[dest_size - 1] = '\0';
}

void SafeAppendHexNumber(uint64_t value, char* dest, int dest_size) {
  // 64-bit numbers in hex can have up to 16 digits.
  char buf[17] = {'\0'};
  SafeAppendString(itoa_r(value, buf, sizeof(buf), 16, 0), dest, dest_size);
}

struct FileDescriptor {
  const int fd_;
  explicit FileDescriptor(int fd) : fd_(fd) {}
  ~FileDescriptor() {
    if (fd_ >= 0) {
      NO_INTR(close(fd_));
    }
  }
  int get() { return fd_; }

 private:
  explicit FileDescriptor(const FileDescriptor&);
  void operator=(const FileDescriptor&);
};

// Read up to "count" bytes from file descriptor "fd" into the buffer
// starting at "buf" while handling short reads and EINTR.  On
// success, return the number of bytes read.  Otherwise, return -1.
static ssize_t ReadPersistent(const int fd, void *buf, const size_t count) {
  SAFE_ASSERT(fd >= 0);
  SAFE_ASSERT(count <= std::numeric_limits<ssize_t>::max());
  char *buf0 = reinterpret_cast<char *>(buf);
  ssize_t num_bytes = 0;
  while (num_bytes < count) {
    ssize_t len;
    NO_INTR(len = read(fd, buf0 + num_bytes, count - num_bytes));
    if (len < 0) {  // There was an error other than EINTR.
      return -1;
    }
    if (len == 0) {  // Reached EOF.
      break;
    }
    num_bytes += len;
  }
  SAFE_ASSERT(num_bytes <= count);
  return num_bytes;
}

// Read up to "count" bytes from "offset" in the file pointed by file
// descriptor "fd" into the buffer starting at "buf".  On success,
// return the number of bytes read.  Otherwise, return -1.
static ssize_t ReadFromOffset(const int fd, void *buf,
                              const size_t count, const off_t offset) {
  off_t off = lseek(fd, offset, SEEK_SET);
  if (off == (off_t)-1) {
    return -1;
  }
  return ReadPersistent(fd, buf, count);
}

// Try reading exactly "count" bytes from "offset" bytes in a file
// pointed by "fd" into the buffer starting at "buf" while handling
// short reads and EINTR.  On success, return true. Otherwise, return
// false.
static bool ReadFromOffsetExact(const int fd, void *buf,
                                const size_t count, const off_t offset) {
  ssize_t len = ReadFromOffset(fd, buf, count, offset);
  return len == count;
}

// Returns elf_header.e_type if the file pointed by fd is an ELF binary.
static int FileGetElfType(const int fd) {
  ElfW(Ehdr) elf_header;
  if (!ReadFromOffsetExact(fd, &elf_header, sizeof(elf_header), 0)) {
    return -1;
  }
  if (memcmp(elf_header.e_ident, ELFMAG, SELFMAG) != 0) {
    return -1;
  }
  return elf_header.e_type;
}

class LineReader {
 public:
  explicit LineReader(int fd, char *buf, int buf_len) : fd_(fd),
    buf_(buf), buf_len_(buf_len), bol_(buf), eol_(buf), eod_(buf) {
  }

  // Read '\n'-terminated line from file.  On success, modify "bol"
  // and "eol", then return true.  Otherwise, return false.
  //
  // Note: if the last line doesn't end with '\n', the line will be
  // dropped.  It's an intentional behavior to make the code simple.
  bool ReadLine(const char **bol, const char **eol) {
    if (BufferIsEmpty()) {  // First time.
      const ssize_t num_bytes = ReadPersistent(fd_, buf_, buf_len_);
      if (num_bytes <= 0) {  // EOF or error.
        return false;
      }
      eod_ = buf_ + num_bytes;
      bol_ = buf_;
    } else {
      bol_ = eol_ + 1;  // Advance to the next line in the buffer.
      SAFE_ASSERT(bol_ <= eod_);  // "bol_" can point to "eod_".
      if (!HasCompleteLine()) {
        const int incomplete_line_length = eod_ - bol_;
        // Move the trailing incomplete line to the beginning.
        memmove(buf_, bol_, incomplete_line_length);
        // Read text from file and append it.
        char * const append_pos = buf_ + incomplete_line_length;
        const int capacity_left = buf_len_ - incomplete_line_length;
        const ssize_t num_bytes = ReadPersistent(fd_, append_pos,
                                                 capacity_left);
        if (num_bytes <= 0) {  // EOF or error.
          return false;
        }
        eod_ = append_pos + num_bytes;
        bol_ = buf_;
      }
    }
    eol_ = FindLineFeed();
    if (eol_ == NULL) {  // '\n' not found.  Malformed line.
      return false;
    }
    *eol_ = '\0';  // Replace '\n' with '\0'.

    *bol = bol_;
    *eol = eol_;
    return true;
  }

  // Beginning of line.
  const char *bol() {
    return bol_;
  }

  // End of line.
  const char *eol() {
    return eol_;
  }

 private:
  explicit LineReader(const LineReader&);
  void operator=(const LineReader&);

  char *FindLineFeed() {
    return reinterpret_cast<char *>(memchr(bol_, '\n', eod_ - bol_));
  }

  bool BufferIsEmpty() {
    return buf_ == eod_;
  }

  bool HasCompleteLine() {
    return !BufferIsEmpty() && FindLineFeed() != NULL;
  }

  const int fd_;
  char * const buf_;
  const int buf_len_;
  char *bol_;
  char *eol_;
  const char *eod_;  // End of data in "buf_".
};

static char *GetHex(const char *start, const char *end, uint64_t *hex) {
  *hex = 0;
  const char *p;
  for (p = start; p < end; ++p) {
    int ch = *p;
    if ((ch >= '0' && ch <= '9') ||
        (ch >= 'A' && ch <= 'F') || (ch >= 'a' && ch <= 'f')) {
      *hex = (*hex << 4) | (ch < 'A' ? ch - '0' : (ch & 0xF) + 9);
    } else {  // Encountered the first non-hex character.
      break;
    }
  }
  SAFE_ASSERT(p <= end);
  return const_cast<char *>(p);
}

static int
OpenObjectFileContainingPcAndGetStartAddress(uint64_t pc,
                                             uint64_t &start_address,
                                             uint64_t &base_address,
                                             char *out_file_name,
                                             int out_file_name_size) {
  int object_fd;

  // Open /proc/self/maps.
  int maps_fd;
  NO_INTR(maps_fd = open("/proc/self/maps", O_RDONLY));
  FileDescriptor wrapped_maps_fd(maps_fd);
  if (wrapped_maps_fd.get() < 0) {
    return -1;
  }

  // Iterate over maps and look for the map containing the pc.  Then
  // look into the symbol tables inside.
  char buf[1024];  // Big enough for line of sane /proc/self/maps
  int num_maps = 0;
  LineReader reader(wrapped_maps_fd.get(), buf, sizeof(buf));
  while (true) {
    num_maps++;
    const char *cursor;
    const char *eol;
    if (!reader.ReadLine(&cursor, &eol)) {  // EOF or malformed line.
      return -1;
    }

    // Start parsing line in /proc/self/maps.  Here is an example:
    //
    // 08048000-0804c000 r-xp 00000000 08:01 2142121    /bin/cat
    //
    // We want start address (08048000), end address (0804c000), flags
    // (r-xp) and file name (/bin/cat).

    // Read start address.
    cursor = GetHex(cursor, eol, &start_address);
    if (cursor == eol || *cursor != '-') {
      return -1;  // Malformed line.
    }
    ++cursor;  // Skip '-'.

    // Read end address.
    uint64_t end_address;
    cursor = GetHex(cursor, eol, &end_address);
    if (cursor == eol || *cursor != ' ') {
      return -1;  // Malformed line.
    }
    ++cursor;  // Skip ' '.

    // Check start and end addresses.
    if (!(start_address <= pc && pc < end_address)) {
      continue;  // We skip this map.  PC isn't in this map.
    }

    // Read flags.  Skip flags until we encounter a space or eol.
    const char * const flags_start = cursor;
    while (cursor < eol && *cursor != ' ') {
      ++cursor;
    }
    // We expect at least four letters for flags (ex. "r-xp").
    if (cursor == eol || cursor < flags_start + 4) {
      return -1;  // Malformed line.
    }

    // Check flags.  We are only interested in "r-x" maps.
    if (memcmp(flags_start, "r-x", 3) != 0) {  // Not a "r-x" map.
      continue;  // We skip this map.
    }
    ++cursor;  // Skip ' '.

    // Read file offset.
    uint64_t file_offset;
    cursor = GetHex(cursor, eol, &file_offset);
    if (cursor == eol || *cursor != ' ') {
      return -1;  // Malformed line.
    }
    ++cursor;  // Skip ' '.

    // Don't subtract 'start_address' from the first entry:
    // * If a binary is compiled w/o -pie, then the first entry in
    //   process maps is likely the binary itself (all dynamic libs
    //   are mapped higher in address space). For such a binary,
    //   instruction offset in binary coincides with the actual
    //   instruction address in virtual memory (as code section
    //   is mapped to a fixed memory range).
    // * If a binary is compiled with -pie, all the modules are
    //   mapped high at address space (in particular, higher than
    //   shadow memory of the tool), so the module can't be the
    //   first entry.
    base_address = ((num_maps == 1) ? 0U : start_address) - file_offset;

    // Skip to file name.  "cursor" now points to dev.  We need to
    // skip at least two spaces for dev and inode.
    int num_spaces = 0;
    while (cursor < eol) {
      if (*cursor == ' ') {
        ++num_spaces;
      } else if (num_spaces >= 2) {
        // The first non-space character after skipping two spaces
        // is the beginning of the file name.
        break;
      }
      ++cursor;
    }
    if (cursor == eol) {
      return -1;  // Malformed line.
    }

    // Finally, "cursor" now points to file name of our interest.
    NO_INTR(object_fd = open(cursor, O_RDONLY));
    if (object_fd < 0) {
      // Failed to open object file.  Copy the object file name to
      // |out_file_name|.
      strncpy(out_file_name, cursor, out_file_name_size);
      // Making sure |out_file_name| is always null-terminated.
      out_file_name[out_file_name_size - 1] = '\0';
      return -1;
    }
    return object_fd;
  }
}

static bool
GetSectionHeaderByType(const int fd, ElfW(Half) sh_num, const off_t sh_offset,
                       ElfW(Word) type, ElfW(Shdr) *out) {
  // Read at most 16 section headers at a time to save read calls.
  ElfW(Shdr) buf[16];
  for (int i = 0; i < sh_num;) {
    const ssize_t num_bytes_left = (sh_num - i) * sizeof(buf[0]);
    const ssize_t num_bytes_to_read =
        (sizeof(buf) > num_bytes_left) ? num_bytes_left : sizeof(buf);
    const ssize_t len = ReadFromOffset(fd, buf, num_bytes_to_read,
                                       sh_offset + i * sizeof(buf[0]));
    SAFE_ASSERT(len % sizeof(buf[0]) == 0);
    const ssize_t num_headers_in_buf = len / sizeof(buf[0]);
    SAFE_ASSERT(num_headers_in_buf <= sizeof(buf) / sizeof(buf[0]));
    for (int j = 0; j < num_headers_in_buf; ++j) {
      if (buf[j].sh_type == type) {
        *out = buf[j];
        return true;
      }
    }
    i += num_headers_in_buf;
  }
  return false;
}

static bool
FindSymbol(uint64_t pc, const int fd, char *out, int out_size,
           uint64_t symbol_offset, const ElfW(Shdr) *strtab,
           const ElfW(Shdr) *symtab) {
  if (symtab == NULL) {
    return false;
  }
  const int num_symbols = symtab->sh_size / symtab->sh_entsize;
  for (int i = 0; i < num_symbols;) {
    off_t offset = symtab->sh_offset + i * symtab->sh_entsize;

    // If we are reading Elf64_Sym's, we want to limit this array to
    // 32 elements (to keep stack consumption low), otherwise we can
    // have a 64 element Elf32_Sym array.
#if __WORDSIZE == 64
#define NUM_SYMBOLS 32
#else
#define NUM_SYMBOLS 64
#endif

    // Read at most NUM_SYMBOLS symbols at once to save read() calls.
    ElfW(Sym) buf[NUM_SYMBOLS];
    const ssize_t len = ReadFromOffset(fd, &buf, sizeof(buf), offset);
    SAFE_ASSERT(len % sizeof(buf[0]) == 0);
    const ssize_t num_symbols_in_buf = len / sizeof(buf[0]);
    SAFE_ASSERT(num_symbols_in_buf <= sizeof(buf)/sizeof(buf[0]));
    for (int j = 0; j < num_symbols_in_buf; ++j) {
      const ElfW(Sym)& symbol = buf[j];
      uint64_t start_address = symbol.st_value;
      start_address += symbol_offset;
      uint64_t end_address = start_address + symbol.st_size;
      if (symbol.st_value != 0 &&  // Skip null value symbols.
          symbol.st_shndx != 0 &&  // Skip undefined symbols.
          start_address <= pc && pc < end_address) {
        ssize_t len1 = ReadFromOffset(fd, out, out_size,
                                      strtab->sh_offset + symbol.st_name);
        if (len1 <= 0 || memchr(out, '\0', out_size) == NULL) {
          return false;
        }
        return true;  // Obtained the symbol name.
      }
    }
    i += num_symbols_in_buf;
  }
  return false;
}

static bool GetSymbolFromObjectFile(const int fd, uint64_t pc,
                                    char *out, int out_size,
                                    uint64_t map_start_address) {
  // Read the ELF header.
  ElfW(Ehdr) elf_header;
  if (!ReadFromOffsetExact(fd, &elf_header, sizeof(elf_header), 0)) {
    return false;
  }

  uint64_t symbol_offset = 0;
  if (elf_header.e_type == ET_DYN) {  // DSO needs offset adjustment.
    symbol_offset = map_start_address;
  }

  ElfW(Shdr) symtab, strtab;

  // Consult a regular symbol table first.
  if (GetSectionHeaderByType(fd, elf_header.e_shnum, elf_header.e_shoff,
                             SHT_SYMTAB, &symtab)) {
    if (!ReadFromOffsetExact(fd, &strtab, sizeof(strtab), elf_header.e_shoff +
                             symtab.sh_link * sizeof(symtab))) {
      return false;
    }
    if (FindSymbol(pc, fd, out, out_size, symbol_offset,
                   &strtab, &symtab)) {
      return true;  // Found the symbol in a regular symbol table.
    }
  }

  // If the symbol is not found, then consult a dynamic symbol table.
  if (GetSectionHeaderByType(fd, elf_header.e_shnum, elf_header.e_shoff,
                             SHT_DYNSYM, &symtab)) {
    if (!ReadFromOffsetExact(fd, &strtab, sizeof(strtab), elf_header.e_shoff +
                             symtab.sh_link * sizeof(symtab))) {
      return false;
    }
    if (FindSymbol(pc, fd, out, out_size, symbol_offset,
                   &strtab, &symtab)) {
      return true;  // Found the symbol in a dynamic symbol table.
    }
  }

  return false;
}

static void DemangleInplace(char *out, int out_size) {
  char demangled[256];  // Big enough for sane demangled symbols.
  if (Demangle(out, demangled, sizeof(demangled))) {
    // Demangling succeeded. Copy to out if the space allows.
    size_t len = strlen(demangled);
    if (len + 1 <= (size_t)out_size) {  // +1 for '\0'.
      SAFE_ASSERT(len < sizeof(demangled));
      memmove(out, demangled, len + 1);
    }
  }
}

static bool SymbolizeAndDemangle(void *pc, char *out,
                                 int out_size) {
  uint64_t pc0 = reinterpret_cast<uintptr_t>(pc);
  uint64_t start_address = 0;
  uint64_t base_address = 0;
  int object_fd = -1;

  if (out_size < 1) {
    return false;
  }
  out[0] = '\0';
  SafeAppendString("(", out, out_size);

  object_fd = OpenObjectFileContainingPcAndGetStartAddress(pc0, start_address,
                                                           base_address,
                                                           out + 1,
                                                           out_size - 1);

  // Check whether a file name was returned.
  if (object_fd < 0) {
    if (out[1]) {
      // The object file containing PC was determined successfully however the
      // object file was not opened successfully.  This is still considered
      // success because the object file name and offset are known and tools
      // like asan_symbolize.py can be used for the symbolization.
      out[out_size - 1] = '\0';  // Making sure |out| is always null-terminated.
      SafeAppendString("+0x", out, out_size);
      SafeAppendHexNumber(pc0 - base_address, out, out_size);
      SafeAppendString(")", out, out_size);
      return true;
    }
    // Failed to determine the object file containing PC.  Bail out.
    return false;
  }

  FileDescriptor wrapped_object_fd(object_fd);
  int elf_type = FileGetElfType(wrapped_object_fd.get());
  if (elf_type == -1) {
    return false;
  }

  if (!GetSymbolFromObjectFile(wrapped_object_fd.get(), pc0,
                               out, out_size, start_address)) {
    return false;
  }

  // Symbolization succeeded.  Now we try to demangle the symbol.
  DemangleInplace(out, out_size);
  return true;
}

bool Symbolize(void *pc, char *out, int out_size) {
    SAFE_ASSERT(out_size >= 0);
    return SymbolizeAndDemangle(pc, out, out_size);
}

}
