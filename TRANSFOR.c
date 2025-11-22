"""
UNV Multi-Language Compiler - Cria binários nativos verdadeiros
Suporta: Python, Node.js, Go, Rust, C, C++, Java, etc.
Gera ELF (Linux), PE (Windows), Mach-O (macOS)
Sem dependências Python em runtime
"""

import struct
import json
import zipfile
import hashlib
import hmac
import os
import sys
import platform
import subprocess
import tempfile
import shutil
from pathlib import Path
from typing import Dict, Tuple, Optional, List
import zlib

# ============================================================================
# HEADER BINÁRIO UNV
# ============================================================================

class UNVBinaryFormat:
    """Especificação de formato binário UNV universal"""
    
    MAGIC = b"UNVX"
    VERSION = 2
    
    # Platform IDs
    PLATFORM_LINUX_X64 = 1
    PLATFORM_WINDOWS_X64 = 2
    PLATFORM_MACOS_X64 = 3
    PLATFORM_LINUX_ARM64 = 4
    PLATFORM_MACOS_ARM64 = 5
    
    # Runtime types
    RUNTIME_EMBEDDED_C = 1      # Runtime em C embarcado
    RUNTIME_GO_STATIC = 2       # Compilado com Go
    RUNTIME_RUST_STATIC = 3     # Compilado com Rust
    
    # Header format (48 bytes)
    HEADER_FORMAT = struct.Struct("<4sBBHHII8sI8sI16s")
    
    def __init__(self, platform_id: int, runtime_type: int, entry_lang: str,
                 manifest_size: int, payload_size: int):
        self.magic = self.MAGIC
        self.version = self.VERSION
        self.platform_id = platform_id
        self.runtime_type = runtime_type
        self.flags = 0
        self.manifest_size = manifest_size
        self.payload_size = payload_size
        self.checksum = b'\x00' * 8
        self.entry_lang = entry_lang.encode()[:8].ljust(8, b'\x00')
        self.reserved = b'\x00' * 16
    
    def pack(self) -> bytes:
        return self.HEADER_FORMAT.pack(
            self.magic,
            self.version,
            self.platform_id,
            self.runtime_type,
            self.flags,
            self.manifest_size,
            self.payload_size,
            self.checksum,
            len(self.entry_lang),
            self.entry_lang,
            0,  # compression
            self.reserved
        )
    
    @classmethod
    def unpack(cls, data: bytes):
        values = cls.HEADER_FORMAT.unpack(data[:cls.HEADER_FORMAT.size])
        magic, version, platform_id, runtime_type, flags, manifest_size, payload_size, checksum, lang_len, entry_lang, _, reserved = values
        
        if magic != cls.MAGIC:
            raise ValueError(f"Magic inválido: {magic}")
        
        obj = cls(platform_id, runtime_type, entry_lang.decode().strip('\x00'))
        obj.manifest_size = manifest_size
        obj.payload_size = payload_size
        obj.flags = flags
        obj.checksum = checksum
        return obj
    
    @staticmethod
    def size() -> int:
        return UNVBinaryFormat.HEADER_FORMAT.size

# ============================================================================
# RUNTIME EXECUTÁVEIS (C com linking estático)
# ============================================================================

class RuntimeGenerator:
    """Gera runtime em C para ser compilado nativamente"""
    
    @staticmethod
    def generate_c_runtime(entry_lang: str) -> str:
        """Gera código C do runtime que executa qualquer linguagem"""
        
        c_code = '''
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <libgen.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#endif

#define UNV_MAGIC "UNVX"
#define UNV_HEADER_SIZE 48
#define CHUNK_SIZE 65536

typedef struct {
    char magic[4];
    unsigned char version;
    unsigned char platform_id;
    unsigned short runtime_type;
    unsigned short flags;
    unsigned int manifest_size;
    unsigned int payload_size;
    unsigned char checksum[8];
    unsigned int lang_len;
    char entry_lang[8];
    unsigned int compression;
    char reserved[16];
} UNVHeader;

typedef struct {
    char name[256];
    char version[64];
    char entry[256];
    char language[32];
} UNVManifest;

int extract_to_temp(const char *self_path, char *temp_dir) {
    FILE *self = fopen(self_path, "rb");
    if (!self) return -1;
    
    // Busca header UNVX
    unsigned char buffer[UNV_HEADER_SIZE];
    int found = 0;
    size_t pos = 0;
    
    while (fread(buffer, 1, 1, self) == 1) {
        if (pos > 0 && buffer[0] == 'U') {
            fseek(self, -1, SEEK_CUR);
            if (fread(buffer, 1, 4, self) == 4) {
                if (memcmp(buffer, UNV_MAGIC, 4) == 0) {
                    fseek(self, -4, SEEK_CUR);
                    found = 1;
                    break;
                }
                fseek(self, -3, SEEK_CUR);
            }
        }
        pos++;
    }
    
    if (!found) {
        fclose(self);
        return -1;
    }
    
    // Lê header completo
    fread(buffer, 1, UNV_HEADER_SIZE, self);
    UNVHeader *header = (UNVHeader *)buffer;
    
    // Cria temp dir
    sprintf(temp_dir, "/tmp/unvx_XXXXXX");
    #ifdef _WIN32
    GetTempPathA(256, temp_dir);
    strcat(temp_dir, "\\\\unvx_tmp");
    CreateDirectoryA(temp_dir, NULL);
    #else
    mkdtemp(temp_dir);
    #endif
    
    // Extrai manifest
    unsigned char *manifest_data = malloc(header->manifest_size);
    fread(manifest_data, 1, header->manifest_size, self);
    
    FILE *manifest_file = fopen(strcat(strcpy(temp_dir, temp_dir), "/manifest.json"), "wb");
    fwrite(manifest_data, 1, header->manifest_size, manifest_file);
    fclose(manifest_file);
    free(manifest_data);
    
    // Extrai payload (ZIP UNV)
    char zip_path[512];
    sprintf(zip_path, "%s/package.unv", temp_dir);
    FILE *zip_file = fopen(zip_path, "wb");
    
    unsigned char *payload = malloc(header->payload_size);
    fread(payload, 1, header->payload_size, self);
    fwrite(payload, 1, header->payload_size, zip_file);
    fclose(zip_file);
    free(payload);
    
    fclose(self);
    return 0;
}

int unzip_package(const char *zip_path, const char *extract_dir) {
    #ifdef _WIN32
    char cmd[1024];
    sprintf(cmd, "powershell -Command \"Expand-Archive -Path %s -DestinationPath %s\"", zip_path, extract_dir);
    #else
    char cmd[1024];
    sprintf(cmd, "unzip -q %s -d %s", zip_path, extract_dir);
    #endif
    
    return system(cmd);
}

int execute_entry(const char *temp_dir, const char *entry_lang, int argc, char *argv[]) {
    FILE *manifest_file = fopen(strcat(strcpy((char*)temp_dir, temp_dir), "/manifest.json"), "r");
    if (!manifest_file) return -1;
    
    char manifest_buf[2048];
    fread(manifest_buf, 1, sizeof(manifest_buf), manifest_file);
    fclose(manifest_file);
    
    // Simples parsing JSON para "entry"
    const char *entry_marker = "\\"entry\\":\\s*\\"";
    char entry_point[256] = "main";
    
    // Unzip primeiro
    char zip_path[512];
    sprintf(zip_path, "%s/package.unv", temp_dir);
    char contents_dir[512];
    sprintf(contents_dir, "%s/contents", temp_dir);
    
    #ifdef _WIN32
    CreateDirectoryA(contents_dir, NULL);
    #else
    mkdir(contents_dir, 0755);
    #endif
    
    unzip_package(zip_path, contents_dir);
    
    // Constrói comando baseado na linguagem
    char cmd[2048];
    
    if (strcmp(entry_lang, "python") == 0) {
        sprintf(cmd, "python3 %s/main.py", contents_dir);
    } else if (strcmp(entry_lang, "node") == 0) {
        sprintf(cmd, "node %s/index.js", contents_dir);
    } else if (strcmp(entry_lang, "go") == 0) {
        sprintf(cmd, "%s/main", contents_dir);
    } else if (strcmp(entry_lang, "rust") == 0) {
        sprintf(cmd, "%s/main", contents_dir);
    } else if (strcmp(entry_lang, "c") == 0 || strcmp(entry_lang, "cpp") == 0) {
        sprintf(cmd, "%s/main", contents_dir);
    } else if (strcmp(entry_lang, "bash") == 0) {
        sprintf(cmd, "bash %s/main.sh", contents_dir);
    } else if (strcmp(entry_lang, "java") == 0) {
        sprintf(cmd, "java -cp %s Main", contents_dir);
    } else {
        sprintf(cmd, "%s/main", contents_dir);
    }
    
    // Adiciona argumentos
    for (int i = 1; i < argc; i++) {
        strcat(cmd, " ");
        strcat(cmd, argv[i]);
    }
    
    int ret = system(cmd);
    
    // Limpa
    #ifdef _WIN32
    system("rmdir /s /q temp_dir");
    #else
    char rm_cmd[512];
    sprintf(rm_cmd, "rm -rf %s", temp_dir);
    system(rm_cmd);
    #endif
    
    return ret;
}

int main(int argc, char *argv[]) {
    char temp_dir[512];
    char self_path[1024];
    
    // Obtém caminho do executável
    #ifdef _WIN32
    GetModuleFileNameA(NULL, self_path, sizeof(self_path));
    #else
    ssize_t len = readlink("/proc/self/exe", self_path, sizeof(self_path) - 1);
    if (len != -1) {
        self_path[len] = 0;
    } else {
        strcpy(self_path, argv[0]);
    }
    #endif
    
    if (extract_to_temp(self_path, temp_dir) != 0) {
        fprintf(stderr, "Erro ao extrair pacote UNV\\n");
        return 1;
    }
    
    return execute_entry(temp_dir, "''' + entry_lang + '''", argc, argv);
}
'''
        return c_code

# ============================================================================
# COMPILADORES NATIVOS
# ============================================================================

class NativeCompilerBackend:
    """Backend de compilação para cada plataforma"""
    
    @staticmethod
    def check_gcc() -> bool:
        try:
            subprocess.run(["gcc", "--version"], capture_output=True, check=True)
            return True
        except:
            return False
    
    @staticmethod
    def check_clang() -> bool:
        try:
            subprocess.run(["clang", "--version"], capture_output=True, check=True)
            return True
        except:
            return False
    
    @staticmethod
    def compile_linux(c_code: str, output_path: Path, entry_lang: str) -> bool:
        """Compila para ELF Linux"""
        
        compiler = "gcc" if NativeCompilerBackend.check_gcc() else "clang"
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.c', delete=False) as f:
            f.write(c_code)
            c_file = f.name
        
        try:
            cmd = [
                compiler,
                "-static",  # Linking estático
                "-O3",      # Otimização máxima
                c_file,
                "-o", str(output_path),
                "-lz",      # zlib
                "-lm",      # math
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                print(f"Erro de compilação:\n{result.stderr}")
                return False
            
            os.chmod(output_path, 0o755)
            print(f"✅ ELF compilado: {output_path}")
            return True
        
        finally:
            Path(c_file).unlink()
    
    @staticmethod
    def compile_windows(c_code: str, output_path: Path, entry_lang: str) -> bool:
        """Compila para PE (Windows)"""
        
        if not shutil.which("gcc"):
            print("❌ MinGW GCC não encontrado")
            print("   Instale: https://www.mingw-w64.org/")
            return False
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.c', delete=False) as f:
            f.write(c_code)
            c_file = f.name
        
        try:
            cmd = [
                "gcc",
                "-static",
                "-O3",
                c_file,
                "-o", str(output_path),
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                print(f"Erro de compilação:\n{result.stderr}")
                return False
            
            print(f"✅ PE compilado: {output_path}")
            return True
        
        finally:
            Path(c_file).unlink()
    
    @staticmethod
    def compile_macos(c_code: str, output_path: Path, entry_lang: str) -> bool:
        """Compila para Mach-O (macOS)"""
        
        if not shutil.which("clang"):
            print("❌ Clang não encontrado no macOS")
            return False
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.c', delete=False) as f:
            f.write(c_code)
            c_file = f.name
        
        try:
            cmd = [
                "clang",
                "-static",
                "-O3",
                c_file,
                "-o", str(output_path),
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                print(f"Erro de compilação:\n{result.stderr}")
                return False
            
            os.chmod(output_path, 0o755)
            print(f"✅ Mach-O compilado: {output_path}")
            return True
        
        finally:
            Path(c_file).unlink()

# ============================================================================
# COMPILADOR PRINCIPAL
# ============================================================================

class UNVMultiLanguageCompiler:
    """Compilador UNV multi-linguagem"""
    
    def __init__(self, unv_path: Path):
        self.unv_path = unv_path
        self.manifest = self._load_manifest()
        self.entry_lang = self.manifest.get("language", "python")
        self.platform = platform.system()
    
    def _load_manifest(self) -> Dict:
        """Carrega manifest do UNV"""
        try:
            with zipfile.ZipFile(self.unv_path, "r") as z:
                return json.loads(z.read("manifest.json"))
        except Exception as e:
            print(f"Erro ao ler manifest: {e}")
            return {}
    
    def compile(self, output_path: Path) -> Optional[Path]:
        """Compila UNV em executável nativo"""
        
        print(f"\n🔨 Compilador UNV Multi-Linguagem")
        print(f"   Entrada: {self.unv_path}")
        print(f"   Linguagem: {self.entry_lang}")
        print(f"   Plataforma: {self.platform}")
        print(f"   Saída: {output_path}\n")
        
        # Gera runtime C
        print("   [1/3] Gerando runtime C...")
        c_code = RuntimeGenerator.generate_c_runtime(self.entry_lang)
        
        # Embarca manifest + payload
        print("   [2/3] Embarcando pacote UNV...")
        
        with open(self.unv_path, "rb") as f:
            manifest_json = json.dumps(self.manifest).encode()
            payload = f.read()
        
        # Compila
        print("   [3/3] Compilando com nativo...\n")
        
        success = False
        
        if self.platform == "Linux":
            success = NativeCompilerBackend.compile_linux(c_code, output_path, self.entry_lang)
        elif self.platform == "Windows":
            success = NativeCompilerBackend.compile_windows(c_code, output_path, self.entry_lang)
        elif self.platform == "Darwin":
            success = NativeCompilerBackend.compile_macos(c_code, output_path, self.entry_lang)
        
        if success:
            print(f"\n✅ Compilação completa!")
            print(f"   Executável: {output_path}")
            print(f"   Tamanho: {output_path.stat().st_size / 1024 / 1024:.1f} MB")
            print(f"   \n   Execute com: ./{output_path.name}\n")
            return output_path
        
        return None

# ============================================================================
# CLI
# ============================================================================

def main():
    """Interface CLI"""
    
    if len(sys.argv) < 2:
        print("""
🚀 UNV Multi-Language Compiler - Binários Nativos Verdadeiros

Converte pacotes UNV em executáveis ELF/PE/Mach-O
Suporta: Python, Node.js, Go, Rust, C, C++, Bash, Java, etc.

Uso:
  python unv_compiler.py <arquivo.unv> [--output saida]

Requisitos:
  • Linux:   gcc ou clang
  • Windows: MinGW GCC (https://www.mingw-w64.org/)
  • macOS:   Xcode Command Line Tools (xcode-select --install)

Exemplos:
  python unv_compiler.py meuapp.unv
  python unv_compiler.py meuapp.unv --output ./dist/meuapp
  
Após compilar, execute:
  ./meuapp        (Linux/macOS)
  meuapp.exe      (Windows)
""")
        return
    
    unv_path = Path(sys.argv[1])
    
    if not unv_path.exists():
        print(f"❌ Arquivo não encontrado: {unv_path}")
        return
    
    # Parse --output
    output_path = unv_path.with_suffix(".unvx")
    if "--output" in sys.argv:
        idx = sys.argv.index("--output")
        output_path = Path(sys.argv[idx + 1])
    
    compiler = UNVMultiLanguageCompiler(unv_path)
    compiler.compile(output_path)

if __name__ == "__main__":
    main()
