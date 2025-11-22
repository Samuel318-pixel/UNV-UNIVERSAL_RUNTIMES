"""
UNV Runtime - Sistema de Instalação e Integração
Registra .unv como executáveis nativos no sistema
Autoruns e extensão de arquivo integrada
"""

import sys
import json
import zipfile
import tempfile
import hashlib
import shutil
import subprocess
import os
import platform

if platform.system() != "Windows":
    import resource
import signal
import logging
import platform
import winreg
from pathlib import Path
from datetime import datetime
from typing import Dict, Optional, Tuple
from dataclasses import dataclass, asdict

try:
    from PyQt6.QtWidgets import (
        QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
        QPushButton, QLabel, QTextEdit, QFileDialog, QMessageBox,
        QProgressBar, QTabWidget, QListWidget, QListWidgetItem,
        QCheckBox, QComboBox
    )
    from PyQt6.QtCore import Qt, pyqtSignal, QThread
    from PyQt6.QtGui import QFont, QIcon
    HAS_GUI = True
except ImportError:
    HAS_GUI = False

# Configuração
INSTALL_DIR = Path.home() / ".unv" / "runtime"
CACHE_DIR = Path.home() / ".unv" / "cache"
LOGS_DIR = Path.home() / ".unv" / "logs"
CONFIG_DIR = Path.home() / ".unv" / "config"
SHORTCUTS_DIR = Path.home() / ".unv" / "shortcuts"

MAX_MEMORY_MB = 512
MAX_CPU_TIME = 300
CACHE_VERSION = 1

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@dataclass
class UNVMetadata:
    """Metadata para pacote UNV"""
    name: str
    version: str
    entry: str
    hash: str
    timestamp: str
    permissions: Dict[str, bool]
    description: str = ""
    icon: Optional[str] = None

class SystemIntegration:
    """Integração com o sistema operacional"""
    
    @staticmethod
    def get_os_type() -> str:
        """Detecta SO"""
        return platform.system()
    
    @staticmethod
    def register_file_association_windows(runtime_exe: Path):
        """Registra .unv no Windows"""
        try:
            key_path = r"Software\Classes\.unv"
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_path) as key:
                winreg.SetValueEx(key, "", 0, winreg.REG_SZ, "UNVPackage")
            
            # Associação com ícone e ação de abertura
            prog_id = r"Software\Classes\UNVPackage"
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, prog_id) as key:
                winreg.SetValueEx(key, "", 0, winreg.REG_SZ, "UNV Package")
            
            # Shell -> Open -> Command
            cmd_path = prog_id + r"\shell\open\command"
            cmd = f'"{runtime_exe}" "%1" %*'
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, cmd_path) as key:
                winreg.SetValueEx(key, "", 0, winreg.REG_SZ, cmd)
            
            # Context menu
            ctx_path = prog_id + r"\shell\run_as_admin\command"
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, ctx_path) as key:
                winreg.SetValueEx(key, "", 0, winreg.REG_SZ, cmd)
            
            logger.info("✓ Windows file association registered")
            return True
        except Exception as e:
            logger.error(f"✗ Windows registration failed: {e}")
            return False
    
    @staticmethod
    def register_file_association_linux():
        """Registra .unv no Linux"""
        try:
            # Cria .desktop file
            desktop_content = f"""[Desktop Entry]
Version=1.0
Type=Application
Name=UNV Runtime
Exec={INSTALL_DIR / 'unv-runtime'} %F
MimeType=application/x-unv;
Categories=Development;
Terminal=false
Icon=application-x-unv
"""
            
            apps_dir = Path.home() / ".local" / "share" / "applications"
            apps_dir.mkdir(parents=True, exist_ok=True)
            
            desktop_file = apps_dir / "unv-runtime.desktop"
            desktop_file.write_text(desktop_content)
            os.chmod(desktop_file, 0o755)
            
            # MIME type
            mime_dir = Path.home() / ".local" / "share" / "mime" / "packages"
            mime_dir.mkdir(parents=True, exist_ok=True)
            
            mime_content = """<?xml version="1.0" encoding="UTF-8"?>
<mime-info xmlns="http://www.freedesktop.org/standards/shared-mime-info">
  <mime-type type="application/x-unv">
    <comment>UNV Package</comment>
    <glob pattern="*.unv"/>
    <icon name="application-x-unv"/>
  </mime-type>
</mime-info>
"""
            mime_file = mime_dir / "unv-runtime.xml"
            mime_file.write_text(mime_content)
            
            # Atualiza MIME database
            subprocess.run(["update-mime-database", str(Path.home() / ".local" / "share" / "mime")],
                          capture_output=True)
            
            logger.info("✓ Linux file association registered")
            return True
        except Exception as e:
            logger.error(f"✗ Linux registration failed: {e}")
            return False
    
    @staticmethod
    def register_file_association_macos():
        """Registra .unv no macOS"""
        try:
            # Cria Info.plist para UTType
            plist_content = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>UTTypeIdentifier</key>
    <string>com.unv.package</string>
    <key>UTTypeDescription</key>
    <string>UNV Package</string>
    <key>UTTypeConformsTo</key>
    <array>
        <string>com.apple.package</string>
    </array>
    <key>UTTypeTagSpecification</key>
    <dict>
        <key>com.apple.filename-extension</key>
        <array>
            <string>unv</string>
        </array>
    </dict>
</dict>
</plist>
"""
            config_dir = CONFIG_DIR / "macos"
            config_dir.mkdir(parents=True, exist_ok=True)
            (config_dir / "Info.plist").write_text(plist_content)
            
            logger.info("✓ macOS file association prepared")
            return True
        except Exception as e:
            logger.error(f"✗ macOS registration failed: {e}")
            return False

class SignatureManager:
    """Gerencia assinaturas criptográficas"""
    
    @staticmethod
    def calculate_hash(file_path: Path) -> str:
        """Calcula SHA256"""
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    
    @staticmethod
    def create_metadata(unv_path: Path, manifest: Dict) -> UNVMetadata:
        """Cria metadata com assinatura"""
        return UNVMetadata(
            name=manifest.get("name", "Unknown"),
            version=manifest.get("version", "0.0.0"),
            entry=manifest.get("entry", "main.py"),
            hash=SignatureManager.calculate_hash(unv_path),
            timestamp=datetime.now().isoformat(),
            permissions=manifest.get("permissions", {}),
            description=manifest.get("description", ""),
            icon=manifest.get("icon")
        )

class CacheManager:
    """Gerencia cache com verificação de integridade"""
    
    def __init__(self):
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        LOGS_DIR.mkdir(parents=True, exist_ok=True)
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        SHORTCUTS_DIR.mkdir(parents=True, exist_ok=True)
    
    def get_cache_key(self, unv_hash: str) -> Path:
        """Obtém diretório de cache"""
        return CACHE_DIR / unv_hash
    
    def is_cached(self, unv_hash: str, metadata_hash: str) -> bool:
        """Verifica se está em cache"""
        cache_dir = self.get_cache_key(unv_hash)
        meta_file = cache_dir / ".metadata"
        
        if not cache_dir.exists() or not meta_file.exists():
            return False
        
        try:
            stored_meta = json.loads(meta_file.read_text())
            return stored_meta.get("hash") == metadata_hash
        except Exception:
            return False
    
    def save_cache(self, unv_hash: str, extract_dir: Path, metadata: UNVMetadata):
        """Salva cache"""
        cache_dir = self.get_cache_key(unv_hash)
        if cache_dir.exists():
            shutil.rmtree(cache_dir)
        
        shutil.copytree(extract_dir, cache_dir)
        meta_file = cache_dir / ".metadata"
        meta_file.write_text(json.dumps(asdict(metadata)))
        logger.info(f"✓ Cache: {unv_hash}")
    
    def load_cache(self, unv_hash: str) -> Optional[Path]:
        """Carrega cache"""
        cache_dir = self.get_cache_key(unv_hash)
        if cache_dir.exists():
            return cache_dir
        return None

class Sandbox:
    """Executa app em ambiente sandboxed"""
    
    @staticmethod
    def set_limits():
        """Define limites de recursos"""
        if sys.platform != "win32":
            try:
                resource.setrlimit(resource.RLIMIT_AS,
                                 (MAX_MEMORY_MB * 1024 * 1024,
                                  MAX_MEMORY_MB * 1024 * 1024))
                resource.setrlimit(resource.RLIMIT_CPU,
                                 (MAX_CPU_TIME, MAX_CPU_TIME))
            except Exception as e:
                logger.warning(f"Limites não aplicáveis: {e}")
    
    @staticmethod
    def create_env(allowed_network: bool = False) -> Dict[str, str]:
        """Cria ambiente restrito"""
        env = os.environ.copy()
        
        for key in ["SSH_AUTH_SOCK", "AWS_SECRET_ACCESS_KEY"]:
            env.pop(key, None)
        
        if not allowed_network:
            env["http_proxy"] = "127.0.0.1:1"
            env["https_proxy"] = "127.0.0.1:1"
        
        return env
    
    @staticmethod
    def run(cmd: list, work_dir: Path, permissions: Dict,
            timeout: int = MAX_CPU_TIME) -> Tuple[int, str, str]:
        """Executa comando"""
        try:
            env = Sandbox.create_env(allowed_network=permissions.get("network", False))
            
            proc = subprocess.Popen(
                cmd,
                cwd=work_dir,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                preexec_fn=Sandbox.set_limits if sys.platform != "win32" else None
            )
            
            try:
                stdout, stderr = proc.communicate(timeout=timeout)
                return proc.returncode, stdout, stderr
            except subprocess.TimeoutExpired:
                proc.kill()
                return -1, "", f"Timeout após {timeout}s"
        except Exception as e:
            return -1, "", str(e)

class UNVRuntime:
    """Engine principal do UNV Runtime"""
    
    def __init__(self):
        self.cache_manager = CacheManager()
        self.sig_manager = SignatureManager()
    
    def load_manifest(self, unv_path: Path) -> Dict:
        """Carrega manifest.json"""
        with zipfile.ZipFile(unv_path, "r") as z:
            if "manifest.json" not in z.namelist():
                raise ValueError("manifest.json não encontrado")
            return json.loads(z.read("manifest.json").decode("utf-8"))
    
    def extract_unv(self, unv_path: Path, use_cache: bool = True) -> Tuple[Path, UNVMetadata]:
        """Extrai UNV com cache opcional"""
        manifest = self.load_manifest(unv_path)
        unv_hash = self.sig_manager.calculate_hash(unv_path)
        metadata = self.sig_manager.create_metadata(unv_path, manifest)
        
        if use_cache:
            cached = self.cache_manager.load_cache(unv_hash)
            if cached:
                return cached, metadata
        
        tmp = Path(tempfile.mkdtemp(prefix="unv_"))
        try:
            with zipfile.ZipFile(unv_path, "r") as z:
                z.extractall(tmp)
            
            if not (tmp / manifest.get("entry", "main.py")).exists():
                raise ValueError(f"Entry point não encontrado: {manifest.get('entry')}")
            
            if use_cache:
                self.cache_manager.save_cache(unv_hash, tmp, metadata)
            
            return tmp, metadata
        except Exception as e:
            shutil.rmtree(tmp, ignore_errors=True)
            raise
    
    def run(self, unv_path: Path, args: list = None) -> Dict:
        """Executa UNV"""
        args = args or []
        results = {
            "success": False,
            "returncode": -1,
            "stdout": "",
            "stderr": "",
            "timestamp": datetime.now().isoformat()
        }
        
        try:
            extract_dir, metadata = self.extract_unv(unv_path)
            
            cmd = [sys.executable, str(extract_dir / metadata.entry)] + args
            rc, stdout, stderr = Sandbox.run(cmd, extract_dir, metadata.permissions)
            
            results["success"] = rc == 0
            results["returncode"] = rc
            results["stdout"] = stdout
            results["stderr"] = stderr
            
            logger.info(f"✓ {metadata.name} v{metadata.version} executado: rc={rc}")
        except Exception as e:
            results["stderr"] = str(e)
            logger.error(f"✗ Execução falhou: {e}")
        
        return results

class SystemInstaller:
    """Instalador do sistema"""
    
    def __init__(self):
        self.runtime = UNVRuntime()
    
    def create_runtime_executable(self) -> Path:
        """Cria executável do runtime"""
        INSTALL_DIR.mkdir(parents=True, exist_ok=True)
        
        runtime_code = '''#!/usr/bin/env python3
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from unv_runtime_core import UNVRuntime

if __name__ == "__main__":
    runtime = UNVRuntime()
    if len(sys.argv) < 2:
        print("Uso: unv-runtime arquivo.unv [argumentos...]")
        sys.exit(1)
    results = runtime.run(Path(sys.argv[1]), sys.argv[2:])
    print(results["stdout"])
    if results["stderr"]:
        print("ERRO:", results["stderr"], file=sys.stderr)
    sys.exit(results["returncode"])
'''
        
        exe_path = INSTALL_DIR / "unv-runtime"
        exe_path.write_text(runtime_code)
        os.chmod(exe_path, 0o755)
        
        logger.info(f"✓ Executável criado: {exe_path}")
        return exe_path
    
    def add_to_path(self) -> bool:
        """Adiciona ao PATH do sistema"""
        os_type = SystemIntegration.get_os_type()
        
        if os_type == "Windows":
            try:
                import winreg
                path_var = Path.home() / ".unv" / "runtime"
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                   r"Environment", 0, winreg.KEY_WRITE) as key:
                    current_path = winreg.QueryValueEx(key, "Path")[0]
                    if str(path_var) not in current_path:
                        new_path = current_path + f";{path_var}"
                        winreg.SetValueEx(key, "Path", 0, winreg.REG_EXPAND_SZ, new_path)
                logger.info("✓ PATH atualizado (Windows)")
                return True
            except Exception as e:
                logger.error(f"✗ Não foi possível atualizar PATH: {e}")
                return False
        else:
            # Linux/macOS
            shell_rc = Path.home() / ".bashrc"
            if not shell_rc.exists():
                shell_rc = Path.home() / ".zshrc"
            
            path_line = f'\nexport PATH="$HOME/.unv/runtime:$PATH"\n'
            content = shell_rc.read_text() if shell_rc.exists() else ""
            
            if path_line.strip() not in content:
                with open(shell_rc, "a") as f:
                    f.write(path_line)
            
            logger.info("✓ PATH atualizado (Unix)")
            return True
    
    def install(self) -> bool:
        """Executa instalação completa"""
        print("\n🔧 Instalando UNV Runtime no sistema...\n")
        
        try:
            # 1. Cria executável
            exe = self.create_runtime_executable()
            
            # 2. Adiciona ao PATH
            self.add_to_path()
            
            # 3. Registra extensão de arquivo
            os_type = SystemIntegration.get_os_type()
            if os_type == "Windows":
                SystemIntegration.register_file_association_windows(exe)
            elif os_type == "Linux":
                SystemIntegration.register_file_association_linux()
            elif os_type == "Darwin":
                SystemIntegration.register_file_association_macos()
            
            print("\n✅ Instalação completa!\n")
            print("Agora você pode:")
            print("  • Executar: unv-runtime seu_app.unv")
            print("  • Clicar duplo em .unv no gerenciador de arquivos")
            print(f"  • Usar a GUI: unv-launcher")
            print(f"\nPasta de instalação: {INSTALL_DIR}")
            
            return True
        except Exception as e:
            print(f"\n❌ Erro na instalação: {e}\n")
            logger.error(f"Instalação falhou: {e}")
            return False

class ExecutorThread(QThread):
    """Thread de execução"""
    finished = pyqtSignal(dict)
    
    def __init__(self, runtime: UNVRuntime, unv_path: Path, args: list):
        super().__init__()
        self.runtime = runtime
        self.unv_path = unv_path
        self.args = args
    
    def run(self):
        results = self.runtime.run(self.unv_path, self.args)
        self.finished.emit(results)

class UNVLauncher(QMainWindow):
    """GUI moderna"""
    
    def __init__(self):
        super().__init__()
        self.runtime = UNVRuntime()
        self.current_unv = None
        self.init_ui()
        self.setAcceptDrops(True)
    
    def init_ui(self):
        """Inicializa UI"""
        self.setWindowTitle("🚀 UNV Launcher")
        self.setGeometry(100, 100, 900, 700)
        
        central = QWidget()
        layout = QVBoxLayout()
        
        title = QLabel("UNV Runtime Launcher")
        title_font = QFont()
        title_font.setPointSize(14)
        title_font.setBold(True)
        title.setFont(title_font)
        layout.addWidget(title)
        
        tabs = QTabWidget()
        
        # Aba Executar
        exec_widget = QWidget()
        exec_layout = QVBoxLayout()
        
        btn_layout = QHBoxLayout()
        self.btn_open = QPushButton("📂 Abrir .unv")
        self.btn_open.clicked.connect(self.open_file)
        self.btn_run = QPushButton("▶ Executar")
        self.btn_run.clicked.connect(self.run_unv)
        self.btn_run.setEnabled(False)
        self.btn_install = QPushButton("⚙️ Instalar Sistema")
        self.btn_install.clicked.connect(self.install_system)
        
        btn_layout.addWidget(self.btn_open)
        btn_layout.addWidget(self.btn_run)
        btn_layout.addWidget(self.btn_install)
        exec_layout.addLayout(btn_layout)
        
        self.file_label = QLabel("Nenhum pacote carregado")
        exec_layout.addWidget(self.file_label)
        
        self.progress = QProgressBar()
        self.progress.setVisible(False)
        exec_layout.addWidget(self.progress)
        
        self.output = QTextEdit()
        self.output.setReadOnly(True)
        self.output.setFont(QFont("Courier", 9))
        exec_layout.addWidget(QLabel("Saída:"))
        exec_layout.addWidget(self.output)
        
        exec_widget.setLayout(exec_layout)
        tabs.addTab(exec_widget, "Executar")
        
        # Aba Cache
        cache_widget = QWidget()
        cache_layout = QVBoxLayout()
        
        self.cache_list = QListWidget()
        cache_layout.addWidget(QLabel("Pacotes em Cache:"))
        cache_layout.addWidget(self.cache_list)
        
        cache_btn_layout = QHBoxLayout()
        self.btn_refresh_cache = QPushButton("🔄 Atualizar")
        self.btn_refresh_cache.clicked.connect(self.refresh_cache)
        self.btn_clear_cache = QPushButton("🗑️ Limpar Cache")
        self.btn_clear_cache.clicked.connect(self.clear_cache)
        cache_btn_layout.addWidget(self.btn_refresh_cache)
        cache_btn_layout.addWidget(self.btn_clear_cache)
        cache_layout.addLayout(cache_btn_layout)
        
        cache_widget.setLayout(cache_layout)
        tabs.addTab(cache_widget, "Gerenciador de Cache")
        
        layout.addWidget(tabs)
        central.setLayout(layout)
        self.setCentralWidget(central)
        
        self.refresh_cache()
    
    def open_file(self):
        """Abre diálogo"""
        path, _ = QFileDialog.getOpenFileName(
            self, "Abrir Pacote UNV", "", "Pacotes UNV (*.unv)"
        )
        if path:
            self.load_unv(Path(path))
    
    def load_unv(self, path: Path):
        """Carrega UNV"""
        try:
            manifest = self.runtime.load_manifest(path)
            self.current_unv = path
            self.file_label.setText(
                f"✓ {manifest.get('name')} v{manifest.get('version')} ({path.name})"
            )
            self.btn_run.setEnabled(True)
            self.output.clear()
        except Exception as e:
            QMessageBox.critical(self, "Erro", f"Pacote inválido: {e}")
    
    def run_unv(self):
        """Executa UNV"""
        if not self.current_unv:
            return
        
        self.btn_run.setEnabled(False)
        self.progress.setVisible(True)
        self.progress.setRange(0, 0)
        self.output.setText("Executando...")
        
        self.executor = ExecutorThread(self.runtime, self.current_unv, [])
        self.executor.finished.connect(self.on_execution_done)
        self.executor.start()
    
    def on_execution_done(self, results: Dict):
        """Completa execução"""
        self.progress.setVisible(False)
        self.btn_run.setEnabled(True)
        
        output = f"Código de Retorno: {results['returncode']}\n\n"
        output += "=== STDOUT ===\n" + results['stdout'] + "\n\n"
        if results['stderr']:
            output += "=== STDERR ===\n" + results['stderr']
        
        self.output.setText(output)
    
    def install_system(self):
        """Instala no sistema"""
        if QMessageBox.question(self, "Confirmar",
                               "Instalar UNV Runtime no sistema?\n\n"
                               "Isso permitirá executar .unv de qualquer lugar."):
            installer = SystemInstaller()
            if installer.install():
                QMessageBox.information(self, "Sucesso", "Instalação completa!")
            else:
                QMessageBox.critical(self, "Erro", "Falha na instalação")
    
    def refresh_cache(self):
        """Atualiza lista de cache"""
        self.cache_list.clear()
        if CACHE_DIR.exists():
            for item in CACHE_DIR.iterdir():
                if item.is_dir():
                    meta_file = item / ".metadata"
                    if meta_file.exists():
                        meta = json.loads(meta_file.read_text())
                        self.cache_list.addItem(
                            f"{meta['name']} v{meta['version']}"
                        )
    
    def clear_cache(self):
        """Limpa cache"""
        if QMessageBox.question(self, "Confirmar", "Limpar todos os pacotes em cache?"):
            shutil.rmtree(CACHE_DIR, ignore_errors=True)
            self.refresh_cache()

def main_cli(unv_path: str, args: list = None):
    """Interface CLI"""
    runtime = UNVRuntime()
    results = runtime.run(Path(unv_path), args or [])
    
    print(results["stdout"])
    if results["stderr"]:
        print("STDERR:", results["stderr"], file=sys.stderr)
    
    sys.exit(results["returncode"])

def main():
    """Ponto de entrada"""
    if len(sys.argv) > 1:
        if sys.argv[1] == "--install":
            installer = SystemInstaller()
            installer.install()
        else:
            main_cli(sys.argv[1], sys.argv[2:])
    elif HAS_GUI:
        app = QApplication(sys.argv)
        launcher = UNVLauncher()
        launcher.show()
        sys.exit(app.exec())
    else:
        print("GUI não disponível. Instale PyQt6: pip install PyQt6")

if __name__ == "__main__":
    main()
