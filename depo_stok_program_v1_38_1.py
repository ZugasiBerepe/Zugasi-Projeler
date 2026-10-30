# -*- coding: utf-8 -*-
"""
Depo & Stok Yönetim Programı
V1.38.0: Depo içi raf/lokasyon tanımları, ürün yerleşimi ve lokasyon hareketleri eklendi.

Python 3.10+ / PyQt5 / SQLite
Çalıştırma:
    python depo_stok_urun_kartlari.py

Bu sürüm mevcut depo_stok.db veritabanını kullanır ve eksik ürün alanlarını
ilk çalıştırmada otomatik olarak ekler.
"""

import csv
import re
import sqlite3
import sys
import tempfile
import hashlib
import json
import os
import unicodedata
import socket
from datetime import datetime
from pathlib import Path

try:
    from PyQt5.QtCore import Qt, QDate, QRegularExpression, QSettings, QTimer, QTime, QObject, pyqtSignal, QThread
    from PyQt5.QtGui import QFont, QIcon, QDoubleValidator, QIntValidator, QColor, QTextDocument
    from PyQt5.QtPrintSupport import QPrinter, QPrintDialog
    from PyQt5.QtWidgets import (
        QApplication, QComboBox, QDateEdit, QDialog, QDialogButtonBox, QFileDialog, QWizard, QWizardPage,
        QFormLayout, QFrame, QGridLayout, QGroupBox, QHBoxLayout, QHeaderView,
        QLabel, QLineEdit, QListWidget, QListWidgetItem, QMainWindow, QMessageBox, QPushButton,
        QRadioButton, QSpinBox, QSplitter, QStatusBar, QStyle, QSizePolicy, QTableWidget, QScrollArea,
        QTableWidgetItem, QTabWidget, QTextEdit, QPlainTextEdit, QProgressBar, QToolButton, QTimeEdit, QVBoxLayout, QWidget, QMenu,
        QAction, QCheckBox, QAbstractItemView, QInputDialog, QCompleter
    )
except ModuleNotFoundError as exc:
    if exc.name == "PyQt5":
        print("PyQt5 bulunamadı. Kurulum için: py -3.14 -m pip install --upgrade PyQt5")
    raise

APP_TITLE = "Depo & Stok Yönetim Programı"
APP_VERSION = "V1.38.1"
APP_VERSION_DATE = "30.10.2026"
APP_SETTINGS = QSettings("TUA Bilisim", "DepoStokClient") if getattr(sys, "frozen", False) else QSettings("ErcanSoft", "DepoStokYonetim")


# V1.35.0: Veritabanı şema sürümü uygulama sürümünden bağımsız tutulur.
# Böylece gelecekte V1.36.0 vb. sürümlerde birden fazla migration adımı güvenli biçimde uygulanabilir.
DB_SCHEMA_VERSION = 5
UPDATE_CHECK_TIMEOUT = 8


def connect_live_text_filter(line_edit, callback, delay=300):
    """Ürün arama kutularını yazarken otomatik filtreler.

    Hızlı yazım sırasında her karakterde ağır SQL sorgusu çalıştırmak yerine
    son karakter girişinden sonra kısa bir gecikmeyle filtreyi tetikler.
    """
    timer = QTimer(line_edit)
    timer.setSingleShot(True)
    line_edit._live_filter_timer = timer
    line_edit.textChanged.connect(lambda _text: timer.start(delay))
    timer.timeout.connect(callback)


def app_version_tuple(version_text: str):
    nums = re.findall(r"\d+", str(version_text or ""))
    vals = [int(x) for x in nums[:3]]
    while len(vals) < 3:
        vals.append(0)
    return tuple(vals)


def is_newer_version(remote_version: str, current_version: str = APP_VERSION) -> bool:
    return app_version_tuple(remote_version) > app_version_tuple(current_version)


_TURKISH_SORT_ORDER = "abcçdefgğhıijklmnoöprsştuüvyz"
_TURKISH_SORT_RANK = {ch: i for i, ch in enumerate(_TURKISH_SORT_ORDER)}

def turkish_sort_key(value):
    """Menü başlıklarını Türk alfabesine göre, noktalama ve boşlukları yok sayarak sıralar."""
    text = str(value or "").replace("İ", "i").replace("I", "ı").lower()
    text = unicodedata.normalize("NFC", text)
    text = re.sub(r"[^abcçdefgğhıijklmnoöprsştuüvyz0-9]+", "", text)
    return tuple(_TURKISH_SORT_RANK.get(ch, len(_TURKISH_SORT_RANK) + ord(ch)) for ch in text)


def _migration_backup_root():
    """Kullanıcıya yazılabilir, sürüm yükseltme yedekleri için ortak klasör."""
    if sys.platform == "win32":
        root = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "TUA Bilisim" / "DepoStok" / "yedekler" / "migrations"
    else:
        root = Path.home() / ".tua_bilisim" / "depostok" / "yedekler" / "migrations"
    root.mkdir(parents=True, exist_ok=True)
    return root


class MigrationError(RuntimeError):
    def __init__(self, message, backup_path=None):
        super().__init__(message)
        self.backup_path = Path(backup_path) if backup_path else None



def _dpapi_protect(text: str) -> str:
    """Windows DPAPI ile gizli değeri kullanıcı hesabına bağlı olarak şifreler."""
    if text is None:
        text = ""
    if sys.platform != "win32":
        return ""
    try:
        import ctypes
        from ctypes import wintypes
        class DATA_BLOB(ctypes.Structure):
            _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]
        data = text.encode("utf-8")
        buf = (ctypes.c_ubyte * len(data))(*data) if data else (ctypes.c_ubyte * 1)(0)
        in_blob = DATA_BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_ubyte)))
        out_blob = DATA_BLOB()
        crypt = ctypes.windll.crypt32.CryptProtectData
        crypt.argtypes = [ctypes.POINTER(DATA_BLOB), wintypes.LPWSTR, ctypes.POINTER(DATA_BLOB), wintypes.LPVOID,
                          wintypes.LPVOID, wintypes.DWORD, ctypes.POINTER(DATA_BLOB)]
        crypt.restype = wintypes.BOOL
        if not crypt(ctypes.byref(in_blob), "DepoStok", None, None, None, 0, ctypes.byref(out_blob)):
            return ""
        try:
            raw = ctypes.string_at(out_blob.pbData, out_blob.cbData)
            return raw.hex()
        finally:
            ctypes.windll.kernel32.LocalFree(out_blob.pbData)
    except Exception:
        return ""


def _dpapi_unprotect(value: str) -> str:
    if not value or sys.platform != "win32":
        return ""
    try:
        import ctypes
        from ctypes import wintypes
        class DATA_BLOB(ctypes.Structure):
            _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]
        raw = bytes.fromhex(value)
        buf = (ctypes.c_ubyte * len(raw))(*raw)
        in_blob = DATA_BLOB(len(raw), ctypes.cast(buf, ctypes.POINTER(ctypes.c_ubyte)))
        out_blob = DATA_BLOB()
        crypt = ctypes.windll.crypt32.CryptUnprotectData
        crypt.argtypes = [ctypes.POINTER(DATA_BLOB), ctypes.POINTER(wintypes.LPWSTR), ctypes.POINTER(DATA_BLOB),
                          wintypes.LPVOID, wintypes.LPVOID, wintypes.DWORD, ctypes.POINTER(DATA_BLOB)]
        crypt.restype = wintypes.BOOL
        if not crypt(ctypes.byref(in_blob), None, None, None, None, 0, ctypes.byref(out_blob)):
            return ""
        try:
            return ctypes.string_at(out_blob.pbData, out_blob.cbData).decode("utf-8")
        finally:
            ctypes.windll.kernel32.LocalFree(out_blob.pbData)
    except Exception:
        return ""


def get_pg_password() -> str:
    enc = (APP_SETTINGS.value("postgres/password_enc", "") or "").strip()
    if enc:
        val = _dpapi_unprotect(enc)
        if val != "":
            return val
    # Eski sürümde açık saklandıysa bir kez okuyup şifreli forma taşı.
    legacy = APP_SETTINGS.value("postgres/password", "") or ""
    if legacy and sys.platform == "win32":
        enc2 = _dpapi_protect(legacy)
        if enc2:
            APP_SETTINGS.setValue("postgres/password_enc", enc2)
            APP_SETTINGS.remove("postgres/password")
            APP_SETTINGS.sync()
    return legacy


def save_pg_password(password: str) -> None:
    enc = _dpapi_protect(password or "") if sys.platform == "win32" else ""
    if enc:
        APP_SETTINGS.setValue("postgres/password_enc", enc)
        APP_SETTINGS.remove("postgres/password")
    else:
        # Windows dışı ortamlar için geri dönüş. Windows hedefinde DPAPI kullanılır.
        APP_SETTINGS.setValue("postgres/password", password or "")
    APP_SETTINGS.sync()


def get_configured_db_path():
    configured = (APP_SETTINGS.value("database/path", "") or "").strip()
    if configured:
        return Path(configured).expanduser()
    # Kurulu .exe altında Program Files'a yazmaya çalışmamak için
    # varsayılan SQLite veritabanını kullanıcıya yazılabilir LocalAppData altında tut.
    if sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "TUA Bilisim" / "DepoStok"
        base.mkdir(parents=True, exist_ok=True)
        return base / "depo_stok.db"
    return Path(__file__).resolve().with_name("depo_stok.db")


DB_PATH = get_configured_db_path()

def _sort_text_value(text):
    """Başlıkla sıralamada sayı, tarih ve metin türünü otomatik algılar."""
    import re
    from datetime import datetime
    s = (text or "").strip()
    if not s:
        return (0, "")
    n = s.upper().replace("TL", "").replace("₺", "").strip().replace(" ", "")
    if re.fullmatch(r"-?[0-9.]+(?:,[0-9]+)?", n):
        try:
            return (1, float(n.replace(".", "").replace(",", ".")))
        except ValueError:
            pass
    for fmt in ("%d.%m.%Y", "%Y-%m-%d", "%d.%m.%Y %H:%M:%S", "%Y-%m-%d %H:%M:%S"):
        try:
            return (2, datetime.strptime(s, fmt))
        except ValueError:
            continue
    return (3, s.casefold())


def _sort_table_column(table, column, ascending):
    """QTableWidget satırlarını başlık tıklamasına göre sıralar.
    Düzenlenebilir fiş/sayım satırlarında model-satır ilişkisini bozmamak için
    sıralama uygulanmaz; diğer liste ekranlarında sayı ve tarih de doğru sıralanır."""
    if table.editTriggers() != QAbstractItemView.NoEditTriggers:
        return
    rows = table.rowCount()
    if rows <= 1:
        return
    current_item = table.item(table.currentRow(), 0) if table.currentRow() >= 0 else None
    snapshot = []
    for r in range(rows):
        items = [table.takeItem(r, c) for c in range(table.columnCount())]
        key_text = items[column].text() if column < len(items) and items[column] is not None else ""
        snapshot.append((_sort_text_value(key_text), items))
    snapshot.sort(key=lambda x: x[0], reverse=not ascending)
    table.setUpdatesEnabled(False)
    try:
        for r, (_key, items) in enumerate(snapshot):
            for c, item in enumerate(items):
                table.setItem(r, c, item)
    finally:
        table.setUpdatesEnabled(True)
    header = table.horizontalHeader()
    header.setSortIndicator(column, Qt.AscendingOrder if ascending else Qt.DescendingOrder)
    if current_item is not None:
        for r in range(table.rowCount()):
            if table.item(r, 0) is current_item:
                table.selectRow(r)
                break


def configure_resizable_table(table, key, default_widths=None, stretch_column=None):
    """Liste tablolarında kalıcı sütun genişliği ve başlık tıklamayla sıralama."""
    table.setObjectName(key)
    header = table.horizontalHeader()
    header.setStretchLastSection(False)
    header.setSectionsMovable(True)
    header.setMinimumSectionSize(45)
    header.setSectionResizeMode(QHeaderView.Interactive)
    table.setSortingEnabled(False)
    header.setSortIndicatorShown(True)
    table._header_sort_state = {}

    if default_widths:
        for idx, width in enumerate(default_widths):
            if idx < table.columnCount() and width:
                header.resizeSection(idx, int(width))
    else:
        header.resizeSections(QHeaderView.ResizeToContents)
        for idx in range(table.columnCount()):
            width = header.sectionSize(idx)
            header.resizeSection(idx, max(45, min(width, 360)))

    if stretch_column is not None and 0 <= stretch_column < table.columnCount():
        width = max(180, min(360, header.sectionSize(stretch_column)))
        header.resizeSection(stretch_column, width)

    restore_key = f"tables/{key}/widths"
    saved = APP_SETTINGS.value(restore_key, None)
    if isinstance(saved, (list, tuple)) and len(saved) == table.columnCount():
        try:
            for i, w in enumerate(saved):
                table.setColumnWidth(i, int(w))
        except (TypeError, ValueError):
            pass

    def save_widths(_logical, _old, _new):
        APP_SETTINGS.setValue(restore_key, [table.columnWidth(i) for i in range(table.columnCount())])
        APP_SETTINGS.sync()
    header.sectionResized.connect(save_widths)

    def on_header_clicked(section):
        state = table._header_sort_state
        ascending = not state.get(section, False)
        state[section] = ascending
        _sort_table_column(table, section, ascending)
    header.sectionClicked.connect(on_header_clicked)
    return table



class _PGRow:
    def __init__(self, columns, values):
        self._map = dict(zip(columns, values))
        self._values = list(values)
    def __getitem__(self, key):
        if isinstance(key, int): return self._values[key]
        return self._map[key]
    def __iter__(self): return iter(self._values)
    def keys(self): return self._map.keys()
    def get(self, key, default=None): return self._map.get(key, default)

class _PGCursor:
    def __init__(self, cursor):
        self._c=cursor
        self._lastrowid=None
    @property
    def rowcount(self): return self._c.rowcount
    @property
    def description(self): return self._c.description
    def fetchone(self):
        row=self._c.fetchone()
        return _PGRow([d[0] for d in self._c.description], row) if row is not None and self._c.description else row
    def fetchall(self):
        rows=self._c.fetchall()
        return [_PGRow([d[0] for d in self._c.description], r) for r in rows] if self._c.description else rows
    def __iter__(self):
        cols=[d[0] for d in self._c.description] if self._c.description else []
        for r in self._c:
            yield _PGRow(cols,r)
    @property
    def lastrowid(self): return self._lastrowid

class _PGCompatConnection:
    def __init__(self, **dsn):
        self._dsn = dict(dsn)
        self._pg = None
        self._connect()

    def _connect(self):
        import psycopg2
        dsn = dict(self._dsn)
        dsn.setdefault("connect_timeout", 10)
        dsn.setdefault("application_name", f"TUA-DepoStok/{socket.gethostname()}")
        dsn.setdefault("keepalives", 1)
        dsn.setdefault("keepalives_idle", 30)
        dsn.setdefault("keepalives_interval", 10)
        dsn.setdefault("keepalives_count", 5)
        self._pg = psycopg2.connect(**dsn)
        self._pg.autocommit = False
        cur = self._pg.cursor()
        # Her istemci aynı güvenli transaction ve bağlantı zaman aşımı kurallarını kullanır.
        cur.execute("SET application_name = %s", (dsn["application_name"],))
        cur.execute("SET statement_timeout = %s", (60000,))
        cur.execute("SET lock_timeout = %s", (15000,))
        cur.execute("SET idle_in_transaction_session_timeout = %s", (300000,))
        self._pg.commit()
        cur.close()

    @property
    def closed(self):
        return self._pg is None or self._pg.closed != 0

    def _reset_failed_transaction(self):
        if self._pg is None or self._pg.closed:
            return False
        try:
            import psycopg2.extensions as _pgext
            status = self._pg.get_transaction_status()
            if status == _pgext.TRANSACTION_STATUS_INERROR:
                self._pg.rollback()
            return True
        except Exception:
            return False

    def ping(self):
        if self.closed:
            self.reconnect()
        else:
            self._reset_failed_transaction()
        cur = self._pg.cursor()
        try:
            cur.execute("SELECT 1")
            cur.fetchone()
            return True
        except Exception:
            try:
                cur.close()
            except Exception:
                pass
            self.reconnect()
            cur = self._pg.cursor()
            try:
                cur.execute("SELECT 1")
                cur.fetchone()
                return True
            finally:
                cur.close()
        finally:
            try:
                cur.close()
            except Exception:
                pass

    def reconnect(self):
        try:
            if self._pg is not None and self._pg.closed == 0:
                try: self._pg.rollback()
                except Exception: pass
                try: self._pg.close()
                except Exception: pass
        finally:
            self._connect()
    @staticmethod
    def _sql(sql):
        sql=str(sql)
        # SQLite qmark placeholders -> psycopg2 placeholders
        sql=sql.replace('COLLATE NOCASE','')
        sql=sql.replace(' LIKE ?',' ILIKE %s')
        sql=sql.replace(' like ?',' ILIKE %s')
        import re
        sql=sql.replace('INSERT OR IGNORE','INSERT')
        if sql.lstrip().upper().startswith('INSERT') and 'ON CONFLICT' not in sql.upper() and 'INSERT INTO ROLLER' in sql.upper():
            sql += ' ON CONFLICT DO NOTHING'
        sql=re.sub(r'\?', '%s', sql)
        return sql
    def execute(self, sql, params=()):
        sql0=str(sql).strip()
        if sql0.upper().startswith('PRAGMA'):
            class _PragmaCursor:
                def __init__(self): self._rows=[]; self._done=False; self._lastrowid=None
                def fetchone(self): return self._rows[0] if self._rows else None
                def fetchall(self): return self._rows
                def __iter__(self): return iter(self._rows)
                @property
                def lastrowid(self): return self._lastrowid
            c=_PragmaCursor()
            low=sql0.lower()
            if 'foreign_keys' in low: c._rows=[(1,)]
            elif 'busy_timeout' in low: c._rows=[(30000,)]
            elif 'journal_mode' in low: c._rows=[('postgresql',)]
            elif 'table_info' in low:
                import re
                m=re.search(r'table_info\(([^)]+)\)',low); table=m.group(1).strip() if m else ''
                cur=self._pg.cursor(); cur.execute("SELECT ordinal_position, column_name, data_type, is_nullable, column_default FROM information_schema.columns WHERE table_schema='public' AND table_name=%s ORDER BY ordinal_position",(table,)); rows=cur.fetchall(); cur.close(); c._rows=[(r[0],r[1],r[2],None,r[4],None) for r in rows]
            elif 'integrity_check' in low: c._rows=[('ok',)]
            return c
        translated=self._sql(sql)
        # Bağlantı kapalı veya önceki bir PostgreSQL hatası nedeniyle transaction abort
        # durumundaysa SELECT/SHOW gibi okuma sorgularından önce transaction'ı temizle.
        if self.closed:
            self.reconnect()
        else:
            self._reset_failed_transaction()
        is_read_only = translated.lstrip().upper().startswith(("SELECT", "WITH", "SHOW", "EXPLAIN"))
        for attempt in range(2 if is_read_only else 1):
            cur=self._pg.cursor()
            try:
                cur.execute(translated, params or ())
                out=_PGCursor(cur)
                break
            except Exception as exc:
                try:
                    import psycopg2
                    in_failed_tx = False
                    try:
                        import psycopg2.extensions as _pgext
                        in_failed_tx = self._pg.get_transaction_status() == _pgext.TRANSACTION_STATUS_INERROR
                    except Exception:
                        pass
                    retryable = is_read_only and (isinstance(exc, psycopg2.OperationalError) or in_failed_tx)
                    if retryable and attempt == 0:
                        try: cur.close()
                        except Exception: pass
                        try:
                            if in_failed_tx:
                                self._pg.rollback()
                            else:
                                self.reconnect()
                        except Exception:
                            pass
                        continue
                    if isinstance(exc, psycopg2.IntegrityError):
                        cur.close(); raise sqlite3.IntegrityError(str(exc)) from exc
                    if isinstance(exc, psycopg2.DatabaseError):
                        try:
                            self._pg.rollback()
                        except Exception:
                            pass
                        cur.close(); raise sqlite3.DatabaseError(str(exc)) from exc
                except ImportError:
                    pass
                try: cur.close()
                except Exception: pass
                raise
        else:
            raise sqlite3.DatabaseError("PostgreSQL bağlantısı yeniden kurulamadı.")
        if translated.lstrip().upper().startswith('INSERT') and cur.description is None:
            try:
                c2=self._pg.cursor(); c2.execute('SELECT LASTVAL()'); out._lastrowid=c2.fetchone()[0]; c2.close()
            except Exception:
                out._lastrowid=None
        return out
    def executescript(self, script):
        import re
        # Translate SQLite DDL to PostgreSQL and execute each statement.
        script=re.sub(r'INTEGER PRIMARY KEY AUTOINCREMENT','BIGSERIAL PRIMARY KEY',script,flags=re.I)
        script=script.replace('REAL','DOUBLE PRECISION')
        statements=[x.strip() for x in script.split(';') if x.strip()]
        for st in statements:
            self.execute(st)
        self.commit()
    def commit(self): self._pg.commit()
    def rollback(self): self._pg.rollback()
    def close(self): self._pg.close()
    def __enter__(self):
        return self
    def __exit__(self, exc_type, exc_value, traceback):
        try:
            if exc_type is None:
                self.commit()
            else:
                self.rollback()
        except Exception:
            try:
                self.rollback()
            except Exception:
                pass
        return False
    def cursor(self): return self._pg.cursor()

class Database:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.backend = (APP_SETTINGS.value("database/backend", "sqlite") or "sqlite").strip().lower()
        if self.backend == "postgresql":
            dsn = {
                "host": (APP_SETTINGS.value("postgres/host", "localhost") or "localhost").strip(),
                "port": int(APP_SETTINGS.value("postgres/port", 5432) or 5432),
                "dbname": (APP_SETTINGS.value("postgres/dbname", "depo_stok") or "depo_stok").strip(),
                "user": (APP_SETTINGS.value("postgres/user", "postgres") or "postgres").strip(),
                "password": get_pg_password(),
                "connect_timeout": 10,
                "application_name": f"TUA-DepoStok/{socket.gethostname()}/{os.getpid()}",
            }
            try:
                self.conn = _PGCompatConnection(**dsn)
            except Exception:
                # PostgreSQL sunucusu yeni başladıysa veya bağlantı kısa süreli kesildiyse
                # açılışta bir kez daha bağlanmayı dene. Başarısız olursa mevcut kurtarma ekranı devreye girer.
                import time
                time.sleep(1.0)
                self.conn = _PGCompatConnection(**dsn)
        else:
            self.backend = "sqlite"
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.conn = sqlite3.connect(str(self.path), timeout=30, check_same_thread=False)
            self.conn.row_factory = sqlite3.Row
            self.conn.execute("PRAGMA foreign_keys = ON")
            self.conn.execute("PRAGMA busy_timeout = 30000")
            try: self.conn.execute("PRAGMA journal_mode = DELETE")
            except sqlite3.DatabaseError: pass
            self.conn.execute("PRAGMA synchronous = NORMAL")
        self._schema_version_before_init_value = self._schema_version_before_init()
        self.last_migration_backup = None
        self.last_migration_backup_warning = None
        if 0 < self._schema_version_before_init_value < DB_SCHEMA_VERSION:
            self.last_migration_backup = self._create_pre_migration_backup()
        self.init_db()
        self.run_schema_migrations(self._schema_version_before_init_value)
        # PostgreSQL'de aktarılmış/restore edilmiş ID'ler sequence değerlerini geride bırakabilir.
        try:
            self._sync_postgres_sequences()
        except Exception:
            pass

    def _schema_version_before_init(self):
        """init_db() herhangi bir değişiklik yapmadan önce mevcut sürümü okur."""
        try:
            if self.backend == "postgresql":
                import psycopg2
                conn = psycopg2.connect(
                    host=(APP_SETTINGS.value("postgres/host", "localhost") or "localhost").strip(),
                    port=int(APP_SETTINGS.value("postgres/port", 5432) or 5432),
                    dbname=(APP_SETTINGS.value("postgres/dbname", "depo_stok") or "depo_stok").strip(),
                    user=(APP_SETTINGS.value("postgres/user", "postgres") or "postgres").strip(),
                    password=get_pg_password(), connect_timeout=5,
                )
                try:
                    cur=conn.cursor()
                    cur.execute("SELECT current_version FROM db_schema_version WHERE id=1")
                    row=cur.fetchone()
                    cur.close()
                    return int(row[0]) if row else 1
                except Exception:
                    return 1
                finally:
                    conn.close()
            if not self.path.exists() or self.path.stat().st_size == 0:
                return 0
            con=sqlite3.connect(str(self.path), timeout=8)
            try:
                row=con.execute("SELECT current_version FROM db_schema_version WHERE id=1").fetchone()
                return int(row[0]) if row else 1
            except sqlite3.DatabaseError:
                return 1
            finally:
                con.close()
        except Exception:
            # Eski/harici bir veritabanında sürüm tablosu yoksa legacy v1 kabul edilir.
            return 1 if getattr(self, "path", None) and self.path.exists() else 0

    def _create_pre_migration_backup(self):
        """Migration başlamadan önce zorunlu güvenlik yedeği oluşturur."""
        stamp=datetime.now().strftime("%Y%m%d_%H%M%S")
        root=_migration_backup_root()
        if self.backend == "postgresql":
            target=root / f"depo_stok_pre_migration_{stamp}.dump"
            try:
                out=perform_postgres_backup(target, "Custom (.dump)")
                return Path(out)
            except FileNotFoundError as exc:
                # V1.35.1: PostgreSQL istemcilerinde pg_dump.exe bulunmayabilir.
                # V1.35.x migration adımları yalnızca indeks ve metadata oluşturduğundan
                # bu eksiklik migration'ı bloke etmez. Daha riskli gelecekteki migration'larda
                # zorunlu yedek politikası ayrıca uygulanacaktır.
                self.last_migration_backup_warning = (
                    "Migration öncesi PostgreSQL yedeği alınamadı: pg_dump.exe bulunamadı. "
                    "V1.35.x migration adımları veri silmediğinden işlem yedeksiz devam etti."
                )
                return None
            except Exception as exc:
                raise MigrationError(f"PostgreSQL migration öncesi yedek alınamadı: {exc}") from exc
        target=root / f"depo_stok_pre_migration_{stamp}.db"
        try:
            out=self.backup_to(target)
            return Path(out)
        except Exception as exc:
            raise MigrationError(f"SQLite migration öncesi yedek alınamadı: {exc}") from exc

    def _ensure_schema_version_table(self):
        if self.backend == "postgresql":
            self.conn.execute("""CREATE TABLE IF NOT EXISTS db_schema_version (
                id INTEGER PRIMARY KEY,
                current_version INTEGER NOT NULL,
                updated_at TEXT NOT NULL,
                app_version TEXT
            )""")
        else:
            self.conn.execute("""CREATE TABLE IF NOT EXISTS db_schema_version (
                id INTEGER PRIMARY KEY,
                current_version INTEGER NOT NULL,
                updated_at TEXT NOT NULL,
                app_version TEXT
            )""")

    def _get_schema_version(self):
        row=self.conn.execute("SELECT current_version FROM db_schema_version WHERE id=1").fetchone()
        return int(row[0]) if row else 1

    def _set_schema_version(self, version):
        now=datetime.now().isoformat(timespec="seconds")
        if self.backend == "postgresql":
            # PostgreSQL'de iki istemcinin aynı anda migration kontrolünde
            # INSERT yarışına girmesini önlemek için gerçek UPSERT kullanılır.
            self.conn.execute(
                "INSERT INTO db_schema_version(id,current_version,updated_at,app_version) "
                "VALUES(1,%s,%s,%s) "
                "ON CONFLICT (id) DO UPDATE SET "
                "current_version=EXCLUDED.current_version, "
                "updated_at=EXCLUDED.updated_at, "
                "app_version=EXCLUDED.app_version",
                (int(version), now, APP_VERSION),
            )
            return
        cur=self.conn.execute(
            "UPDATE db_schema_version SET current_version=?, updated_at=?, app_version=? WHERE id=1",
            (int(version),now,APP_VERSION),
        )
        if getattr(cur, "rowcount", 0) == 0:
            self.conn.execute(
                "INSERT INTO db_schema_version(id,current_version,updated_at,app_version) VALUES(1,?,?,?)",
                (int(version),now,APP_VERSION),
            )

    def _ensure_migration_history_table(self):
        if self.backend == "postgresql":
            sql="""CREATE TABLE IF NOT EXISTS db_migration_history (
                id BIGSERIAL PRIMARY KEY,
                from_version INTEGER NOT NULL,
                to_version INTEGER NOT NULL,
                started_at TEXT NOT NULL,
                finished_at TEXT,
                status TEXT NOT NULL,
                app_version TEXT,
                backup_path TEXT,
                details TEXT
            )"""
        else:
            sql="""CREATE TABLE IF NOT EXISTS db_migration_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                from_version INTEGER NOT NULL,
                to_version INTEGER NOT NULL,
                started_at TEXT NOT NULL,
                finished_at TEXT,
                status TEXT NOT NULL,
                app_version TEXT,
                backup_path TEXT,
                details TEXT
            )"""
        self.conn.execute(sql)

    def _acquire_migration_lock(self):
        if self.backend == "postgresql":
            self.conn.execute("SELECT pg_advisory_lock(4382213501)").fetchone()
            return "postgresql"
        self.conn.execute("BEGIN IMMEDIATE")
        return "sqlite"

    def _release_migration_lock(self, kind):
        if kind == "postgresql":
            try:self.conn.execute("SELECT pg_advisory_unlock(4382213501)").fetchone()
            finally:
                self.conn.commit()
        else:
            try:self.conn.commit()
            except Exception:self.conn.rollback()

    def _migration_2(self):
        """V1.35.0: Sorgu performansını iyileştiren indeksler."""
        statements=[
            "CREATE INDEX IF NOT EXISTS idx_stok_hareket_urun_depo_tarih ON stok_hareketleri(urun_id, depo_id, tarih)",
            "CREATE INDEX IF NOT EXISTS idx_stok_hareket_fis_no ON stok_hareketleri(fis_no)",
            "CREATE INDEX IF NOT EXISTS idx_stok_hareket_depo_tarih ON stok_hareketleri(depo_id, tarih)",
            "CREATE INDEX IF NOT EXISTS idx_stok_fis_tarih_depo ON stok_fisleri(tarih, depo_id)",
            "CREATE INDEX IF NOT EXISTS idx_sayim_tarih_depo ON sayim_fisleri(tarih, depo_id)",
            "CREATE INDEX IF NOT EXISTS idx_transfer_tarih ON stok_transferleri(tarih)",
            "CREATE INDEX IF NOT EXISTS idx_urun_barkod ON urunler(barkod)",
            "CREATE INDEX IF NOT EXISTS idx_cari_unvan ON cariler(unvan)",
        ]
        for sql in statements:
            self.conn.execute(sql)

    def _migration_4(self):
        """V1.36.0: Dönem/yıl sonu yönetimi ve açılış devir kayıtları."""
        if self.backend == "postgresql":
            self.conn.execute("""CREATE TABLE IF NOT EXISTS stok_donemleri (
                id BIGSERIAL PRIMARY KEY,
                kod TEXT NOT NULL UNIQUE,
                ad TEXT NOT NULL,
                baslangic_tarihi TEXT NOT NULL,
                bitis_tarihi TEXT NOT NULL,
                durum TEXT NOT NULL DEFAULT 'Açık',
                onceki_donem_id BIGINT,
                kapanis_id BIGINT,
                olusturma_tarihi TEXT NOT NULL,
                kapatma_tarihi TEXT,
                kullanici_id BIGINT
            )""")
            self.conn.execute("""CREATE TABLE IF NOT EXISTS stok_donem_acilis_stoklari (
                id BIGSERIAL PRIMARY KEY,
                donem_id BIGINT NOT NULL,
                kaynak_kapanis_id BIGINT,
                depo_id BIGINT NOT NULL,
                urun_id BIGINT NOT NULL,
                miktar DOUBLE PRECISION NOT NULL,
                birim_maliyet DOUBLE PRECISION DEFAULT 0,
                stok_degeri DOUBLE PRECISION DEFAULT 0,
                UNIQUE(donem_id, depo_id, urun_id)
            )""")
        else:
            self.conn.execute("""CREATE TABLE IF NOT EXISTS stok_donemleri (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                kod TEXT NOT NULL UNIQUE,
                ad TEXT NOT NULL,
                baslangic_tarihi TEXT NOT NULL,
                bitis_tarihi TEXT NOT NULL,
                durum TEXT NOT NULL DEFAULT 'Açık',
                onceki_donem_id INTEGER,
                kapanis_id INTEGER,
                olusturma_tarihi TEXT NOT NULL,
                kapatma_tarihi TEXT,
                kullanici_id INTEGER
            )""")
            self.conn.execute("""CREATE TABLE IF NOT EXISTS stok_donem_acilis_stoklari (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                donem_id INTEGER NOT NULL,
                kaynak_kapanis_id INTEGER,
                depo_id INTEGER NOT NULL,
                urun_id INTEGER NOT NULL,
                miktar REAL NOT NULL,
                birim_maliyet REAL DEFAULT 0,
                stok_degeri REAL DEFAULT 0,
                UNIQUE(donem_id, depo_id, urun_id)
            )""")
        # Existing close records gain explicit state/type/control fields.
        additions = [
            ("durum", "TEXT NOT NULL DEFAULT 'Tamamlandı'"),
            ("devir_turu", "TEXT NOT NULL DEFAULT 'Bakiyeli Devir'"),
            ("yeni_donem_kodu", "TEXT"),
            ("yeni_donem_id", "INTEGER"),
            ("kontrol_sonucu", "TEXT"),
            ("kilitleme_tarihi", "TEXT"),
        ]
        for col, definition in additions:
            self._ensure_column("stok_donem_kapanislari", col, definition)

        now = datetime.now().isoformat(timespec="seconds")
        # Seed a current calendar year period only when none exists.
        try:
            row = self.conn.execute("SELECT id FROM stok_donemleri WHERE baslangic_tarihi<=? AND bitis_tarihi>=? ORDER BY id LIMIT 1", (now[:10], now[:10])).fetchone()
            if not row:
                year = int(now[:4])
                kod = str(year)
                ad = f"{year} Dönemi"
                self.conn.execute("INSERT INTO stok_donemleri(kod,ad,baslangic_tarihi,bitis_tarihi,durum,olusturma_tarihi) VALUES(?,?,?,?,?,?)",
                                  (kod, ad, f"{year}-01-01", f"{year}-12-31", "Açık", now))
        except Exception:
            pass

    def _migration_5(self):
        """V1.38.0: Depo içi raf/lokasyon tanımları, ürün yerleşimleri ve hareket geçmişi."""
        if self.backend == "postgresql":
            self.conn.execute("""CREATE TABLE IF NOT EXISTS depo_lokasyonlari (
                id BIGSERIAL PRIMARY KEY,
                depo_id BIGINT NOT NULL REFERENCES depolar(id),
                kod TEXT NOT NULL,
                ad TEXT NOT NULL,
                bolum TEXT,
                koridor TEXT,
                raf TEXT,
                kat TEXT,
                goz TEXT,
                barkod TEXT UNIQUE,
                aktif INTEGER NOT NULL DEFAULT 1,
                aciklama TEXT,
                olusturma_tarihi TEXT NOT NULL,
                UNIQUE(depo_id, kod)
            )""")
            self.conn.execute("""CREATE TABLE IF NOT EXISTS stok_lokasyonlari (
                id BIGSERIAL PRIMARY KEY,
                depo_id BIGINT NOT NULL REFERENCES depolar(id),
                lokasyon_id BIGINT NOT NULL REFERENCES depo_lokasyonlari(id),
                urun_id BIGINT NOT NULL REFERENCES urunler(id),
                miktar DOUBLE PRECISION NOT NULL DEFAULT 0,
                guncelleme_tarihi TEXT NOT NULL,
                UNIQUE(lokasyon_id, urun_id)
            )""")
            self.conn.execute("""CREATE TABLE IF NOT EXISTS stok_lokasyon_hareketleri (
                id BIGSERIAL PRIMARY KEY,
                tarih TEXT NOT NULL,
                depo_id BIGINT NOT NULL,
                urun_id BIGINT NOT NULL,
                kaynak_lokasyon_id BIGINT,
                hedef_lokasyon_id BIGINT,
                miktar DOUBLE PRECISION NOT NULL,
                kullanici_id BIGINT,
                aciklama TEXT
            )""")
        else:
            self.conn.execute("""CREATE TABLE IF NOT EXISTS depo_lokasyonlari (
                id INTEGER PRIMARY KEY AUTOINCREMENT, depo_id INTEGER NOT NULL, kod TEXT NOT NULL, ad TEXT NOT NULL,
                bolum TEXT, koridor TEXT, raf TEXT, kat TEXT, goz TEXT, barkod TEXT UNIQUE,
                aktif INTEGER NOT NULL DEFAULT 1, aciklama TEXT, olusturma_tarihi TEXT NOT NULL,
                UNIQUE(depo_id, kod), FOREIGN KEY(depo_id) REFERENCES depolar(id))""")
            self.conn.execute("""CREATE TABLE IF NOT EXISTS stok_lokasyonlari (
                id INTEGER PRIMARY KEY AUTOINCREMENT, depo_id INTEGER NOT NULL, lokasyon_id INTEGER NOT NULL,
                urun_id INTEGER NOT NULL, miktar REAL NOT NULL DEFAULT 0, guncelleme_tarihi TEXT NOT NULL,
                UNIQUE(lokasyon_id, urun_id), FOREIGN KEY(depo_id) REFERENCES depolar(id),
                FOREIGN KEY(lokasyon_id) REFERENCES depo_lokasyonlari(id), FOREIGN KEY(urun_id) REFERENCES urunler(id))""")
            self.conn.execute("""CREATE TABLE IF NOT EXISTS stok_lokasyon_hareketleri (
                id INTEGER PRIMARY KEY AUTOINCREMENT, tarih TEXT NOT NULL, depo_id INTEGER NOT NULL,
                urun_id INTEGER NOT NULL, kaynak_lokasyon_id INTEGER, hedef_lokasyon_id INTEGER,
                miktar REAL NOT NULL, kullanici_id INTEGER, aciklama TEXT)""")
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_depo_lokasyon_depo ON depo_lokasyonlari(depo_id, aktif)")
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_stok_lokasyon_urun ON stok_lokasyonlari(depo_id, urun_id)")
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_lokasyon_hareket_tarih ON stok_lokasyon_hareketleri(tarih, depo_id)")
        # Sistem bilgi kartını da yeni uygulama/şema sürümüyle eşitle.
        try:
            self.conn.execute("UPDATE uygulama_sistem_bilgileri SET app_version=?, schema_version=?, updated_at=?, bilgisayar_adi=? WHERE id=1",
                              (APP_VERSION, DB_SCHEMA_VERSION, datetime.now().isoformat(timespec="seconds"), socket.gethostname()))
        except Exception:
            pass

    def _migration_3(self):
        """V1.35.0: Kurulum/şema bilgilerini izlemek için metadata tablosu."""
        self.conn.execute("""CREATE TABLE IF NOT EXISTS uygulama_sistem_bilgileri (
            id INTEGER PRIMARY KEY,
            app_version TEXT,
            schema_version INTEGER NOT NULL,
            updated_at TEXT NOT NULL,
            bilgisayar_adi TEXT,
            son_migration_backup TEXT
        )""")
        now=datetime.now().isoformat(timespec="seconds")
        host=socket.gethostname()
        existing=self.conn.execute("SELECT id FROM uygulama_sistem_bilgileri WHERE id=1").fetchone()
        if existing:
            self.conn.execute("UPDATE uygulama_sistem_bilgileri SET app_version=?,schema_version=?,updated_at=?,bilgisayar_adi=?,son_migration_backup=? WHERE id=1",
                              (APP_VERSION,DB_SCHEMA_VERSION,now,host,str(getattr(self,"last_migration_backup","") or "")))
        else:
            self.conn.execute("INSERT INTO uygulama_sistem_bilgileri(id,app_version,schema_version,updated_at,bilgisayar_adi,son_migration_backup) VALUES(1,?,?,?,?,?)",
                              (APP_VERSION,DB_SCHEMA_VERSION,now,host,str(getattr(self,"last_migration_backup","") or "")))

    def run_schema_migrations(self, before):
        """Eksik migration'ları sıralı, kilitli ve önceden alınmış yedekle uygular."""
        self.migration_performed=False
        self.last_migration_from=before
        self.last_migration_to=before
        if before >= DB_SCHEMA_VERSION:
            return False
        backup_path=self.last_migration_backup
        lock=None
        try:
            lock=self._acquire_migration_lock()
            self._ensure_schema_version_table()
            current=before
            if current >= DB_SCHEMA_VERSION:
                return False
            if current < 1:
                self._set_schema_version(1); current=1
            self._ensure_migration_history_table()
            migrations={2:self._migration_2,3:self._migration_3,4:self._migration_4,5:self._migration_5}
            for target in range(current+1, DB_SCHEMA_VERSION+1):
                started=datetime.now().isoformat(timespec="seconds")
                self.conn.execute("INSERT INTO db_migration_history(from_version,to_version,started_at,status,app_version,backup_path,details) VALUES(?,?,?,?,?,?,?)",
                                  (target-1,target,started,"Başladı",APP_VERSION,str(backup_path or ""),""))
                try:
                    migrations[target]()
                    self._set_schema_version(target)
                    self.conn.execute("UPDATE db_migration_history SET finished_at=?,status=?,details=? WHERE id=(SELECT MAX(id) FROM db_migration_history)",
                                      (datetime.now().isoformat(timespec="seconds"),"Başarılı",f"Migration {target-1} -> {target} tamamlandı."))
                    current=target
                except Exception as exc:
                    self.conn.rollback()
                    # Hata kalıcı bir kayıt olarak saklanabiliyorsa sakla. Yeni DB'de
                    # tablo yaratımı da rollback olmuş olabileceği için tabloları yeniden kuruyoruz.
                    try:
                        self._ensure_schema_version_table()
                        self._ensure_migration_history_table()
                        self.conn.execute("INSERT INTO db_migration_history(from_version,to_version,started_at,finished_at,status,app_version,backup_path,details) VALUES(?,?,?,?,?,?,?,?)",
                                          (target-1,target,started,datetime.now().isoformat(timespec="seconds"),"Başarısız",APP_VERSION,str(backup_path or ""),str(exc)))
                        self.conn.commit()
                    except Exception: pass
                    raise MigrationError(f"Veritabanı migration {target-1} → {target} başarısız oldu: {exc}", backup_path) from exc
            self.conn.commit()
            self.migration_performed=True
            self.last_migration_to=DB_SCHEMA_VERSION
            return True
        finally:
            if lock:
                try:self._release_migration_lock(lock)
                except Exception:pass

    def _sync_postgres_sequences(self):
        """SQLite -> PostgreSQL aktarımı veya manuel restore sonrasında SERIAL/BIGSERIAL
        sequence değerlerini tablolardaki mevcut MAX(id) değerleriyle senkronlar.
        Böylece ilk yeni kayıt, mevcut bir ID ile çakışmaz."""
        if self.backend != "postgresql":
            return
        tables = [
            "depolar", "urun_gruplari", "departmanlar", "birimler", "urun_turleri",
            "departman_alt_birimleri", "cariler", "urunler", "stok_hareketleri",
            "stok_fisleri", "stok_fis_satirlari", "sayim_fisleri", "sayim_satirlari",
            "stok_transferleri", "stok_transfer_satirlari", "stok_donemleri",
            "stok_donem_kapanislari", "stok_devir_satirlari", "stok_donem_acilis_stoklari",
            "roller", "kullanicilar", "oturum_loglari", "islem_loglari", "db_migration_history",
            "depo_lokasyonlari", "stok_lokasyonlari", "stok_lokasyon_hareketleri"
        ]
        for table in tables:
            try:
                row = self.conn.execute(
                    "SELECT pg_get_serial_sequence(%s, 'id') AS seq, COALESCE(MAX(id),0) AS max_id FROM " + table,
                    (table,)
                ).fetchone()
                if not row or not row["seq"]:
                    continue
                seq = row["seq"]
                max_id = int(row["max_id"] or 0)
                if max_id > 0:
                    self.conn.execute("SELECT setval(%s, %s, true)", (seq, max_id))
                else:
                    self.conn.execute("SELECT setval(%s, 1, false)", (seq, 1))
            except Exception:
                # Sequence olmayan/eksik tablo diğerlerinin senkronizasyonunu engellemez.
                continue
        self.conn.commit()

    def connection_info(self):
        if self.backend == "postgresql":
            host = (APP_SETTINGS.value("postgres/host", "localhost") or "localhost").strip()
            port = int(APP_SETTINGS.value("postgres/port", 5432) or 5432)
            dbname = (APP_SETTINGS.value("postgres/dbname", "depo_stok") or "depo_stok").strip()
            share = (APP_SETTINGS.value("postgres/share_path", "") or "").strip()
            base = f"PostgreSQL | {host}:{port}/{dbname}"
            return base + (f" | Referans/Paylaşım: {share}" if share else "")
        return f"SQLite | {self.path}"

    def ping(self):
        if self.backend == "postgresql":
            return bool(self.conn and hasattr(self.conn, "ping") and self.conn.ping())
        self.conn.execute("SELECT 1").fetchone()
        return True

    def reconnect(self):
        if self.backend != "postgresql":
            return False
        dsn = {
            "host": (APP_SETTINGS.value("postgres/host", "localhost") or "localhost").strip(),
            "port": int(APP_SETTINGS.value("postgres/port", 5432) or 5432),
            "dbname": (APP_SETTINGS.value("postgres/dbname", "depo_stok") or "depo_stok").strip(),
            "user": (APP_SETTINGS.value("postgres/user", "postgres") or "postgres").strip(),
            "password": get_pg_password(),
            "connect_timeout": 8,
        }
        self.conn.reconnect()
        self.init_db()
        return True

    def _ensure_column(self, table, column, definition):
        if self.backend == "postgresql":
            row=self.conn.execute("SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name=%s AND column_name=%s",(table,column)).fetchone()
            if not row:
                self.conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition.replace('INTEGER','BIGINT').replace('REAL','DOUBLE PRECISION')}")
            return
        cols = {r[1] for r in self.conn.execute(f"PRAGMA table_info({table})")}
        if column not in cols:
            self.conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")

    def init_db(self):
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS depolar (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                kod TEXT NOT NULL UNIQUE,
                ad TEXT NOT NULL,
                aktif INTEGER NOT NULL DEFAULT 1
            );

            CREATE TABLE IF NOT EXISTS urun_gruplari (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                kod TEXT UNIQUE,
                ad TEXT NOT NULL,
                aktif INTEGER NOT NULL DEFAULT 1
            );

            CREATE TABLE IF NOT EXISTS departmanlar (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                kod TEXT UNIQUE,
                ad TEXT NOT NULL,
                aktif INTEGER NOT NULL DEFAULT 1
            );

            CREATE TABLE IF NOT EXISTS birimler (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                kod TEXT UNIQUE,
                ad TEXT NOT NULL UNIQUE,
                aktif INTEGER NOT NULL DEFAULT 1
            );

            CREATE TABLE IF NOT EXISTS urun_turleri (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                kod TEXT UNIQUE,
                ad TEXT NOT NULL UNIQUE,
                aktif INTEGER NOT NULL DEFAULT 1
            );

            CREATE TABLE IF NOT EXISTS departman_alt_birimleri (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                departman_id INTEGER NOT NULL,
                kod TEXT NOT NULL,
                ad TEXT NOT NULL,
                aktif INTEGER NOT NULL DEFAULT 1,
                UNIQUE(departman_id, kod),
                UNIQUE(departman_id, ad),
                FOREIGN KEY(departman_id) REFERENCES departmanlar(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS cariler (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                kod TEXT UNIQUE,
                unvan TEXT NOT NULL,
                telefon TEXT,
                email TEXT,
                adres TEXT,
                aktif INTEGER NOT NULL DEFAULT 1
            );

            CREATE TABLE IF NOT EXISTS urunler (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                kod TEXT NOT NULL UNIQUE,
                ad TEXT NOT NULL,
                barkod TEXT,
                grup_id INTEGER,
                birim TEXT DEFAULT 'ADET',
                birim_id INTEGER,
                min_seviye REAL DEFAULT 0,
                max_seviye REAL DEFAULT 0,
                aktif INTEGER NOT NULL DEFAULT 1,
                FOREIGN KEY (grup_id) REFERENCES urun_gruplari(id)
            );

            CREATE TABLE IF NOT EXISTS stok_hareketleri (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tarih TEXT NOT NULL,
                fis_no TEXT,
                islem_tipi TEXT NOT NULL,
                urun_id INTEGER NOT NULL,
                depo_id INTEGER NOT NULL,
                miktar REAL NOT NULL,
                birim_fiyat REAL DEFAULT 0,
                cari_id INTEGER,
                departman_id INTEGER,
                alt_birim_id INTEGER,
                teslim_eden TEXT,
                teslim_alan TEXT,
                aciklama TEXT,
                FOREIGN KEY (urun_id) REFERENCES urunler(id),
                FOREIGN KEY (depo_id) REFERENCES depolar(id),
                FOREIGN KEY (cari_id) REFERENCES cariler(id),
                FOREIGN KEY (departman_id) REFERENCES departmanlar(id)
            );

            CREATE TABLE IF NOT EXISTS stok_fisleri (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                fis_no TEXT NOT NULL UNIQUE,
                tarih TEXT NOT NULL,
                islem_tipi TEXT NOT NULL,
                depo_id INTEGER NOT NULL,
                cari_id INTEGER,
                departman_id INTEGER,
                alt_birim_id INTEGER,
                teslim_eden TEXT,
                teslim_alan TEXT,
                aciklama TEXT,
                olusturma_tarihi TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (depo_id) REFERENCES depolar(id),
                FOREIGN KEY (cari_id) REFERENCES cariler(id),
                FOREIGN KEY (departman_id) REFERENCES departmanlar(id)
            );

            CREATE TABLE IF NOT EXISTS islem_loglari (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                islem_turu TEXT NOT NULL,
                referans_id INTEGER NOT NULL,
                referans_no TEXT,
                tarih TEXT NOT NULL,
                kullanici_id INTEGER,
                aciklama TEXT,
                FOREIGN KEY(kullanici_id) REFERENCES kullanicilar(id)
            );

            CREATE TABLE IF NOT EXISTS stok_fis_satirlari (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                fis_id INTEGER NOT NULL,
                urun_id INTEGER NOT NULL,
                miktar REAL NOT NULL,
                birim_fiyat REAL DEFAULT 0,
                aciklama TEXT,
                FOREIGN KEY (fis_id) REFERENCES stok_fisleri(id) ON DELETE CASCADE,
                FOREIGN KEY (urun_id) REFERENCES urunler(id)
            );

            CREATE TABLE IF NOT EXISTS sayim_fisleri (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sayim_no TEXT NOT NULL UNIQUE,
                tarih TEXT NOT NULL,
                depo_id INTEGER NOT NULL,
                aciklama TEXT,
                olusturma_tarihi TEXT DEFAULT CURRENT_TIMESTAMP,
                kullanici_id INTEGER,
                FOREIGN KEY (depo_id) REFERENCES depolar(id),
                FOREIGN KEY (kullanici_id) REFERENCES kullanicilar(id)
            );

            CREATE TABLE IF NOT EXISTS sayim_satirlari (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sayim_id INTEGER NOT NULL,
                urun_id INTEGER NOT NULL,
                sistem_miktari REAL NOT NULL,
                sayilan_miktar REAL NOT NULL,
                fark REAL NOT NULL,
                aciklama TEXT,
                FOREIGN KEY (sayim_id) REFERENCES sayim_fisleri(id) ON DELETE CASCADE,
                FOREIGN KEY (urun_id) REFERENCES urunler(id)
            );

            CREATE TABLE IF NOT EXISTS stok_transferleri (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                transfer_no TEXT NOT NULL UNIQUE,
                tarih TEXT NOT NULL,
                kaynak_depo_id INTEGER NOT NULL,
                hedef_depo_id INTEGER NOT NULL,
                kullanici_id INTEGER,
                aciklama TEXT,
                FOREIGN KEY (kaynak_depo_id) REFERENCES depolar(id),
                FOREIGN KEY (hedef_depo_id) REFERENCES depolar(id),
                FOREIGN KEY (kullanici_id) REFERENCES kullanicilar(id)
            );

            CREATE TABLE IF NOT EXISTS stok_transfer_satirlari (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                transfer_id INTEGER NOT NULL,
                urun_id INTEGER NOT NULL,
                miktar REAL NOT NULL,
                aciklama TEXT,
                FOREIGN KEY (transfer_id) REFERENCES stok_transferleri(id) ON DELETE CASCADE,
                FOREIGN KEY (urun_id) REFERENCES urunler(id)
            );

            CREATE TABLE IF NOT EXISTS stok_donem_kapanislari (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                kapanis_no TEXT NOT NULL UNIQUE,
                tarih TEXT NOT NULL,
                depo_id INTEGER,
                aciklama TEXT,
                kullanici_id INTEGER,
                olusturma_tarihi TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (depo_id) REFERENCES depolar(id),
                FOREIGN KEY (kullanici_id) REFERENCES kullanicilar(id)
            );

            CREATE TABLE IF NOT EXISTS stok_devir_satirlari (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                kapanis_id INTEGER NOT NULL,
                depo_id INTEGER NOT NULL,
                urun_id INTEGER NOT NULL,
                miktar REAL NOT NULL,
                birim_maliyet REAL DEFAULT 0,
                stok_degeri REAL DEFAULT 0,
                FOREIGN KEY (kapanis_id) REFERENCES stok_donem_kapanislari(id) ON DELETE CASCADE,
                FOREIGN KEY (depo_id) REFERENCES depolar(id),
                FOREIGN KEY (urun_id) REFERENCES urunler(id)
            );

            CREATE TABLE IF NOT EXISTS roller (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ad TEXT NOT NULL UNIQUE,
                aciklama TEXT,
                aktif INTEGER NOT NULL DEFAULT 1
            );

            CREATE TABLE IF NOT EXISTS kullanicilar (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                kullanici_adi TEXT NOT NULL UNIQUE,
                ad_soyad TEXT,
                sifre_hash TEXT NOT NULL,
                rol_id INTEGER,
                aktif INTEGER NOT NULL DEFAULT 1,
                olusturma_tarihi TEXT DEFAULT CURRENT_TIMESTAMP,
                son_giris TEXT,
                FOREIGN KEY (rol_id) REFERENCES roller(id)
            );

            CREATE TABLE IF NOT EXISTS oturum_loglari (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                kullanici_id INTEGER,
                kullanici_adi TEXT,
                tarih TEXT NOT NULL,
                olay TEXT NOT NULL,
                aciklama TEXT,
                FOREIGN KEY (kullanici_id) REFERENCES kullanicilar(id)
            );

            """
        )

        # Ürün kartı ekranında kullanacağımız ilave alanlar.
        extra_columns = {
            "urun_turu_id": "INTEGER",
            "uretici_kodu": "TEXT",
            "uretici": "TEXT",
            "urun_tipi": "TEXT",
            "marka": "TEXT",
            "model": "TEXT",
            "kdv": "REAL DEFAULT 20",
            "alis_fiyati": "REAL DEFAULT 0",
            "satis_fiyati": "REAL DEFAULT 0",
            "raf_bilgisi": "TEXT",
            "aciklama": "TEXT",
            "notlar": "TEXT",
            "resim_yolu": "TEXT",
            "demirbas_no": "TEXT",
            "birim_id": "INTEGER",
            "aktif": "INTEGER NOT NULL DEFAULT 1",
        }
        for col, definition in extra_columns.items():
            self._ensure_column("urunler", col, definition)
        self._ensure_column("stok_hareketleri", "alt_birim_id", "INTEGER")
        self._ensure_column("stok_hareketleri", "iptal_hareketi", "INTEGER NOT NULL DEFAULT 0")
        self._ensure_column("stok_fisleri", "durum", "TEXT NOT NULL DEFAULT 'Aktif'")
        self._ensure_column("stok_fisleri", "iptal_tarihi", "TEXT")
        self._ensure_column("stok_fisleri", "iptal_kullanici_id", "INTEGER")
        self._ensure_column("stok_fisleri", "iptal_nedeni", "TEXT")
        self._ensure_column("sayim_fisleri", "durum", "TEXT NOT NULL DEFAULT 'Aktif'")
        self._ensure_column("sayim_fisleri", "iptal_tarihi", "TEXT")
        self._ensure_column("sayim_fisleri", "iptal_kullanici_id", "INTEGER")
        self._ensure_column("sayim_fisleri", "iptal_nedeni", "TEXT")
        self._ensure_column("stok_transferleri", "durum", "TEXT NOT NULL DEFAULT 'Aktif'")
        self._ensure_column("stok_transferleri", "iptal_tarihi", "TEXT")
        self._ensure_column("stok_transferleri", "iptal_kullanici_id", "INTEGER")
        self._ensure_column("stok_transferleri", "iptal_nedeni", "TEXT")

        # Varsayılan tanımlar.
        if self.conn.execute("SELECT COUNT(*) FROM depolar").fetchone()[0] == 0:
            self.conn.execute("INSERT INTO depolar(kod, ad) VALUES (?, ?)", ("D001", "MERKEZ DEPO"))
        if self.conn.execute("SELECT COUNT(*) FROM urun_gruplari").fetchone()[0] == 0:
            self.conn.executemany(
                "INSERT INTO urun_gruplari(kod, ad) VALUES (?, ?)",
                [("G001", "GENEL ÜRÜNLER"), ("G002", "SARF MALZEMELERİ"), ("G003", "YEDEK PARÇA")],
            )
        if self.conn.execute("SELECT COUNT(*) FROM birimler").fetchone()[0] == 0:
            self.conn.executemany(
                "INSERT INTO birimler(kod, ad) VALUES (?, ?)",
                [("ADET", "ADET"), ("KG", "KG"), ("GR", "GR"), ("MT", "METRE"),
                 ("LT", "LİTRE"), ("SET", "SET"), ("KUTU", "KUTU"), ("PAKET", "PAKET")],
            )
        if self.conn.execute("SELECT COUNT(*) FROM urun_turleri").fetchone()[0] == 0:
            self.conn.executemany(
                "INSERT INTO urun_turleri(kod, ad) VALUES (?, ?)",
                [("PC", "PC"), ("NB", "NOTEBOOK"), ("MON", "MONİTÖR"),
                 ("MDM", "MODEM"), ("YAZ", "YAZICI"), ("BAR", "BARKOD OKUYUCU")],
            )

        # Varsayılan roller. Yeni kurulumda oluşturulur; mevcut sistemlerde
        # eksik roller varsa da mevcut kullanıcıları bozmadan eklenir.
        default_roles = [
            ("Yönetici", "Tüm işlemlere erişim"),
            ("Stok Kullanıcısı", "Stok ve tanım işlemleri"),
            ("Rapor Kullanıcısı", "Rapor ve görüntüleme işlemleri"),
        ]
        for role_name, role_desc in default_roles:
            self.conn.execute(
                "INSERT OR IGNORE INTO roller(ad, aciklama, aktif) VALUES (?, ?, 1)",
                (role_name, role_desc),
            )

        # Yeni/veri tabanı sıfır kurulumu için otomatik yönetici hesabı.
        # Kullanıcı tablosu tamamen boşsa yalnızca bir kez oluşturulur:
        # Kullanıcı adı: Admin / Şifre: 1234
        # Şifre düz metin değil, mevcut hash_password mekanizması ile saklanır.
        user_count = self.conn.execute("SELECT COUNT(*) FROM kullanicilar").fetchone()[0]
        if user_count == 0:
            admin_role = self.conn.execute(
                "SELECT id FROM roller WHERE ad=? LIMIT 1", ("Yönetici",)
            ).fetchone()
            if admin_role:
                self.conn.execute(
                    "INSERT INTO kullanicilar(kullanici_adi, ad_soyad, sifre_hash, rol_id, aktif) "
                    "VALUES (?, ?, ?, ?, 1)",
                    ("Admin", "Sistem Yöneticisi", self.hash_password("1234"), admin_role[0]),
                )

        self.conn.commit()

        # Eski ürün kartlarındaki metinsel birimleri yeni birim tablosuna bağla.
        self._migrate_product_units()
        self.conn.commit()

    def groups(self, include_inactive=False):
        where = "" if include_inactive else "WHERE aktif=1"
        return self.conn.execute(f"SELECT id, kod, ad, aktif FROM urun_gruplari {where} ORDER BY ad").fetchall()

    def units(self):
        return self.conn.execute("SELECT id, kod, ad FROM birimler WHERE aktif=1 ORDER BY ad").fetchall()

    def product_types(self, include_inactive=False):
        where = "" if include_inactive else "WHERE aktif=1"
        return self.conn.execute(f"SELECT id, kod, ad, aktif FROM urun_turleri {where} ORDER BY ad").fetchall()

    def subunits(self, department_id, include_inactive=True):
        where = '' if include_inactive else 'AND aktif=1'
        return self.conn.execute(
            f"SELECT id, departman_id, kod, ad, aktif FROM departman_alt_birimleri WHERE departman_id=? {where} ORDER BY kod",
            (department_id,)
        ).fetchall()

    def save_subunit(self, department_id, code, name, active, item_id=None):
        if item_id:
            self.conn.execute("UPDATE departman_alt_birimleri SET kod=?, ad=?, aktif=? WHERE id=? AND departman_id=?",
                              (code, name, active, item_id, department_id))
        else:
            self.conn.execute("INSERT INTO departman_alt_birimleri(departman_id, kod, ad, aktif) VALUES (?, ?, ?, ?)",
                              (department_id, code, name, active))
        self.conn.commit()

    def toggle_subunit(self, item_id):
        row = self.conn.execute("SELECT aktif FROM departman_alt_birimleri WHERE id=?", (item_id,)).fetchone()
        if row:
            self.conn.execute("UPDATE departman_alt_birimleri SET aktif=? WHERE id=?", (0 if row['aktif'] else 1, item_id))
            self.conn.commit()

    def warehouses(self):
        return self.conn.execute("SELECT id, kod, ad, aktif FROM depolar ORDER BY ad").fetchall()

    def departments(self):
        return self.conn.execute("SELECT id, kod, ad, aktif FROM departmanlar ORDER BY ad").fetchall()

    def _migrate_product_units(self):
        rows = self.conn.execute("SELECT id, birim, birim_id FROM urunler").fetchall()
        unit_map = {str(r['ad']).strip().upper(): r['id'] for r in self.conn.execute("SELECT id, ad FROM birimler") }
        for r in rows:
            if r['birim_id']:
                continue
            txt = (r['birim'] or 'ADET').strip().upper()
            uid = unit_map.get(txt)
            if uid:
                self.conn.execute("UPDATE urunler SET birim_id=? WHERE id=?", (uid, r['id']))

    def list_definition(self, table, include_inactive=True):
        if table not in {'urun_gruplari','depolar','departmanlar','birimler','urun_turleri'}:
            raise ValueError('Geçersiz tanım tablosu')
        where = '' if include_inactive else 'WHERE aktif=1'
        return self.conn.execute(f"SELECT id, kod, ad, aktif FROM {table} {where} ORDER BY ad").fetchall()

    def save_definition(self, table, code, name, active, item_id=None):
        if table not in {'urun_gruplari','depolar','departmanlar','birimler','urun_turleri'}:
            raise ValueError('Geçersiz tanım tablosu')
        dup = self.definition_duplicate(table, code, name, item_id)
        if dup:
            field_name = 'kodu' if dup['field']=='kod' else 'adı'
            raise ValueError(f"Bu {field_name} zaten kayıtlı: {dup['row']['kod']} - {dup['row']['ad']}")
        if item_id:
            self.conn.execute(f"UPDATE {table} SET kod=?, ad=?, aktif=? WHERE id=?", (code, name, active, item_id))
        else:
            self.conn.execute(f"INSERT INTO {table}(kod, ad, aktif) VALUES (?, ?, ?)", (code, name, active))
        self.conn.commit()

    def deactivate_definition(self, table, item_id):
        if table == 'urun_gruplari':
            used = self.conn.execute("SELECT COUNT(*) FROM urunler WHERE grup_id=?", (item_id,)).fetchone()[0]
            self.conn.execute("UPDATE urun_gruplari SET aktif=0 WHERE id=?", (item_id,))
            self.conn.commit()
            return used
        if table == 'depolar':
            used = self.conn.execute("SELECT COUNT(*) FROM stok_hareketleri WHERE depo_id=?", (item_id,)).fetchone()[0]
            self.conn.execute("UPDATE depolar SET aktif=0 WHERE id=?", (item_id,))
            self.conn.commit()
            return used
        if table == 'departmanlar':
            used = self.conn.execute("SELECT COUNT(*) FROM stok_hareketleri WHERE departman_id=?", (item_id,)).fetchone()[0]
            self.conn.execute("UPDATE departmanlar SET aktif=0 WHERE id=?", (item_id,))
            self.conn.commit()
            return used
        if table == 'birimler':
            used = self.conn.execute("SELECT COUNT(*) FROM urunler WHERE birim_id=?", (item_id,)).fetchone()[0]
            self.conn.execute("UPDATE birimler SET aktif=0 WHERE id=?", (item_id,))
            self.conn.commit()
            return used

    def delete_definition(self, table, item_id):
        """Tanım kaydını fiziksel olarak siler; geçmiş hareketlerle ilişkiliyse silmeye izin vermez."""
        allowed = {"departmanlar"}
        if table not in allowed:
            raise ValueError("Bu tanım için fiziksel silme desteklenmiyor.")
        if table == "departmanlar":
            movement_count = self.conn.execute(
                "SELECT COUNT(*) FROM stok_hareketleri WHERE departman_id=?", (item_id,)
            ).fetchone()[0]
            slip_count = self.conn.execute(
                "SELECT COUNT(*) FROM stok_fisleri WHERE departman_id=?", (item_id,)
            ).fetchone()[0]
            if movement_count or slip_count:
                return {"deleted": False, "reason": "used", "movement_count": movement_count, "slip_count": slip_count}
            self.conn.execute("DELETE FROM departmanlar WHERE id=?", (item_id,))
            self.conn.commit()
            return {"deleted": True, "reason": "deleted"}

    def definition_duplicate(self, table, code, name, item_id=None):
        """Case/space-insensitive duplicate check for definition code/name."""
        allowed = {'urun_gruplari','depolar','departmanlar','birimler','urun_turleri'}
        if table not in allowed:
            raise ValueError('Geçersiz tanım tablosu')
        code_key = self._normalize_key(code)
        name_key = self._normalize_key(name)
        rows = self.conn.execute(f"SELECT id,kod,ad FROM {table}").fetchall()
        for row in rows:
            if item_id is not None and row['id'] == item_id:
                continue
            if code_key and self._normalize_key(row['kod']) == code_key:
                return {'field':'kod','row':row}
            if name_key and self._normalize_key(row['ad']) == name_key:
                return {'field':'ad','row':row}
        return None

    def definition_usage(self, table, item_id):
        """Return historical references that prevent safe physical deletion."""
        checks = []
        if table == 'urun_gruplari':
            checks = [('Ürünler', 'SELECT COUNT(*) FROM urunler WHERE grup_id=?')]
        elif table == 'urun_turleri':
            checks = [('Ürünler', 'SELECT COUNT(*) FROM urunler WHERE urun_turu_id=?')]
        elif table == 'birimler':
            checks = [('Ürünler', 'SELECT COUNT(*) FROM urunler WHERE birim_id=?')]
        elif table == 'departmanlar':
            checks = [
                ('Alt birimler', 'SELECT COUNT(*) FROM departman_alt_birimleri WHERE departman_id=?'),
                ('Stok hareketleri', 'SELECT COUNT(*) FROM stok_hareketleri WHERE departman_id=?'),
                ('Stok fişleri', 'SELECT COUNT(*) FROM stok_fisleri WHERE departman_id=?'),
            ]
        elif table == 'depolar':
            checks = [
                ('Stok hareketleri', 'SELECT COUNT(*) FROM stok_hareketleri WHERE depo_id=?'),
                ('Stok fişleri', 'SELECT COUNT(*) FROM stok_fisleri WHERE depo_id=?'),
                ('Sayım fişleri', 'SELECT COUNT(*) FROM sayim_fisleri WHERE depo_id=?'),
                ('Transfer (kaynak)', 'SELECT COUNT(*) FROM stok_transferleri WHERE kaynak_depo_id=?'),
                ('Transfer (hedef)', 'SELECT COUNT(*) FROM stok_transferleri WHERE hedef_depo_id=?'),
                ('Devir satırları', 'SELECT COUNT(*) FROM stok_devir_satirlari WHERE depo_id=?'),
                ('Dönem kapanışları', 'SELECT COUNT(*) FROM stok_donem_kapanislari WHERE depo_id=?'),
            ]
        else:
            raise ValueError('Geçersiz tanım tablosu')
        result = []
        total = 0
        for label, sql in checks:
            n = int(self.conn.execute(sql, (item_id,)).fetchone()[0])
            if n:
                result.append((label, n))
                total += n
        return total, result

    def delete_definition_safe(self, table, item_id):
        """Delete if unused; otherwise deactivate and preserve history."""
        allowed = {'urun_gruplari','depolar','departmanlar','birimler','urun_turleri'}
        if table not in allowed:
            raise ValueError('Geçersiz tanım tablosu')
        usage_total, usage = self.definition_usage(table, item_id)
        if usage_total:
            self.conn.execute(f"UPDATE {table} SET aktif=0 WHERE id=?", (item_id,))
            self.conn.commit()
            return {'deleted':False,'deactivated':True,'usage':usage}
        if table == 'departmanlar':
            self.conn.execute('DELETE FROM departman_alt_birimleri WHERE departman_id=?', (item_id,))
        self.conn.execute(f"DELETE FROM {table} WHERE id=?", (item_id,))
        self.conn.commit()
        return {'deleted':True,'deactivated':False,'usage':[]}

    def cari_usage(self, item_id):
        checks = [
            ('Stok hareketleri', 'SELECT COUNT(*) FROM stok_hareketleri WHERE cari_id=?'),
            ('Stok fişleri', 'SELECT COUNT(*) FROM stok_fisleri WHERE cari_id=?'),
        ]
        usage=[]; total=0
        for label, sql in checks:
            n=int(self.conn.execute(sql,(item_id,)).fetchone()[0])
            if n: usage.append((label,n)); total += n
        return total, usage

    def delete_cari_safe(self, item_id):
        total, usage = self.cari_usage(item_id)
        if total:
            self.conn.execute('UPDATE cariler SET aktif=0 WHERE id=?',(item_id,))
            self.conn.commit()
            return {'deleted':False,'deactivated':True,'usage':usage}
        self.conn.execute('DELETE FROM cariler WHERE id=?',(item_id,))
        self.conn.commit()
        return {'deleted':True,'deactivated':False,'usage':[]}

    def delete_subunit(self, item_id):
        movement_count = self.conn.execute(
            "SELECT COUNT(*) FROM stok_hareketleri WHERE alt_birim_id=?", (item_id,)
        ).fetchone()[0]
        slip_count = self.conn.execute(
            "SELECT COUNT(*) FROM stok_fisleri WHERE alt_birim_id=?", (item_id,)
        ).fetchone()[0]
        if movement_count or slip_count:
            return {"deleted": False, "reason": "used", "movement_count": movement_count, "slip_count": slip_count}
        self.conn.execute("DELETE FROM departman_alt_birimleri WHERE id=?", (item_id,))
        self.conn.commit()
        return {"deleted": True, "reason": "deleted"}

    def restore_definition(self, table, item_id):
        if table not in {'urun_gruplari','depolar','departmanlar','birimler','urun_turleri'}:
            raise ValueError('Geçersiz tanım tablosu')
        self.conn.execute(f"UPDATE {table} SET aktif=1 WHERE id=?", (item_id,))
        self.conn.commit()

    def list_products(self, code="", name="", group_id=None, active_only=False, product_type_id=None, brand="", model=""):
        q = """
            SELECT u.*, g.ad AS grup_adi, t.ad AS urun_turu_adi,
                   COALESCE((SELECT SUM(CASE WHEN sh.islem_tipi IN ('Giriş','İade') THEN sh.miktar ELSE -sh.miktar END)
                             FROM stok_hareketleri sh WHERE sh.urun_id=u.id), 0) AS mevcut
            FROM urunler u
            LEFT JOIN urun_gruplari g ON g.id=u.grup_id
            LEFT JOIN urun_turleri t ON t.id=u.urun_turu_id
            WHERE 1=1
        """
        p = []
        if code.strip():
            q += " AND u.kod LIKE ? COLLATE NOCASE"
            p.append(f"%{code.strip()}%")
        if name.strip():
            q += " AND u.ad LIKE ? COLLATE NOCASE"
            p.append(f"%{name.strip()}%")
        if group_id:
            q += " AND u.grup_id=?"
            p.append(group_id)
        if product_type_id:
            q += " AND u.urun_turu_id=?"
            p.append(product_type_id)
        if brand.strip():
            q += " AND u.marka LIKE ? COLLATE NOCASE"
            p.append(f"%{brand.strip()}%")
        if model.strip():
            q += " AND u.model LIKE ? COLLATE NOCASE"
            p.append(f"%{model.strip()}%")
        if active_only:
            q += " AND u.aktif=1"
        q += " ORDER BY u.kod"
        return self.conn.execute(q, p).fetchall()

    def ensure_sayim_no(self):
        row = self.conn.execute("SELECT sayim_no FROM sayim_fisleri ORDER BY id DESC LIMIT 1").fetchone()
        if not row or not row[0]:
            return "SAY0001"
        m = re.search(r"(\d+)$", str(row[0]))
        n = int(m.group(1)) + 1 if m else 1
        return f"SAY{n:04d}"

    def inventory_count_products(self, depot_id, search=""):
        params=[depot_id]
        where="WHERE u.aktif=1"
        if search.strip():
            like=f"%{search.strip()}%"
            where += " AND (u.kod LIKE ? OR u.ad LIKE ? OR COALESCE(u.barkod,'') LIKE ? OR COALESCE(u.marka,'') LIKE ? OR COALESCE(u.model,'') LIKE ?)"
            params += [like,like,like,like,like]
        q=f"""
            SELECT u.id,u.kod,u.ad,u.barkod,COALESCE(u.birim,'ADET') AS birim,
                   COALESCE(u.marka,'') AS marka, COALESCE(u.model,'') AS model,
                   COALESCE((SELECT SUM(CASE WHEN sh.islem_tipi IN ('Giriş','İade') THEN sh.miktar ELSE -sh.miktar END)
                             FROM stok_hareketleri sh WHERE sh.urun_id=u.id AND sh.depo_id=?),0) AS mevcut
            FROM urunler u
            {where}
            ORDER BY u.kod
        """
        # depot_id is already used in the correlated subquery parameter.
        return self.conn.execute(q, [depot_id]+params[1:]).fetchall()

    def validate_transaction_date(self, date_text, warehouse_ids=None):
        """Kapalı döneme geçmiş tarihli stok işlemi yazılmasını engeller."""
        try: ids=[int(x) for x in (warehouse_ids if isinstance(warehouse_ids,(list,tuple,set)) else [warehouse_ids]) if x is not None]
        except Exception: ids=[]
        locks=self.conn.execute("SELECT tarih,depo_id FROM stok_donem_kapanislari WHERE COALESCE(durum,'Tamamlandı')<>'İptal' AND kilitleme_tarihi IS NOT NULL ORDER BY tarih DESC").fetchall()
        for lock in locks:
            if str(date_text) <= str(lock['tarih']):
                if lock['depo_id'] is None or not ids or any(int(lock['depo_id'])==x for x in ids):
                    raise ValueError(f"{lock['tarih']} tarihinde dönem kapatılmıştır. Bu tarihe veya öncesine yeni stok işlemi kaydedilemez. Önce dönem kapanışını iptal edin veya doğru dönemi seçin.")
        return True

    def _acquire_stock_locks(self, product_warehouse_pairs):
        """PostgreSQL'de aynı ürün/depo üzerinde eşzamanlı değişiklikleri sıralar. SQLite'ta no-op."""
        if self.backend != "postgresql":
            return
        seen=set()
        for pid, wid in product_warehouse_pairs:
            key = int.from_bytes(hashlib.sha256(f"stock:{int(pid)}:{int(wid)}".encode("utf-8")).digest()[:8], "big", signed=False)
            if key >= 2**63: key -= 2**64
            if key in seen: continue
            seen.add(key)
            self.conn.execute("SELECT pg_advisory_xact_lock(?)", (key,)).fetchone()

    def save_inventory_count(self, depot_id, date_text, description, lines, user_id=None):
        self.validate_transaction_date(date_text, depot_id)
        if not lines:
            raise ValueError("Sayım fişinde en az bir ürün olmalıdır.")
        sayim_no=self.ensure_sayim_no()
        now=datetime.now().isoformat(timespec='seconds')
        with self.conn:
            self._acquire_stock_locks([(int(line['urun_id']), int(depot_id)) for line in lines])
            cur=self.conn.execute("INSERT INTO sayim_fisleri(sayim_no,tarih,depo_id,aciklama,kullanici_id) VALUES(?,?,?,?,?)",
                                  (sayim_no,date_text,depot_id,description,user_id))
            sayim_id=cur.lastrowid
            for line in lines:
                current=self.stock_balance(line['urun_id'], depot_id)
                # UI modeli 'sayilan' alanını kullanıyor; eski/harici çağrılar
                # 'sayilan_miktar' gönderebilir. Her iki biçimi de kabul et.
                raw_counted = line.get('sayilan', line.get('sayilan_miktar'))
                if raw_counted is None:
                    raise ValueError(f"{line.get('kod','Ürün')} için sayılan miktar girilmemiş.")
                counted = float(raw_counted)
                if counted < 0:
                    raise ValueError(f"{line['kod']} için sayılan miktar negatif olamaz.")
                diff=counted-current
                self.conn.execute("INSERT INTO sayim_satirlari(sayim_id,urun_id,sistem_miktari,sayilan_miktar,fark,aciklama) VALUES(?,?,?,?,?,?)",
                                  (sayim_id,line['urun_id'],current,counted,diff,line.get('aciklama','')))
                if abs(diff) > 1e-9:
                    self.conn.execute(
                        "INSERT INTO stok_hareketleri(tarih,fis_no,islem_tipi,urun_id,depo_id,miktar,birim_fiyat,cari_id,departman_id,alt_birim_id,teslim_eden,teslim_alan,aciklama) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                        (date_text,sayim_no,'Giriş' if diff>0 else 'Çıkış',line['urun_id'],depot_id,abs(diff),0,None,None,None,None,None,
                         f"Stok sayım düzeltmesi | Sistem: {current:g} | Sayılan: {counted:g} | Fark: {diff:g}"))
            return sayim_id, sayim_no

    def ensure_transfer_no(self):
        row = self.conn.execute("SELECT transfer_no FROM stok_transferleri ORDER BY id DESC LIMIT 1").fetchone()
        if not row or not row[0]: return "TRF0001"
        m = re.search(r"(\d+)$", str(row[0])); n = int(m.group(1)) + 1 if m else 1
        return f"TRF{n:04d}"

    def list_inventory_counts(self, start_date=None, end_date=None, warehouse_id=None, search=None):
        q = """SELECT sf.id,sf.sayim_no,sf.tarih,sf.depo_id,sf.aciklama,sf.olusturma_tarihi,sf.durum,
                     d.kod AS depo_kodu,d.ad AS depo_adi,
                     COALESCE(k.ad_soyad,k.kullanici_adi,'') AS kullanici,
                     (SELECT COUNT(*) FROM sayim_satirlari ss WHERE ss.sayim_id=sf.id) AS satir_sayisi,
                     COALESCE((SELECT SUM(ABS(ss.fark)) FROM sayim_satirlari ss WHERE ss.sayim_id=sf.id),0) AS toplam_mutlak_fark,
                     COALESCE((SELECT SUM(CASE WHEN ss.fark>0 THEN ss.fark ELSE 0 END) FROM sayim_satirlari ss WHERE ss.sayim_id=sf.id),0) AS toplam_fazla,
                     COALESCE((SELECT SUM(CASE WHEN ss.fark<0 THEN -ss.fark ELSE 0 END) FROM sayim_satirlari ss WHERE ss.sayim_id=sf.id),0) AS toplam_eksik
              FROM sayim_fisleri sf JOIN depolar d ON d.id=sf.depo_id
              LEFT JOIN kullanicilar k ON k.id=sf.kullanici_id WHERE 1=1"""
        params=[]
        if start_date: q += " AND sf.tarih>=?"; params.append(start_date)
        if end_date: q += " AND sf.tarih<=?"; params.append(end_date)
        if warehouse_id: q += " AND sf.depo_id=?"; params.append(warehouse_id)
        if search:
            q += " AND (sf.sayim_no LIKE ? OR sf.aciklama LIKE ? OR d.kod LIKE ? OR d.ad LIKE ?)"
            t=f"%{search}%"; params += [t,t,t,t]
        q += " ORDER BY sf.id DESC"
        return self.conn.execute(q,params).fetchall()

    def inventory_count_details(self, sayim_id):
        return self.conn.execute("""SELECT ss.*,u.kod AS urun_kodu,u.ad AS urun_adi,u.barkod,COALESCE(u.birim,'ADET') AS birim,
                                           sf.sayim_no,sf.tarih,d.kod AS depo_kodu,d.ad AS depo_adi
                                    FROM sayim_satirlari ss JOIN urunler u ON u.id=ss.urun_id
                                    JOIN sayim_fisleri sf ON sf.id=ss.sayim_id JOIN depolar d ON d.id=sf.depo_id
                                    WHERE ss.sayim_id=? ORDER BY u.kod""",(sayim_id,)).fetchall()

    def inventory_difference_report(self, start_date=None, end_date=None, warehouse_id=None, product_search=None):
        q = """SELECT sf.sayim_no,sf.tarih,d.kod AS depo_kodu,d.ad AS depo_adi,
                     u.kod AS urun_kodu,u.ad AS urun_adi,COALESCE(u.barkod,'') AS barkod,COALESCE(u.birim,'ADET') AS birim,
                     ss.sistem_miktari,ss.sayilan_miktar,ss.fark,
                     CASE WHEN ss.fark>0 THEN 'Fazla' WHEN ss.fark<0 THEN 'Eksik' ELSE 'Eşit' END AS durum,
                     COALESCE(k.ad_soyad,k.kullanici_adi,'') AS kullanici,ss.aciklama
              FROM sayim_satirlari ss JOIN sayim_fisleri sf ON sf.id=ss.sayim_id JOIN depolar d ON d.id=sf.depo_id
              JOIN urunler u ON u.id=ss.urun_id LEFT JOIN kullanicilar k ON k.id=sf.kullanici_id WHERE sf.durum='Aktif'"""
        params=[]
        if start_date: q += " AND sf.tarih>=?"; params.append(start_date)
        if end_date: q += " AND sf.tarih<=?"; params.append(end_date)
        if warehouse_id: q += " AND sf.depo_id=?"; params.append(warehouse_id)
        if product_search:
            q += " AND (u.kod LIKE ? OR u.ad LIKE ? OR u.barkod LIKE ? OR u.marka LIKE ? OR u.model LIKE ?)"
            t=f"%{product_search}%"; params += [t]*5
        q += " ORDER BY sf.id DESC,u.kod"
        return self.conn.execute(q,params).fetchall()

    def save_stock_transfer(self, source_depot_id, target_depot_id, date_text, lines, user_id=None, description=''):
        self.validate_transaction_date(date_text, [source_depot_id, target_depot_id])
        if source_depot_id == target_depot_id: raise ValueError('Kaynak ve hedef depo aynı olamaz.')
        if not lines: raise ValueError('Transfer fişinde en az bir ürün bulunmalıdır.')
        requested={}
        for line in lines:
            pid=int(line['urun_id']); qty=float(line['miktar'])
            if qty <= 0: raise ValueError('Transfer miktarı sıfırdan büyük olmalıdır.')
            requested[pid]=requested.get(pid,0)+qty
        shortages=[]
        for pid,qty in requested.items():
            bal=self.stock_balance(pid,source_depot_id)
            if bal+1e-9 < qty:
                prod=self.get_product(pid); shortages.append(f"{prod['kod']} - {prod['ad']}: Mevcut {bal:,.3f} / Transfer {qty:,.3f}")
        if shortages: raise ValueError('Kaynak depoda yeterli stok yok.\n\n'+'\n'.join(shortages))
        no=self.ensure_transfer_no()
        with self.conn:
            self._acquire_stock_locks([(int(line['urun_id']), int(source_depot_id)) for line in lines] + [(int(line['urun_id']), int(target_depot_id)) for line in lines])
            cur=self.conn.execute('INSERT INTO stok_transferleri(transfer_no,tarih,kaynak_depo_id,hedef_depo_id,kullanici_id,aciklama) VALUES(?,?,?,?,?,?)',(no,date_text,source_depot_id,target_depot_id,user_id,description)); tid=cur.lastrowid
            for line in lines:
                pid=int(line['urun_id']); qty=float(line['miktar']); note=line.get('aciklama','')
                self.conn.execute('INSERT INTO stok_transfer_satirlari(transfer_id,urun_id,miktar,aciklama) VALUES(?,?,?,?)',(tid,pid,qty,note))
                self.conn.execute("INSERT INTO stok_hareketleri(tarih,fis_no,islem_tipi,urun_id,depo_id,miktar,birim_fiyat,aciklama) VALUES(?,?,?,?,?,?,?,?)",(date_text,no,'Çıkış',pid,source_depot_id,qty,0,f'Depolar arası transfer → {target_depot_id}'))
                self.conn.execute("INSERT INTO stok_hareketleri(tarih,fis_no,islem_tipi,urun_id,depo_id,miktar,birim_fiyat,aciklama) VALUES(?,?,?,?,?,?,?,?)",(date_text,no,'Giriş',pid,target_depot_id,qty,0,f'Depolar arası transfer ← {source_depot_id}'))
        return tid,no

    def list_stock_transfers(self, start_date=None, end_date=None, source_depot_id=None, target_depot_id=None, search=None):
        q="""SELECT st.*,sd.kod AS kaynak_kod,sd.ad AS kaynak_ad,td.kod AS hedef_kod,td.ad AS hedef_ad,
                     COALESCE(k.ad_soyad,k.kullanici_adi,'') AS kullanici,
                     (SELECT COUNT(*) FROM stok_transfer_satirlari sts WHERE sts.transfer_id=st.id) AS satir_sayisi,
                     COALESCE((SELECT SUM(sts.miktar) FROM stok_transfer_satirlari sts WHERE sts.transfer_id=st.id),0) AS toplam_miktar
              FROM stok_transferleri st JOIN depolar sd ON sd.id=st.kaynak_depo_id JOIN depolar td ON td.id=st.hedef_depo_id
              LEFT JOIN kullanicilar k ON k.id=st.kullanici_id WHERE 1=1"""
        params=[]
        if start_date:q+=' AND st.tarih>=?';params.append(start_date)
        if end_date:q+=' AND st.tarih<=?';params.append(end_date)
        if source_depot_id:q+=' AND st.kaynak_depo_id=?';params.append(source_depot_id)
        if target_depot_id:q+=' AND st.hedef_depo_id=?';params.append(target_depot_id)
        if search:
            q+=' AND (st.transfer_no LIKE ? OR st.aciklama LIKE ? OR sd.kod LIKE ? OR sd.ad LIKE ? OR td.kod LIKE ? OR td.ad LIKE ?)'; t=f"%{search}%"; params += [t]*6
        return self.conn.execute(q+' ORDER BY st.id DESC',params).fetchall()

    def get_product(self, product_id):
        return self.conn.execute("SELECT * FROM urunler WHERE id=?", (product_id,)).fetchone()

    @staticmethod
    def _normalize_key(value):
        return re.sub(r"\s+", " ", str(value or "").strip()).casefold()

    def product_duplicate_fields(self, barkod=None, uretici_kodu=None, product_id=None):
        """Barkod ve üretici kodunun başka bir aktif üründe kullanılıp kullanılmadığını kontrol eder.
        Düzenleme sırasında kontrol edilen ürünün kendi kaydı kesin olarak hariç tutulur.
        """
        result = {"barkod": [], "uretici_kodu": []}
        candidates = self.conn.execute(
            "SELECT id, kod, ad, barkod, uretici_kodu FROM urunler WHERE aktif=1"
        ).fetchall()
        barkod_key = self._normalize_key(barkod) if str(barkod or "").strip() else ""
        uretici_key = self._normalize_key(uretici_kodu) if str(uretici_kodu or "").strip() else ""

        try:
            current_id = int(product_id) if product_id is not None else None
        except (TypeError, ValueError):
            current_id = None

        for row in candidates:
            try:
                row_id = int(row["id"])
            except (TypeError, ValueError):
                row_id = row["id"]
            if current_id is not None and row_id == current_id:
                continue
            if barkod_key and self._normalize_key(row["barkod"]) == barkod_key:
                result["barkod"].append(row)
            if uretici_key and self._normalize_key(row["uretici_kodu"]) == uretici_key:
                result["uretici_kodu"].append(row)
        return result

    def cari_duplicate_unvan(self, unvan, cari_id=None):
        """Cari ünvanının mevcut cariler arasında tekrar edip etmediğini kontrol eder."""
        key = self._normalize_key(unvan)
        if not key:
            return None
        rows = self.conn.execute("SELECT id, kod, unvan FROM cariler").fetchall()
        for row in rows:
            if cari_id is not None and row["id"] == cari_id:
                continue
            if self._normalize_key(row["unvan"]) == key:
                return row
        return None

    def save_product(self, data, product_id=None):
        fields = [
            "kod", "ad", "barkod", "grup_id", "birim", "birim_id", "min_seviye", "max_seviye", "urun_turu_id",
            "uretici_kodu", "uretici", "urun_tipi", "marka", "model", "kdv",
            "alis_fiyati", "satis_fiyati", "raf_bilgisi", "aciklama", "notlar", "resim_yolu", "demirbas_no", "aktif"
        ]
        values = [data.get(k) for k in fields]
        if product_id:
            self.conn.execute(
                f"UPDATE urunler SET {', '.join(f'{f}=?' for f in fields)} WHERE id=?",
                values + [product_id],
            )
        else:
            placeholders = ",".join("?" for _ in fields)
            self.conn.execute(f"INSERT INTO urunler({','.join(fields)}) VALUES({placeholders})", values)
        self.conn.commit()

    def delete_product(self, product_id):
        # Geçmişte hareketi olan ürünü fiziksel silmek yerine pasifleştiriyoruz.
        count = self.conn.execute("SELECT COUNT(*) FROM stok_hareketleri WHERE urun_id=?", (product_id,)).fetchone()[0]
        if count:
            self.conn.execute("UPDATE urunler SET aktif=0 WHERE id=?", (product_id,))
        else:
            self.conn.execute("DELETE FROM urunler WHERE id=?", (product_id,))
        self.conn.commit()
        return count > 0

    def ensure_kapanis_no(self):
        row = self.conn.execute("SELECT kapanis_no FROM stok_donem_kapanislari ORDER BY id DESC LIMIT 1").fetchone()
        if not row or not row[0]:
            return "KAP000001"
        m = re.search(r"(\d+)$", str(row[0]))
        n = int(m.group(1)) + 1 if m else 1
        return f"KAP{n:06d}"

    def period_close_control(self, date_text, warehouse_id=None):
        """Yıl sonu/dönem kapanışı öncesi kontrol özeti."""
        params=[]
        scope_sql=""
        if warehouse_id:
            scope_sql=" AND sh.depo_id=?"; params.append(warehouse_id)
        future = self.conn.execute(
            f"SELECT COUNT(*) FROM stok_hareketleri sh WHERE sh.tarih>?{scope_sql}",
            [date_text] + params
        ).fetchone()[0]

        negative_rows = 0
        negative_qty = 0.0
        nonzero_rows = 0
        total_value = 0.0
        depots = self.conn.execute("SELECT id FROM depolar WHERE aktif=1" + (" AND id=?" if warehouse_id else "") + " ORDER BY id", ((warehouse_id,) if warehouse_id else ())).fetchall()
        for d in depots:
            rows = self.conn.execute("""SELECT COALESCE((SELECT SUM(CASE WHEN sh.islem_tipi IN ('Giriş','İade') THEN sh.miktar ELSE -sh.miktar END)
                        FROM stok_hareketleri sh WHERE sh.urun_id=u.id AND sh.depo_id=? AND sh.tarih<=?),0) AS bakiye,
                        COALESCE(u.alis_fiyati,0) AS alis_fiyati
                        FROM urunler u WHERE u.aktif=1""", (d['id'], date_text)).fetchall()
            for r in rows:
                qty=float(r['bakiye'] or 0)
                if abs(qty) > 1e-12:
                    nonzero_rows += 1
                    total_value += qty * float(r['alis_fiyati'] or 0)
                if qty < -1e-12:
                    negative_rows += 1
                    negative_qty += qty
        return {
            'future_movements': int(future),
            'negative_rows': int(negative_rows),
            'negative_qty': float(negative_qty),
            'nonzero_rows': int(nonzero_rows),
            'total_value': float(total_value),
        }

    def _ensure_period(self, code, name, start_date, end_date, user_id=None, previous_id=None):
        row=self.conn.execute("SELECT * FROM stok_donemleri WHERE kod=?", (code,)).fetchone()
        if row:
            return row['id']
        now=datetime.now().isoformat(timespec='seconds')
        cur=self.conn.execute("INSERT INTO stok_donemleri(kod,ad,baslangic_tarihi,bitis_tarihi,durum,onceki_donem_id,olusturma_tarihi,kullanici_id) VALUES(?,?,?,?,?,?,?,?)",
                              (code,name,start_date,end_date,'Açık',previous_id,now,user_id))
        self.conn.commit()
        return cur.lastrowid

    def create_period_close(self, date_text, warehouse_id=None, description="", user_id=None, devir_turu="Bakiyeli Devir", next_period_code=None, next_period_name=None, next_start=None, lock_period=True, control_override=False):
        """Dönem/yıl sonu kapanışı: snapshot + yeni dönem açılış bakiyesi kaydı.
        Mevcut tarihsel stok hareketleri değiştirilmez. PostgreSQL/SQLite farkı gözetilmeden
        transaction açıkça commit/rollback edilir; connection context manager kullanılmaz."""
        if warehouse_id:
            depots = self.conn.execute("SELECT id,kod,ad FROM depolar WHERE id=? AND aktif=1", (warehouse_id,)).fetchall()
            if not depots:
                raise ValueError("Seçilen depo bulunamadı veya pasif.")
        else:
            depots = self.conn.execute("SELECT id,kod,ad FROM depolar WHERE aktif=1 ORDER BY kod").fetchall()
        if not depots:
            raise ValueError("Kapanış için aktif depo bulunamadı.")
        if warehouse_id:
            exists = self.conn.execute("SELECT 1 FROM stok_donem_kapanislari WHERE tarih=? AND depo_id=? AND COALESCE(durum,'Tamamlandı')<>'İptal' LIMIT 1", (date_text,warehouse_id)).fetchone()
        else:
            exists = self.conn.execute("SELECT 1 FROM stok_donem_kapanislari WHERE tarih=? AND depo_id IS NULL AND COALESCE(durum,'Tamamlandı')<>'İptal' LIMIT 1", (date_text,)).fetchone()
        if exists:
            raise ValueError("Bu tarih/kapsam için daha önce aktif bir dönem kapanışı oluşturulmuş.")

        control=self.period_close_control(date_text, warehouse_id)
        if control['future_movements']:
            raise ValueError(f"Kapanış tarihi sonrasında {control['future_movements']} adet stok hareketi bulunuyor. Önce bu ileri tarihli hareketleri kontrol edin.")
        if control['negative_rows'] and not control_override:
            raise ValueError(f"Seçilen kapsamda {control['negative_rows']} ürün/depo satırında negatif stok var. Kapanıştan önce düzeltin veya yönetici onayıyla tekrar deneyin.")

        kapanis_no=self.ensure_kapanis_no()
        now=datetime.now().isoformat(timespec='seconds')
        next_year=int(date_text[:4])+1
        next_period_code=(next_period_code or str(next_year)).strip()
        next_start=(next_start or f"{next_year}-01-01").strip()
        next_end=f"{next_year}-12-31"
        next_period_name=(next_period_name or f"{next_period_code} Dönemi").strip()
        snapshot_rows=[]
        try:
            cur=self.conn.execute("INSERT INTO stok_donem_kapanislari(kapanis_no,tarih,depo_id,aciklama,kullanici_id,olusturma_tarihi,durum,devir_turu,yeni_donem_kodu,kontrol_sonucu,kilitleme_tarihi) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                                  (kapanis_no,date_text,warehouse_id,description,user_id,now,'Tamamlandı',devir_turu,next_period_code,json.dumps(control,ensure_ascii=False),date_text if lock_period else None))
            kid=cur.lastrowid
            for dep in depots:
                rows=self.conn.execute("""SELECT u.id,u.alis_fiyati,
                               COALESCE((SELECT SUM(CASE WHEN sh.islem_tipi IN ('Giriş','İade') THEN sh.miktar ELSE -sh.miktar END)
                                         FROM stok_hareketleri sh WHERE sh.urun_id=u.id AND sh.depo_id=? AND sh.tarih<=?),0) AS bakiye
                        FROM urunler u WHERE u.aktif=1""",(dep['id'],date_text)).fetchall()
                for r in rows:
                    qty=float(r['bakiye'] or 0)
                    if abs(qty) < 1e-12:
                        continue
                    cost=float(r['alis_fiyati'] or 0)
                    snapshot_rows.append((dep['id'],r['id'],qty,cost,qty*cost))
                    self.conn.execute("INSERT INTO stok_devir_satirlari(kapanis_id,depo_id,urun_id,miktar,birim_maliyet,stok_degeri) VALUES(?,?,?,?,?,?)",(kid,dep['id'],r['id'],qty,cost,qty*cost))

            # Yeni dönem: devir türüne göre açılış bakiyesi oluştur.
            previous_period=self.conn.execute("SELECT id FROM stok_donemleri WHERE kod=?",(str(int(date_text[:4])),)).fetchone()
            previous_id=previous_period['id'] if previous_period else None
            cur_period=self.conn.execute("SELECT id FROM stok_donemleri WHERE kod=?",(next_period_code,)).fetchone()
            if cur_period:
                next_id=cur_period['id']
                self.conn.execute("UPDATE stok_donemleri SET ad=?,baslangic_tarihi=?,bitis_tarihi=?,durum='Açık',onceki_donem_id=?,kapanis_id=?,kullanici_id=? WHERE id=?",
                                  (next_period_name,next_start,next_end,previous_id,kid,user_id,next_id))
            else:
                c2=self.conn.execute("INSERT INTO stok_donemleri(kod,ad,baslangic_tarihi,bitis_tarihi,durum,onceki_donem_id,kapanis_id,olusturma_tarihi,kullanici_id) VALUES(?,?,?,?,?,?,?,?,?)",
                                    (next_period_code,next_period_name,next_start,next_end,'Açık',previous_id,kid,now,user_id))
                next_id=c2.lastrowid
            self.conn.execute("UPDATE stok_donem_kapanislari SET yeni_donem_id=? WHERE id=?",(next_id,kid))
            if devir_turu == 'Bakiyeli Devir':
                for dep_id,urun_id,qty,cost,value in snapshot_rows:
                    self.conn.execute("INSERT INTO stok_donem_acilis_stoklari(donem_id,kaynak_kapanis_id,depo_id,urun_id,miktar,birim_maliyet,stok_degeri) VALUES(?,?,?,?,?,?,?) ON CONFLICT(donem_id,depo_id,urun_id) DO UPDATE SET kaynak_kapanis_id=EXCLUDED.kaynak_kapanis_id,miktar=EXCLUDED.miktar,birim_maliyet=EXCLUDED.birim_maliyet,stok_degeri=EXCLUDED.stok_degeri" if self.backend=='postgresql' else "INSERT OR REPLACE INTO stok_donem_acilis_stoklari(donem_id,kaynak_kapanis_id,depo_id,urun_id,miktar,birim_maliyet,stok_degeri) VALUES(?,?,?,?,?,?,?)",(next_id,kid,dep_id,urun_id,qty,cost,value))
            elif devir_turu in ('Bakiyesiz Devir','Sadece Kartlar'):
                # Dönem oluşturulur; stok açılış bakiyesi oluşturulmaz.
                pass
            self.conn.execute("UPDATE stok_donem_kapanislari SET kontrol_sonucu=? WHERE id=?",(json.dumps(control,ensure_ascii=False),kid))
            self.conn.commit()
            return kid,kapanis_no,next_id,control
        except Exception:
            try:self.conn.rollback()
            except Exception: pass
            raise

    def list_period_closes(self, start_date=None, end_date=None, warehouse_id=None):
        q="""SELECT k.id,k.kapanis_no,k.tarih,k.depo_id,k.aciklama,k.olusturma_tarihi,
                     k.durum,k.devir_turu,k.yeni_donem_kodu,k.yeni_donem_id,
                     COALESCE(d.kod || ' - ' || d.ad,'Tüm Depolar') AS kapsam,
                     COALESCE(u.ad_soyad,u.kullanici_adi,'') AS kullanici,
                     (SELECT COUNT(*) FROM stok_devir_satirlari s WHERE s.kapanis_id=k.id) AS satir_sayisi,
                     COALESCE((SELECT SUM(s.miktar) FROM stok_devir_satirlari s WHERE s.kapanis_id=k.id),0) AS toplam_miktar,
                     COALESCE((SELECT SUM(s.stok_degeri) FROM stok_devir_satirlari s WHERE s.kapanis_id=k.id),0) AS toplam_deger
              FROM stok_donem_kapanislari k
              LEFT JOIN depolar d ON d.id=k.depo_id
              LEFT JOIN kullanicilar u ON u.id=k.kullanici_id WHERE 1=1"""
        p=[]
        if start_date:q+=" AND k.tarih>=?";p.append(start_date)
        if end_date:q+=" AND k.tarih<=?";p.append(end_date)
        if warehouse_id:q+=" AND k.depo_id=?";p.append(warehouse_id)
        q+=" ORDER BY k.tarih DESC,k.id DESC"
        return self.conn.execute(q,p).fetchall()

    def list_periods(self):
        return self.conn.execute("""SELECT d.*, k.kapanis_no FROM stok_donemleri d LEFT JOIN stok_donem_kapanislari k ON k.id=d.kapanis_id ORDER BY d.baslangic_tarihi DESC, d.id DESC""").fetchall()

    def cancel_period_close(self, close_id, user_id=None):
        row=self.conn.execute("SELECT * FROM stok_donem_kapanislari WHERE id=?",(close_id,)).fetchone()
        if not row: raise ValueError("Kapanış bulunamadı.")
        if str(row['durum'] or '') == 'İptal': raise ValueError("Bu kapanış zaten iptal edilmiş.")
        next_id=row['yeni_donem_id']
        next_start=None
        if next_id:
            p=self.conn.execute("SELECT * FROM stok_donemleri WHERE id=?",(next_id,)).fetchone()
            if p: next_start=p['baslangic_tarihi']
        if next_start:
            try:
                future_count=self.conn.execute("SELECT COUNT(*) FROM stok_hareketleri WHERE tarih>=?",(next_start,)).fetchone()[0]
                if future_count:
                    raise ValueError(f"Yeni dönemde {future_count} stok hareketi bulunduğu için kapanış iptal edilemez.")
            except KeyError:
                pass
        try:
            self.conn.execute("UPDATE stok_donem_kapanislari SET durum='İptal', kilitleme_tarihi=NULL, kontrol_sonucu=COALESCE(kontrol_sonucu,'') || ? WHERE id=?", ("\nİptal eden kullanıcı: " + str(user_id or ''), close_id))
            if next_id:
                self.conn.execute("UPDATE stok_donemleri SET durum='İptal', kapanis_id=NULL WHERE id=?",(next_id,))
                self.conn.execute("DELETE FROM stok_donem_acilis_stoklari WHERE donem_id=?",(next_id,))
            self.conn.commit()
        except Exception:
            self.conn.rollback(); raise

    def period_close_details(self, close_id):
        return self.conn.execute("""SELECT s.*,u.kod AS urun_kodu,u.ad AS urun_adi,u.barkod,u.birim,u.marka,u.model,
                                        d.kod AS depo_kodu,d.ad AS depo_adi
                                 FROM stok_devir_satirlari s
                                 JOIN urunler u ON u.id=s.urun_id
                                 JOIN depolar d ON d.id=s.depo_id
                                 WHERE s.kapanis_id=? ORDER BY d.kod,u.kod""",(close_id,)).fetchall()

    def comprehensive_stock_rows(self, warehouse_id=None, group_id=None, product_type_id=None, status='Tümü', search=''):
        params=[]
        stock_expr="COALESCE((SELECT SUM(CASE WHEN sh.islem_tipi IN ('Giriş','İade') THEN sh.miktar ELSE -sh.miktar END) FROM stok_hareketleri sh WHERE sh.urun_id=u.id"
        if warehouse_id:
            stock_expr += " AND sh.depo_id=?"; params.append(warehouse_id)
        stock_expr += "),0)"
        q=f"""SELECT u.id,u.kod,u.ad,u.birim,u.min_seviye,u.max_seviye,u.alis_fiyati,
                          COALESCE(g.ad,'') AS grup_adi,COALESCE(t.ad,'') AS urun_turu_adi,
                          COALESCE(u.marka,'') AS marka,COALESCE(u.model,'') AS model,
                          {stock_expr} AS mevcut
                   FROM urunler u
                   LEFT JOIN urun_gruplari g ON g.id=u.grup_id
                   LEFT JOIN urun_turleri t ON t.id=u.urun_turu_id
                   WHERE u.aktif=1"""
        if group_id:q+=" AND u.grup_id=?";params.append(group_id)
        if product_type_id:q+=" AND u.urun_turu_id=?";params.append(product_type_id)
        if search:
            like=f"%{search}%";q+=" AND (u.kod LIKE ? OR u.ad LIKE ? OR COALESCE(u.barkod,'') LIKE ? OR COALESCE(u.marka,'') LIKE ? OR COALESCE(u.model,'') LIKE ?)";params += [like]*5
        q+=" ORDER BY u.kod"
        rows=self.conn.execute(q,params).fetchall()
        out=[]
        for r in rows:
            cur=float(r['mevcut'] or 0); mn=float(r['min_seviye'] or 0); mx=float(r['max_seviye'] or 0)
            st='Negatif' if cur<0 else 'Minimum Altı' if mn and cur<mn else 'Maksimum Üstü' if mx and cur>mx else 'Normal' if cur!=0 else 'Sıfır'
            if status!='Tümü':
                wanted={'Negatif':'Negatif','Minimum Altı':'Minimum Altı','Maksimum Üstü':'Maksimum Üstü','Sıfır':'Sıfır','Normal':'Normal'}.get(status,status)
                if st!=wanted: continue
            d=dict(r); d['durum']=st; d['stok_degeri']=cur*float(r['alis_fiyati'] or 0); out.append(d)
        return out

    def warehouse_summary(self):
        out=[]
        for d in self.conn.execute("SELECT id,kod,ad FROM depolar WHERE aktif=1 ORDER BY kod").fetchall():
            rows=self.comprehensive_stock_rows(d['id'])
            out.append({'id':d['id'],'kod':d['kod'],'ad':d['ad'],'urun_sayisi':sum(1 for r in rows if abs(float(r['mevcut']))>1e-12),'toplam_miktar':sum(float(r['mevcut']) for r in rows),'stok_degeri':sum(float(r['stok_degeri']) for r in rows),'negatif':sum(1 for r in rows if r['durum']=='Negatif'),'min_alt':sum(1 for r in rows if r['durum']=='Minimum Altı')})
        return out

    def department_consumption(self, start_date, end_date, warehouse_id=None, department_id=None):
        # PostgreSQL, SELECT içindeki toplulaştırılmamış departman/alt birim alanlarının
        # GROUP BY içinde açıkça yer almasını ister. SQLite bu konuda daha gevşektir.
        q="""SELECT COALESCE(dp.kod || ' - ' || dp.ad,'Departmansız') AS departman,
                         COALESCE(ab.kod || ' - ' || ab.ad,'Alt Birimsiz') AS alt_birim,
                         COUNT(*) AS hareket, COALESCE(SUM(sh.miktar),0) AS miktar
                  FROM stok_hareketleri sh
                  LEFT JOIN departmanlar dp ON dp.id=sh.departman_id
                  LEFT JOIN departman_alt_birimleri ab ON ab.id=sh.alt_birim_id
                  WHERE sh.tarih>=? AND sh.tarih<=? AND sh.islem_tipi='Çıkış'"""
        p=[start_date,end_date]
        if warehouse_id:q+=" AND sh.depo_id=?";p.append(warehouse_id)
        if department_id:q+=" AND sh.departman_id=?";p.append(department_id)
        q+=" GROUP BY sh.departman_id, dp.kod, dp.ad, sh.alt_birim_id, ab.kod, ab.ad ORDER BY miktar DESC,departman,alt_birim"
        return self.conn.execute(q,p).fetchall()

    @staticmethod
    def hash_password(password):
        return hashlib.sha256((password or "").encode("utf-8")).hexdigest()

    def roles(self):
        return self.conn.execute("SELECT id, ad, aciklama, aktif FROM roller ORDER BY ad").fetchall()

    def users(self):
        return self.conn.execute("SELECT k.id, k.kullanici_adi, k.ad_soyad, k.aktif, k.olusturma_tarihi, k.son_giris, r.id AS rol_id, r.ad AS rol_adi FROM kullanicilar k LEFT JOIN roller r ON r.id=k.rol_id ORDER BY k.kullanici_adi").fetchall()

    def save_user(self, username, fullname, password, role_id, active, user_id=None):
        username=(username or "").strip(); fullname=(fullname or "").strip()
        if not username: raise ValueError("Kullanıcı adı boş bırakılamaz.")
        # Kullanıcı adını boşluk/büyük-küçük harf farkıyla tekrar oluşturmayı engelle.
        existing = self.conn.execute(
            "SELECT id, kullanici_adi FROM kullanicilar WHERE LOWER(TRIM(kullanici_adi)) = LOWER(TRIM(?))",
            (username,)
        ).fetchone()
        if existing is not None and (user_id is None or int(existing["id"]) != int(user_id)):
            raise sqlite3.IntegrityError("Bu kullanıcı adı zaten kayıtlı: " + str(existing["kullanici_adi"]))

        if user_id:
            if password:
                self.conn.execute("UPDATE kullanicilar SET kullanici_adi=?, ad_soyad=?, sifre_hash=?, rol_id=?, aktif=? WHERE id=?", (username,fullname,self.hash_password(password),role_id,int(active),user_id))
            else:
                self.conn.execute("UPDATE kullanicilar SET kullanici_adi=?, ad_soyad=?, rol_id=?, aktif=? WHERE id=?", (username,fullname,role_id,int(active),user_id))
        else:
            if not password: raise ValueError("Yeni kullanıcı için şifre girilmelidir.")
            self.conn.execute("INSERT INTO kullanicilar(kullanici_adi,ad_soyad,sifre_hash,rol_id,aktif) VALUES (?,?,?,?,?)", (username,fullname,self.hash_password(password),role_id,int(active)))
        self.conn.commit()

    def delete_user(self, user_id):
        self.conn.execute("DELETE FROM kullanicilar WHERE id=?", (user_id,)); self.conn.commit()

    def backup_to(self, destination):
        if self.backend == "postgresql":
            raise RuntimeError("PostgreSQL kullanımında SQLite dosya yedeği yerine PostgreSQL yedekleme yöntemi kullanılmalıdır.")
        destination=Path(destination); destination.parent.mkdir(parents=True,exist_ok=True); self.conn.commit()
        target=sqlite3.connect(str(destination))
        try:
            with target: self.conn.backup(target)
        finally: target.close()
        return destination

    def counts(self):
        return {
            "urun": self.conn.execute("SELECT COUNT(*) FROM urunler WHERE aktif=1").fetchone()[0],
            "depo": self.conn.execute("SELECT COUNT(*) FROM depolar WHERE aktif=1").fetchone()[0],
            "cari": self.conn.execute("SELECT COUNT(*) FROM cariler WHERE aktif=1").fetchone()[0],
            "hareket": self.conn.execute("SELECT COUNT(*) FROM stok_hareketleri").fetchone()[0],
        }

    def active_cariler(self):
        return self.conn.execute("SELECT id, kod, unvan FROM cariler WHERE aktif=1 ORDER BY unvan").fetchall()

    def ensure_fis_no(self, prefix):
        import re
        row = self.conn.execute(
            "SELECT fis_no FROM stok_fisleri WHERE fis_no LIKE ? ORDER BY id DESC LIMIT 1",
            (f"{prefix}%",)
        ).fetchone()
        if not row:
            return f"{prefix}000001"
        m = re.search(r"(\d+)$", row[0] or "")
        n = int(m.group(1)) + 1 if m else 1
        return f"{prefix}{n:06d}"

    def product_by_code_or_barcode(self, text):
        key = (text or '').strip()
        if not key:
            return None
        return self.conn.execute(
            "SELECT id, kod, ad, barkod, birim, birim_id, alis_fiyati, satis_fiyati "
            "FROM urunler WHERE aktif=1 AND (kod=? OR barkod=?) LIMIT 1",
            (key, key)
        ).fetchone()

    def stock_balance(self, product_id, warehouse_id=None):
        q = "SELECT COALESCE(SUM(CASE WHEN islem_tipi IN ('Giriş','İade') " \
            "THEN miktar ELSE -miktar END),0) FROM stok_hareketleri WHERE urun_id=?"
        params = [product_id]
        if warehouse_id:
            q += " AND depo_id=?"
            params.append(warehouse_id)
        return float(self.conn.execute(q, params).fetchone()[0] or 0)

    def save_stock_slip(self, header, lines):
        self.validate_transaction_date(header.get("tarih") or datetime.now().strftime("%Y-%m-%d"), header.get("depo_id"))
        if not lines:
            raise ValueError("Fişte en az bir ürün satırı bulunmalıdır.")
        islem = header["islem_tipi"]
        if islem not in ("Giriş", "Çıkış"):
            raise ValueError("Geçersiz işlem tipi.")

        # PostgreSQL çok kullanıcılı ortamında stok kontrolü ve kayıt aynı transaction içinde kilitlenir.
        self._pending_stock_locks = [(int(line["urun_id"]), int(header["depo_id"])) for line in lines]
        # PostgreSQL'de stok kontrolünden ÖNCE transaction advisory lock al.
        # Aynı ürün/depo için iki istemcinin aynı anda çıkış yarışına girmesini önler.
        self._acquire_stock_locks(self._pending_stock_locks)

        # Gerçek stok kontrolü: Çıkışlarda, kullanıcı açıkça izin vermediyse
        # ilgili depodaki mevcut stok 0 altına düşürülemez.
        if islem == "Çıkış" and not header.get("allow_negative", False):
            requested = {}
            for line in lines:
                pid = int(line["urun_id"])
                requested[pid] = requested.get(pid, 0.0) + float(line["miktar"] or 0)
            shortages = []
            for pid, qty in requested.items():
                available = self.stock_balance(pid, header["depo_id"])
                if available + 1e-9 < qty:
                    product = self.get_product(pid)
                    shortages.append(
                        f"{product['kod']} - {product['ad']}: Mevcut {available:,.3f} / Çıkış {qty:,.3f}"
                    )
            if shortages:
                try: self.conn.rollback()
                except Exception: pass
                raise ValueError(
                    "Yetersiz stok nedeniyle çıkış kaydedilemedi.\n\n" + "\n".join(shortages) +
                    "\n\n'Eksi stoğa izin ver' seçeneğini kullanırsanız işlem negatif bakiye oluşturabilir."
                )

        with self.conn:
            self._acquire_stock_locks(getattr(self, "_pending_stock_locks", []))
            cur = self.conn.execute(
                "INSERT INTO stok_fisleri "
                "(fis_no,tarih,islem_tipi,depo_id,cari_id,departman_id,alt_birim_id,"
                " teslim_eden,teslim_alan,aciklama) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (
                    header["fis_no"], header["tarih"], islem, header["depo_id"],
                    header.get("cari_id"), header.get("departman_id"), header.get("alt_birim_id"),
                    header.get("teslim_eden", ""), header.get("teslim_alan", ""), header.get("aciklama", "")
                )
            )
            fis_id = cur.lastrowid
            for line in lines:
                self.conn.execute(
                    "INSERT INTO stok_fis_satirlari(fis_id,urun_id,miktar,birim_fiyat,aciklama) "
                    "VALUES(?,?,?,?,?)",
                    (fis_id, line["urun_id"], line["miktar"], line.get("birim_fiyat", 0), line.get("aciklama", ""))
                )
                self.conn.execute(
                    "INSERT INTO stok_hareketleri "
                    "(tarih,fis_no,islem_tipi,urun_id,depo_id,miktar,birim_fiyat,cari_id,"
                    "departman_id,alt_birim_id,teslim_eden,teslim_alan,aciklama) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        header["tarih"], header["fis_no"], islem, line["urun_id"], header["depo_id"],
                        line["miktar"], line.get("birim_fiyat", 0), header.get("cari_id"),
                        header.get("departman_id"), header.get("alt_birim_id"),
                        header.get("teslim_eden", ""), header.get("teslim_alan", ""),
                        line.get("aciklama") or header.get("aciklama", "")
                    )
                )
        try: del self._pending_stock_locks
        except Exception: pass
        return fis_id

    def _log_operation(self, operation_type, reference_id, reference_no, user_id, description):
        self.conn.execute(
            "INSERT INTO islem_loglari(islem_turu,referans_id,referans_no,tarih,kullanici_id,aciklama) VALUES(?,?,?,?,?,?)",
            (operation_type, reference_id, reference_no, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), user_id, description or "")
        )

    def cancel_stock_slip(self, slip_id, user_id=None, reason=""):
        slip = self.conn.execute("SELECT * FROM stok_fisleri WHERE id=?", (slip_id,)).fetchone()
        if not slip:
            raise ValueError("Fiş bulunamadı.")
        if slip['durum'] == 'İptal':
            raise ValueError("Bu fiş daha önce iptal edilmiş.")
        lines = self.conn.execute("SELECT * FROM stok_fis_satirlari WHERE fis_id=? ORDER BY id", (slip_id,)).fetchall()
        if slip['islem_tipi'] == 'Giriş':
            shortages=[]
            for line in lines:
                available=self.stock_balance(line['urun_id'], slip['depo_id'])
                if available + 1e-9 < float(line['miktar']):
                    prod=self.get_product(line['urun_id'])
                    shortages.append(f"{prod['kod']} - {prod['ad']}: Mevcut {available:,.3f} / İptal edilmek istenen {float(line['miktar']):,.3f}")
            if shortages:
                raise ValueError("Fiş iptal edilemiyor; mevcut stok iptal edilecek giriş miktarının altında.\n\n"+'\n'.join(shortages))
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cancel_no = f"{slip['fis_no']}-IPTAL"
        with self.conn:
            for line in lines:
                reverse_type = 'Çıkış' if slip['islem_tipi'] == 'Giriş' else 'Giriş'
                self.conn.execute(
                    "INSERT INTO stok_hareketleri "
                    "(tarih,fis_no,islem_tipi,urun_id,depo_id,miktar,birim_fiyat,cari_id,departman_id,alt_birim_id,teslim_eden,teslim_alan,aciklama,iptal_hareketi) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,1)",
                    (now[:10], cancel_no, reverse_type, line['urun_id'], slip['depo_id'], line['miktar'], line['birim_fiyat'],
                     slip['cari_id'], slip['departman_id'], slip['alt_birim_id'], slip['teslim_eden'], slip['teslim_alan'],
                     f"{slip['fis_no']} numaralı fişin iptali | {reason or 'İptal'}")
                )
            self.conn.execute("UPDATE stok_fisleri SET durum='İptal', iptal_tarihi=?, iptal_kullanici_id=?, iptal_nedeni=? WHERE id=?",
                              (now, user_id, reason or '', slip_id))
            self._log_operation('Fiş İptali', slip_id, slip['fis_no'], user_id, reason or 'Fiş iptal edildi.')
        return cancel_no

    def cancel_inventory_count(self, sayim_id, user_id=None, reason=""):
        sayim = self.conn.execute("SELECT * FROM sayim_fisleri WHERE id=?", (sayim_id,)).fetchone()
        if not sayim:
            raise ValueError("Sayım bulunamadı.")
        if sayim['durum'] == 'İptal':
            raise ValueError("Bu sayım daha önce iptal edilmiş.")
        details = self.conn.execute("SELECT * FROM sayim_satirlari WHERE sayim_id=? AND ABS(fark)>1e-9 ORDER BY id", (sayim_id,)).fetchall()
        shortages=[]
        for line in details:
            if float(line['fark']) > 0:
                available=self.stock_balance(line['urun_id'], sayim['depo_id'])
                if available + 1e-9 < float(line['fark']):
                    prod=self.get_product(line['urun_id'])
                    shortages.append(f"{prod['kod']} - {prod['ad']}: Mevcut {available:,.3f} / İptal farkı {float(line['fark']):,.3f}")
        if shortages:
            raise ValueError("Sayım iptal edilemiyor; mevcut stok pozitif sayım farkının altında.\n\n"+'\n'.join(shortages))
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cancel_no = f"{sayim['sayim_no']}-IPTAL"
        with self.conn:
            for line in details:
                reverse_type = 'Çıkış' if float(line['fark']) > 0 else 'Giriş'
                qty = abs(float(line['fark']))
                self.conn.execute(
                    "INSERT INTO stok_hareketleri "
                    "(tarih,fis_no,islem_tipi,urun_id,depo_id,miktar,birim_fiyat,cari_id,departman_id,alt_birim_id,teslim_eden,teslim_alan,aciklama,iptal_hareketi) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,1)",
                    (now[:10], cancel_no, reverse_type, line['urun_id'], sayim['depo_id'], qty, 0, None, None, None, None, None,
                     f"{sayim['sayim_no']} numaralı sayımın iptali | {reason or 'İptal'}")
                )
            self.conn.execute("UPDATE sayim_fisleri SET durum='İptal', iptal_tarihi=?, iptal_kullanici_id=?, iptal_nedeni=? WHERE id=?",
                              (now, user_id, reason or '', sayim_id))
            self._log_operation('Sayım İptali', sayim_id, sayim['sayim_no'], user_id, reason or 'Sayım iptal edildi.')
        return cancel_no

    def cancel_stock_transfer(self, transfer_id, user_id=None, reason=""):
        tr = self.conn.execute("SELECT * FROM stok_transferleri WHERE id=?", (transfer_id,)).fetchone()
        if not tr:
            raise ValueError("Transfer bulunamadı.")
        if tr['durum'] == 'İptal':
            raise ValueError("Bu transfer daha önce iptal edilmiş.")
        lines = self.conn.execute("SELECT * FROM stok_transfer_satirlari WHERE transfer_id=? ORDER BY id", (transfer_id,)).fetchall()
        shortages=[]
        for line in lines:
            available=self.stock_balance(line['urun_id'], tr['hedef_depo_id'])
            if available + 1e-9 < float(line['miktar']):
                prod=self.get_product(line['urun_id'])
                shortages.append(f"{prod['kod']} - {prod['ad']}: Hedef depoda mevcut {available:,.3f} / İptal miktarı {float(line['miktar']):,.3f}")
        if shortages:
            raise ValueError("Transfer iptal edilemiyor; hedef depodaki mevcut stok transfer miktarının altında.\n\n"+'\n'.join(shortages))
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cancel_no = f"{tr['transfer_no']}-IPTAL"
        with self.conn:
            for line in lines:
                pid = line['urun_id']; qty = line['miktar']
                self.conn.execute(
                    "INSERT INTO stok_hareketleri(tarih,fis_no,islem_tipi,urun_id,depo_id,miktar,birim_fiyat,aciklama,iptal_hareketi) VALUES(?,?,?,?,?,?,?,?,1)",
                    (now[:10], cancel_no, 'Giriş', pid, tr['kaynak_depo_id'], qty, 0, f"{tr['transfer_no']} transfer iptali - kaynak depoya iade")
                )
                self.conn.execute(
                    "INSERT INTO stok_hareketleri(tarih,fis_no,islem_tipi,urun_id,depo_id,miktar,birim_fiyat,aciklama,iptal_hareketi) VALUES(?,?,?,?,?,?,?,?,1)",
                    (now[:10], cancel_no, 'Çıkış', pid, tr['hedef_depo_id'], qty, 0, f"{tr['transfer_no']} transfer iptali - hedef depodan düşüm")
                )
            self.conn.execute("UPDATE stok_transferleri SET durum='İptal', iptal_tarihi=?, iptal_kullanici_id=?, iptal_nedeni=? WHERE id=?",
                              (now, user_id, reason or '', transfer_id))
            self._log_operation('Transfer İptali', transfer_id, tr['transfer_no'], user_id, reason or 'Transfer iptal edildi.')
        return cancel_no

    def log_session(self, user_id, username, event, description=""):
        try:
            self.conn.execute(
                "INSERT INTO oturum_loglari(kullanici_id,kullanici_adi,tarih,olay,aciklama) VALUES(?,?,?,?,?)",
                (user_id, username or "", datetime.now().strftime("%Y-%m-%d %H:%M:%S"), event, description or "")
            )
            self.conn.commit()
        except Exception:
            try: self.conn.rollback()
            except Exception: pass

    def list_operation_logs(self, limit=1000):
        return self.conn.execute("""
            SELECT l.*, COALESCE(k.ad_soyad,k.kullanici_adi,'') AS kullanici
            FROM islem_loglari l LEFT JOIN kullanicilar k ON k.id=l.kullanici_id
            ORDER BY l.id DESC LIMIT ?
        """, (limit,)).fetchall()

    def list_stock_movements(self, start_date=None, end_date=None, warehouse_id=None,
                             product_id=None, movement_type=None, product_search=None,
                             product_type_id=None, group_id=None, brand=None, model=None,
                             department_id=None, alt_unit_id=None, barcode=None,
                             delivery_search=None):
        q = """SELECT sh.*, u.kod AS urun_kodu, u.ad AS urun_adi, u.barkod,
                       u.marka, u.model, pt.ad AS urun_turu_adi, ug.ad AS grup_adi,
                       d.kod AS depo_kodu, d.ad AS depo_adi,
                       dp.kod AS departman_kodu, dp.ad AS departman_adi,
                       ab.kod AS alt_birim_kodu, ab.ad AS alt_birim_adi
                FROM stok_hareketleri sh
                JOIN urunler u ON u.id=sh.urun_id
                JOIN depolar d ON d.id=sh.depo_id
                LEFT JOIN urun_turleri pt ON pt.id=u.urun_turu_id
                LEFT JOIN urun_gruplari ug ON ug.id=u.grup_id
                LEFT JOIN departmanlar dp ON dp.id=sh.departman_id
                LEFT JOIN departman_alt_birimleri ab ON ab.id=sh.alt_birim_id
                WHERE 1=1"""
        params = []
        if start_date: q += " AND sh.tarih>=?"; params.append(start_date)
        if end_date: q += " AND sh.tarih<=?"; params.append(end_date)
        if warehouse_id: q += " AND sh.depo_id=?"; params.append(warehouse_id)
        if product_id: q += " AND sh.urun_id=?"; params.append(product_id)
        if movement_type: q += " AND sh.islem_tipi=?"; params.append(movement_type)
        if product_search:
            term=f"%{product_search}%"; q += " AND (u.kod LIKE ? OR u.ad LIKE ? OR u.barkod LIKE ?)"; params.extend([term,term,term])
        if product_type_id: q += " AND u.urun_turu_id=?"; params.append(product_type_id)
        if group_id: q += " AND u.grup_id=?"; params.append(group_id)
        if brand: q += " AND u.marka LIKE ?"; params.append(f"%{brand}%")
        if model: q += " AND u.model LIKE ?"; params.append(f"%{model}%")
        if barcode: q += " AND u.barkod LIKE ?"; params.append(f"%{barcode}%")
        if department_id: q += " AND sh.departman_id=?"; params.append(department_id)
        if alt_unit_id: q += " AND sh.alt_birim_id=?"; params.append(alt_unit_id)
        if delivery_search:
            term=f"%{delivery_search}%"; q += " AND (sh.teslim_eden LIKE ? OR sh.teslim_alan LIKE ?)"; params.extend([term,term])
        q += " ORDER BY sh.id DESC"
        return self.conn.execute(q, params).fetchall()

    def get_stock_movement_detail(self, movement_id):
        return self.conn.execute("""
            SELECT sh.*, u.kod AS urun_kodu, u.ad AS urun_adi, u.barkod, u.marka, u.model,
                   pt.ad AS urun_turu_adi, ug.ad AS grup_adi,
                   d.kod AS depo_kodu, d.ad AS depo_adi,
                   dp.kod AS departman_kodu, dp.ad AS departman_adi,
                   ab.kod AS alt_birim_kodu, ab.ad AS alt_birim_adi,
                   c.kod AS cari_kodu, c.unvan AS cari_unvan
            FROM stok_hareketleri sh
            JOIN urunler u ON u.id=sh.urun_id
            JOIN depolar d ON d.id=sh.depo_id
            LEFT JOIN urun_turleri pt ON pt.id=u.urun_turu_id
            LEFT JOIN urun_gruplari ug ON ug.id=u.grup_id
            LEFT JOIN departmanlar dp ON dp.id=sh.departman_id
            LEFT JOIN departman_alt_birimleri ab ON ab.id=sh.alt_birim_id
            LEFT JOIN cariler c ON c.id=sh.cari_id
            WHERE sh.id=?""", (movement_id,)).fetchone()


    def list_slips(self, start_date=None, end_date=None, movement_type=None, warehouse_id=None, search=None):
        q = """SELECT sf.*, d.kod AS depo_kodu, d.ad AS depo_adi,
                       c.kod AS cari_kodu, c.unvan AS cari_unvan,
                       dp.kod AS departman_kodu, dp.ad AS departman_adi,
                       ab.kod AS alt_birim_kodu, ab.ad AS alt_birim_adi,
                       (SELECT COUNT(*) FROM stok_fis_satirlari sfs WHERE sfs.fis_id=sf.id) AS satir_sayisi,
                       (SELECT COALESCE(SUM(sfs.miktar*sfs.birim_fiyat),0) FROM stok_fis_satirlari sfs WHERE sfs.fis_id=sf.id) AS toplam_tutar
                FROM stok_fisleri sf
                JOIN depolar d ON d.id=sf.depo_id
                LEFT JOIN cariler c ON c.id=sf.cari_id
                LEFT JOIN departmanlar dp ON dp.id=sf.departman_id
                LEFT JOIN departman_alt_birimleri ab ON ab.id=sf.alt_birim_id
                WHERE 1=1"""
        params=[]
        if start_date: q += " AND sf.tarih>=?"; params.append(start_date)
        if end_date: q += " AND sf.tarih<=?"; params.append(end_date)
        if movement_type: q += " AND sf.islem_tipi=?"; params.append(movement_type)
        if warehouse_id: q += " AND sf.depo_id=?"; params.append(warehouse_id)
        if search:
            q += " AND (sf.fis_no LIKE ? OR sf.teslim_eden LIKE ? OR sf.teslim_alan LIKE ? OR c.unvan LIKE ?)"
            term=f"%{search}%"; params.extend([term,term,term,term])
        q += " ORDER BY sf.id DESC"
        return self.conn.execute(q, params).fetchall()

    def get_slip(self, slip_id):
        header = self.conn.execute(
            """SELECT sf.*, d.kod AS depo_kodu, d.ad AS depo_adi,
                      c.kod AS cari_kodu, c.unvan AS cari_unvan,
                      dp.kod AS departman_kodu, dp.ad AS departman_adi,
                      ab.kod AS alt_birim_kodu, ab.ad AS alt_birim_adi
               FROM stok_fisleri sf
               JOIN depolar d ON d.id=sf.depo_id
               LEFT JOIN cariler c ON c.id=sf.cari_id
               LEFT JOIN departmanlar dp ON dp.id=sf.departman_id
               LEFT JOIN departman_alt_birimleri ab ON ab.id=sf.alt_birim_id
               WHERE sf.id=?""", (slip_id,)
        ).fetchone()
        if not header: return None, []
        lines = self.conn.execute(
            """SELECT sfs.*, u.kod AS urun_kodu, u.ad AS urun_adi, u.barkod, COALESCE(u.birim,'ADET') AS birim
               FROM stok_fis_satirlari sfs JOIN urunler u ON u.id=sfs.urun_id
               WHERE sfs.fis_id=? ORDER BY sfs.id""", (slip_id,)
        ).fetchall()
        return header, lines

    def demirbas_rows(self, warehouse_id=None, group_id=None, search="", include_zero=False,
                      department_id=None, alt_unit_id=None):
        # Depo bakiyeleri ile departman/alt birim teslim kayıtlarını bir listede birleştirir.
        like = f"%{search.strip()}%" if search and search.strip() else None
        results = []

        # Departman filtresi yoksa depoda bulunan demirbaşları göster.
        if department_id is None and alt_unit_id is None:
            stock_expr = "COALESCE((SELECT SUM(CASE WHEN sh.islem_tipi IN ('Giriş','İade') THEN sh.miktar ELSE -sh.miktar END) FROM stok_hareketleri sh WHERE sh.urun_id=u.id"
            stock_params = []
            if warehouse_id is not None:
                stock_expr += " AND sh.depo_id=?"
                stock_params.append(warehouse_id)
            stock_expr += "),0)"
            q = f'''SELECT u.*, COALESCE(g.kod,'') AS grup_kodu, COALESCE(g.ad,'') AS grup_adi,
                           COALESCE(t.kod,'') AS urun_turu_kodu, COALESCE(t.ad,'') AS urun_turu_adi,
                           COALESCE(b.kod,'') AS birim_kodu, COALESCE(b.ad,'') AS birim_adi,
                           {stock_expr} AS mevcut
                    FROM urunler u
                    LEFT JOIN urun_gruplari g ON g.id=u.grup_id
                    LEFT JOIN urun_turleri t ON t.id=u.urun_turu_id
                    LEFT JOIN birimler b ON b.id=u.birim_id
                    WHERE u.aktif=1'''
            params = list(stock_params)
            if group_id is not None:
                q += " AND u.grup_id=?"
                params.append(group_id)
            if like:
                q += " AND (u.kod LIKE ? OR u.ad LIKE ? OR COALESCE(u.barkod,'') LIKE ? OR COALESCE(u.uretici_kodu,'') LIKE ? OR COALESCE(u.uretici,'') LIKE ? OR COALESCE(u.marka,'') LIKE ? OR COALESCE(u.model,'') LIKE ? OR COALESCE(u.raf_bilgisi,'') LIKE ?)"
                params.extend([like] * 8)
            q += " ORDER BY u.kod"
            for raw in self.conn.execute(q, params).fetchall():
                row = dict(raw)
                qty = float(row.get("mevcut") or 0)
                if not include_zero and abs(qty) < 1e-9:
                    continue
                row.update({
                    "kayit_turu": "Depoda",
                    "depo_adi": "Tüm Depolar" if warehouse_id is None else "",
                    "departman": "",
                    "alt_birim": "",
                    "departman_id": None,
                    "alt_birim_id": None,
                    "teslim_edilen_miktar": 0,
                    "son_teslim_tarihi": "",
                })
                if warehouse_id is not None:
                    depot = self.conn.execute("SELECT kod,ad FROM depolar WHERE id=?", (warehouse_id,)).fetchone()
                    if depot:
                        row["depo_adi"] = f"{depot['kod']} - {depot['ad']}"
                results.append(row)

        # Aktif fişlerdeki departmanlı çıkışlar; iptal kayıtları hariç tutulur.
        issue_where = [
            "sh.islem_tipi='Çıkış'",
            "sh.departman_id IS NOT NULL",
            "COALESCE(sh.iptal_hareketi,0)=0",
            "(sf.id IS NULL OR COALESCE(sf.durum,'Aktif')<>'İptal')",
        ]
        issue_params = []
        if warehouse_id is not None:
            issue_where.append("sh.depo_id=?")
            issue_params.append(warehouse_id)
        if department_id is not None:
            issue_where.append("sh.departman_id=?")
            issue_params.append(department_id)
        if alt_unit_id is not None:
            issue_where.append("sh.alt_birim_id=?")
            issue_params.append(alt_unit_id)
        if group_id is not None:
            issue_where.append("u.grup_id=?")
            issue_params.append(group_id)
        if like:
            issue_where.append("(u.kod LIKE ? OR u.ad LIKE ? OR COALESCE(u.barkod,'') LIKE ? OR COALESCE(u.uretici_kodu,'') LIKE ? OR COALESCE(u.uretici,'') LIKE ? OR COALESCE(u.marka,'') LIKE ? OR COALESCE(u.model,'') LIKE ? OR COALESCE(u.raf_bilgisi,'') LIKE ?)")
            issue_params.extend([like] * 8)
        issue_sql = f'''SELECT sh.urun_id, sh.depo_id, sh.departman_id, sh.alt_birim_id,
                               SUM(sh.miktar) AS teslim_edilen_miktar,
                               MAX(sh.tarih) AS son_teslim_tarihi
                        FROM stok_hareketleri sh
                        LEFT JOIN stok_fisleri sf ON sf.fis_no=sh.fis_no
                        JOIN urunler u ON u.id=sh.urun_id
                        WHERE {' AND '.join(issue_where)}
                        GROUP BY sh.urun_id, sh.depo_id, sh.departman_id, sh.alt_birim_id
                        HAVING SUM(sh.miktar)>0'''
        assignments = self.conn.execute(issue_sql, issue_params).fetchall()
        for assignment in assignments:
            product_query = f'''SELECT u.*, COALESCE(g.kod,'') AS grup_kodu, COALESCE(g.ad,'') AS grup_adi,
                                      COALESCE(t.kod,'') AS urun_turu_kodu, COALESCE(t.ad,'') AS urun_turu_adi,
                                      COALESCE(b.kod,'') AS birim_kodu, COALESCE(b.ad,'') AS birim_adi,
                                      COALESCE((SELECT SUM(CASE WHEN bal.islem_tipi IN ('Giriş','İade') THEN bal.miktar ELSE -bal.miktar END)
                                                FROM stok_hareketleri bal WHERE bal.urun_id=u.id AND bal.depo_id=?),0) AS mevcut,
                                      d.kod AS kaynak_depo_kodu, d.ad AS kaynak_depo_adi,
                                      dp.kod AS departman_kodu, dp.ad AS departman_adi,
                                      ab.kod AS alt_birim_kodu, ab.ad AS alt_birim_adi
                               FROM urunler u
                               LEFT JOIN urun_gruplari g ON g.id=u.grup_id
                               LEFT JOIN urun_turleri t ON t.id=u.urun_turu_id
                               LEFT JOIN birimler b ON b.id=u.birim_id
                               LEFT JOIN depolar d ON d.id=?
                               LEFT JOIN departmanlar dp ON dp.id=?
                               LEFT JOIN departman_alt_birimleri ab ON ab.id=?
                               WHERE u.id=? AND u.aktif=1'''
            raw = self.conn.execute(product_query, (assignment["depo_id"], assignment["depo_id"],
                                                     assignment["departman_id"], assignment["alt_birim_id"],
                                                     assignment["urun_id"])).fetchone()
            if not raw:
                continue
            row = dict(raw)
            row.update({
                "kayit_turu": "Departmana Teslim",
                "depo_adi": f"{row.get('kaynak_depo_kodu') or ''} - {row.get('kaynak_depo_adi') or ''}".strip(" -"),
                "departman": f"{row.get('departman_kodu') or ''} - {row.get('departman_adi') or ''}".strip(" -"),
                "alt_birim": f"{row.get('alt_birim_kodu') or ''} - {row.get('alt_birim_adi') or ''}".strip(" -"),
                "departman_id": assignment["departman_id"],
                "alt_birim_id": assignment["alt_birim_id"],
                "teslim_edilen_miktar": float(assignment["teslim_edilen_miktar"] or 0),
                "son_teslim_tarihi": assignment["son_teslim_tarihi"] or "",
            })
            results.append(row)

        results.sort(key=lambda r: (str(r.get("kod") or ""),
                                   0 if r.get("kayit_turu") == "Depoda" else 1,
                                   str(r.get("departman") or ""),
                                   str(r.get("alt_birim") or ""),
                                   str(r.get("depo_adi") or "")))
        return results

    def close(self):
        self.conn.close()


def fmt_qty_tr(value):
    return f"{float(value or 0):,.3f}".replace(",", "X").replace(".", ",").replace("X", ".")

def fmt_money_tr(value):
    return f"{float(value or 0):,.2f} TL".replace(",", "X").replace(".", ",").replace("X", ".")

def build_slip_html(db, slip_id):
    header, lines = db.get_slip(slip_id)
    if not header: raise ValueError("Fiş bulunamadı.")
    html=['<html><head><meta charset="utf-8"><style>body{font-family:Arial,sans-serif;font-size:10pt;color:#111}h1{text-align:center;font-size:16pt}.meta{width:100%;border-collapse:collapse}.meta td{border:1px solid #999;padding:4px}table{width:100%;border-collapse:collapse}th,td{border:1px solid #777;padding:4px}th{background:#e8edf2}.right{text-align:right}.sign{margin-top:26px}.sign td{text-align:center;padding-top:10px}</style></head><body>', f'<h1>ÜRÜN {header["islem_tipi"].upper()} FİŞİ</h1>', '<table class="meta">']
    cari=f'{header["cari_kodu"]} - ' if header['cari_kodu'] else ''
    cari += header['cari_unvan'] or ''
    dept=f'{header["departman_kodu"]} - ' if header['departman_kodu'] else ''
    dept += header['departman_adi'] or ''
    alt=f'{header["alt_birim_kodu"]} - ' if header['alt_birim_kodu'] else ''
    alt += header['alt_birim_adi'] or ''
    html += [f'<tr><td><b>Fiş No</b></td><td>{header["fis_no"]}</td><td><b>Tarih</b></td><td>{header["tarih"]}</td></tr>', f'<tr><td><b>Depo</b></td><td>{header["depo_kodu"]} - {header["depo_adi"]}</td><td><b>Cari</b></td><td>{cari}</td></tr>', f'<tr><td><b>Departman</b></td><td>{dept}</td><td><b>Alt Birim</b></td><td>{alt}</td></tr>', '</table>', '<br><table><tr><th>No</th><th>Ürün Kodu</th><th>Ürün Adı</th><th>Barkod</th><th>Birim</th><th>Miktar</th><th>Birim Fiyat</th><th>Tutar</th></tr>']
    total=0.0
    for i,row in enumerate(lines,1):
        amount=float(row['miktar'] or 0)*float(row['birim_fiyat'] or 0); total += amount
        html.append(f'<tr><td>{i}</td><td>{row["urun_kodu"]}</td><td>{row["urun_adi"]}</td><td>{row["barkod"] or ""}</td><td>{row["birim"] or ""}</td><td class="right">{fmt_qty_tr(row["miktar"])}</td><td class="right">{fmt_money_tr(row["birim_fiyat"])}</td><td class="right">{fmt_money_tr(amount)}</td></tr>')
    html.append(f'<tr><td colspan="7" class="right"><b>TOPLAM</b></td><td class="right"><b>{fmt_money_tr(total)}</b></td></tr></table>')
    if header['aciklama']: html.append(f'<p><b>Açıklama:</b> {header["aciklama"]}</p>')
    html.append(f'<table class="sign"><tr><td><b>Teslim Eden</b><br><br>{header["teslim_eden"] or ""}<br>____________________</td><td><b>Teslim Alan</b><br><br>{header["teslim_alan"] or ""}<br>____________________</td></tr></table></body></html>')
    return ''.join(html)

def print_slip(parent, db, slip_id):
    try: html=build_slip_html(db, slip_id)
    except Exception as exc: QMessageBox.critical(parent, 'Fiş Yazdırma', str(exc)); return False
    printer=QPrinter(QPrinter.HighResolution); printer.setDocName(f'Fiş_{slip_id}')
    dlg=QPrintDialog(printer,parent)
    if dlg.exec_()!=QDialog.Accepted: return False
    doc=QTextDocument(); doc.setHtml(html); doc.print_(printer); return True

class StockSlipListDialog(QDialog):
    def __init__(self,parent,db):
        super().__init__(parent); self.db=db; self.setWindowTitle('Fiş Listesi / Fiş Yazdırma'); self.resize(1220,680)
        root=QVBoxLayout(self); title=QLabel('GİRİŞ / ÇIKIŞ FİŞLERİ'); title.setObjectName('dialogTitle'); root.addWidget(title)
        f=QGridLayout(); self.start=QDateEdit(QDate.currentDate().addMonths(-1)); self.start.setCalendarPopup(True); self.end=QDateEdit(QDate.currentDate()); self.end.setCalendarPopup(True); self.mode=QComboBox(); self.mode.addItems(['Tümü','Giriş','Çıkış']); self.depo=QComboBox(); self.depo.addItem('Tüm Depolar',None)
        for r in db.warehouses():
            if r['aktif']: self.depo.addItem(f"{r['kod']} - {r['ad']}",r['id'])
        self.search=QLineEdit(); self.search.setPlaceholderText('Fiş no / cari / teslim eden / teslim alan...'); q=QPushButton('Sorgula'); q.clicked.connect(self.refresh)
        f.addWidget(QLabel('Başlangıç'),0,0); f.addWidget(self.start,0,1); f.addWidget(QLabel('Bitiş'),0,2); f.addWidget(self.end,0,3); f.addWidget(QLabel('İşlem'),0,4); f.addWidget(self.mode,0,5); f.addWidget(QLabel('Depo'),1,0); f.addWidget(self.depo,1,1,1,2); f.addWidget(QLabel('Arama'),1,3); f.addWidget(self.search,1,4,1,2); f.addWidget(q,0,6,2,1); root.addLayout(f)
        self.table=QTableWidget(0,11); self.table.setHorizontalHeaderLabels(['No','Fiş No','Tarih','İşlem','Depo','Cari','Departman','Alt Birim','Satır','Toplam','Durum']); configure_resizable_table(self.table,'fis_listesi',[55,110,100,90,180,220,180,140,70,120,90]); self.table.setSelectionBehavior(QAbstractItemView.SelectRows); self.table.setEditTriggers(QAbstractItemView.NoEditTriggers); root.addWidget(self.table,1)
        btns=QHBoxLayout(); pr=QPushButton('Fişi Yazdır'); pr.clicked.connect(self.print_selected); cancel=QPushButton('Fişi İptal Et'); cancel.clicked.connect(self.cancel_selected); cancel.setEnabled(getattr(parent,'role_name','').casefold()=='yönetici'); close=QPushButton('Kapat'); close.clicked.connect(self.accept); btns.addWidget(pr); btns.addWidget(cancel); btns.addStretch(); btns.addWidget(close); root.addLayout(btns); self.cancel_btn=cancel; self.refresh()
    def refresh(self):
        st=self.start.date().toString('yyyy-MM-dd'); en=self.end.date().toString('yyyy-MM-dd'); mt=None if self.mode.currentText()=='Tümü' else self.mode.currentText(); rows=self.db.list_slips(st,en,mt,self.depo.currentData(),self.search.text().strip()); self.table.setRowCount(0)
        for i,r in enumerate(rows,1):
            rr=self.table.rowCount(); self.table.insertRow(rr); vals=[i,r['fis_no'],r['tarih'],r['islem_tipi'],f"{r['depo_kodu']} - {r['depo_adi']}",f"{r['cari_kodu']} - {r['cari_unvan']}" if r['cari_unvan'] else '',f"{r['departman_kodu']} - {r['departman_adi']}" if r['departman_adi'] else '',f"{r['alt_birim_kodu']} - {r['alt_birim_adi']}" if r['alt_birim_adi'] else '',r['satir_sayisi'],fmt_money_tr(r['toplam_tutar']),r['durum']]
            for c,v in enumerate(vals): self.table.setItem(rr,c,QTableWidgetItem(str(v)))
            self.table.item(rr,1).setData(Qt.UserRole,r['id'])
    def cancel_selected(self):
        row=self.table.currentRow()
        if row<0: QMessageBox.information(self,'Seçim','İptal etmek için bir fiş seçin.'); return
        slip_id=self.table.item(row,1).data(Qt.UserRole)
        if str(self.table.item(row,10).text())=='İptal': QMessageBox.information(self,'Fiş','Bu fiş zaten iptal edilmiş.'); return
        reason,ok=QInputDialog.getText(self,'Fiş İptali','İptal nedeni:')
        if not ok: return
        if QMessageBox.question(self,'Fiş İptali',f'{self.table.item(row,1).text()} numaralı fişi iptal etmek istediğinizden emin misiniz?\n\nStok etkisini tersine çevirecek bir iptal hareketi oluşturulacaktır.',QMessageBox.Yes|QMessageBox.No,QMessageBox.No)!=QMessageBox.Yes:return
        try:
            uid=getattr(self.parent(),'current_user',None)
            self.db.cancel_stock_slip(slip_id, uid['id'] if uid else None, reason.strip())
            self.refresh()
            QMessageBox.information(self,'İptal','Fiş iptal edildi. Stok etkisi tersine çevrildi.')
        except Exception as exc: QMessageBox.critical(self,'İptal Hatası',str(exc))

    def print_selected(self):
        row=self.table.currentRow()
        if row<0: QMessageBox.information(self,'Seçim','Yazdırmak için bir fiş seçin.'); return
        print_slip(self,self.db,self.table.item(row,1).data(Qt.UserRole))

class ProductDialog(QDialog):
    def __init__(self, parent, db: Database, product_id=None, copy_mode=False):
        super().__init__(parent)
        self.db = db
        self.product_id = product_id
        self.copy_mode = copy_mode
        # Düzenleme sırasında mevcut barkod/üretici kodunu sakla.
        # Eski kayıtlarda daha önceden oluşmuş mükerrer değerler varsa, kullanıcı
        # başka bir alanı (ör. Ürün Türü) değiştirdiğinde bu mevcut değeri
        # yeniden doğrulayıp işlemi gereksiz yere engellemeyelim.
        self.original_barcode = ""
        self.original_manufacturer_code = ""
        self.setWindowTitle("Ürün Kartı" if not copy_mode else "Ürün Kartını Kopyala")
        self.setMinimumSize(800, 590)
        self.resize(860, 660)
        self.build_ui()
        self.load_groups()
        self.load_product_types()
        if product_id:
            self.load_product(product_id)
        else:
            self.code.setText(self.next_code())
            self.active.setChecked(True)

    def build_ui(self):
        root = QVBoxLayout(self)
        tabs = QTabWidget()
        self.tabs = tabs
        root.addWidget(tabs, 1)

        general = QWidget()
        self.general_tab = general
        g = QGridLayout(general)
        g.setHorizontalSpacing(12)
        g.setVerticalSpacing(10)

        self.code = QLineEdit()
        self.name = QLineEdit()
        self.group = QComboBox()
        self.barcode = QLineEdit()
        self.manufacturer_code = QLineEdit()
        self.manufacturer = QLineEdit()
        self.product_type = QComboBox()
        self.brand = QLineEdit()
        self.model = QLineEdit()
        self.unit = QComboBox()
        self.unit.setEditable(False)
        self.vat = QLineEdit("20")
        self.purchase = QLineEdit("0,00")
        self.sale = QLineEdit("0,00")
        self.min_stock = QLineEdit("0")
        self.max_stock = QLineEdit("0")
        self.shelf = QLineEdit()
        self.fixed_asset_no = QLineEdit()
        self.fixed_asset_no.setMaxLength(100)
        self.fixed_asset_no.setPlaceholderText("Demirbaş numarasını girin...")
        self.fixed_asset_no.setToolTip("Yalnızca Demirbaş ürün grubu seçildiğinde giriş yapılabilir.")
        self.fixed_asset_no_label = QLabel("Demirbaş No")
        self.fixed_asset_no_info = QLabel("Demirbaş grubunda kullanılır.")
        self.fixed_asset_no_info.setStyleSheet("color: #666;")
        self.active = QCheckBox("Aktif ürün")

        self.vat.setValidator(QDoubleValidator(0, 100, 2))
        self.purchase.setValidator(QDoubleValidator(0, 999999999, 4))
        self.sale.setValidator(QDoubleValidator(0, 999999999, 4))
        self.min_stock.setValidator(QDoubleValidator(0, 999999999, 3))
        self.max_stock.setValidator(QDoubleValidator(0, 999999999, 3))

        rows = [
            ("Ürün Kodu*", self.code, "Ürün Adı*", self.name),
            ("Ürün Grubu", self.group, "Barkod Kodu", self.barcode),
            ("Üretici Kodu", self.manufacturer_code, "Üretici", self.manufacturer),
            ("Ürün Tipi", self.product_type, "Marka", self.brand),
            ("Model", self.model, "Birim", self.unit),
            ("KDV %", self.vat, "Alış Fiyatı", self.purchase),
            ("Satış Fiyatı", self.sale, "Min. Seviye", self.min_stock),
            ("Max. Seviye", self.max_stock, "Raf / Lokasyon", self.shelf),
        ]
        for r, (l1, w1, l2, w2) in enumerate(rows):
            g.addWidget(QLabel(l1), r, 0)
            g.addWidget(w1, r, 1)
            g.addWidget(QLabel(l2), r, 2)
            g.addWidget(w2, r, 3)
        asset_row = len(rows)
        g.addWidget(self.fixed_asset_no_label, asset_row, 0)
        g.addWidget(self.fixed_asset_no, asset_row, 1)
        g.addWidget(self.fixed_asset_no_info, asset_row, 2, 1, 2)
        g.addWidget(self.active, asset_row + 1, 0, 1, 2)
        g.setColumnStretch(1, 1)
        g.setColumnStretch(3, 1)
        tabs.addTab(general, "Genel Bilgiler")
        self.group.currentIndexChanged.connect(self.update_fixed_asset_field_state)

        other = QWidget()
        o = QFormLayout(other)
        self.description = QTextEdit()
        self.notes = QTextEdit()
        self.description.setPlaceholderText("Ürün hakkında açıklama...")
        self.notes.setPlaceholderText("İç notlar, teknik notlar veya özel açıklamalar...")
        o.addRow("Açıklama:", self.description)
        o.addRow("Notlar:", self.notes)
        tabs.addTab(other, "Diğer Bilgiler")

        image_tab = QWidget()
        il = QVBoxLayout(image_tab)
        self.image_path = QLineEdit()
        browse = QPushButton("Görsel Seç...")
        browse.clicked.connect(self.select_image)
        row = QHBoxLayout()
        row.addWidget(self.image_path)
        row.addWidget(browse)
        il.addLayout(row)
        self.image_info = QLabel("Ürün görseli yolu burada tutulacaktır. Görsel gösterimi sonraki aşamada genişletilebilir.")
        self.image_info.setWordWrap(True)
        il.addWidget(self.image_info)
        il.addStretch()
        tabs.addTab(image_tab, "Ürün Resmi")

        buttons = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        root.addWidget(buttons)

        self.code.setFocus()

    @staticmethod
    def _normalize_asset_group_text(value):
        """Türkçe karakterleri ve Unicode birleşik işaretleri güvenilir biçimde normalize eder."""
        text = unicodedata.normalize("NFKD", str(value or ""))
        text = "".join(ch for ch in text if not unicodedata.combining(ch))
        text = text.casefold().replace("ı", "i")
        return re.sub(r"[^a-z0-9]+", " ", text).strip()

    def is_fixed_asset_group(self):
        """Seçili ürün grubunun demirbaş grubu olup olmadığını belirler.

        Önce ekranda görünen grup adını kontrol eder; ardından grup ID'si üzerinden
        veritabanındaki kod/ad değerlerine de bakar. Böylece Türkçe İ/ı/ş karakterleri
        veya veritabanı satır biçimi nedeniyle alanın pasif kalması önlenir.
        """
        candidates = [self.group.currentText()]
        group_id = self.group.currentData()
        if group_id is not None:
            try:
                row = self.db.conn.execute(
                    "SELECT COALESCE(kod,''), COALESCE(ad,'') FROM urun_gruplari WHERE id=?",
                    (group_id,),
                ).fetchone()
            except Exception:
                row = None
            if row:
                try:
                    candidates.extend([row[0], row[1]])
                except (IndexError, KeyError, TypeError):
                    pass
        for value in candidates:
            text = self._normalize_asset_group_text(value)
            if "demirbas" in text or "fixed asset" in text or "sabit kiymet" in text:
                return True
        return False

    def update_fixed_asset_field_state(self, *_args):
        enabled = self.is_fixed_asset_group()
        self.fixed_asset_no.setEnabled(enabled)
        self.fixed_asset_no_label.setEnabled(enabled)
        self.fixed_asset_no_info.setEnabled(enabled)
        self.fixed_asset_no.setToolTip(
            "Demirbaş grubunda numara girilmelidir; boş bırakılırsa kaydetme sırasında sorulur."
            if enabled else "Yalnızca Demirbaş ürün grubu seçildiğinde giriş yapılabilir."
        )

    def load_groups(self):
        self.group.clear()
        self.group.addItem("-- Seçiniz --", None)
        for row in self.db.groups():
            self.group.addItem(f"{row['kod']} - {row['ad']}", row["id"])
        self.unit.clear()
        for row in self.db.units():
            self.unit.addItem(f"{row['kod']} - {row['ad']}", row["id"])

    def load_product_types(self):
        self.product_type.clear()
        self.product_type.addItem("-- Seçiniz --", None)
        for row in self.db.product_types():
            self.product_type.addItem(f"{row['kod']} - {row['ad']}", row["id"])

    def next_code(self):
        row = self.db.conn.execute("SELECT kod FROM urunler ORDER BY id DESC LIMIT 1").fetchone()
        if not row:
            return "SK000001"
        code = row[0] or "SK000000"
        digits = ''.join(ch for ch in code if ch.isdigit())
        try:
            n = int(digits) + 1
        except ValueError:
            n = 1
        return f"SK{n:06d}"

    @staticmethod
    def number(text):
        text = (text or "").strip().replace(".", "").replace(",", ".")
        try:
            return float(text)
        except ValueError:
            return 0.0

    def select_image(self):
        path, _ = QFileDialog.getOpenFileName(self, "Ürün Görseli Seç", "", "Resimler (*.png *.jpg *.jpeg *.bmp *.webp)")
        if path:
            self.image_path.setText(path)

    def load_product(self, product_id):
        row = self.db.get_product(product_id)
        if not row:
            return
        self.code.setText(row["kod"] or "")
        self.name.setText(row["ad"] or "")
        self.barcode.setText(row["barkod"] or "")
        self.original_barcode = self.db._normalize_key(row["barkod"] or "")
        self.original_manufacturer_code = self.db._normalize_key(row["uretici_kodu"] or "")
        idx = self.group.findData(row["grup_id"])
        self.group.setCurrentIndex(idx if idx >= 0 else 0)
        self.manufacturer_code.setText(row["uretici_kodu"] or "")
        self.manufacturer.setText(row["uretici"] or "")
        type_idx = self.product_type.findData(row["urun_turu_id"])
        if type_idx >= 0:
            self.product_type.setCurrentIndex(type_idx)
        elif row["urun_tipi"]:
            self.product_type.setCurrentText(row["urun_tipi"])
        self.brand.setText(row["marka"] or "")
        self.model.setText(row["model"] or "")
        unit_idx = self.unit.findData(row["birim_id"])
        if unit_idx >= 0:
            self.unit.setCurrentIndex(unit_idx)
        else:
            self.unit.setCurrentText(row["birim"] or "ADET")
        self.vat.setText(str(row["kdv"] if row["kdv"] is not None else 20))
        self.purchase.setText(f"{row['alis_fiyati'] or 0:.2f}".replace('.', ','))
        self.sale.setText(f"{row['satis_fiyati'] or 0:.2f}".replace('.', ','))
        self.min_stock.setText(str(row["min_seviye"] or 0))
        self.max_stock.setText(str(row["max_seviye"] or 0))
        self.shelf.setText(row["raf_bilgisi"] or "")
        self.description.setPlainText(row["aciklama"] or "")
        self.notes.setPlainText(row["notlar"] or "")
        self.image_path.setText(row["resim_yolu"] or "")
        self.fixed_asset_no.setText(row["demirbas_no"] or "")
        self.update_fixed_asset_field_state()
        self.active.setChecked(bool(row["aktif"]))
        if self.copy_mode:
            self.code.setText(self.next_code())

    def get_data(self):
        return {
            "kod": self.code.text().strip(),
            "ad": self.name.text().strip(),
            "barkod": self.barcode.text().strip(),
            "grup_id": self.group.currentData(),
            "birim": self.unit.currentText().strip() or "ADET",
            "birim_id": self.unit.currentData(),
            "min_seviye": self.number(self.min_stock.text()),
            "max_seviye": self.number(self.max_stock.text()),
            "uretici_kodu": self.manufacturer_code.text().strip(),
            "uretici": self.manufacturer.text().strip(),
            "urun_tipi": self.product_type.currentText().strip() if self.product_type.currentData() is None else self.product_type.currentText().split(' - ', 1)[-1].strip(),
            "urun_turu_id": self.product_type.currentData(),
            "marka": self.brand.text().strip(),
            "model": self.model.text().strip(),
            "kdv": self.number(self.vat.text()),
            "alis_fiyati": self.number(self.purchase.text()),
            "satis_fiyati": self.number(self.sale.text()),
            "raf_bilgisi": self.shelf.text().strip(),
            "aciklama": self.description.toPlainText().strip(),
            "notlar": self.notes.toPlainText().strip(),
            "resim_yolu": self.image_path.text().strip(),
            "demirbas_no": self.fixed_asset_no.text().strip(),
            "aktif": 1 if self.active.isChecked() else 0,
        }

    def accept(self):
        data = self.get_data()
        if not data["kod"] or not data["ad"]:
            QMessageBox.warning(self, "Eksik Bilgi", "Ürün Kodu ve Ürün Adı zorunludur.")
            return
        if data["max_seviye"] and data["min_seviye"] > data["max_seviye"]:
            QMessageBox.warning(self, "Seviye Hatası", "Minimum seviye maksimum seviyeden büyük olamaz.")
            return

        # Demirbaş grubunda numara boşsa kullanıcıya numara girme veya devam etme seçeneği ver.
        if self.is_fixed_asset_group() and not data["demirbas_no"]:
            warning = QMessageBox(self)
            warning.setIcon(QMessageBox.Warning)
            warning.setWindowTitle("Demirbaş Numarası Eksik")
            warning.setText("Demirbaş numarası girmediniz.")
            warning.setInformativeText("Demirbaş numarası girmek ister misiniz?")
            enter_no = warning.addButton("Demirbaş No gir", QMessageBox.AcceptRole)
            continue_save = warning.addButton("Devam et", QMessageBox.ActionRole)
            warning.setDefaultButton(enter_no)
            warning.exec_()
            clicked = warning.clickedButton()
            if clicked == enter_no:
                self.tabs.setCurrentWidget(self.general_tab)
                self.fixed_asset_no.setFocus(Qt.OtherFocusReason)
                return
            if clicked != continue_save:
                return

        # Barkod ve üretici kodu ürünler arasında tekil olmalıdır.
        # Ancak eski verilerde daha önceden oluşmuş mükerrer bir barkod/üretici
        # kodu varsa ve kullanıcı bu alanı değiştirmiyorsa, sadece başka bir
        # alanı (ör. Ürün Türü, Marka, Model) güncellemesine engel olmayalım.
        is_update = self.product_id is not None and not self.copy_mode
        effective_id = self.product_id if is_update else None

        current_barcode_key = self.db._normalize_key(data["barkod"])
        current_manufacturer_key = self.db._normalize_key(data["uretici_kodu"])

        check_barcode = True
        check_manufacturer = True
        if is_update:
            check_barcode = current_barcode_key != self.original_barcode
            check_manufacturer = current_manufacturer_key != self.original_manufacturer_code

        duplicates = {"barkod": [], "uretici_kodu": []}
        if check_barcode or check_manufacturer:
            found = self.db.product_duplicate_fields(
                data["barkod"] if check_barcode else "",
                data["uretici_kodu"] if check_manufacturer else "",
                effective_id
            )
            duplicates = found
        if duplicates["barkod"] or duplicates["uretici_kodu"]:
            lines = []
            if duplicates["barkod"]:
                refs = ", ".join(f"{r['kod']} - {r['ad']}" for r in duplicates["barkod"][:5])
                lines.append(f"• Barkod kodu zaten kullanılıyor: {data['barkod']}\n  Ürün: {refs}")
            if duplicates["uretici_kodu"]:
                refs = ", ".join(f"{r['kod']} - {r['ad']}" for r in duplicates["uretici_kodu"][:5])
                lines.append(f"• Üretici kodu zaten kullanılıyor: {data['uretici_kodu']}\n  Ürün: {refs}")
            QMessageBox.warning(
                self,
                "Mükerrer Ürün Bilgisi",
                "Aynı barkod veya üretici koduna sahip ikinci bir ürün kaydedilemez.\n\n" + "\n\n".join(lines)
            )
            return

        try:
            self.db.save_product(data, effective_id)
        except sqlite3.IntegrityError as exc:
            QMessageBox.critical(self, "Kayıt Hatası", f"Ürün kaydedilemedi.\n\n{exc}")
            return

        # Ürün kartı penceresinin doğrudan üst nesnesi ProductCardsDialog
        # olduğu için burada QDialog.statusBar() çağrılamaz.
        # Ürün listesi ekranındaki durum etiketi güncellenir.
        parent = self.parent()
        if parent is not None and hasattr(parent, "status"):
            if is_update:
                parent.status.setText(f"{data['kod']} - {data['ad']} ürünü güncellendi.")
            else:
                parent.status.setText(f"{data['kod']} - {data['ad']} ürünü kaydedildi.")
        super().accept()


class ProductCardsDialog(QDialog):
    def __init__(self, parent, db: Database):
        super().__init__(parent)
        self.db = db
        self.setWindowTitle("STOK KARTLARI / ÜRÜN TANIMLARI")
        self.setMinimumSize(1150, 650)
        self.resize(1320, 760)
        self.build_ui()
        self.load_groups()
        self.refresh()

    def build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(10, 10, 10, 10)
        root.setSpacing(8)

        top = QFrame()
        top.setObjectName("productHeader")
        th = QHBoxLayout(top)
        title = QLabel("📦  STOK KARTLARI")
        title.setObjectName("productTitle")
        th.addWidget(title)
        th.addStretch()
        close = QPushButton("KAPAT")
        close.clicked.connect(self.accept)
        th.addWidget(close)
        root.addWidget(top)

        filters = QGroupBox("Ürün Arama / Filtre")
        fl = QGridLayout(filters)
        self.f_code = QLineEdit()
        self.f_name = QLineEdit()
        self.f_type = QComboBox()
        self.f_brand = QLineEdit()
        self.f_model = QLineEdit()
        self.f_group = QComboBox()
        self.f_active = QCheckBox("Sadece aktif ürünler")
        self.f_active.setChecked(True)
        self.f_code.setPlaceholderText("Ürün kodu...")
        self.f_name.setPlaceholderText("Ürün adı...")
        self.f_brand.setPlaceholderText("Marka...")
        self.f_model.setPlaceholderText("Model...")

        fl.addWidget(QLabel("Ürün Kodu"), 0, 0)
        fl.addWidget(self.f_code, 0, 1)
        fl.addWidget(QLabel("Ürün Adı"), 0, 2)
        fl.addWidget(self.f_name, 0, 3)
        fl.addWidget(QLabel("Ürün Türü"), 0, 4)
        fl.addWidget(self.f_type, 0, 5)
        fl.addWidget(QLabel("Marka"), 0, 6)
        fl.addWidget(self.f_brand, 0, 7)

        fl.addWidget(QLabel("Model"), 1, 0)
        fl.addWidget(self.f_model, 1, 1)
        fl.addWidget(QLabel("Grup"), 1, 2)
        fl.addWidget(self.f_group, 1, 3)
        fl.addWidget(self.f_active, 1, 4, 1, 2)
        search = QPushButton("Sorgula")
        search.clicked.connect(self.refresh)
        fl.addWidget(search, 1, 7)
        root.addWidget(filters)

        actions = QHBoxLayout()
        action_defs = [
            ("Yeni", self.new_product),
            ("Düzenle", self.edit_product),
            ("Kopyala", self.copy_product),
            ("Sil / Pasifleştir", self.delete_product),
            ("Yenile", self.refresh),
            ("Excel'e Aktar", self.export_excel),
        ]
        for text, slot in action_defs:
            b = QPushButton(text)
            b.clicked.connect(slot)
            actions.addWidget(b)
        actions.addStretch()
        self.info = QLabel("0 kayıt")
        actions.addWidget(self.info)
        root.addLayout(actions)

        self.table = QTableWidget(0, 15)
        headers = [
            "No", "Ürün Kodu", "Ürün Adı", "Grup", "Ürün Türü", "Barkod", "Üretici", "Marka", "Model",
            "Birim", "Min.", "Mevcut", "Max.", "Alış Fiyatı", "Satış Fiyatı"
        ]
        self.table.setHorizontalHeaderLabels(headers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.doubleClicked.connect(lambda _: self.edit_product())
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self.show_context_menu)
        configure_resizable_table(self.table, "urun_kartlari", [55, 110, 220, 130, 120, 115, 120, 110, 110, 80, 90, 95, 90, 115, 115])
        root.addWidget(self.table, 1)

        status = QHBoxLayout()
        self.status = QLabel("Hazır")
        status.addWidget(self.status)
        status.addStretch()
        root.addLayout(status)

        self.f_code.textChanged.connect(self._auto_filter)
        self.f_name.textChanged.connect(self._auto_filter)
        self.f_brand.textChanged.connect(self._auto_filter)
        self.f_model.textChanged.connect(self._auto_filter)
        self.f_type.currentIndexChanged.connect(self._auto_filter)

    def _auto_filter(self):
        # Yazarken yeniden sorgulama; küçük veri setlerinde akıcı çalışır.
        self.refresh()

    def load_groups(self):
        self.f_group.clear()
        self.f_group.addItem("Tüm Gruplar", None)
        for row in self.db.groups():
            self.f_group.addItem(f"{row['kod']} - {row['ad']}", row["id"])

        self.f_type.clear()
        self.f_type.addItem("Tüm Ürün Türleri", None)
        for row in self.db.product_types():
            self.f_type.addItem(f"{row['kod']} - {row['ad']}", row["id"])

    def selected_id(self):
        row = self.table.currentRow()
        if row < 0:
            return None
        item = self.table.item(row, 0)
        return item.data(Qt.UserRole) if item else None

    def refresh(self):
        self.table.setSortingEnabled(False)
        self.table.setRowCount(0)
        rows = self.db.list_products(
            code=self.f_code.text(),
            name=self.f_name.text(),
            group_id=self.f_group.currentData(),
            active_only=self.f_active.isChecked(),
            product_type_id=self.f_type.currentData(),
            brand=self.f_brand.text(),
            model=self.f_model.text(),
        )
        for i, row in enumerate(rows, 1):
            r = self.table.rowCount()
            self.table.insertRow(r)
            vals = [
                i,
                row["kod"], row["ad"], row["grup_adi"] or "", row["urun_turu_adi"] or row["urun_tipi"] or "", row["barkod"] or "", row["uretici"] or "",
                row["marka"] or "", row["model"] or "", row["birim"] or "",
                self.fmt_qty(row["min_seviye"]), self.fmt_qty(row["mevcut"]), self.fmt_qty(row["max_seviye"]),
                self.fmt_money(row["alis_fiyati"]), self.fmt_money(row["satis_fiyati"]),
            ]
            for c, value in enumerate(vals):
                item = QTableWidgetItem(str(value))
                if c == 0:
                    item.setData(Qt.UserRole, row["id"])
                    item.setTextAlignment(Qt.AlignCenter)
                self.table.setItem(r, c, item)
            current = float(row["mevcut"] or 0)
            min_s = float(row["min_seviye"] or 0)
            max_s = float(row["max_seviye"] or 0)
            if current < 0:
                for c in range(self.table.columnCount()):
                    self.table.item(r, c).setData(Qt.BackgroundRole, QColor(Qt.red).lighter(170))
            elif min_s and current < min_s:
                for c in range(self.table.columnCount()):
                    self.table.item(r, c).setData(Qt.BackgroundRole, QColor(Qt.yellow).lighter(170))
            elif max_s and current > max_s:
                for c in range(self.table.columnCount()):
                    self.table.item(r, c).setData(Qt.BackgroundRole, QColor(Qt.cyan).lighter(185))
        self.table.setSortingEnabled(False)
        self.info.setText(f"Toplam {len(rows)} kayıt")
        self.status.setText("Ürün kartları güncellendi.")

    @staticmethod
    def fmt_qty(v):
        x = float(v or 0)
        return f"{x:,.3f}".replace(',', 'X').replace('.', ',').replace('X', '.')

    @staticmethod
    def fmt_money(v):
        x = float(v or 0)
        return f"{x:,.2f} TL".replace(',', 'X').replace('.', ',').replace('X', '.')

    def new_product(self):
        dlg = ProductDialog(self, self.db)
        if dlg.exec_() == QDialog.Accepted:
            self.refresh()

    def edit_product(self):
        product_id = self.selected_id()
        if not product_id:
            QMessageBox.information(self, "Seçim", "Düzenlemek için bir ürün seçin.")
            return
        dlg = ProductDialog(self, self.db, product_id)
        if dlg.exec_() == QDialog.Accepted:
            self.refresh()

    def copy_product(self):
        product_id = self.selected_id()
        if not product_id:
            QMessageBox.information(self, "Seçim", "Kopyalamak için bir ürün seçin.")
            return
        dlg = ProductDialog(self, self.db, product_id, copy_mode=True)
        if dlg.exec_() == QDialog.Accepted:
            self.refresh()

    def delete_product(self):
        product_id = self.selected_id()
        if not product_id:
            QMessageBox.information(self, "Seçim", "Silmek için bir ürün seçin.")
            return
        row = self.db.get_product(product_id)
        if not row:
            return
        reply = QMessageBox.question(
            self, "Ürün Silme", f"'{row['kod']} - {row['ad']}' ürünü silinsin/pasifleştirilsin mi?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            archived = self.db.delete_product(product_id)
            QMessageBox.information(self, "İşlem Tamam", "Ürün stok hareketi içerdiği için pasifleştirildi." if archived else "Ürün silindi.")
            self.refresh()

    def _table_export_rows(self):
        headers = [self.table.horizontalHeaderItem(i).text() for i in range(self.table.columnCount())]
        rows = []
        for r in range(self.table.rowCount()):
            rows.append([self.table.item(r, c).text() if self.table.item(r, c) else "" for c in range(self.table.columnCount())])
        return headers, rows

    def export_excel(self):
        filters = (
            "Excel Çalışma Kitabı (*.xlsx);;"
            "Excel 97-2003 Çalışma Kitabı (*.xls);;"
            "CSV Dosyası (*.csv)"
        )
        path, selected_filter = QFileDialog.getSaveFileName(
            self,
            "Ürün Kartlarını Excel'e Aktar",
            "urun_kartlari.xlsx",
            filters
        )
        if not path:
            return

        # Kullanıcı uzantıyı filtreden farklı seçmişse beklenen uzantıyı ekle/değiştir.
        selected_lower = selected_filter.lower()
        if "xlsx" in selected_lower:
            if not path.lower().endswith('.xlsx'):
                path += '.xlsx'
            self._export_xlsx(path)
        elif "xls" in selected_lower:
            if not path.lower().endswith('.xls'):
                path += '.xls'
            self._export_xls(path)
        else:
            if not path.lower().endswith('.csv'):
                path += '.csv'
            self._export_csv(path)

    def _export_csv(self, path):
        headers, rows = self._table_export_rows()
        try:
            with open(path, "w", newline="", encoding="utf-8-sig") as fh:
                writer = csv.writer(fh, delimiter=';')
                writer.writerow(headers)
                writer.writerows(rows)
            QMessageBox.information(self, "Aktarım", f"CSV dosyası oluşturuldu.\n\n{path}")
        except (OSError, PermissionError) as exc:
            QMessageBox.critical(self, "Aktarım Hatası", str(exc))

    def _export_xlsx(self, path):
        headers, rows = self._table_export_rows()
        try:
            import xlsxwriter
        except ImportError:
            QMessageBox.critical(
                self,
                "Eksik Paket",
                "XLSX aktarımı için XlsxWriter paketi kurulu değil.\n\n"
                "Terminalde şu komutu çalıştırın:\n"
                "python -m pip install XlsxWriter"
            )
            return

        try:
            workbook = xlsxwriter.Workbook(path)
            worksheet = workbook.add_worksheet("Ürün Kartları")
            header_fmt = workbook.add_format({
                "bold": True, "bg_color": "#D9EAF7", "border": 1,
                "align": "center", "valign": "vcenter"
            })
            cell_fmt = workbook.add_format({"border": 1, "valign": "top"})
            num_fmt = workbook.add_format({"border": 1, "num_format": '#,##0.000'})
            money_fmt = workbook.add_format({"border": 1, "num_format": '#,##0.00'})

            for c, header in enumerate(headers):
                worksheet.write(0, c, header, header_fmt)

            money_cols = {13, 14}
            qty_cols = {10, 11, 12}
            for r, row in enumerate(rows, 1):
                for c, value in enumerate(row):
                    if c in money_cols:
                        try:
                            numeric = float(value.replace(' TL', '').replace('.', '').replace(',', '.'))
                            worksheet.write_number(r, c, numeric, money_fmt)
                            continue
                        except (TypeError, ValueError):
                            pass
                    if c in qty_cols:
                        try:
                            numeric = float(value.replace('.', '').replace(',', '.'))
                            worksheet.write_number(r, c, numeric, num_fmt)
                            continue
                        except (TypeError, ValueError):
                            pass
                    worksheet.write(r, c, value, cell_fmt)

            widths = [8, 14, 28, 22, 20, 18, 20, 18, 16, 12, 12, 14, 12, 16, 16]
            for c, width in enumerate(widths[:len(headers)]):
                worksheet.set_column(c, c, width)
            worksheet.freeze_panes(1, 0)
            worksheet.autofilter(0, 0, len(rows), len(headers) - 1)
            worksheet.set_landscape()
            worksheet.fit_to_pages(1, 0)
            workbook.close()
            QMessageBox.information(self, "Aktarım", f"XLSX dosyası oluşturuldu.\n\n{path}")
        except Exception as exc:
            QMessageBox.critical(self, "XLSX Aktarım Hatası", str(exc))
            try:
                Path(path).unlink(missing_ok=True)
            except OSError:
                pass

    def _export_xls(self, path):
        # Gerçek Excel 97-2003 (.xls) dosyası için Windows'taki Microsoft Excel
        # COM arayüzünü kullanıyoruz. Bu yöntem, uzantısı .xls olan gerçek BIFF8
        # dosyası üretir; yalnızca CSV'yi .xls olarak yeniden adlandırmaz.
        try:
            import win32com.client  # pywin32
        except ImportError:
            QMessageBox.critical(
                self,
                "Eksik Paket",
                "XLS aktarımı için pywin32 paketi gerekli.\n\n"
                "Terminalde şu komutu çalıştırın:\n"
                "python -m pip install pywin32\n\n"
                "Ayrıca bilgisayarınızda Microsoft Excel kurulu olmalıdır."
            )
            return

        temp_xlsx = None
        excel = None
        wb = None
        try:
            with tempfile.NamedTemporaryFile(suffix='.xlsx', delete=False) as tmp:
                temp_xlsx = tmp.name

            # Önce XlsxWriter ile geçici bir çalışma kitabı oluştur.
            headers, rows = self._table_export_rows()
            try:
                import xlsxwriter
            except ImportError:
                QMessageBox.critical(
                    self,
                    "Eksik Paket",
                    "XLS aktarımı için XlsxWriter paketi de gerekli.\n\n"
                    "Terminalde şu komutu çalıştırın:\n"
                    "python -m pip install XlsxWriter pywin32"
                )
                return
            workbook = xlsxwriter.Workbook(temp_xlsx)
            worksheet = workbook.add_worksheet("Ürün Kartları")
            header_fmt = workbook.add_format({
                "bold": True, "bg_color": "#D9EAF7", "border": 1,
                "align": "center", "valign": "vcenter"
            })
            cell_fmt = workbook.add_format({"border": 1})
            for c, header in enumerate(headers):
                worksheet.write(0, c, header, header_fmt)
            for r, row in enumerate(rows, 1):
                for c, value in enumerate(row):
                    worksheet.write(r, c, value, cell_fmt)
            for c, width in enumerate([8, 14, 28, 22, 20, 18, 20, 18, 16, 12, 12, 14, 12, 16, 16][:len(headers)]):
                worksheet.set_column(c, c, width)
            worksheet.freeze_panes(1, 0)
            worksheet.autofilter(0, 0, len(rows), len(headers) - 1)
            workbook.close()

            excel = win32com.client.DispatchEx("Excel.Application")
            excel.Visible = False
            excel.DisplayAlerts = False
            wb = excel.Workbooks.Open(str(Path(temp_xlsx).resolve()))
            wb.SaveAs(str(Path(path).resolve()), FileFormat=56)  # xlExcel8
            wb.Close(SaveChanges=False)
            wb = None
            excel.Quit()
            excel = None
            QMessageBox.information(self, "Aktarım", f"XLS dosyası oluşturuldu.\n\n{path}")
        except Exception as exc:
            QMessageBox.critical(
                self,
                "XLS Aktarım Hatası",
                "Excel 97-2003 (.xls) aktarımı sırasında hata oluştu.\n\n" + str(exc)
            )
        finally:
            try:
                if wb is not None:
                    wb.Close(SaveChanges=False)
            except Exception:
                pass
            try:
                if excel is not None:
                    excel.Quit()
            except Exception:
                pass
            if temp_xlsx:
                try:
                    Path(temp_xlsx).unlink(missing_ok=True)
                except OSError:
                    pass

    def show_context_menu(self, pos):
        from PyQt5.QtWidgets import QMenu
        menu = QMenu(self)
        menu.addAction("Düzenle", self.edit_product)
        menu.addAction("Kopyala", self.copy_product)
        menu.addAction("Sil / Pasifleştir", self.delete_product)
        menu.exec_(self.table.viewport().mapToGlobal(pos))


class DefinitionDialog(QDialog):
    """Ürün grubu, depo, departman, alt birim, birim ve ürün türlerini DB üzerinden yönetir."""
    CONFIG = {
        'urun_gruplari': ('Ürün Grupları', 'Grup Kodu', 'Grup Adı'),
        'depolar': ('Depolar', 'Depo Kodu', 'Depo Adı'),
        'departmanlar': ('Departmanlar', 'Departman Kodu', 'Departman Adı'),
        'birimler': ('Birimler', 'Birim Kodu', 'Birim Adı'),
        'urun_turleri': ('Ürün Türleri', 'Tür Kodu', 'Tür Adı'),
    }

    def __init__(self, parent, db, table):
        super().__init__(parent)
        self.db = db
        self.table_name = table
        self.item_id = None
        title, code_label, name_label = self.CONFIG[table]
        self.setWindowTitle(title)
        self.resize(820 if table != 'departmanlar' else 1040, 620)
        root = QVBoxLayout(self)

        head = QHBoxLayout()
        lbl = QLabel(title.upper())
        lbl.setObjectName('dialogTitle')
        head.addWidget(lbl)
        head.addStretch()
        self.show_inactive = QCheckBox('Pasifleri göster')
        self.show_inactive.stateChanged.connect(self.refresh)
        head.addWidget(self.show_inactive)
        root.addLayout(head)

        content = QHBoxLayout()
        left = QVBoxLayout()
        form = QGroupBox('Tanım Bilgisi')
        f = QGridLayout(form)
        self.code = QLineEdit()
        self.name = QLineEdit()
        self.active = QCheckBox('Aktif')
        self.active.setChecked(True)
        f.addWidget(QLabel(code_label), 0, 0)
        f.addWidget(self.code, 0, 1)
        f.addWidget(QLabel(name_label), 0, 2)
        f.addWidget(self.name, 0, 3)
        f.addWidget(self.active, 0, 4)
        self.save_btn = QPushButton('Kaydet')
        self.save_btn.clicked.connect(self.save)
        self.new_btn = QPushButton('Yeni / Temizle')
        self.new_btn.clicked.connect(self.clear_form)
        f.addWidget(self.new_btn, 1, 3)
        f.addWidget(self.save_btn, 1, 4)
        left.addWidget(form)

        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(['No', 'Kod', 'Ad', 'Durum'])
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.doubleClicked.connect(lambda _: self.load_selected())
        configure_resizable_table(self.table, f"tanım_{table}", [55, 120, 240, 100])
        if table == 'departmanlar':
            self.table.itemSelectionChanged.connect(self.load_selected_subunits)
        left.addWidget(self.table, 1)
        content.addLayout(left, 3)

        if table == 'departmanlar':
            right = QGroupBox('Departmana Bağlı Alt Birimler')
            rv = QVBoxLayout(right)
            self.selected_department = QLabel('Departman seçiniz.')
            self.selected_department.setObjectName('dialogTitle')
            rv.addWidget(self.selected_department)
            subform = QGridLayout()
            self.sub_code = QLineEdit()
            self.sub_name = QLineEdit()
            self.sub_active = QCheckBox('Aktif')
            self.sub_active.setChecked(True)
            subform.addWidget(QLabel('Alt Birim Kodu'), 0, 0)
            subform.addWidget(self.sub_code, 0, 1)
            subform.addWidget(QLabel('Alt Birim Adı'), 1, 0)
            subform.addWidget(self.sub_name, 1, 1)
            subform.addWidget(self.sub_active, 2, 0, 1, 2)
            self.sub_save = QPushButton('Alt Birimi Kaydet')
            self.sub_save.clicked.connect(self.save_subunit)
            self.sub_new = QPushButton('Yeni / Temizle')
            self.sub_new.clicked.connect(self.clear_subunit_form)
            subform.addWidget(self.sub_new, 3, 0)
            subform.addWidget(self.sub_save, 3, 1)
            rv.addLayout(subform)
            self.subtable = QTableWidget(0, 4)
            self.subtable.setHorizontalHeaderLabels(['No', 'Kod', 'Ad', 'Durum'])
            self.subtable.setSelectionBehavior(QAbstractItemView.SelectRows)
            self.subtable.setSelectionMode(QAbstractItemView.SingleSelection)
            self.subtable.setEditTriggers(QAbstractItemView.NoEditTriggers)
            self.subtable.setAlternatingRowColors(True)
            self.subtable.doubleClicked.connect(lambda _: self.load_subunit())
            configure_resizable_table(self.subtable, "departman_alt_birimleri", [55, 120, 220, 100])
            rv.addWidget(self.subtable, 1)
            subactions = QHBoxLayout()
            se = QPushButton('Düzenle')
            se.clicked.connect(self.load_subunit)
            st = QPushButton('Aktif / Pasif')
            st.clicked.connect(self.toggle_subunit)
            sd = QPushButton('Sil')
            sd.clicked.connect(self.delete_selected_subunit)
            subactions.addWidget(se)
            subactions.addWidget(st)
            subactions.addWidget(sd)
            rv.addLayout(subactions)
            content.addWidget(right, 2)
            self.subunit_id = None
        root.addLayout(content, 1)

        actions = QHBoxLayout()
        self.edit_btn = QPushButton('Düzenle')
        self.edit_btn.clicked.connect(self.load_selected)
        self.toggle_btn = QPushButton('Aktif / Pasif')
        self.toggle_btn.clicked.connect(self.toggle_selected)
        self.delete_btn = QPushButton('Sil / Pasifleştir')
        self.delete_btn.clicked.connect(self.delete_selected_definition)
        close = QPushButton('Kapat')
        close.clicked.connect(self.accept)
        actions.addWidget(self.edit_btn)
        actions.addWidget(self.toggle_btn)
        if self.delete_btn is not None:
            actions.addWidget(self.delete_btn)
        actions.addStretch()
        actions.addWidget(close)
        root.addLayout(actions)
        self.refresh()

    def refresh(self):
        rows = self.db.list_definition(self.table_name, not self.show_inactive.isChecked())
        self.table.setRowCount(0)
        for i, row in enumerate(rows, 1):
            r = self.table.rowCount()
            self.table.insertRow(r)
            vals = [i, row['kod'] or '', row['ad'], 'AKTİF' if row['aktif'] else 'PASİF']
            for c, val in enumerate(vals):
                item = QTableWidgetItem(str(val))
                if c == 0:
                    item.setData(Qt.UserRole, row['id'])
                    item.setTextAlignment(Qt.AlignCenter)
                if not row['aktif']:
                    item.setData(Qt.BackgroundRole, Qt.lightGray)
                self.table.setItem(r, c, item)
        self.clear_form()
        if self.table_name == 'departmanlar':
            self.clear_subunit_form()
            self.subtable.setRowCount(0)
            self.selected_department.setText('Departman seçiniz.')

    def selected_id(self):
        r = self.table.currentRow()
        if r < 0 or not self.table.item(r, 0):
            return None
        return self.table.item(r, 0).data(Qt.UserRole)

    def load_selected(self):
        iid = self.selected_id()
        if not iid:
            QMessageBox.information(self, 'Seçim', 'Düzenlemek için bir kayıt seçin.')
            return
        row = self.db.conn.execute(f'SELECT * FROM {self.table_name} WHERE id=?', (iid,)).fetchone()
        if not row:
            return
        self.item_id = iid
        self.code.setText(row['kod'] or '')
        self.name.setText(row['ad'] or '')
        self.active.setChecked(bool(row['aktif']))
        self.save_btn.setText('Güncelle')
        self.code.setFocus()
        if self.table_name == 'departmanlar':
            self.load_selected_subunits()

    def clear_form(self):
        self.item_id = None
        self.code.clear()
        self.name.clear()
        self.active.setChecked(True)
        self.save_btn.setText('Kaydet')
        self.table.clearSelection()

    def save(self):
        code = self.code.text().strip().upper()
        name = self.name.text().strip()
        if not code or not name:
            QMessageBox.warning(self, 'Eksik Bilgi', 'Kod ve ad alanları zorunludur.')
            return
        try:
            self.db.save_definition(self.table_name, code, name, 1 if self.active.isChecked() else 0, self.item_id)
        except sqlite3.IntegrityError as exc:
            QMessageBox.critical(self, 'Kayıt Hatası', f'Kayıt yapılamadı. Aynı kod/ad zaten kullanılabilir.\n\n{exc}')
            return
        self.refresh()

    def delete_selected_definition(self):
        """Selected definition: physically delete if unused; otherwise deactivate safely."""
        iid = self.selected_id()
        if not iid:
            QMessageBox.information(self, 'Seçim', 'Silmek için bir kayıt seçin.')
            return
        row = self.db.conn.execute(
            f'SELECT kod, ad, aktif FROM {self.table_name} WHERE id=?', (iid,)
        ).fetchone()
        if not row:
            QMessageBox.warning(self, 'Kayıt bulunamadı', 'Seçilen kayıt artık mevcut değil.')
            self.refresh()
            return
        if not row['aktif']:
            QMessageBox.information(self, 'Pasif Kayıt', 'Seçilen kayıt zaten pasif durumda.')
            return
        usage_total, usage = self.db.definition_usage(self.table_name, iid)
        if usage_total:
            detail = '\n'.join(f'- {label}: {count}' for label, count in usage)
            reply = QMessageBox.question(
                self,
                'Silme / Pasifleştirme',
                f"'{row['ad']}' geçmiş kayıtlarda kullanılmıştır.\n\n{detail}\n\n"
                'Geçmiş kayıtların bütünlüğü için fiziksel olarak silinemez. Pasifleştirilsin mi?',
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.Yes
            )
            if reply == QMessageBox.Yes:
                self.db.conn.execute(
                    f'UPDATE {self.table_name} SET aktif=0 WHERE id=?', (iid,)
                )
                self.db.conn.commit()
                QMessageBox.information(self, 'İşlem Tamam', 'Kayıt pasifleştirildi.')
                self.refresh()
            return
        reply = QMessageBox.question(
            self, 'Silme Onayı',
            f"'{row['ad']}' kaydı silinsin mi? Bu işlem geri alınamaz.",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No
        )
        if reply != QMessageBox.Yes:
            return
        try:
            result = self.db.delete_definition_safe(self.table_name, iid)
            if result.get('deleted'):
                QMessageBox.information(self, 'İşlem Tamam', 'Kayıt silindi.')
            else:
                QMessageBox.information(self, 'İşlem Tamam', 'Kayıt pasifleştirildi.')
        except Exception as exc:
            QMessageBox.critical(self, 'Silme Hatası', f'Kayıt silinemedi.\n\n{exc}')
            return
        self.refresh()

    def delete_selected_department(self):
        # Geriye dönük uyumluluk: eski çağrılar aynı güvenli silme işlemini kullansın.
        self.delete_selected_definition()

    def toggle_selected(self):
        iid = self.selected_id()
        if not iid:
            QMessageBox.information(self, 'Seçim', 'Aktif/pasif yapmak için bir kayıt seçin.')
            return
        row = self.db.conn.execute(f'SELECT aktif, ad FROM {self.table_name} WHERE id=?', (iid,)).fetchone()
        if not row:
            return
        if row['aktif']:
            used = self.db.deactivate_definition(self.table_name, iid)
            msg = 'Kayıt pasifleştirildi.'
            if used:
                msg += f'\nBu tanım geçmişte {used} kayıtla ilişkili; fiziksel silme yapılmadı.'
        else:
            self.db.restore_definition(self.table_name, iid)
            msg = 'Kayıt tekrar aktifleştirildi.'
        QMessageBox.information(self, 'İşlem Tamam', msg)
        self.refresh()

    # ---- Departman alt birimleri ----
    def load_selected_subunits(self):
        if self.table_name != 'departmanlar':
            return
        dept_id = self.selected_id()
        if not dept_id:
            self.selected_department.setText('Departman seçiniz.')
            self.subtable.setRowCount(0)
            return
        row = self.db.conn.execute('SELECT kod, ad FROM departmanlar WHERE id=?', (dept_id,)).fetchone()
        self.selected_department.setText(f"{row['kod']} - {row['ad']} / Alt Birimler")
        self.subunit_id = None
        self.clear_subunit_form(clear_selection=False)
        rows = self.db.subunits(dept_id, True)
        self.subtable.setRowCount(0)
        for i, sr in enumerate(rows, 1):
            r = self.subtable.rowCount()
            self.subtable.insertRow(r)
            vals = [i, sr['kod'], sr['ad'], 'AKTİF' if sr['aktif'] else 'PASİF']
            for c, val in enumerate(vals):
                item = QTableWidgetItem(str(val))
                if c == 0:
                    item.setData(Qt.UserRole, sr['id'])
                    item.setTextAlignment(Qt.AlignCenter)
                if not sr['aktif']:
                    item.setData(Qt.BackgroundRole, Qt.lightGray)
                self.subtable.setItem(r, c, item)

    def selected_subunit_id(self):
        if self.table_name != 'departmanlar':
            return None
        r = self.subtable.currentRow()
        if r < 0 or not self.subtable.item(r, 0):
            return None
        return self.subtable.item(r, 0).data(Qt.UserRole)

    def clear_subunit_form(self, clear_selection=True):
        if self.table_name != 'departmanlar':
            return
        self.subunit_id = None
        self.sub_code.clear()
        self.sub_name.clear()
        self.sub_active.setChecked(True)
        self.sub_save.setText('Alt Birimi Kaydet')
        if clear_selection:
            self.subtable.clearSelection()

    def load_subunit(self):
        iid = self.selected_subunit_id()
        dept_id = self.selected_id()
        if not iid or not dept_id:
            QMessageBox.information(self, 'Seçim', 'Düzenlemek için bir alt birim seçin.')
            return
        row = self.db.conn.execute('SELECT * FROM departman_alt_birimleri WHERE id=? AND departman_id=?', (iid, dept_id)).fetchone()
        if not row:
            return
        self.subunit_id = iid
        self.sub_code.setText(row['kod'])
        self.sub_name.setText(row['ad'])
        self.sub_active.setChecked(bool(row['aktif']))
        self.sub_save.setText('Alt Birimi Güncelle')

    def save_subunit(self):
        dept_id = self.selected_id()
        if not dept_id:
            QMessageBox.warning(self, 'Departman Seçimi', 'Önce sol taraftan bir departman seçin.')
            return
        code = self.sub_code.text().strip().upper()
        name = self.sub_name.text().strip()
        if not code or not name:
            QMessageBox.warning(self, 'Eksik Bilgi', 'Alt Birim Kodu ve Alt Birim Adı zorunludur.')
            return
        existing = self.db.conn.execute(
            "SELECT id, kod, ad FROM departman_alt_birimleri WHERE departman_id=?", (dept_id,)
        ).fetchall()
        ckey, nkey = self.db._normalize_key(code), self.db._normalize_key(name)
        for ex in existing:
            if self.subunit_id is not None and ex['id'] == self.subunit_id:
                continue
            if ckey and self.db._normalize_key(ex['kod']) == ckey:
                QMessageBox.warning(self, 'Mükerrer Alt Birim Kodu', f"Bu departmanda '{ex['kod']}' kodu zaten kullanılıyor.")
                return
            if nkey and self.db._normalize_key(ex['ad']) == nkey:
                QMessageBox.warning(self, 'Mükerrer Alt Birim Adı', f"Bu departmanda '{ex['ad']}' adı zaten kullanılıyor.")
                return
        try:
            self.db.save_subunit(dept_id, code, name, 1 if self.sub_active.isChecked() else 0, self.subunit_id)
        except sqlite3.IntegrityError as exc:
            QMessageBox.critical(self, 'Kayıt Hatası', f'Alt birim kaydedilemedi. Aynı departmanda kod/ad tekrar edemez.\n\n{exc}')
            return
        self.load_selected_subunits()
        self.clear_subunit_form()

    def delete_selected_subunit(self):
        iid = self.selected_subunit_id()
        if not iid:
            QMessageBox.information(self, 'Seçim', 'Silmek için bir alt birim seçin.')
            return
        row = self.db.conn.execute(
            'SELECT kod, ad FROM departman_alt_birimleri WHERE id=?', (iid,)
        ).fetchone()
        if not row:
            return
        reply = QMessageBox.question(
            self, 'Alt Birim Silme',
            f"'{row['kod']} - {row['ad']}' alt birimi kalıcı olarak silinsin mi?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No
        )
        if reply != QMessageBox.Yes:
            return
        result = self.db.delete_subunit(iid)
        if not result['deleted']:
            QMessageBox.warning(
                self, 'Silme Engellendi',
                'Bu alt birim geçmiş stok fişi/hareketleriyle ilişkili olduğu için fiziksel olarak silinemez.\n\n'
                f"Stok hareketi: {result['movement_count']}\nFiş: {result['slip_count']}\n\n"
                'Geçmiş kayıtların bütünlüğü için alt birimi pasif yapabilirsiniz.'
            )
            return
        QMessageBox.information(self, 'İşlem Tamam', 'Alt birim silindi.')
        self.load_selected_subunits()
        self.clear_subunit_form()

    def toggle_subunit(self):
        iid = self.selected_subunit_id()
        if not iid:
            QMessageBox.information(self, 'Seçim', 'Aktif/pasif yapmak için bir alt birim seçin.')
            return
        self.db.toggle_subunit(iid)
        self.load_selected_subunits()


class CariDialog(QDialog):
    def __init__(self, parent, db):
        super().__init__(parent)
        self.db = db
        self.item_id = None
        self.setWindowTitle("Cari Hesap Tanımları")
        self.resize(950, 620)
        root = QVBoxLayout(self)

        top = QHBoxLayout()
        title = QLabel("CARİ HESAP TANIMLARI")
        title.setObjectName("dialogTitle")
        top.addWidget(title)
        top.addStretch()
        self.show_inactive = QCheckBox("Pasifleri göster")
        self.show_inactive.stateChanged.connect(self.refresh)
        top.addWidget(self.show_inactive)
        root.addLayout(top)

        form = QGroupBox("Cari Bilgileri")
        f = QGridLayout(form)
        self.code = QLineEdit()
        self.title = QLineEdit()
        self.phone = QLineEdit()
        self.email = QLineEdit()
        self.address = QLineEdit()
        self.active = QCheckBox("Aktif")
        self.active.setChecked(True)
        fields = [
            ("Cari Kodu", self.code), ("Ünvan", self.title), ("Telefon", self.phone),
            ("E-posta", self.email), ("Adres", self.address)
        ]
        for i, (label, widget) in enumerate(fields):
            f.addWidget(QLabel(label), i, 0)
            f.addWidget(widget, i, 1, 1, 3)
        f.addWidget(self.active, 5, 0, 1, 2)
        self.save_btn = QPushButton("Kaydet")
        self.save_btn.clicked.connect(self.save)
        f.addWidget(self.save_btn, 5, 3)
        root.addWidget(form)

        actions = QHBoxLayout()
        new_btn = QPushButton("Yeni / Temizle")
        new_btn.clicked.connect(self.clear_form)
        edit_btn = QPushButton("Düzenle")
        edit_btn.clicked.connect(self.load_selected)
        toggle_btn = QPushButton("Aktif / Pasif")
        toggle_btn.clicked.connect(self.toggle)
        delete_btn = QPushButton("Sil / Pasifleştir")
        delete_btn.clicked.connect(self.delete_selected)
        actions.addWidget(new_btn)
        actions.addWidget(edit_btn)
        actions.addWidget(toggle_btn)
        actions.addWidget(delete_btn)
        actions.addStretch()
        root.addLayout(actions)

        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["No", "Kod", "Ünvan", "Telefon", "Durum"])
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        configure_resizable_table(self.table, "cari_hesaplar", [55, 120, 260, 150, 100])
        self.table.doubleClicked.connect(lambda _: self.load_selected())
        root.addWidget(self.table, 1)

        close_btn = QPushButton("Kapat")
        close_btn.clicked.connect(self.accept)
        root.addWidget(close_btn, 0, Qt.AlignRight)
        self.refresh()

    def refresh(self):
        where = "" if self.show_inactive.isChecked() else "WHERE aktif=1"
        rows = self.db.conn.execute(f"SELECT * FROM cariler {where} ORDER BY unvan").fetchall()
        self.table.setRowCount(0)
        for i, row in enumerate(rows, 1):
            r = self.table.rowCount()
            self.table.insertRow(r)
            values = [i, row["kod"] or "", row["unvan"], row["telefon"] or "", "AKTİF" if row["aktif"] else "PASİF"]
            for c, value in enumerate(values):
                item = QTableWidgetItem(str(value))
                if c == 0:
                    item.setData(Qt.UserRole, row["id"])
                    item.setTextAlignment(Qt.AlignCenter)
                if not row["aktif"]:
                    item.setData(Qt.BackgroundRole, Qt.lightGray)
                self.table.setItem(r, c, item)
        self.clear_form()

    def selected_id(self):
        row = self.table.currentRow()
        if row < 0 or not self.table.item(row, 0):
            return None
        return self.table.item(row, 0).data(Qt.UserRole)

    def clear_form(self):
        self.item_id = None
        self.code.clear()
        self.code.setText(self.next_code())
        for widget in (self.title, self.phone, self.email, self.address):
            widget.clear()
        self.active.setChecked(True)
        self.save_btn.setText("Kaydet")
        self.code.setFocus()

    def next_code(self):
        """Bir sonraki boş cari kodunu CRI0001 formatında üretir.

        Kullanıcı kod alanını değiştirebilir; otomatik numaralandırma yalnızca
        yeni cari kaydında başlangıç değeri olarak kullanılır. Mevcut kayıtlardaki
        en yüksek CRI/CRİ sayısal eki taranır; arada boşluk varsa kullanılmayan
        en küçük numara tercih edilir.
        """
        rows = self.db.conn.execute("SELECT kod FROM cariler WHERE kod IS NOT NULL").fetchall()
        used = set()
        pattern = re.compile(r"^CR[Iİ](\d+)$", re.IGNORECASE)
        for row in rows:
            code = (row["kod"] or "").strip().upper()
            match = pattern.match(code)
            if match:
                try:
                    used.add(int(match.group(1)))
                except ValueError:
                    pass
        n = 1
        while n in used:
            n += 1
        return f"CRI{n:04d}"

    def load_selected(self):
        item_id = self.selected_id()
        if not item_id:
            QMessageBox.information(self, "Seçim", "Bir cari seçin.")
            return
        row = self.db.conn.execute("SELECT * FROM cariler WHERE id=?", (item_id,)).fetchone()
        if not row:
            return
        self.item_id = item_id
        self.code.setText(row["kod"] or "")
        self.title.setText(row["unvan"] or "")
        self.phone.setText(row["telefon"] or "")
        self.email.setText(row["email"] or "")
        self.address.setText(row["adres"] or "")
        self.active.setChecked(bool(row["aktif"]))
        self.save_btn.setText("Güncelle")

    def save(self):
        code = self.code.text().strip().upper()
        title = self.title.text().strip()
        if not code or not title:
            QMessageBox.warning(self, "Eksik Bilgi", "Cari Kodu ve Ünvan zorunludur.")
            return

        duplicate = self.db.cari_duplicate_unvan(title, self.item_id)
        if duplicate:
            QMessageBox.warning(
                self,
                "Mükerrer Cari Ünvanı",
                f"Bu ünvana sahip bir cari zaten kayıtlı.\n\n"
                f"Kod: {duplicate['kod'] or '-'}\n"
                f"Ünvan: {duplicate['unvan']}\n\n"
                "Aynı ünvana sahip ikinci bir cari hesap kaydedilemez."
            )
            return

        try:
            values = (code, title, self.phone.text().strip(), self.email.text().strip(), self.address.text().strip(), 1 if self.active.isChecked() else 0)
            if self.item_id:
                self.db.conn.execute("UPDATE cariler SET kod=?,unvan=?,telefon=?,email=?,adres=?,aktif=? WHERE id=?", values + (self.item_id,))
            else:
                self.db.conn.execute("INSERT INTO cariler(kod,unvan,telefon,email,adres,aktif) VALUES(?,?,?,?,?,?)", values)
            self.db.conn.commit()
        except sqlite3.IntegrityError as exc:
            QMessageBox.critical(self, "Kayıt Hatası", str(exc))
            return
        self.refresh()

    def toggle(self):
        item_id = self.selected_id()
        if not item_id:
            QMessageBox.information(self, "Seçim", "Bir cari seçin.")
            return
        row = self.db.conn.execute("SELECT aktif FROM cariler WHERE id=?", (item_id,)).fetchone()
        self.db.conn.execute("UPDATE cariler SET aktif=? WHERE id=?", (0 if row["aktif"] else 1, item_id))
        self.db.conn.commit()
        self.refresh()


    def delete_selected(self):
        iid = self.selected_id()
        if not iid:
            QMessageBox.information(self, 'Seçim', 'Silmek için bir cari seçin.')
            return
        row = self.db.conn.execute('SELECT kod, unvan, aktif FROM cariler WHERE id=?', (iid,)).fetchone()
        if not row:
            return
        total, usage = self.db.cari_usage(iid)
        if total:
            detail='\n'.join(f'• {label}: {count}' for label,count in usage)
            reply=QMessageBox.question(self,'Cari Kullanımda',
                f"'{row['kod']} - {row['unvan']}' geçmiş işlemlerde kullanılmış.\n\n{detail}\n\nPasifleştirilsin mi?",
                QMessageBox.Yes|QMessageBox.No,QMessageBox.Yes)
            if reply != QMessageBox.Yes: return
        else:
            reply=QMessageBox.question(self,'Cari Silme',
                f"'{row['kod']} - {row['unvan']}' kalıcı olarak silinsin mi?\n\nBu kayıt kullanılmıyor.",
                QMessageBox.Yes|QMessageBox.No,QMessageBox.No)
            if reply != QMessageBox.Yes: return
        result=self.db.delete_cari_safe(iid)
        if result['deleted']:
            QMessageBox.information(self,'İşlem Tamam','Cari hesap silindi.')
        else:
            QMessageBox.information(self,'İşlem Tamam','Cari hesap pasifleştirildi; geçmiş kayıtlar korundu.')
        self.refresh()

class InventoryCountDialog(QDialog):
    def __init__(self, parent, db, current_user=None):
        super().__init__(parent)
        self.db=db; self.current_user=current_user; self.rows=[]
        self.setWindowTitle("Stok Sayım Fişi")
        self.setMinimumSize(1250,760); self.resize(1400,820)
        self.build_ui(); self.load_definitions()

    def build_ui(self):
        root=QVBoxLayout(self)
        title=QLabel("STOK SAYIM FİŞİ"); title.setObjectName("dialogTitle"); root.addWidget(title)
        header=QGroupBox("Sayım Bilgileri"); g=QGridLayout(header)
        self.sayim_no=QLineEdit(); self.sayim_no.setReadOnly(True)
        self.tarih=QDateEdit(QDate.currentDate()); self.tarih.setCalendarPopup(True)
        self.depo=QComboBox(); self.search=QLineEdit(); self.search.setPlaceholderText("Kod, ürün adı, barkod, marka veya model...")
        self.aciklama=QLineEdit(); self.aciklama.setPlaceholderText("Sayım açıklaması / dönem / ekip...")
        g.addWidget(QLabel("Sayım No"),0,0); g.addWidget(self.sayim_no,0,1)
        g.addWidget(QLabel("Tarih*"),0,2); g.addWidget(self.tarih,0,3)
        g.addWidget(QLabel("Depo*"),0,4); g.addWidget(self.depo,0,5)
        g.addWidget(QLabel("Açıklama"),1,0); g.addWidget(self.aciklama,1,1,1,5)
        root.addWidget(header)
        toolbar=QHBoxLayout()
        btn_load=QPushButton("Mevcut Stokları Getir"); btn_load.clicked.connect(self.load_products)
        btn_scan=QPushButton("Barkod / Kod Bul"); btn_scan.clicked.connect(self.lookup_product)
        self.search.textChanged.connect(self.filter_table)
        toolbar.addWidget(btn_load); toolbar.addWidget(btn_scan); toolbar.addWidget(QLabel("Ürün Ara:")); toolbar.addWidget(self.search,1)
        root.addLayout(toolbar)
        self.table=QTableWidget(0,9)
        self.table.setHorizontalHeaderLabels(["Ürün Kodu","Ürün Adı","Barkod","Birim","Sistem Stok","Sayılan","Fark","Durum","Açıklama"])
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows); self.table.setEditTriggers(QAbstractItemView.DoubleClicked|QAbstractItemView.EditKeyPressed)
        configure_resizable_table(self.table,"stok_sayim_satirlari",[115,250,130,75,110,110,100,120,220])
        self.table.cellChanged.connect(self.cell_changed)
        root.addWidget(self.table,1)
        info=QLabel("Sayılan sütununa fiziksel sayım sonucunu girin. Fark = Sayılan - Sistem Stok. Kaydetme sırasında güncel stok tekrar hesaplanır.")
        info.setObjectName("stockInfo"); root.addWidget(info)
        btns=QDialogButtonBox(QDialogButtonBox.Save|QDialogButtonBox.Cancel); btns.accepted.connect(self.save); btns.rejected.connect(self.reject); root.addWidget(btns)
        self.depo.currentIndexChanged.connect(lambda _=0: self.load_products())

    def load_definitions(self):
        self.depo.clear(); self.depo.addItem("-- Seçiniz --",None)
        for r in self.db.warehouses():
            if r['aktif']: self.depo.addItem(f"{r['kod']} - {r['ad']}",r['id'])
        self.sayim_no.setText(self.db.ensure_sayim_no())

    def load_products(self):
        self.rows=[]; self.table.setRowCount(0)
        wid=self.depo.currentData()
        if not wid: return
        rows=self.db.inventory_count_products(wid,self.search.text())
        for r in rows:
            self.rows.append({"id":r['id'],"urun_id":r['id'],"kod":r['kod'],"ad":r['ad'],"barkod":r['barkod'] or '',"birim":r['birim'] or 'ADET',"sistem":float(r['mevcut'] or 0),"sayilan":None,"aciklama":""})
        self.render()

    def render(self):
        # Listeyi yeniden doldururken cellChanged sinyalini kapat.
        # Aksi halde setItem() sırasında ara sütunlar henüz oluşmadan
        # cell_changed() tetiklenip NoneType hatasına yol açabilir.
        self.table.blockSignals(True)
        try:
            self.table.setRowCount(0)
            for line in self.rows:
                r=self.table.rowCount(); self.table.insertRow(r)
                vals=[line['kod'],line['ad'],line['barkod'],line['birim'],self.fmt(line['sistem']),'' if line['sayilan'] is None else self.fmt(line['sayilan']),self.fmt((line['sayilan']-line['sistem']) if line['sayilan'] is not None else 0),self.status(line),line['aciklama']]
                for c,v in enumerate(vals):
                    self.table.setItem(r,c,QTableWidgetItem(str(v)))
        finally:
            self.table.blockSignals(False)
    def cell_changed(self,row,col):
        if row<0 or row>=len(self.rows): return
        if col==5:
            txt=self.table.item(row,col).text().strip() if self.table.item(row,col) else ''
            if txt=='': self.rows[row]['sayilan']=None
            else:
                try:
                    val=float(txt.replace('.','').replace(',','.'))
                    if val<0: raise ValueError
                    self.rows[row]['sayilan']=val
                except ValueError:
                    self.rows[row]['sayilan']=None
                    QMessageBox.warning(self,"Sayım Miktarı","Sayılan miktar geçerli bir sayı olmalıdır ve negatif olamaz.")
            diff=0 if self.rows[row]['sayilan'] is None else self.rows[row]['sayilan']-self.rows[row]['sistem']
            self.table.blockSignals(True)
            try:
                if self.table.item(row,6) is None:
                    self.table.setItem(row,6,QTableWidgetItem())
                if self.table.item(row,7) is None:
                    self.table.setItem(row,7,QTableWidgetItem())
                self.table.item(row,6).setText(self.fmt(diff))
                self.table.item(row,7).setText(self.status(self.rows[row]))
            finally:
                self.table.blockSignals(False)
        elif col==8:
            self.rows[row]['aciklama']=self.table.item(row,col).text() if self.table.item(row,col) else ''

    def filter_table(self):
        # Arama kutusu tüm ürün listesini filtreler; kaydedilmemiş sayımlar korunur.
        wid=self.depo.currentData()
        if not wid: return
        query=self.search.text().strip().casefold()
        for i,line in enumerate(self.rows):
            hay=' '.join([line['kod'],line['ad'],line['barkod']]).casefold()
            self.table.setRowHidden(i, query not in hay)

    def lookup_product(self):
        text=self.search.text().strip()
        if not text: return
        for i,line in enumerate(self.rows):
            if text.casefold() in line['kod'].casefold() or text.casefold() in line['barkod'].casefold():
                self.table.setRowHidden(i,False); self.table.setCurrentCell(i,5); self.table.scrollToItem(self.table.item(i,5)); self.table.editItem(self.table.item(i,5)); return
        QMessageBox.information(self,"Ürün Bulunamadı","Bu barkod veya ürün koduna uygun ürün bulunamadı. 'Mevcut Stokları Getir' ile listeyi yenileyin.")

    def status(self,line):
        if line['sayilan'] is None: return "Bekliyor"
        diff=line['sayilan']-line['sistem']
        if abs(diff)<1e-9: return "Eşit"
        return "Fazla" if diff>0 else "Eksik"

    def save(self):
        wid=self.depo.currentData()
        if not wid: QMessageBox.warning(self,"Depo","Depo seçin."); return
        changed=[x for x in self.rows if x['sayilan'] is not None]
        if not changed: QMessageBox.warning(self,"Sayım","En az bir ürün için sayılan miktarı girin."); return
        # UI'dan son düzenlemeleri model'e aktar.
        self.table.blockSignals(True)
        for i,line in enumerate(self.rows):
            item=self.table.item(i,5)
            txt=item.text().strip() if item else ''
            if txt!='':
                try: line['sayilan']=float(txt.replace('.','').replace(',','.'))
                except ValueError: self.table.blockSignals(False); QMessageBox.warning(self,"Sayım Miktarı",f"{line['kod']} için sayılam miktar geçersiz."); return
        self.table.blockSignals(False)
        changed=[x for x in self.rows if x['sayilan'] is not None]
        if any(x['sayilan']<0 for x in changed): QMessageBox.warning(self,"Sayım Miktarı","Negatif sayım miktarına izin verilmez."); return
        try:
            sayim_id,sayim_no=self.db.save_inventory_count(wid,self.tarih.date().toString('yyyy-MM-dd'),self.aciklama.text().strip(),changed,self.current_user['id'] if self.current_user else None)
        except (sqlite3.DatabaseError,ValueError) as exc:
            QMessageBox.critical(self,"Sayım Kaydedilemedi",str(exc)); return
        QMessageBox.information(self,"Sayım Kaydedildi",f"{sayim_no} numaralı sayım kaydedildi.\nSayım farkları stok bakiyesine işlendi.")
        self.accept()

    @staticmethod
    def fmt(v): return f"{float(v or 0):,.3f}".replace(',','X').replace('.',',').replace('X','.')

class StockSlipDialog(QDialog):
    def __init__(self, parent, db, movement_type):
        super().__init__(parent)
        self.db = db
        self.movement_type = movement_type
        self.lines = []
        self.setWindowTitle(f"Ürün {movement_type} Fişi")
        self.setMinimumSize(1180, 720)
        self.resize(1280, 780)
        self.build_ui()
        self.load_definitions()

    def build_ui(self):
        root = QVBoxLayout(self)
        title = QLabel(f"ÜRÜN {self.movement_type.upper()} FİŞİ")
        title.setObjectName("dialogTitle")
        root.addWidget(title)

        header = QGroupBox("Fiş Bilgileri")
        grid = QGridLayout(header)
        self.fis_no = QLineEdit()
        self.tarih = QDateEdit(QDate.currentDate())
        self.tarih.setCalendarPopup(True)
        self.depo = QComboBox()
        self.cari = QComboBox()
        self.departman = QComboBox()
        self.alt_birim = QComboBox()
        self.veren = QLineEdit()
        self.alan = QLineEdit()
        self.aciklama = QLineEdit()

        grid.addWidget(QLabel("Fiş No*"), 0, 0); grid.addWidget(self.fis_no, 0, 1)
        grid.addWidget(QLabel("Tarih*"), 0, 2); grid.addWidget(self.tarih, 0, 3)
        grid.addWidget(QLabel("Depo*"), 0, 4); grid.addWidget(self.depo, 0, 5)
        grid.addWidget(QLabel("Cari"), 1, 0); grid.addWidget(self.cari, 1, 1)
        grid.addWidget(QLabel("Departman"), 1, 2); grid.addWidget(self.departman, 1, 3)
        grid.addWidget(QLabel("Alt Birim"), 1, 4); grid.addWidget(self.alt_birim, 1, 5)
        grid.addWidget(QLabel("Teslim Eden"), 2, 0); grid.addWidget(self.veren, 2, 1)
        grid.addWidget(QLabel("Teslim Alan"), 2, 2); grid.addWidget(self.alan, 2, 3)
        grid.addWidget(QLabel("Açıklama"), 2, 4); grid.addWidget(self.aciklama, 2, 5)
        root.addWidget(header)

        if self.movement_type == "Giriş":
            self.departman.setEnabled(False)
            self.alt_birim.setEnabled(False)
        self.departman.currentIndexChanged.connect(self.load_subunits)

        line = QHBoxLayout()
        self.product = QComboBox()
        self.product.setEditable(True)
        self.product.setInsertPolicy(QComboBox.NoInsert)
        self.product.setMinimumWidth(380)
        self.product.setToolTip("Ürün kodu veya ürün adının herhangi bir bölümünü yazın; liste anında daralır.")
        # V1.37.5: Ürün alanında yazılan her karakterle çalışan canlı arama.
        # QCompleter ürün kodu ve ürün adında geçen ifadeleri (MatchContains) filtreler.
        self.product_completer = QCompleter(self.product.model(), self.product)
        self.product_completer.setCaseSensitivity(Qt.CaseInsensitive)
        self.product_completer.setFilterMode(Qt.MatchContains)
        self.product_completer.setCompletionMode(QCompleter.PopupCompletion)
        self.product.setCompleter(self.product_completer)
        self.product_completer.activated[str].connect(self.select_product_completion)
        self.barcode = QLineEdit()
        self.barcode.setPlaceholderText("Barkod / ürün kodu ile ara...")
        self.qty = QLineEdit("1")
        self.price = QLineEdit("0,00")
        self.add_btn = QPushButton("Satıra Ekle")
        self.add_btn.clicked.connect(self.add_line)
        self.qty.setValidator(QDoubleValidator(0.000001, 999999999, 3))
        self.price.setValidator(QDoubleValidator(0, 999999999, 4))
        self.current_stock = QLabel("Mevcut stok: -")
        self.current_stock.setObjectName("stockInfo")
        self.allow_negative = QCheckBox("Eksi stoğa izin ver")
        self.allow_negative.setChecked(False)
        self.allow_negative.setEnabled(self.movement_type == "Çıkış")
        for label, widget in [("Ürün", self.product), ("Barkod/Kod", self.barcode), ("Miktar", self.qty), ("Birim Fiyat", self.price)]:
            line.addWidget(QLabel(label)); line.addWidget(widget)
        line.addWidget(self.current_stock)
        line.addWidget(self.allow_negative)
        line.addWidget(self.add_btn)
        root.addLayout(line)
        self.product.currentIndexChanged.connect(self.update_current_stock)
        self.depo.currentIndexChanged.connect(self.update_current_stock)
        self.barcode.returnPressed.connect(self.barcode_lookup)

        self.table = QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels(["No", "Ürün Kodu", "Ürün Adı", "Barkod", "Birim", "Miktar", "Birim Fiyat"])
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        configure_resizable_table(self.table, "stok_fis_satirlari", [55, 120, 250, 130, 85, 100, 120])
        root.addWidget(self.table, 1)

        bottom = QHBoxLayout()
        remove_btn = QPushButton("Seçili Satırı Sil")
        remove_btn.clicked.connect(self.remove_line)
        clear_btn = QPushButton("Tüm Satırları Temizle")
        clear_btn.clicked.connect(self.clear_lines)
        self.total = QLabel("Toplam Tutar: 0,00 TL")
        self.total.setObjectName("dialogTitle")
        bottom.addWidget(remove_btn); bottom.addWidget(clear_btn); bottom.addStretch(); bottom.addWidget(self.total)
        root.addLayout(bottom)

        buttons = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.save)
        buttons.rejected.connect(self.reject)
        root.addWidget(buttons)

    def load_definitions(self):
        self.depo.clear(); self.depo.addItem("-- Seçiniz --", None)
        for row in self.db.warehouses():
            if row["aktif"]: self.depo.addItem(f"{row['kod']} - {row['ad']}", row["id"])
        self.cari.clear(); self.cari.addItem("-- Seçiniz --", None)
        for row in self.db.active_cariler(): self.cari.addItem(f"{row['kod']} - {row['unvan']}", row["id"])
        self.departman.clear(); self.departman.addItem("-- Seçiniz --", None)
        for row in self.db.departments():
            if row["aktif"]: self.departman.addItem(f"{row['kod']} - {row['ad']}", row["id"])
        self.load_products()
        self.fis_no.setText(self.db.ensure_fis_no("GIN" if self.movement_type == "Giriş" else "CIK"))

    def load_products(self):
        self.product.clear(); self.product.addItem("-- Ürün seçiniz --", None)
        for row in self.db.list_products(active_only=True):
            self.product.addItem(f"{row['kod']} - {row['ad']}", row['id'])
        self.update_current_stock()

    def select_product_completion(self, text):
        """Completer'dan seçilen ürünü gerçek combo kaydına bağlar."""
        index = self.product.findText(text, Qt.MatchExactly)
        if index >= 0:
            self.product.setCurrentIndex(index)
            self.product.lineEdit().setText(text)
        self.update_current_stock()

    def update_current_stock(self):
        pid = self.product.currentData()
        wid = self.depo.currentData()
        if not pid or not wid:
            self.current_stock.setText("Mevcut stok: -")
            return
        balance = self.db.stock_balance(pid, wid)
        self.current_stock.setText(f"Mevcut stok: {self.fmt_qty(balance)}")

    def load_subunits(self):
        self.alt_birim.clear()
        self.alt_birim.addItem("-- Seçilmedi --", None)
        department_id = self.departman.currentData()
        has_subunits = False
        if department_id:
            rows = self.db.subunits(department_id, False)
            has_subunits = bool(rows)
            for row in rows:
                self.alt_birim.addItem(f"{row['kod']} - {row['ad']}", row['id'])
        # Alt birim yoksa seçim zorunlu değildir; departman seçimi yine geçerlidir.
        self.alt_birim.setEnabled(self.movement_type == "Çıkış" and bool(department_id) and has_subunits)
        if self.movement_type == "Çıkış" and department_id and not has_subunits:
            self.alt_birim.setToolTip("Bu departmana bağlı alt birim bulunmuyor; alt birim seçimi zorunlu değildir.")
        else:
            self.alt_birim.setToolTip("")

    def barcode_lookup(self):
        row = self.db.product_by_code_or_barcode(self.barcode.text())
        if not row:
            QMessageBox.warning(self, "Ürün Bulunamadı", "Barkod veya ürün koduna ait aktif ürün bulunamadı.")
            return
        index = self.product.findData(row["id"])
        if index >= 0:
            self.product.setCurrentIndex(index)
        price = row["alis_fiyati"] if self.movement_type == "Giriş" else row["satis_fiyati"]
        self.price.setText(f"{float(price or 0):.2f}".replace(".", ","))
        self.qty.selectAll(); self.qty.setFocus()

    @staticmethod
    def number(text):
        text = (text or "").strip().replace(".", "").replace(",", ".")
        try: return float(text)
        except ValueError: return 0.0

    def add_line(self):
        product_id = self.product.currentData()
        if not product_id:
            QMessageBox.warning(self, "Ürün", "Lütfen ürün arama listesinden bir ürün seçin.")
            return
        qty = self.number(self.qty.text())
        price = self.number(self.price.text())
        if qty <= 0:
            QMessageBox.warning(self, "Miktar", "Miktar 0'dan büyük olmalıdır.")
            return
        product = self.db.get_product(product_id)
        if self.movement_type == "Çıkış" and not self.allow_negative.isChecked():
            warehouse_id = self.depo.currentData()
            already_requested = sum(float(line["miktar"]) for line in self.lines if line["urun_id"] == product_id)
            available = self.db.stock_balance(product_id, warehouse_id)
            if available + 1e-9 < already_requested + qty:
                QMessageBox.warning(
                    self, "Yetersiz Stok",
                    f"{product['kod']} - {product['ad']} için yeterli stok yok.\n\n"
                    f"Mevcut: {self.fmt_qty(available)}\n"
                    f"Fişte toplam istenen: {self.fmt_qty(already_requested + qty)}\n\n"
                    "Eksi stok oluşturmak istiyorsanız 'Eksi stoğa izin ver' seçeneğini işaretleyin."
                )
                return
        for line in self.lines:
            if line["urun_id"] == product_id:
                line["miktar"] += qty
                line["birim_fiyat"] = price
                self.render_lines()
                return
        self.lines.append({
            "urun_id": product_id, "kod": product["kod"], "ad": product["ad"],
            "barkod": product["barkod"] or "", "birim": product["birim"] or "ADET",
            "miktar": qty, "birim_fiyat": price
        })
        self.render_lines()
        self.barcode.clear(); self.product.setCurrentIndex(0); self.qty.setText("1")

    def render_lines(self):
        self.table.setRowCount(0)
        total = 0.0
        for index, line in enumerate(self.lines, 1):
            row = self.table.rowCount(); self.table.insertRow(row)
            values = [index, line["kod"], line["ad"], line["barkod"], line["birim"], self.fmt_qty(line["miktar"]), self.fmt_money(line["birim_fiyat"])]
            total += line["miktar"] * line["birim_fiyat"]
            for col, value in enumerate(values):
                item = QTableWidgetItem(str(value))
                if col == 0: item.setTextAlignment(Qt.AlignCenter)
                self.table.setItem(row, col, item)
        self.total.setText(f"Toplam Tutar: {self.fmt_money(total)}")

    def remove_line(self):
        row = self.table.currentRow()
        if row >= 0:
            self.lines.pop(row); self.render_lines()

    def clear_lines(self):
        self.lines = []
        self.render_lines()

    def save(self):
        if not self.depo.currentData():
            QMessageBox.warning(self, "Depo", "Depo seçin."); return
        department_id = self.departman.currentData() if self.movement_type == "Çıkış" else None
        subunit_id = self.alt_birim.currentData() if self.movement_type == "Çıkış" else None
        if self.movement_type == "Çıkış" and not department_id:
            QMessageBox.warning(self, "Departman", "Çıkış için departman seçin."); return
        if self.movement_type == "Çıkış" and department_id:
            has_subunits = bool(self.db.subunits(department_id, False))
            if has_subunits and not subunit_id:
                QMessageBox.warning(self, "Alt Birim", "Bu departmanda alt birimler bulunduğu için çıkışta alt birim seçmelisiniz."); return
        if not self.lines:
            QMessageBox.warning(self, "Fiş", "Fişte ürün satırı bulunmuyor."); return
        header = {
            "fis_no": self.fis_no.text().strip(),
            "tarih": self.tarih.date().toString("yyyy-MM-dd"),
            "islem_tipi": self.movement_type,
            "depo_id": self.depo.currentData(),
            "cari_id": self.cari.currentData(),
            "departman_id": department_id,
            "alt_birim_id": subunit_id,
            "teslim_eden": self.veren.text().strip(),
            "teslim_alan": self.alan.text().strip(),
            "aciklama": self.aciklama.text().strip(),
            "allow_negative": self.allow_negative.isChecked(),
        }
        try:
            slip_id = self.db.save_stock_slip(header, self.lines)
        except (sqlite3.IntegrityError, ValueError) as exc:
            QMessageBox.critical(self, "Fiş Kaydedilemedi", str(exc)); return
        answer = QMessageBox.question(self, "Kayıt Tamamlandı", f"{self.fis_no.text()} numaralı {self.movement_type.lower()} fişi kaydedildi.\nStok bakiyesi güncellendi.\n\nFişi şimdi yazdırmak ister misiniz?", QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes)
        if answer == QMessageBox.Yes:
            print_slip(self, self.db, slip_id)
        self.accept()

    @staticmethod
    def fmt_qty(value): return f"{float(value or 0):,.3f}".replace(",", "X").replace(".", ",").replace("X", ".")
    @staticmethod
    def fmt_money(value): return f"{float(value or 0):,.2f} TL".replace(",", "X").replace(".", ",").replace("X", ".")


class BarcodeTransactionDialog(QDialog):
    """Barkod okuyucu ile hızlı giriş/çıkış. Barkod okuyucuların çoğu Enter gönderdiği
    için barkod kutusu Enter ile anında satıra eklenir ve tekrar odaklanır."""
    def __init__(self, parent, db, movement_type=None):
        super().__init__(parent)
        self.db = db
        self.movement_type = movement_type
        self.lines = []
        self.setWindowTitle("Barkodlu İşlem" if movement_type is None else f"Barkodlu {movement_type}")
        self.resize(1050, 650)
        self.build_ui()
        self.load_definitions()
        self.update_mode_ui()
        self.barcode.setFocus()

    def build_ui(self):
        root = QVBoxLayout(self)
        title = QLabel("BARKODLU GİRİŞ / ÇIKIŞ")
        title.setObjectName("dialogTitle")
        root.addWidget(title)

        header = QGroupBox("İşlem Bilgileri")
        grid = QGridLayout(header)
        self.mode = QComboBox()
        self.mode.addItems(["Giriş", "Çıkış"])
        if self.movement_type in ("Giriş", "Çıkış"):
            self.mode.setCurrentText(self.movement_type)
            self.mode.setEnabled(False)
        self.depo = QComboBox()
        self.cari = QComboBox()
        self.departman = QComboBox()
        self.alt_birim = QComboBox()
        self.fis_no = QLineEdit()
        self.tarih = QDateEdit(QDate.currentDate()); self.tarih.setCalendarPopup(True)
        self.veren = QLineEdit(); self.alan = QLineEdit(); self.aciklama = QLineEdit()
        grid.addWidget(QLabel("İşlem*"), 0, 0); grid.addWidget(self.mode, 0, 1)
        grid.addWidget(QLabel("Depo*"), 0, 2); grid.addWidget(self.depo, 0, 3)
        grid.addWidget(QLabel("Fiş No*"), 0, 4); grid.addWidget(self.fis_no, 0, 5)
        grid.addWidget(QLabel("Tarih*"), 1, 0); grid.addWidget(self.tarih, 1, 1)
        grid.addWidget(QLabel("Cari"), 1, 2); grid.addWidget(self.cari, 1, 3)
        grid.addWidget(QLabel("Departman"), 2, 0); grid.addWidget(self.departman, 2, 1)
        grid.addWidget(QLabel("Alt Birim"), 2, 2); grid.addWidget(self.alt_birim, 2, 3)
        grid.addWidget(QLabel("Teslim Eden"), 3, 0); grid.addWidget(self.veren, 3, 1)
        grid.addWidget(QLabel("Teslim Alan"), 3, 2); grid.addWidget(self.alan, 3, 3)
        grid.addWidget(QLabel("Açıklama"), 4, 0); grid.addWidget(self.aciklama, 4, 1, 1, 5)
        root.addWidget(header)

        scan = QGroupBox("Barkod Okut")
        scan_lay = QHBoxLayout(scan)
        self.barcode = QLineEdit(); self.barcode.setPlaceholderText("Barkodu okutun ve Enter'a basın...")
        self.qty = QLineEdit("1"); self.qty.setMaximumWidth(100)
        self.qty.setValidator(QDoubleValidator(0.000001, 999999999, 3))
        self.price = QLineEdit("0,00"); self.price.setMaximumWidth(120)
        self.price.setValidator(QDoubleValidator(0, 999999999, 4))
        self.stock_info = QLabel("Mevcut stok: -"); self.stock_info.setObjectName("stockInfo")
        add = QPushButton("Barkodu Ekle")
        add.clicked.connect(self.add_scan)
        scan_lay.addWidget(QLabel("Barkod")); scan_lay.addWidget(self.barcode, 1)
        scan_lay.addWidget(QLabel("Miktar")); scan_lay.addWidget(self.qty)
        scan_lay.addWidget(QLabel("Birim Fiyat")); scan_lay.addWidget(self.price)
        scan_lay.addWidget(self.stock_info)
        scan_lay.addWidget(add)
        root.addWidget(scan)
        self.barcode.returnPressed.connect(self.add_scan)
        self.barcode.textChanged.connect(self.lookup_scan_stock)
        self.mode.currentTextChanged.connect(self.on_mode_changed)
        self.depo.currentIndexChanged.connect(self.lookup_scan_stock)
        self.departman.currentIndexChanged.connect(self.load_subunits)

        self.table = QTableWidget(0, 8)
        self.table.setHorizontalHeaderLabels(["No", "Ürün Kodu", "Ürün Adı", "Barkod", "Birim", "Miktar", "Birim Fiyat", "Depo Mevcut"])
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        configure_resizable_table(self.table, "barkodlu_islem", [55, 120, 250, 130, 85, 100, 120, 120])
        root.addWidget(self.table, 1)

        bottom = QHBoxLayout()
        remove = QPushButton("Seçili Satırı Sil"); remove.clicked.connect(self.remove_line)
        clear = QPushButton("Temizle"); clear.clicked.connect(self.clear_lines)
        self.total = QLabel("Toplam: 0,00 TL"); self.total.setObjectName("dialogTitle")
        bottom.addWidget(remove); bottom.addWidget(clear); bottom.addStretch(); bottom.addWidget(self.total)
        root.addLayout(bottom)

        buttons = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.save)
        buttons.rejected.connect(self.reject)
        root.addWidget(buttons)

    def load_definitions(self):
        self.depo.clear(); self.depo.addItem("-- Seçiniz --", None)
        for row in self.db.warehouses():
            if row["aktif"]: self.depo.addItem(f"{row['kod']} - {row['ad']}", row["id"])
        self.cari.clear(); self.cari.addItem("-- Seçiniz --", None)
        for row in self.db.active_cariler(): self.cari.addItem(f"{row['kod']} - {row['unvan']}", row["id"])
        self.departman.clear(); self.departman.addItem("-- Seçiniz --", None)
        for row in self.db.departments():
            if row["aktif"]: self.departman.addItem(f"{row['kod']} - {row['ad']}", row["id"])
        self.load_subunits()
        self.set_fis_no()

    def set_fis_no(self):
        prefix = "BIN" if self.mode.currentText() == "Giriş" else "BOUT"
        self.fis_no.setText(self.db.ensure_fis_no(prefix))

    def on_mode_changed(self):
        self.update_mode_ui()
        self.set_fis_no()
        self.lookup_scan_stock()

    def update_mode_ui(self):
        is_out = self.mode.currentText() == "Çıkış"
        self.departman.setEnabled(is_out)
        if not is_out:
            self.departman.setCurrentIndex(0)
            self.alt_birim.clear()
            self.alt_birim.addItem("-- Seçilmedi --", None)
            self.alt_birim.setEnabled(False)
        else:
            self.load_subunits()

    def load_subunits(self):
        self.alt_birim.clear()
        self.alt_birim.addItem("-- Seçilmedi --", None)
        dep_id = self.departman.currentData()
        has_subunits = False
        if dep_id and self.mode.currentText() == "Çıkış":
            rows = self.db.subunits(dep_id, False)
            has_subunits = bool(rows)
            for row in rows:
                self.alt_birim.addItem(f"{row['kod']} - {row['ad']}", row['id'])
        self.alt_birim.setEnabled(self.mode.currentText() == "Çıkış" and bool(dep_id) and has_subunits)
        if self.mode.currentText() == "Çıkış" and dep_id and not has_subunits:
            self.alt_birim.setToolTip("Bu departmana bağlı alt birim bulunmuyor; alt birim seçimi zorunlu değildir.")
        else:
            self.alt_birim.setToolTip("")

    @staticmethod
    def number(text):
        text = (text or "").strip().replace(".", "").replace(",", ".")
        try: return float(text)
        except ValueError: return 0.0

    def lookup_scan_stock(self):
        row = self.db.product_by_code_or_barcode(self.barcode.text().strip())
        if not row or not self.depo.currentData():
            self.stock_info.setText("Mevcut stok: -")
            return
        balance = self.db.stock_balance(row["id"], self.depo.currentData())
        self.stock_info.setText(f"Mevcut stok: {self.fmt_qty(balance)}")
        if self.mode.currentText() == "Giriş":
            self.price.setText(self.fmt_num(row["alis_fiyati"]))
        else:
            self.price.setText(self.fmt_num(row["satis_fiyati"]))

    def add_scan(self):
        code = self.barcode.text().strip()
        if not code:
            self.barcode.setFocus(); return
        if not self.depo.currentData():
            QMessageBox.warning(self, "Depo", "Önce depo seçin.")
            return
        product = self.db.product_by_code_or_barcode(code)
        if not product:
            QMessageBox.warning(self, "Ürün Bulunamadı", f"'{code}' koduna ait aktif ürün bulunamadı.")
            self.barcode.selectAll(); self.barcode.setFocus(); return
        qty = self.number(self.qty.text())
        price = self.number(self.price.text())
        if qty <= 0:
            QMessageBox.warning(self, "Miktar", "Miktar 0'dan büyük olmalıdır.")
            self.qty.selectAll(); self.qty.setFocus(); return
        if self.mode.currentText() == "Çıkış":
            available = self.db.stock_balance(product["id"], self.depo.currentData())
            existing = sum(x["miktar"] for x in self.lines if x["urun_id"] == product["id"])
            if available + 1e-9 < existing + qty:
                QMessageBox.warning(
                    self, "Yetersiz Stok",
                    f"{product['kod']} - {product['ad']} için yeterli stok yok.\\n\\n"
                    f"Depo mevcut: {self.fmt_qty(available)}\\n"
                    f"Bu fişte istenen: {self.fmt_qty(existing + qty)}"
                )
                return
        found = None
        for line in self.lines:
            if line["urun_id"] == product["id"]:
                found = line; break
        if found:
            found["miktar"] += qty
            found["birim_fiyat"] = price
        else:
            self.lines.append({
                "urun_id": product["id"], "kod": product["kod"], "ad": product["ad"],
                "barkod": product["barkod"] or "", "birim": product["birim"] or "ADET",
                "miktar": qty, "birim_fiyat": price,
            })
        self.render_lines()
        self.barcode.clear(); self.qty.setText("1"); self.lookup_scan_stock(); self.barcode.setFocus()

    def render_lines(self):
        self.table.setRowCount(0); total = 0.0
        wid = self.depo.currentData()
        for i, line in enumerate(self.lines, 1):
            r = self.table.rowCount(); self.table.insertRow(r)
            stock = self.db.stock_balance(line["urun_id"], wid) if wid else 0
            values = [i, line["kod"], line["ad"], line["barkod"], line["birim"], self.fmt_qty(line["miktar"]), self.fmt_money(line["birim_fiyat"]), self.fmt_qty(stock)]
            total += line["miktar"] * line["birim_fiyat"]
            for c, value in enumerate(values): self.table.setItem(r, c, QTableWidgetItem(str(value)))
            if self.mode.currentText() == "Çıkış" and stock + 1e-9 < line["miktar"]:
                brush = QColor(Qt.red).lighter(170)
                for c in range(self.table.columnCount()): self.table.item(r, c).setData(Qt.BackgroundRole, brush)
        self.total.setText(f"Toplam: {self.fmt_money(total)}")

    def remove_line(self):
        row = self.table.currentRow()
        if row >= 0:
            self.lines.pop(row); self.render_lines()

    def clear_lines(self):
        self.lines = []; self.render_lines()

    def save(self):
        if not self.depo.currentData():
            QMessageBox.warning(self, "Depo", "Depo seçin."); return
        if not self.lines:
            QMessageBox.warning(self, "Fiş", "Fişte ürün bulunmuyor."); return
        is_out = self.mode.currentText() == "Çıkış"
        if is_out and not self.departman.currentData():
            QMessageBox.warning(self, "Departman", "Çıkış için departman seçin."); return
        if is_out and self.departman.currentData():
            has_subunits = bool(self.db.subunits(self.departman.currentData(), False))
            if has_subunits and not self.alt_birim.currentData():
                QMessageBox.warning(self, "Alt Birim", "Bu departmanda alt birimler bulunduğu için çıkışta alt birim seçmelisiniz."); return
        if not is_out:
            self.departman.setCurrentIndex(0); self.alt_birim.setCurrentIndex(0)
        header = {
            "fis_no": self.fis_no.text().strip(),
            "tarih": self.tarih.date().toString("yyyy-MM-dd"),
            "islem_tipi": self.mode.currentText(),
            "depo_id": self.depo.currentData(),
            "cari_id": self.cari.currentData(),
            "departman_id": self.departman.currentData() if is_out else None,
            "alt_birim_id": self.alt_birim.currentData() if is_out else None,
            "teslim_eden": self.veren.text().strip(),
            "teslim_alan": self.alan.text().strip(),
            "aciklama": self.aciklama.text().strip(),
            "allow_negative": False,
        }
        try:
            slip_id = self.db.save_stock_slip(header, self.lines)
        except (sqlite3.IntegrityError, ValueError) as exc:
            QMessageBox.critical(self, "Barkodlu İşlem Kaydedilemedi", str(exc)); return
        answer = QMessageBox.question(self, "İşlem Tamamlandı", f"{header['fis_no']} numaralı barkodlu {header['islem_tipi'].lower()} fişi kaydedildi.\nStok bakiyesi güncellendi.\n\nFişi şimdi yazdırmak ister misiniz?", QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes)
        if answer == QMessageBox.Yes:
            print_slip(self, self.db, slip_id)
        self.accept()

    @staticmethod
    def fmt_qty(v): return f"{float(v or 0):,.3f}".replace(",", "X").replace(".", ",").replace("X", ".")
    @staticmethod
    def fmt_money(v): return f"{float(v or 0):,.2f} TL".replace(",", "X").replace(".", ",").replace("X", ".")
    @staticmethod
    def fmt_num(v): return f"{float(v or 0):.2f}".replace(".", ",")


class StockStatusDialog(QDialog):
    def __init__(self, parent, db):
        super().__init__(parent); self.db=db; self.setWindowTitle("Stok Durumu"); self.resize(1100,650)
        root=QVBoxLayout(self); title=QLabel("DEPO BAZLI STOK DURUMU"); title.setObjectName("dialogTitle"); root.addWidget(title)
        filters=QHBoxLayout(); self.depo=QComboBox(); self.depo.addItem("Tüm Depolar", None)
        for row in db.warehouses():
            if row["aktif"]: self.depo.addItem(f"{row['kod']} - {row['ad']}", row["id"])
        self.search=QLineEdit(); self.search.setPlaceholderText("Ürün kodu / adı...")
        self.show_zero=QCheckBox("Sıfır stoklu ürünleri göster")
        self.show_zero.setChecked(False)
        self.show_zero.setToolTip("İşaretlenirse seçili depoda mevcut miktarı 0 olan ürünler de listelenir.")
        self.depo.setToolTip("Bir depo seçildiğinde varsayılan olarak yalnızca o depoda bakiyesi bulunan ürünler listelenir. Negatif stoklar gösterilir.")
        btn=QPushButton("Sorgula"); btn.clicked.connect(self.refresh)
        self.depo.currentIndexChanged.connect(self.refresh)
        self.search.returnPressed.connect(self.refresh)
        connect_live_text_filter(self.search, self.refresh)
        self.show_zero.stateChanged.connect(self.refresh)
        filters.addWidget(QLabel("Depo")); filters.addWidget(self.depo); filters.addWidget(QLabel("Arama")); filters.addWidget(self.search,1); filters.addWidget(self.show_zero); filters.addWidget(btn); root.addLayout(filters)
        self.table=QTableWidget(0,8); self.table.setHorizontalHeaderLabels(["No","Kod","Ürün","Grup","Birim","Min.","Mevcut","Max."]); configure_resizable_table(self.table, "stok_durumu", [55,120,240,140,85,90,100,90]); self.table.setEditTriggers(QAbstractItemView.NoEditTriggers); root.addWidget(self.table,1)
        close=QPushButton("Kapat"); close.clicked.connect(self.accept); root.addWidget(close,0,Qt.AlignRight); self.refresh()

    def refresh(self):
        warehouse_id = self.depo.currentData()
        search = self.search.text().strip()
        params = []

        stock_expr = "COALESCE((SELECT SUM(CASE WHEN sh2.islem_tipi IN ('Giriş','İade') THEN sh2.miktar ELSE -sh2.miktar END) FROM stok_hareketleri sh2 WHERE sh2.urun_id=u.id"
        if warehouse_id:
            stock_expr += " AND sh2.depo_id=?"
            params.append(warehouse_id)
        stock_expr += "),0)"

        query = f"""
            SELECT u.id,u.kod,u.ad,u.birim,u.min_seviye,u.max_seviye,
                   g.ad AS grup_adi,
                   {stock_expr} AS mevcut
            FROM urunler u
            LEFT JOIN urun_gruplari g ON g.id=u.grup_id
            WHERE u.aktif=1
        """

        # Bir depo seçildiğinde varsayılan görünüm yalnızca o depoda bakiyesi
        # bulunan ürünlerdir. Kullanıcı isterse sıfır stokluları da gösterebilir.
        # Negatif stoklar her iki durumda da gösterilmeye devam eder.
        if warehouse_id and not self.show_zero.isChecked():
            query += " AND ({0}) <> 0".format(stock_expr)
            params.append(warehouse_id)

        if search:
            query += " AND (u.kod LIKE ? OR u.ad LIKE ?)"
            params.extend([f"%{search}%", f"%{search}%"])

        query += " ORDER BY u.kod"
        rows = self.db.conn.execute(query, params).fetchall()
        self.table.setRowCount(0)

        for i, row in enumerate(rows, 1):
            r = self.table.rowCount()
            self.table.insertRow(r)
            values = [
                i, row["kod"], row["ad"], row["grup_adi"] or "",
                row["birim"] or "", self.fmt(row["min_seviye"]),
                self.fmt(row["mevcut"]), self.fmt(row["max_seviye"])
            ]
            for c, value in enumerate(values):
                self.table.setItem(r, c, QTableWidgetItem(str(value)))

            current = float(row["mevcut"] or 0)
            minimum = float(row["min_seviye"] or 0)
            maximum = float(row["max_seviye"] or 0)
            brush = (
                QColor(Qt.red).lighter(170) if current < 0
                else QColor(Qt.yellow).lighter(170) if minimum and current < minimum
                else QColor(Qt.cyan).lighter(185) if maximum and current > maximum
                else None
            )
            if brush:
                for c in range(self.table.columnCount()):
                    self.table.item(r, c).setData(Qt.BackgroundRole, brush)

    @staticmethod
    def fmt(value): return f"{float(value or 0):,.3f}".replace(",","X").replace(".",",").replace("X",".")


class StockMovementDetailDialog(QDialog):
    def __init__(self, parent, db, movement_id):
        super().__init__(parent); self.db=db; self.setWindowTitle("Stok Hareket Detayı"); self.resize(760,560)
        root=QVBoxLayout(self); title=QLabel("STOK HAREKET DETAYI"); title.setObjectName("dialogTitle"); root.addWidget(title)
        row=db.get_stock_movement_detail(movement_id)
        if not row:
            root.addWidget(QLabel("Hareket bulunamadı.")); return
        form=QFormLayout()
        def val(v): return "" if v is None else str(v)
        fields=[
            ("Hareket ID", row['id']), ("Tarih", row['tarih']), ("Fiş No", row['fis_no'] or ''),
            ("İşlem", row['islem_tipi']), ("Depo", f"{row['depo_kodu']} - {row['depo_adi']}"),
            ("Ürün", f"{row['urun_kodu']} - {row['urun_adi']}"), ("Barkod", row['barkod'] or ''),
            ("Ürün Türü", row['urun_turu_adi'] or ''), ("Grup", row['grup_adi'] or ''),
            ("Marka / Model", f"{row['marka'] or ''} / {row['model'] or ''}"),
            ("Miktar", fmt_qty_tr(row['miktar'])), ("Birim Fiyat", fmt_money_tr(row['birim_fiyat'])),
            ("Cari", f"{row['cari_kodu']} - {row['cari_unvan']}" if row['cari_kodu'] else (row['cari_unvan'] or '')),
            ("Departman", f"{row['departman_kodu']} - {row['departman_adi']}" if row['departman_kodu'] else ''),
            ("Alt Birim", f"{row['alt_birim_kodu']} - {row['alt_birim_adi']}" if row['alt_birim_kodu'] else ''),
            ("Teslim Eden", row['teslim_eden'] or ''), ("Teslim Alan", row['teslim_alan'] or ''),
            ("Açıklama", row['aciklama'] or ''), ("İptal Hareketi", "Evet" if row['iptal_hareketi'] else "Hayır")
        ]
        for label,value in fields: form.addRow(QLabel(f"<b>{label}</b>"), QLabel(val(value)))
        root.addLayout(form); b=QPushButton("Kapat"); b.clicked.connect(self.accept); root.addWidget(b,0,Qt.AlignRight)

class StockMovementDialog(QDialog):
    def __init__(self,parent,db):
        super().__init__(parent); self.db=db; self.setWindowTitle("Stok Hareketleri"); self.resize(1450,760)
        root=QVBoxLayout(self); title=QLabel("STOK HAREKETLERİ"); title.setObjectName("dialogTitle"); root.addWidget(title)
        filters=QGridLayout()
        self.start=QDateEdit(QDate.currentDate().addMonths(-1)); self.end=QDateEdit(QDate.currentDate()); self.start.setCalendarPopup(True); self.end.setCalendarPopup(True)
        self.depo=QComboBox(); self.depo.addItem("Tüm Depolar",None)
        self.type=QComboBox(); self.type.addItems(["Tümü","Giriş","Çıkış"])
        self.prod=QLineEdit(); self.prod.setPlaceholderText("Kod / ürün adı / barkod")
        self.ptype=QComboBox(); self.ptype.addItem("Tüm Ürün Türleri",None)
        self.group=QComboBox(); self.group.addItem("Tüm Gruplar",None)
        self.brand=QLineEdit(); self.brand.setPlaceholderText("Marka")
        self.model=QLineEdit(); self.model.setPlaceholderText("Model")
        self.dept=QComboBox(); self.dept.addItem("Tüm Departmanlar",None)
        self.alt=QComboBox(); self.alt.addItem("Tüm Alt Birimler",None)
        self.delivery=QLineEdit(); self.delivery.setPlaceholderText("Teslim eden / alan")
        for row in db.warehouses():
            if row['aktif']: self.depo.addItem(f"{row['kod']} - {row['ad']}",row['id'])
        for row in db.product_types():
            if row['aktif']: self.ptype.addItem(f"{row['kod']} - {row['ad']}",row['id'])
        for row in db.groups():
            if row['aktif']: self.group.addItem(f"{row['kod']} - {row['ad']}",row['id'])
        for row in db.departments():
            if row['aktif']: self.dept.addItem(f"{row['kod']} - {row['ad']}",row['id'])
        for col,label,widget in [(0,'Başlangıç',self.start),(2,'Bitiş',self.end),(4,'Depo',self.depo),(6,'İşlem',self.type),(8,'Ürün',self.prod),(10,'Ürün Türü',self.ptype),(0,'Grup',self.group),(2,'Marka',self.brand),(4,'Model',self.model),(6,'Departman',self.dept),(8,'Alt Birim',self.alt),(10,'Teslim',self.delivery)]:
            pass
        filters.addWidget(QLabel('Başlangıç'),0,0); filters.addWidget(self.start,0,1)
        filters.addWidget(QLabel('Bitiş'),0,2); filters.addWidget(self.end,0,3)
        filters.addWidget(QLabel('Depo'),0,4); filters.addWidget(self.depo,0,5)
        filters.addWidget(QLabel('İşlem'),0,6); filters.addWidget(self.type,0,7)
        filters.addWidget(QLabel('Ürün'),0,8); filters.addWidget(self.prod,0,9,1,3)
        filters.addWidget(QLabel('Ürün Türü'),1,0); filters.addWidget(self.ptype,1,1,1,2)
        filters.addWidget(QLabel('Grup'),1,3); filters.addWidget(self.group,1,4,1,2)
        filters.addWidget(QLabel('Marka'),1,6); filters.addWidget(self.brand,1,7)
        filters.addWidget(QLabel('Model'),1,8); filters.addWidget(self.model,1,9)
        filters.addWidget(QLabel('Departman'),2,0); filters.addWidget(self.dept,2,1,1,2)
        filters.addWidget(QLabel('Alt Birim'),2,3); filters.addWidget(self.alt,2,4,1,2)
        filters.addWidget(QLabel('Teslim Eden/Alan'),2,6); filters.addWidget(self.delivery,2,7,1,2)
        btn=QPushButton('Sorgula'); btn.clicked.connect(self.refresh); filters.addWidget(btn,2,9,1,2)
        root.addLayout(filters)
        self.dept.currentIndexChanged.connect(self.load_alt_units); self.prod.returnPressed.connect(self.refresh); connect_live_text_filter(self.prod, self.refresh); self.delivery.returnPressed.connect(self.refresh)
        self.table=QTableWidget(0,15); self.table.setHorizontalHeaderLabels(['ID','Tarih','Fiş No','İşlem','Depo','Ürün Kodu','Ürün','Barkod','Tür','Grup','Marka','Model','Miktar','Departman','Alt Birim']); configure_resizable_table(self.table,'stok_hareketleri_v19',[55,95,105,80,170,110,230,140,120,140,120,130,100,170,140]); self.table.setEditTriggers(QAbstractItemView.NoEditTriggers); self.table.setSelectionBehavior(QAbstractItemView.SelectRows); self.table.doubleClicked.connect(self.open_detail); root.addWidget(self.table,1)
        buttons=QHBoxLayout(); exp=QPushButton("Excel'e Aktar"); exp.clicked.connect(self.export_excel); pr=QPushButton('Yazdır'); pr.clicked.connect(self.print_report); det=QPushButton('Detay'); det.clicked.connect(self.open_detail); close=QPushButton('Kapat'); close.clicked.connect(self.accept)
        buttons.addWidget(det); buttons.addWidget(exp); buttons.addWidget(pr); buttons.addStretch(); buttons.addWidget(close); root.addLayout(buttons)
        self.refresh()

    def load_alt_units(self):
        self.alt.blockSignals(True); current=self.alt.currentData(); self.alt.clear(); self.alt.addItem('Tüm Alt Birimler',None); did=self.dept.currentData()
        if did:
            for r in self.db.subunits(did):
                if r['aktif']: self.alt.addItem(f"{r['kod']} - {r['ad']}",r['id'])
        idx=self.alt.findData(current); self.alt.setCurrentIndex(idx if idx>=0 else 0); self.alt.blockSignals(False)

    def refresh(self):
        rows=self.db.list_stock_movements(self.start.date().toString('yyyy-MM-dd'),self.end.date().toString('yyyy-MM-dd'),self.depo.currentData(),None,None if self.type.currentText()=='Tümü' else self.type.currentText(),self.prod.text().strip() or None,self.ptype.currentData(),self.group.currentData(),self.brand.text().strip() or None,self.model.text().strip() or None,self.dept.currentData(),self.alt.currentData(),self.prod.text().strip() if self.prod.text().strip().isdigit() else None,self.delivery.text().strip() or None)
        self.table.setRowCount(0)
        for row in rows:
            r=self.table.rowCount(); self.table.insertRow(r); vals=[row['id'],row['tarih'],row['fis_no'] or '',row['islem_tipi'],f"{row['depo_kodu']} - {row['depo_adi']}",row['urun_kodu'],row['urun_adi'],row['barkod'] or '',row['urun_turu_adi'] or '',row['grup_adi'] or '',row['marka'] or '',row['model'] or '',fmt_qty_tr(row['miktar']),f"{row['departman_kodu']} - {row['departman_adi']}" if row['departman_kodu'] else '',f"{row['alt_birim_kodu']} - {row['alt_birim_adi']}" if row['alt_birim_kodu'] else '']
            for c,v in enumerate(vals): self.table.setItem(r,c,QTableWidgetItem(str(v)))

    def open_detail(self):
        row=self.table.currentRow()
        if row<0: QMessageBox.information(self,'Seçim','Detayını görmek için bir hareket seçin.'); return
        StockMovementDetailDialog(self,self.db,int(self.table.item(row,0).text())).exec_()

    def export_excel(self):
        path, selected = QFileDialog.getSaveFileName(self,'Stok Hareketlerini Aktar','stok_hareketleri','Excel Çalışma Kitabı (*.xlsx);;Excel 97-2003 (*.xls);;CSV Dosyası (*.csv)')
        if not path:return
        try:
            headers=[self.table.horizontalHeaderItem(c).text() for c in range(self.table.columnCount())]; rows=[[self.table.item(r,c).text() if self.table.item(r,c) else '' for c in range(self.table.columnCount())] for r in range(self.table.rowCount())]
            if path.lower().endswith('.csv'):
                with open(path,'w',newline='',encoding='utf-8-sig') as f: csv.writer(f,delimiter=';').writerows([headers]+rows)
            else:
                import xlsxwriter; tmp=path if path.lower().endswith('.xlsx') else str(Path(tempfile.gettempdir())/(Path(path).stem+'_v19.xlsx')); wb=xlsxwriter.Workbook(tmp); ws=wb.add_worksheet('Stok Hareketleri'); fmt=wb.add_format({'bold':True,'bg_color':'#D9E2F3','border':1})
                for c,h in enumerate(headers): ws.write(0,c,h,fmt)
                for r,row in enumerate(rows,1):
                    for c,v in enumerate(row): ws.write(r,c,v)
                wb.close()
                if path.lower().endswith('.xls'):
                    try:
                        import win32com.client as win32
                        excel=win32.DispatchEx('Excel.Application'); excel.Visible=False; excel.DisplayAlerts=False; book=excel.Workbooks.Open(str(Path(tmp).resolve())); book.SaveAs(str(Path(path).resolve()),FileFormat=56); book.Close(False); excel.Quit(); Path(tmp).unlink(missing_ok=True)
                    except ImportError: raise RuntimeError('.xls kaydı için pywin32 ve Microsoft Excel gereklidir.')
            QMessageBox.information(self,'Aktarım','Dosya kaydedildi.')
        except Exception as exc: QMessageBox.critical(self,'Aktarım',str(exc))

    def print_report(self):
        if self.table.rowCount()==0: QMessageBox.information(self,'Yazdırma','Yazdırılacak kayıt yok.'); return
        printer=QPrinter(QPrinter.HighResolution); printer.setDocName('Stok Hareketleri'); d=QPrintDialog(printer,self)
        if d.exec_()!=QDialog.Accepted:return
        headers=[self.table.horizontalHeaderItem(c).text() for c in range(self.table.columnCount())]; html=['<html><head><meta charset="utf-8"><style>body{font-family:Arial;font-size:7pt}table{width:100%;border-collapse:collapse}th,td{border:1px solid #777;padding:2px}th{background:#e8edf2}</style></head><body><h2>STOK HAREKETLERİ</h2><table><tr>']+[f'<th>{h}</th>' for h in headers]+['</tr>']
        for r in range(self.table.rowCount()): html.append('<tr>'+''.join(f'<td>{self.table.item(r,c).text() if self.table.item(r,c) else ""}</td>' for c in range(self.table.columnCount()))+'</tr>')
        html.append('</table></body></html>'); doc=QTextDocument(); doc.setHtml(''.join(html)); doc.print_(printer)


class ReportCenterDialog(QDialog):
    """Stok, tarih aralığı ve hareket raporlarını tek merkezden yönetir."""
    def __init__(self, parent, db, start_tab=0):
        super().__init__(parent)
        self.db = db
        self.setWindowTitle("Rapor Merkezi")
        self.setMinimumSize(1250, 720)
        self.resize(1450, 820)
        root = QVBoxLayout(self)
        title = QLabel("RAPOR MERKEZİ")
        title.setObjectName("dialogTitle")
        root.addWidget(title)
        self.tabs = QTabWidget()
        root.addWidget(self.tabs, 1)
        self.build_inventory_tab()
        self.build_period_tab()
        self.build_movements_tab()
        self.tabs.setCurrentIndex(max(0, min(start_tab, self.tabs.count()-1)))
        close = QPushButton("Kapat")
        close.clicked.connect(self.accept)
        root.addWidget(close, 0, Qt.AlignRight)

    @staticmethod
    def fmt_qty(value):
        return f"{float(value or 0):,.3f}".replace(",", "X").replace(".", ",").replace("X", ".")

    @staticmethod
    def fmt_money(value):
        return f"{float(value or 0):,.2f} TL".replace(",", "X").replace(".", ",").replace("X", ".")

    def combo_fill(self, combo, rows, labeler, add_all=True):
        combo.clear()
        if add_all:
            combo.addItem("Tümü", None)
        for row in rows:
            combo.addItem(labeler(row), row["id"])

    def build_inventory_tab(self):
        tab = QWidget(); root = QVBoxLayout(tab)
        filters = QGridLayout()
        self.r_urun_kod = QLineEdit(); self.r_urun_kod.setPlaceholderText("Ürün kodu...")
        self.r_urun_ad = QLineEdit(); self.r_urun_ad.setPlaceholderText("Ürün adı...")
        self.r_tur = QComboBox(); self.r_marka = QLineEdit(); self.r_marka.setPlaceholderText("Marka...")
        self.r_model = QLineEdit(); self.r_model.setPlaceholderText("Model...")
        self.r_grup = QComboBox(); self.r_depo = QComboBox(); self.r_durum = QComboBox()
        self.r_durum.addItems(["Tüm Ürünler", "Stokta Bulunanlar", "Minimum Seviyenin Altında", "Maksimum Seviyeyi Aşanlar", "Eksi Stoklu Ürünler", "Mevcut Sıfır Ürünler"])
        self.combo_fill(self.r_tur, self.db.product_types(), lambda r: f"{r['kod']} - {r['ad']}")
        self.combo_fill(self.r_grup, self.db.groups(), lambda r: f"{r['kod']} - {r['ad']}")
        self.combo_fill(self.r_depo, self.db.warehouses(), lambda r: f"{r['kod']} - {r['ad']}")
        for lab, w, rr, cc in [
            ("Ürün Kodu", self.r_urun_kod, 0,0),("Ürün Adı", self.r_urun_ad,0,2),("Ürün Türü",self.r_tur,0,4),
            ("Marka",self.r_marka,1,0),("Model",self.r_model,1,2),("Ürün Grubu",self.r_grup,1,4),
            ("Depo",self.r_depo,2,0),("Durum",self.r_durum,2,2)]:
            filters.addWidget(QLabel(lab), rr, cc); filters.addWidget(w, rr, cc+1)
        connect_live_text_filter(self.r_urun_kod, self.refresh_inventory)
        connect_live_text_filter(self.r_urun_ad, self.refresh_inventory)
        btn = QPushButton("Sorgula"); btn.clicked.connect(self.refresh_inventory)
        exp = QPushButton("Excel'e Aktar"); exp.clicked.connect(lambda: self.export_table(self.inventory_table, "Stok Raporu"))
        pr = QPushButton("Yazdır"); pr.clicked.connect(lambda: self.print_table(self.inventory_table, "Stok Raporu"))
        filters.addWidget(btn, 2, 4); filters.addWidget(exp, 2, 5); filters.addWidget(pr, 2, 6)
        root.addLayout(filters)
        self.inventory_table = QTableWidget(0, 12)
        self.inventory_table.setHorizontalHeaderLabels(["No","Ürün Kodu","Ürün Adı","Ürün Türü","Marka","Model","Grup","Depo","Birim","Min.","Mevcut","Max."])
        configure_resizable_table(self.inventory_table, "rapor_stok", [55,110,240,150,130,150,150,170,80,90,100,90])
        self.inventory_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        root.addWidget(self.inventory_table, 1)
        self.inv_total = QLabel("Toplam kayıt: 0")
        root.addWidget(self.inv_total)
        self.tabs.addTab(tab, "Stok / Envanter")
        self.refresh_inventory()

    def refresh_inventory(self):
        params=[]
        q = """SELECT u.id,u.kod,u.ad,u.birim,u.min_seviye,u.max_seviye,u.urun_turu_id,u.marka,u.model,
                       g.ad AS grup_adi, ut.ad AS tur_adi
                FROM urunler u
                LEFT JOIN urun_gruplari g ON g.id=u.grup_id
                LEFT JOIN urun_turleri ut ON ut.id=u.urun_turu_id
                WHERE u.aktif=1"""
        if self.r_urun_kod.text().strip(): q += " AND u.kod LIKE ?"; params.append(f"%{self.r_urun_kod.text().strip()}%")
        if self.r_urun_ad.text().strip(): q += " AND u.ad LIKE ?"; params.append(f"%{self.r_urun_ad.text().strip()}%")
        if self.r_tur.currentData(): q += " AND u.urun_turu_id=?"; params.append(self.r_tur.currentData())
        if self.r_marka.text().strip(): q += " AND COALESCE(u.marka,'') LIKE ?"; params.append(f"%{self.r_marka.text().strip()}%")
        if self.r_model.text().strip(): q += " AND COALESCE(u.model,'') LIKE ?"; params.append(f"%{self.r_model.text().strip()}%")
        if self.r_grup.currentData(): q += " AND u.grup_id=?"; params.append(self.r_grup.currentData())
        q += " ORDER BY u.kod"
        products=self.db.conn.execute(q,params).fetchall()
        self.inventory_table.setRowCount(0)
        depot_id=self.r_depo.currentData()
        status=self.r_durum.currentText()
        for p in products:
            depots = [self.db.conn.execute("SELECT id,kod,ad FROM depolar WHERE aktif=1 ORDER BY ad",()).fetchall()] if depot_id is None else [[self.db.conn.execute("SELECT id,kod,ad FROM depolar WHERE id=?",(depot_id,)).fetchone()]]
            for dlist in depots:
                for d in dlist:
                    if not d: continue
                    current=self.db.stock_balance(p['id'], d['id'])
                    mn=float(p['min_seviye'] or 0); mx=float(p['max_seviye'] or 0)
                    if status == "Stokta Bulunanlar" and current <= 0: continue
                    if status == "Minimum Seviyenin Altında" and not (mn and current < mn): continue
                    if status == "Maksimum Seviyeyi Aşanlar" and not (mx and current > mx): continue
                    if status == "Eksi Stoklu Ürünler" and current >= 0: continue
                    if status == "Mevcut Sıfır Ürünler" and abs(current) > 1e-9: continue
                    row=self.inventory_table.rowCount(); self.inventory_table.insertRow(row)
                    vals=[row+1,p['kod'],p['ad'],p['tur_adi'] or p['urun_turu_id'] or "",p['marka'] or "",p['model'] or "",p['grup_adi'] or "",f"{d['kod']} - {d['ad']}",p['birim'] or "",self.fmt_qty(mn),self.fmt_qty(current),self.fmt_qty(mx)]
                    for c,v in enumerate(vals): self.inventory_table.setItem(row,c,QTableWidgetItem(str(v)))
                    brush=QColor(Qt.red).lighter(170) if current < 0 else QColor(Qt.yellow).lighter(170) if mn and current < mn else QColor(Qt.cyan).lighter(185) if mx and current > mx else None
                    if brush:
                        for c in range(self.inventory_table.columnCount()): self.inventory_table.item(row,c).setData(Qt.BackgroundRole, brush)
        self.inv_total.setText(f"Toplam kayıt: {self.inventory_table.rowCount()}")

    def build_period_tab(self):
        tab=QWidget(); root=QVBoxLayout(tab)
        f=QGridLayout(); self.p_start=QDateEdit(QDate.currentDate().addMonths(-1)); self.p_end=QDateEdit(QDate.currentDate())
        for x in (self.p_start,self.p_end): x.setCalendarPopup(True)
        self.p_depo=QComboBox(); self.p_urun=QLineEdit(); self.p_urun.setPlaceholderText("Ürün kodu / adı...")
        self.combo_fill(self.p_depo, self.db.warehouses(), lambda r: f"{r['kod']} - {r['ad']}")
        f.addWidget(QLabel("Başlangıç"),0,0); f.addWidget(self.p_start,0,1); f.addWidget(QLabel("Bitiş"),0,2); f.addWidget(self.p_end,0,3)
        connect_live_text_filter(self.p_urun, self.refresh_period, 500)
        f.addWidget(QLabel("Depo"),0,4); f.addWidget(self.p_depo,0,5); f.addWidget(QLabel("Ürün"),0,6); f.addWidget(self.p_urun,0,7)
        b=QPushButton("Sorgula"); b.clicked.connect(self.refresh_period); f.addWidget(b,0,8)
        e=QPushButton("Excel'e Aktar"); e.clicked.connect(lambda: self.export_table(self.period_table,"Tarih Arası Stok")); f.addWidget(e,0,9)
        pr=QPushButton("Yazdır"); pr.clicked.connect(lambda: self.print_table(self.period_table,"Tarih Arası Stok")); f.addWidget(pr,0,10)
        root.addLayout(f)
        self.period_table=QTableWidget(0,12); self.period_table.setHorizontalHeaderLabels(["No","Depo","Ürün Kodu","Ürün Adı","Birim","Açılış","Giriş","Çıkış","Net","Kapanış","Min.","Max."])
        configure_resizable_table(self.period_table,"rapor_tarih_stok",[55,170,110,240,80,100,100,100,100,100,90,90]); self.period_table.setEditTriggers(QAbstractItemView.NoEditTriggers); root.addWidget(self.period_table,1)
        self.period_total=QLabel("Toplam kayıt: 0"); root.addWidget(self.period_total); self.tabs.addTab(tab,"İki Tarih Arası Stok")
        self.refresh_period()

    def refresh_period(self):
        start=self.p_start.date().toString("yyyy-MM-dd"); end=self.p_end.date().toString("yyyy-MM-dd")
        if start>end:
            QMessageBox.warning(self,"Tarih Hatası","Başlangıç tarihi bitiş tarihinden büyük olamaz."); return
        params=[]; q="SELECT u.id,u.kod,u.ad,u.birim,u.min_seviye,u.max_seviye FROM urunler u WHERE u.aktif=1"
        if self.p_urun.text().strip(): q += " AND (u.kod LIKE ? OR u.ad LIKE ?)"; params.extend([f"%{self.p_urun.text().strip()}%",f"%{self.p_urun.text().strip()}%"])
        products=self.db.conn.execute(q,params).fetchall(); depot_id=self.p_depo.currentData()
        depots=self.db.warehouses(); depots=[r for r in depots if r['aktif'] and (depot_id is None or r['id']==depot_id)]
        self.period_table.setRowCount(0)
        for p in products:
            for d in depots:
                opening=float(self.db.conn.execute("SELECT COALESCE(SUM(CASE WHEN islem_tipi IN ('Giriş','İade') THEN miktar ELSE -miktar END),0) FROM stok_hareketleri WHERE urun_id=? AND depo_id=? AND tarih<?",(p['id'],d['id'],start)).fetchone()[0] or 0)
                incoming=float(self.db.conn.execute("SELECT COALESCE(SUM(miktar),0) FROM stok_hareketleri WHERE urun_id=? AND depo_id=? AND tarih>=? AND tarih<=? AND islem_tipi IN ('Giriş','İade')",(p['id'],d['id'],start,end)).fetchone()[0] or 0)
                outgoing=float(self.db.conn.execute("SELECT COALESCE(SUM(miktar),0) FROM stok_hareketleri WHERE urun_id=? AND depo_id=? AND tarih>=? AND tarih<=? AND islem_tipi='Çıkış'",(p['id'],d['id'],start,end)).fetchone()[0] or 0)
                closing=opening+incoming-outgoing
                if abs(opening)+abs(incoming)+abs(outgoing) < 1e-12 and abs(closing) < 1e-12:
                    continue
                row=self.period_table.rowCount(); self.period_table.insertRow(row)
                vals=[row+1,f"{d['kod']} - {d['ad']}",p['kod'],p['ad'],p['birim'] or "",self.fmt_qty(opening),self.fmt_qty(incoming),self.fmt_qty(outgoing),self.fmt_qty(incoming-outgoing),self.fmt_qty(closing),self.fmt_qty(p['min_seviye']),self.fmt_qty(p['max_seviye'])]
                for c,v in enumerate(vals): self.period_table.setItem(row,c,QTableWidgetItem(str(v)))
                brush=QColor(Qt.red).lighter(170) if closing<0 else QColor(Qt.yellow).lighter(170) if p['min_seviye'] and closing<p['min_seviye'] else None
                if brush:
                    for c in range(self.period_table.columnCount()): self.period_table.item(row,c).setData(Qt.BackgroundRole,brush)
        self.period_total.setText(f"Toplam kayıt: {self.period_table.rowCount()}")

    def build_movements_tab(self):
        tab=QWidget(); root=QVBoxLayout(tab)
        f=QGridLayout(); self.m_start=QDateEdit(QDate.currentDate().addMonths(-1)); self.m_end=QDateEdit(QDate.currentDate())
        for x in (self.m_start,self.m_end): x.setCalendarPopup(True)
        self.m_depo=QComboBox(); self.m_type=QComboBox(); self.m_type.addItems(["Tümü","Giriş","Çıkış"]); self.m_search=QLineEdit(); self.m_search.setPlaceholderText("Ürün kodu / adı...")
        self.m_dep=QComboBox(); self.m_alt=QComboBox(); self.m_alt.addItem("Tümü",None)
        self.combo_fill(self.m_depo,self.db.warehouses(),lambda r:f"{r['kod']} - {r['ad']}"); self.combo_fill(self.m_dep,self.db.departments(),lambda r:f"{r['kod']} - {r['ad']}")
        self.m_dep.currentIndexChanged.connect(self.load_report_alt_units)
        f.addWidget(QLabel("Başlangıç"),0,0); f.addWidget(self.m_start,0,1); f.addWidget(QLabel("Bitiş"),0,2); f.addWidget(self.m_end,0,3)
        f.addWidget(QLabel("Depo"),0,4); f.addWidget(self.m_depo,0,5); f.addWidget(QLabel("İşlem"),0,6); f.addWidget(self.m_type,0,7)
        connect_live_text_filter(self.m_search, self.refresh_movements)
        f.addWidget(QLabel("Ürün"),1,0); f.addWidget(self.m_search,1,1,1,3); f.addWidget(QLabel("Departman"),1,4); f.addWidget(self.m_dep,1,5); f.addWidget(QLabel("Alt Birim"),1,6); f.addWidget(self.m_alt,1,7)
        b=QPushButton("Sorgula"); b.clicked.connect(self.refresh_movements); f.addWidget(b,1,8)
        e=QPushButton("Excel'e Aktar"); e.clicked.connect(lambda: self.export_table(self.mov_table,"Ürün Hareket Raporu")); f.addWidget(e,1,9)
        pr=QPushButton("Yazdır"); pr.clicked.connect(lambda: self.print_table(self.mov_table,"Ürün Hareket Raporu")); f.addWidget(pr,1,10)
        root.addLayout(f)
        self.mov_table=QTableWidget(0,13); self.mov_table.setHorizontalHeaderLabels(["No","Tarih","Fiş No","İşlem","Depo","Ürün Kodu","Ürün","Miktar","Birim Fiyat","Departman","Alt Birim","Teslim Eden","Teslim Alan"])
        configure_resizable_table(self.mov_table,"rapor_hareket",[55,100,100,90,170,110,240,100,115,180,140,140,140]); self.mov_table.setEditTriggers(QAbstractItemView.NoEditTriggers); root.addWidget(self.mov_table,1)
        self.mov_total=QLabel("Toplam kayıt: 0"); root.addWidget(self.mov_total); self.tabs.addTab(tab,"Ürün Hareket Raporu")
        self.refresh_movements()

    def load_report_alt_units(self):
        self.m_alt.clear(); self.m_alt.addItem("Tümü",None); dep_id=self.m_dep.currentData()
        if dep_id:
            for row in self.db.subunits(dep_id, include_inactive=False): self.m_alt.addItem(f"{row['kod']} - {row['ad']}",row['id'])

    def refresh_movements(self):
        start=self.m_start.date().toString("yyyy-MM-dd"); end=self.m_end.date().toString("yyyy-MM-dd")
        if start>end: QMessageBox.warning(self,"Tarih Hatası","Başlangıç tarihi bitiş tarihinden büyük olamaz."); return
        search=self.m_search.text().strip(); product_id=None
        if search:
            rows=self.db.conn.execute("SELECT id FROM urunler WHERE aktif=1 AND (kod LIKE ? OR ad LIKE ?) ORDER BY id",(f"%{search}%",f"%{search}%")).fetchall()
            product_ids=[r['id'] for r in rows]
        else: product_ids=None
        base=self.db.list_stock_movements(start,end,self.m_depo.currentData(),None,None if self.m_type.currentText()=="Tümü" else self.m_type.currentText())
        self.mov_table.setRowCount(0)
        for r0 in base:
            if product_ids is not None and r0['urun_id'] not in product_ids: continue
            if self.m_dep.currentData() and r0['departman_id'] != self.m_dep.currentData(): continue
            if self.m_alt.currentData() and r0['alt_birim_id'] != self.m_alt.currentData(): continue
            r=self.mov_table.rowCount(); self.mov_table.insertRow(r)
            vals=[r+1,r0['tarih'],r0['fis_no'] or "",r0['islem_tipi'],f"{r0['depo_kodu']} - {r0['depo_adi']}",r0['urun_kodu'],r0['urun_adi'],self.fmt_qty(r0['miktar']),self.fmt_money(r0['birim_fiyat']),f"{r0['departman_kodu']} - {r0['departman_adi']}" if r0['departman_kodu'] else "",f"{r0['alt_birim_kodu']} - {r0['alt_birim_adi']}" if r0['alt_birim_kodu'] else "",r0['teslim_eden'] or "",r0['teslim_alan'] or ""]
            for c,v in enumerate(vals): self.mov_table.setItem(r,c,QTableWidgetItem(str(v)))
        self.mov_total.setText(f"Toplam kayıt: {self.mov_table.rowCount()}")

    def export_table(self, table, title):
        path, selected = QFileDialog.getSaveFileName(self, f"{title} Aktar", title.replace(" ", "_").lower(), "Excel Çalışma Kitabı (*.xlsx);;Excel 97-2003 (*.xls);;CSV Dosyası (*.csv)")
        if not path: return
        try:
            headers=[table.horizontalHeaderItem(c).text() if table.horizontalHeaderItem(c) else f"Sütun {c+1}" for c in range(table.columnCount())]
            rows=[[table.item(r,c).text() if table.item(r,c) else "" for c in range(table.columnCount())] for r in range(table.rowCount())]
            lower=path.lower()
            if lower.endswith('.xlsx'):
                import xlsxwriter
                wb=xlsxwriter.Workbook(path); ws=wb.add_worksheet(title[:31]); fmt=wb.add_format({'bold':True,'bg_color':'#D9E2F3','border':1})
                for c,h in enumerate(headers): ws.write(0,c,h,fmt)
                for r,row in enumerate(rows,1):
                    for c,v in enumerate(row): ws.write(r,c,v)
                    
                for c,h in enumerate(headers): ws.set_column(c,c,max(10,min(35,max(len(h)+2,max((len(str(row[c])) for row in rows[:200]),default=0)+2))))
                ws.freeze_panes(1,0); ws.autofilter(0,0,len(rows),len(headers)-1); wb.close()
            elif lower.endswith('.xls'):
                try:
                    import win32com.client as win32
                except ImportError as exc:
                    raise RuntimeError(".xls kaydı için pywin32 ve Windows'ta Microsoft Excel gereklidir.") from exc
                temp_xlsx=Path(tempfile.gettempdir())/(Path(path).stem+"_tmp.xlsx")
                import xlsxwriter
                wb=xlsxwriter.Workbook(str(temp_xlsx)); ws=wb.add_worksheet(title[:31])
                for c,h in enumerate(headers): ws.write(0,c,h)
                for r,row in enumerate(rows,1):
                    for c,v in enumerate(row): ws.write(r,c,v)
                wb.close()
                excel=win32.DispatchEx('Excel.Application'); excel.Visible=False; excel.DisplayAlerts=False
                book=excel.Workbooks.Open(str(temp_xlsx)); book.SaveAs(str(Path(path).resolve()),FileFormat=56); book.Close(False); excel.Quit(); temp_xlsx.unlink(missing_ok=True)
            else:
                with open(path,'w',encoding='utf-8-sig',newline='') as f:
                    w=csv.writer(f,delimiter=';'); w.writerow(headers); w.writerows(rows)
            QMessageBox.information(self,"Aktarım Tamamlandı",f"Rapor kaydedildi:\n{path}")
        except Exception as exc:
            QMessageBox.critical(self,"Aktarım Hatası",str(exc))

    def print_table(self, table, title):
        printer=QPrinter(QPrinter.HighResolution)
        dlg=QPrintDialog(printer,self)
        if dlg.exec_()!=QDialog.Accepted: return
        doc=QTextDocument(); html=[f"<h2>{title}</h2><p>{QDate.currentDate().toString('dd.MM.yyyy')}</p><table border='1' cellspacing='0' cellpadding='3'><tr>"]
        for c in range(table.columnCount()): html.append(f"<th>{table.horizontalHeaderItem(c).text() if table.horizontalHeaderItem(c) else ''}</th>")
        html.append("</tr>")
        for r in range(table.rowCount()):
            html.append("<tr>")
            for c in range(table.columnCount()): html.append(f"<td>{table.item(r,c).text() if table.item(r,c) else ''}</td>")
            html.append("</tr>")
        html.append("</table>"); doc.setHtml("".join(html)); doc.print_(printer)

class PeriodCloseDialog(QDialog):
    """V1.36.0 dönem/yıl sonu kapanışı, kontrol, yeni dönem ve devir yönetimi."""
    def __init__(self,parent,db,current_user=None):
        super().__init__(parent); self.db=db; self.current_user=current_user
        self.setWindowTitle(f'Stok Dönem Kapanışı / Devir - {APP_VERSION}'); self.resize(1250,760); self.setMinimumSize(1100,680)
        root=QVBoxLayout(self)
        title=QLabel('STOK DÖNEM KAPANIŞI / YIL SONU DEVİR'); title.setObjectName('dialogTitle'); root.addWidget(title)
        info=QLabel('Yıl sonu/devir işlemi önce kontrol yapılmasını, ardından dönem kapanış snapshotının alınmasını ve yeni dönem için açılış stoklarının oluşturulmasını sağlar. Eski stok hareketleri silinmez veya değiştirilmez.')
        info.setWordWrap(True); root.addWidget(info)

        f=QGridLayout()
        self.date=QDateEdit(QDate.currentDate()); self.date.setCalendarPopup(True)
        self.depo=QComboBox(); self.depo.addItem('Tüm Depolar',None)
        for d in db.warehouses():
            if d['aktif']: self.depo.addItem(f"{d['kod']} - {d['ad']}",d['id'])
        self.devir_type=QComboBox(); self.devir_type.addItems(['Bakiyeli Devir','Bakiyesiz Devir','Sadece Kartlar'])
        year=QDate.currentDate().year()+1
        self.next_code=QLineEdit(str(year)); self.next_name=QLineEdit(f"{year} Dönemi"); self.next_start=QDateEdit(QDate(year,1,1)); self.next_start.setCalendarPopup(True)
        self.desc=QLineEdit(); self.desc.setPlaceholderText('2026 dönem kapanışı / 2027 devir vb.')
        f.addWidget(QLabel('Kapanış Tarihi'),0,0); f.addWidget(self.date,0,1)
        f.addWidget(QLabel('Kapsam'),0,2); f.addWidget(self.depo,0,3,1,2)
        f.addWidget(QLabel('Devir Türü'),1,0); f.addWidget(self.devir_type,1,1)
        f.addWidget(QLabel('Yeni Dönem Kodu'),1,2); f.addWidget(self.next_code,1,3)
        f.addWidget(QLabel('Yeni Dönem Adı'),2,0); f.addWidget(self.next_name,2,1,1,2)
        f.addWidget(QLabel('Yeni Dönem Başlangıcı'),2,3); f.addWidget(self.next_start,2,4)
        f.addWidget(QLabel('Açıklama'),3,0); f.addWidget(self.desc,3,1,1,4)
        root.addLayout(f)

        self.control=QPlainTextEdit(); self.control.setReadOnly(True); self.control.setMaximumHeight(115); root.addWidget(QLabel('Kapanış Öncesi Kontrol')); root.addWidget(self.control)
        self.table=QTableWidget(0,8); self.table.setHorizontalHeaderLabels(['No','Depo','Ürün Kodu','Ürün','Barkod','Birim','Devir Miktarı','Stok Değeri']); configure_resizable_table(self.table,'devir_onizleme',[55,180,110,240,130,75,110,120]); self.table.setEditTriggers(QAbstractItemView.NoEditTriggers); root.addWidget(self.table,1)
        self.action_status=QLabel('Son işlem: Hazırlanıyor...'); self.action_status.setStyleSheet('color:#35566f;font-weight:600;'); root.addWidget(self.action_status)

        b=QHBoxLayout(); check=QPushButton('Yıl Sonu Kontrollerini Çalıştır'); check.clicked.connect(self.run_control); preview=QPushButton('Devir Önizleme'); preview.clicked.connect(self.preview); history=QPushButton('Kapanış / Devir Geçmişi'); history.clicked.connect(self.open_history); cancel_close=QPushButton('Kapanış Geçmişi / İptal'); cancel_close.clicked.connect(self.open_history); save=QPushButton('Dönemi Kapat ve Yeni Döneme Devret'); save.clicked.connect(self.save); close=QPushButton('Kapat'); close.clicked.connect(self.reject)
        for btn in (check,preview,history,cancel_close): b.addWidget(btn)
        b.addStretch(); b.addWidget(save); b.addWidget(close); root.addLayout(b)
        self.date.dateChanged.connect(lambda _=None: (self.run_control(), self.preview()))
        self.depo.currentIndexChanged.connect(lambda _=None: (self.run_control(), self.preview()))
        self.devir_type.currentIndexChanged.connect(lambda _=None: self.preview())
        self.run_control(); self.preview()

    def _control_data(self):
        return self.db.period_close_control(self.date.date().toString('yyyy-MM-dd'), self.depo.currentData())

    def run_control(self):
        try:
            c=self._control_data()
            lines=[
                f"Kapanış tarihi          : {self.date.date().toString('dd.MM.yyyy')}",
                f"İleri tarihli hareket   : {c['future_movements']}",
                f"Negatif stok satırı     : {c['negative_rows']}",
                f"Negatif stok toplamı    : {self.q(c['negative_qty'])}",
                f"Sıfırdan farklı stok    : {c['nonzero_rows']}",
                f"Tahmini stok değeri     : {self.money(c['total_value'])}",
            ]
            if c['future_movements']:
                lines.append('SONUÇ: İLERİ TARİHLİ HAREKET VAR → KAPANIŞ ENGELLENECEK.')
            elif c['negative_rows']:
                lines.append('SONUÇ: Negatif stok var → yönetici onayıyla devam edilebilir; rapora kaydedilir.')
            else:
                lines.append('SONUÇ: Kontroller başarılı.')
            self.control.setPlainText('\n'.join(lines))
            self.action_status.setText(f"Son işlem: Yıl sonu kontrolleri tamamlandı — {c['nonzero_rows']} farklı stok satırı, {c['negative_rows']} negatif stok satırı.")
        except Exception as exc:
            self.control.setPlainText(f'Kontrol hatası: {exc}')
            self.action_status.setText(f"Son işlem: Kontrol hatası — {exc}")

    def preview(self):
        date=self.date.date().toString('yyyy-MM-dd'); dep=self.depo.currentData(); rows=[]
        depots=[d for d in self.db.warehouses() if d['aktif'] and (dep is None or d['id']==dep)]
        self.table.setRowCount(0); n=0
        for d in depots:
            data=self.db.conn.execute("""SELECT u.kod,u.ad,u.barkod,u.birim,u.alis_fiyati,COALESCE((SELECT SUM(CASE WHEN sh.islem_tipi IN ('Giriş','İade') THEN sh.miktar ELSE -sh.miktar END) FROM stok_hareketleri sh WHERE sh.urun_id=u.id AND sh.depo_id=? AND sh.tarih<=?),0) AS bakiye FROM urunler u WHERE u.aktif=1 ORDER BY u.kod""",(d['id'],date)).fetchall()
            for x in data:
                qty=float(x['bakiye'] or 0)
                if abs(qty)<1e-12: continue
                r=self.table.rowCount(); self.table.insertRow(r); n+=1
                vals=[n,f"{d['kod']} - {d['ad']}",x['kod'],x['ad'],x['barkod'] or '',x['birim'] or '',self.q(qty),self.money(qty*float(x['alis_fiyati'] or 0))]
                for c,v in enumerate(vals): self.table.setItem(r,c,QTableWidgetItem(str(v)))
        self.action_status.setText(f"Son işlem: Devir önizlemesi yenilendi — {n} stok satırı listelendi.")

    def save(self):
        c=self._control_data()
        if c['future_movements']:
            QMessageBox.critical(self,'Kapanış Engellendi',f"Kapanış tarihinden sonra {c['future_movements']} adet stok hareketi var. Önce ileri tarihli hareketleri düzeltin.")
            return
        if c['negative_rows']:
            ans=QMessageBox.question(self,'Negatif Stok Uyarısı',f"{c['negative_rows']} stok satırında negatif bakiye var.\n\nNegatif stokları kontrol ettiniz mi? Yönetici onayı ile devam edilsin mi?",QMessageBox.Yes|QMessageBox.No,QMessageBox.No)
            if ans!=QMessageBox.Yes: return
        if self.table.rowCount()==0 and self.devir_type.currentText()=='Bakiyeli Devir':
            ans=QMessageBox.question(self,'Kapanış','Seçilen kapsamda sıfırdan farklı stok bulunamadı. Yine de boş bakiyeli dönem kapanışı oluşturulsun mu?',QMessageBox.Yes|QMessageBox.No,QMessageBox.No)
            if ans!=QMessageBox.Yes:return
        try:
            kid,no,next_id,control=self.db.create_period_close(
                self.date.date().toString('yyyy-MM-dd'), self.depo.currentData(), self.desc.text().strip(),
                self.current_user['id'] if self.current_user else None, self.devir_type.currentText(),
                self.next_code.text().strip(), self.next_name.text().strip(), self.next_start.date().toString('yyyy-MM-dd'), True, bool(c['negative_rows'])
            )
        except Exception as e:
            QMessageBox.critical(self,'Kapanış Oluşturulamadı',str(e)); self.action_status.setText(f"Son işlem: Kapanış oluşturulamadı — {e}"); return
        QMessageBox.information(self,'Kapanış Tamamlandı',f"{no} numaralı dönem kapanışı oluşturuldu.\n\nYeni dönem: {self.next_code.text().strip()}\nDevir türü: {self.devir_type.currentText()}\n\nTarihsel stok hareketleri değiştirilmedi.")
        self.action_status.setText(f"Son işlem: {no} numaralı dönem kapanışı başarıyla oluşturuldu.")
        self.run_control(); self.preview()

    def cancel_close(self):
        item=self.table.currentItem()
        if item is None:
            QMessageBox.information(self,'Kapanış İptali','İptal edilecek kapanışı Kapanış / Devir Geçmişi ekranından seçmeniz gerekir.'); return
        # Geçmiş dialogu üzerinden güvenli iptal tercih edilir.
        self.open_history()

    def open_history(self): PeriodCloseHistoryDialog(self,self.db).exec_()
    @staticmethod
    def q(v): return f"{float(v or 0):,.3f}".replace(',','X').replace('.',',').replace('X','.')
    @staticmethod
    def money(v): return f"{float(v or 0):,.2f} TL".replace(',','X').replace('.',',').replace('X','.')

class PeriodManagementDialog(QDialog):
    """Dönemleri görüntüleme ve aktif dönem durumunu yönetme ekranı."""
    def __init__(self,parent,db,current_user=None):
        super().__init__(parent); self.db=db; self.current_user=current_user
        self.setWindowTitle(f'Dönem Yönetimi - {APP_VERSION}'); self.resize(1050,560)
        root=QVBoxLayout(self)
        root.addWidget(QLabel('DÖNEM YÖNETİMİ / YIL SONU'))
        info=QLabel('Dönemler açılış/devir kayıtlarını, kapanış durumlarını ve hangi kapanıştan oluşturulduklarını gösterir. Kapanış işlemi tarihsel hareketleri silmez.')
        info.setWordWrap(True); root.addWidget(info)
        self.table=QTableWidget(0,9); self.table.setHorizontalHeaderLabels(['ID','Dönem','Ad','Başlangıç','Bitiş','Durum','Önceki Dönem','Kapanış No','Oluşturma']); configure_resizable_table(self.table,'donem_yonetimi',[55,90,220,105,105,100,110,120,160]); self.table.setEditTriggers(QAbstractItemView.NoEditTriggers); root.addWidget(self.table,1)
        row=QHBoxLayout(); refresh=QPushButton('Yenile'); refresh.clicked.connect(self.refresh); close=QPushButton('Kapat'); close.clicked.connect(self.accept); row.addWidget(refresh); row.addStretch(); row.addWidget(close); root.addLayout(row); self.refresh()
    def refresh(self):
        self.table.setRowCount(0)
        rows=self.db.list_periods()
        for i,x in enumerate(rows,1):
            r=self.table.rowCount(); self.table.insertRow(r)
            vals=[x['id'],x['kod'],x['ad'],x['baslangic_tarihi'],x['bitis_tarihi'],x['durum'],x['onceki_donem_id'] or '',x['kapanis_no'] or '',x['olusturma_tarihi']]
            for c,v in enumerate(vals): self.table.setItem(r,c,QTableWidgetItem(str(v)))

class PeriodCloseHistoryDialog(QDialog):
    def __init__(self,parent,db):
        super().__init__(parent); self.db=db; self.setWindowTitle(f'Stok Dönem Kapanış / Devir Geçmişi - {APP_VERSION}'); self.resize(1450,760)
        root=QVBoxLayout(self); root.addWidget(QLabel('STOK DÖNEM KAPANIŞ / YIL SONU DEVİR GEÇMİŞİ'))
        info=QLabel('Kapanış kayıtları geçmişi silinmez. İptal edilen bir kapanış ayrı durumuyla saklanır; aktif kapanışların oluşturduğu yeni dönemlerde hareket varsa iptal işlemi engellenir.')
        info.setWordWrap(True); root.addWidget(info)
        self.table=QTableWidget(0,13); self.table.setHorizontalHeaderLabels(['No','Kapanış No','Tarih','Kapsam','Devir Türü','Yeni Dönem','Durum','Açıklama','Kullanıcı','Satır','Toplam Miktar','Stok Değeri','Oluşturma']); configure_resizable_table(self.table,'donem_kapanis_gecmisi',[55,110,100,190,130,100,95,220,140,65,120,120,160]); self.table.setEditTriggers(QAbstractItemView.NoEditTriggers); root.addWidget(self.table,1)
        b=QHBoxLayout(); detail=QPushButton('Detay'); detail.clicked.connect(self.detail); cancel=QPushButton('Kapanışı İptal Et'); cancel.clicked.connect(self.cancel); exp=QPushButton("Excel'e Aktar"); exp.clicked.connect(self.export); pr=QPushButton('Yazdır'); pr.clicked.connect(self.print_report); close=QPushButton('Kapat'); close.clicked.connect(self.accept)
        for btn in (detail,cancel,exp,pr): b.addWidget(btn)
        b.addStretch(); b.addWidget(close); root.addLayout(b); self.refresh()
    def refresh(self):
        self.table.setRowCount(0)
        for i,x in enumerate(self.db.list_period_closes(),1):
            r=self.table.rowCount(); self.table.insertRow(r)
            vals=[i,x['kapanis_no'],x['tarih'],x['kapsam'],x['devir_turu'] or '',x['yeni_donem_kodu'] or '',x['durum'] or '',x['aciklama'] or '',x['kullanici'] or '',x['satir_sayisi'],self.q(x['toplam_miktar']),self.money(x['toplam_deger']),x['olusturma_tarihi']]
            for c,v in enumerate(vals): self.table.setItem(r,c,QTableWidgetItem(str(v)))
    def selected_close_id(self):
        item=self.table.currentItem()
        if not item:return None
        no=self.table.item(item.row(),1).text(); row=self.db.conn.execute('SELECT id FROM stok_donem_kapanislari WHERE kapanis_no=?',(no,)).fetchone()
        return row['id'] if row else None
    def detail(self):
        cid=self.selected_close_id()
        if not cid: QMessageBox.information(self,'Detay','Bir kapanış seçin.'); return
        dlg=QDialog(self); dlg.setWindowTitle('Devir Detayı'); dlg.resize(1200,680); l=QVBoxLayout(dlg); t=QTableWidget(0,8); t.setHorizontalHeaderLabels(['Depo','Ürün Kodu','Ürün','Barkod','Birim','Miktar','Birim Maliyet','Stok Değeri']); configure_resizable_table(t,'donem_kapanis_detay',[180,110,260,130,70,110,120,120]);
        for x in self.db.period_close_details(cid):
            r=t.rowCount();t.insertRow(r);vals=[f"{x['depo_kodu']} - {x['depo_adi']}",x['urun_kodu'],x['urun_adi'],x['barkod'] or '',x['birim'] or '',self.q(x['miktar']),self.money(x['birim_maliyet']),self.money(x['stok_degeri'])]
            for c,v in enumerate(vals):t.setItem(r,c,QTableWidgetItem(str(v)))
        l.addWidget(t); bb=QDialogButtonBox(QDialogButtonBox.Close);bb.rejected.connect(dlg.reject);l.addWidget(bb);dlg.exec_()
    def cancel(self):
        cid=self.selected_close_id()
        if not cid:
            QMessageBox.information(self,'Kapanış İptali','İptal edilecek kapanışı seçin.'); return
        row=self.db.conn.execute("SELECT * FROM stok_donem_kapanislari WHERE id=?",(cid,)).fetchone()
        if row and str(row['durum'] or '')=='İptal':
            QMessageBox.information(self,'Kapanış İptali','Seçilen kapanış zaten iptal edilmiş.'); return
        if QMessageBox.question(self,'Kapanış İptali','Seçilen dönem kapanışı iptal edilecek. Yeni dönem açılış snapshotı kaldırılacak. Tarihsel stok hareketleri silinmeyecek. Devam edilsin mi?',QMessageBox.Yes|QMessageBox.No,QMessageBox.No)!=QMessageBox.Yes:return
        try:
            self.db.cancel_period_close(cid)
            QMessageBox.information(self,'Kapanış İptal Edildi','Seçilen dönem kapanışı iptal edildi. Tarihsel stok hareketleri korunmaktadır.')
            self.refresh()
        except Exception as exc: QMessageBox.critical(self,'Kapanış İptal Edilemedi',str(exc))
    def export(self):
        path,_=QFileDialog.getSaveFileName(self,'Kapanış Geçmişi','donem_kapanis_gecmisi','Excel Çalışma Kitabı (*.xlsx);;CSV Dosyası (*.csv)')
        if not path:return
        h=[self.table.horizontalHeaderItem(c).text() for c in range(self.table.columnCount())]; rows=[[self.table.item(r,c).text() if self.table.item(r,c) else '' for c in range(self.table.columnCount())] for r in range(self.table.rowCount())]
        try:
            if path.lower().endswith('.csv'):
                with open(path,'w',newline='',encoding='utf-8-sig') as f: csv.writer(f,delimiter=';').writerows([h]+rows)
            else:
                import xlsxwriter; wb=xlsxwriter.Workbook(path);ws=wb.add_worksheet('Kapanış'); fmt=wb.add_format({'bold':True,'bg_color':'#D9E2F3','border':1})
                for c,v in enumerate(h):ws.write(0,c,v,fmt)
                for r,row in enumerate(rows,1):
                    for c,v in enumerate(row):ws.write(r,c,v)
                wb.close()
            QMessageBox.information(self,'Aktarım','Dosya kaydedildi.')
        except Exception as e: QMessageBox.critical(self,'Aktarım',str(e))
    def print_report(self):
        printer=QPrinter(QPrinter.HighResolution);d=QPrintDialog(printer,self)
        if d.exec_()!=QDialog.Accepted:return
        doc=QTextDocument();html=['<html><head><meta charset="utf-8"><style>body{font-family:Arial;font-size:8pt}table{border-collapse:collapse;width:100%}th,td{border:1px solid #777;padding:3px}</style></head><body><h2>STOK DÖNEM KAPANIŞ GEÇMİŞİ</h2><table><tr>']+[f'<th>{self.table.horizontalHeaderItem(c).text()}</th>' for c in range(self.table.columnCount())]+['</tr>']
        for r in range(self.table.rowCount()):html.append('<tr>'+''.join(f'<td>{self.table.item(r,c).text() if self.table.item(r,c) else ""}</td>' for c in range(self.table.columnCount()))+'</tr>')
        html.append('</table></body></html>');doc.setHtml(''.join(html));doc.print_(printer)
    @staticmethod
    def q(v): return f"{float(v or 0):,.3f}".replace(',','X').replace('.',',').replace('X','.')
    @staticmethod
    def money(v): return f"{float(v or 0):,.2f} TL".replace(',','X').replace('.',',').replace('X','.')

class ComprehensiveStockReportDialog(QDialog):
    """Kapsamlı stok raporları: stok özeti, depo özeti ve departman tüketimi."""
    def __init__(self,parent,db):
        super().__init__(parent); self.db=db; self.setWindowTitle(f"Kapsamlı Stok Raporları - {APP_VERSION}"); self.resize(1450,820)
        root=QVBoxLayout(self); title=QLabel("KAPSAMLI STOK RAPORLARI"); title.setObjectName('dialogTitle'); root.addWidget(title)
        self.tabs=QTabWidget(); root.addWidget(self.tabs,1); self.build_stock_tab(); self.build_warehouse_tab(); self.build_department_tab()
        close=QPushButton('Kapat'); close.clicked.connect(self.accept); root.addWidget(close,0,Qt.AlignRight)
    def build_stock_tab(self):
        tab=QWidget(); root=QVBoxLayout(tab); f=QGridLayout(); self.s_depo=QComboBox(); self.s_depo.addItem('Tüm Depolar',None); self.s_grup=QComboBox(); self.s_grup.addItem('Tüm Gruplar',None); self.s_tip=QComboBox(); self.s_tip.addItem('Tüm Türler',None); self.s_durum=QComboBox(); self.s_durum.addItems(['Tümü','Normal','Minimum Altı','Maksimum Üstü','Negatif','Sıfır']); self.s_search=QLineEdit(); self.s_search.setPlaceholderText('Kod, ad, barkod, marka, model...')
        for d in self.db.warehouses():
            if d['aktif']: self.s_depo.addItem(f"{d['kod']} - {d['ad']}",d['id'])
        for g in self.db.conn.execute('SELECT id,kod,ad FROM urun_gruplari WHERE aktif=1 ORDER BY ad').fetchall(): self.s_grup.addItem(f"{g['kod']} - {g['ad']}",g['id'])
        for t in self.db.conn.execute('SELECT id,kod,ad FROM urun_turleri WHERE aktif=1 ORDER BY ad').fetchall(): self.s_tip.addItem(f"{t['kod']} - {t['ad']}",t['id'])
        connect_live_text_filter(self.s_search, self.refresh_stock)
        q=QPushButton('Sorgula'); q.clicked.connect(self.refresh_stock); ex=QPushButton("Excel'e Aktar"); ex.clicked.connect(lambda:self.export_table(self.stock_table,'Kapsamlı Stok')); pr=QPushButton('Yazdır'); pr.clicked.connect(lambda:self.print_table(self.stock_table,'Kapsamlı Stok Raporu'))
        items=[('Depo',self.s_depo),('Grup',self.s_grup),('Ürün Türü',self.s_tip),('Durum',self.s_durum),('Arama',self.s_search)]
        for i,(lab,w) in enumerate(items): f.addWidget(QLabel(lab),0,i*2); f.addWidget(w,0,i*2+1)
        f.addWidget(q,1,0); f.addWidget(ex,1,1); f.addWidget(pr,1,2); root.addLayout(f)
        self.stock_table=QTableWidget(0,13); self.stock_table.setHorizontalHeaderLabels(['No','Depo','Kod','Ürün','Grup','Tür','Marka','Model','Birim','Mevcut','Min.','Max.','Stok Değeri']); configure_resizable_table(self.stock_table,'kapsamli_stok',[55,170,100,240,150,130,120,130,70,100,90,90,120]); self.stock_table.setEditTriggers(QAbstractItemView.NoEditTriggers); root.addWidget(self.stock_table,1); self.stock_total=QLabel(); root.addWidget(self.stock_total); self.tabs.addTab(tab,'Stok Özeti'); self.refresh_stock()
    def refresh_stock(self):
        rows=self.db.comprehensive_stock_rows(self.s_depo.currentData(),self.s_grup.currentData(),self.s_tip.currentData(),self.s_durum.currentText(),self.s_search.text().strip()); self.stock_table.setRowCount(0)
        depo='Tüm Depolar'
        if self.s_depo.currentData():
            d=self.db.conn.execute('SELECT kod,ad FROM depolar WHERE id=?',(self.s_depo.currentData(),)).fetchone(); depo=f"{d['kod']} - {d['ad']}" if d else ''
        for i,x in enumerate(rows,1):
            r=self.stock_table.rowCount(); self.stock_table.insertRow(r); vals=[i,depo,x['kod'],x['ad'],x['grup_adi'],x['urun_turu_adi'],x['marka'],x['model'],x['birim'] or '',self.q(x['mevcut']),self.q(x['min_seviye']),self.q(x['max_seviye']),self.money(x['stok_degeri'])]
            for c,v in enumerate(vals): self.stock_table.setItem(r,c,QTableWidgetItem(str(v)))
        self.stock_total.setText(f'Toplam kayıt: {len(rows)} | Toplam stok değeri: {self.money(sum(float(x["stok_degeri"]) for x in rows))}')
    def build_warehouse_tab(self):
        tab=QWidget(); root=QVBoxLayout(tab); b=QHBoxLayout(); rf=QPushButton('Yenile'); rf.clicked.connect(self.refresh_warehouses); ex=QPushButton("Excel'e Aktar"); ex.clicked.connect(lambda:self.export_table(self.wh_table,'Depo Stok Özeti')); pr=QPushButton('Yazdır'); pr.clicked.connect(lambda:self.print_table(self.wh_table,'Depo Stok Özeti')); b.addWidget(rf); b.addWidget(ex); b.addWidget(pr); b.addStretch(); root.addLayout(b); self.wh_table=QTableWidget(0,7); self.wh_table.setHorizontalHeaderLabels(['No','Depo','Ürün Sayısı','Toplam Miktar','Stok Değeri','Negatif','Min. Altı']); configure_resizable_table(self.wh_table,'depo_stok_ozeti',[55,240,110,130,140,100,110]); self.wh_table.setEditTriggers(QAbstractItemView.NoEditTriggers); root.addWidget(self.wh_table,1); self.tabs.addTab(tab,'Depo Özeti'); self.refresh_warehouses()
    def refresh_warehouses(self):
        self.wh_table.setRowCount(0)
        for i,x in enumerate(self.db.warehouse_summary(),1):
            r=self.wh_table.rowCount(); self.wh_table.insertRow(r); vals=[i,f"{x['kod']} - {x['ad']}",x['urun_sayisi'],self.q(x['toplam_miktar']),self.money(x['stok_degeri']),x['negatif'],x['min_alt']]
            for c,v in enumerate(vals): self.wh_table.setItem(r,c,QTableWidgetItem(str(v)))
    def build_department_tab(self):
        tab=QWidget(); root=QVBoxLayout(tab); f=QGridLayout(); self.d_start=QDateEdit(QDate.currentDate().addMonths(-1)); self.d_end=QDateEdit(QDate.currentDate()); self.d_depo=QComboBox(); self.d_depo.addItem('Tüm Depolar',None); self.d_dep=QComboBox(); self.d_dep.addItem('Tüm Departmanlar',None)
        for d in self.db.warehouses():
            if d['aktif']: self.d_depo.addItem(f"{d['kod']} - {d['ad']}",d['id'])
        for d in self.db.departments():
            if d['aktif']: self.d_dep.addItem(f"{d['kod']} - {d['ad']}",d['id'])
        for x in (self.d_start,self.d_end): x.setCalendarPopup(True)
        q=QPushButton('Sorgula'); q.clicked.connect(self.refresh_department); ex=QPushButton("Excel'e Aktar"); ex.clicked.connect(lambda:self.export_table(self.dep_table,'Departman Tüketim')); pr=QPushButton('Yazdır'); pr.clicked.connect(lambda:self.print_table(self.dep_table,'Departman Tüketim Raporu'))
        for c,(lab,w) in enumerate([('Başlangıç',self.d_start),('Bitiş',self.d_end),('Depo',self.d_depo),('Departman',self.d_dep)]): f.addWidget(QLabel(lab),0,c*2); f.addWidget(w,0,c*2+1)
        f.addWidget(q,1,0); f.addWidget(ex,1,1); f.addWidget(pr,1,2); root.addLayout(f); self.dep_table=QTableWidget(0,5); self.dep_table.setHorizontalHeaderLabels(['No','Departman','Alt Birim','Çıkış Hareketi','Çıkış Miktarı']); configure_resizable_table(self.dep_table,'departman_tuketim',[55,220,220,130,130]); self.dep_table.setEditTriggers(QAbstractItemView.NoEditTriggers); root.addWidget(self.dep_table,1); self.tabs.addTab(tab,'Departman Tüketimi'); self.refresh_department()
    def refresh_department(self):
        a=self.d_start.date().toString('yyyy-MM-dd'); b=self.d_end.date().toString('yyyy-MM-dd')
        if a>b: QMessageBox.warning(self,'Tarih','Başlangıç tarihi bitişten büyük olamaz.'); return
        rows=self.db.department_consumption(a,b,self.d_depo.currentData(),self.d_dep.currentData()); self.dep_table.setRowCount(0)
        for i,x in enumerate(rows,1):
            r=self.dep_table.rowCount(); self.dep_table.insertRow(r); vals=[i,x['departman'],x['alt_birim'],x['hareket'],self.q(x['miktar'])]
            for c,v in enumerate(vals): self.dep_table.setItem(r,c,QTableWidgetItem(str(v)))
    def export_table(self,table,title):
        path,_=QFileDialog.getSaveFileName(self,title,'rapor','Excel Çalışma Kitabı (*.xlsx);;CSV Dosyası (*.csv)')
        if not path: return
        h=[table.horizontalHeaderItem(c).text() for c in range(table.columnCount())]; rows=[[table.item(r,c).text() if table.item(r,c) else '' for c in range(table.columnCount())] for r in range(table.rowCount())]
        try:
            if path.lower().endswith('.csv'):
                with open(path,'w',newline='',encoding='utf-8-sig') as f: csv.writer(f,delimiter=';').writerows([h]+rows)
            else:
                import xlsxwriter; wb=xlsxwriter.Workbook(path); ws=wb.add_worksheet(title[:31]); fmt=wb.add_format({'bold':True,'bg_color':'#D9E2F3','border':1})
                for c,v in enumerate(h): ws.write(0,c,v,fmt)
                for r,row in enumerate(rows,1):
                    for c,v in enumerate(row): ws.write(r,c,v)
                wb.close()
            QMessageBox.information(self,'Aktarım','Dosya kaydedildi.')
        except Exception as e: QMessageBox.critical(self,'Aktarım',str(e))
    def print_table(self,table,title):
        printer=QPrinter(QPrinter.HighResolution); d=QPrintDialog(printer,self)
        if d.exec_()!=QDialog.Accepted: return
        h=[table.horizontalHeaderItem(c).text() for c in range(table.columnCount())]; html=['<html><head><meta charset="utf-8"><style>body{font-family:Arial;font-size:7pt}table{border-collapse:collapse;width:100%}th,td{border:1px solid #777;padding:2px}th{background:#e8edf2}</style></head><body><h2>'+title+'</h2><table><tr>']+[f'<th>{x}</th>' for x in h]+['</tr>']
        for r in range(table.rowCount()): html.append('<tr>'+''.join(f'<td>{table.item(r,c).text() if table.item(r,c) else ""}</td>' for c in range(table.columnCount()))+'</tr>')
        html.append('</table></body></html>'); doc=QTextDocument(); doc.setHtml(''.join(html)); doc.print_(printer)
    @staticmethod
    def q(v): return f"{float(v or 0):,.3f}".replace(',','X').replace('.',',').replace('X','.')
    @staticmethod
    def money(v): return f"{float(v or 0):,.2f} TL".replace(',','X').replace('.',',').replace('X','.')


class SessionLogDialog(QDialog):
    def __init__(self,parent,db):
        super().__init__(parent); self.db=db; self.setWindowTitle(f"Oturum Kayıtları - {APP_VERSION}"); self.resize(1000,620)
        root=QVBoxLayout(self); root.addWidget(QLabel('OTURUM KAYITLARI')); self.table=QTableWidget(0,6); self.table.setHorizontalHeaderLabels(['No','Kullanıcı','Tarih','Olay','Açıklama','ID']); configure_resizable_table(self.table,'oturum_loglari',[55,180,160,150,420,60]); self.table.setEditTriggers(QAbstractItemView.NoEditTriggers); self.table.setSelectionBehavior(QAbstractItemView.SelectRows); root.addWidget(self.table,1)
        row=QHBoxLayout(); ex=QPushButton("Excel'e Aktar"); ex.clicked.connect(self.export); pr=QPushButton('Yazdır'); pr.clicked.connect(self.print_report); row.addWidget(ex); row.addWidget(pr); row.addStretch(); close=QPushButton('Kapat'); close.clicked.connect(self.accept); row.addWidget(close); root.addLayout(row); self.refresh()
    def refresh(self):
        self.table.setRowCount(0); rows=self.db.conn.execute('SELECT id,kullanici_adi,tarih,olay,aciklama FROM oturum_loglari ORDER BY id DESC LIMIT 2000').fetchall()
        for i,x in enumerate(rows,1):
            r=self.table.rowCount(); self.table.insertRow(r); vals=[i,x[1] or '',x[2] or '',x[3] or '',x[4] or '',x[0]]
            for c,v in enumerate(vals): self.table.setItem(r,c,QTableWidgetItem(str(v)))
    def export(self):
        path,_=QFileDialog.getSaveFileName(self,'Oturum Kayıtları','oturum_loglari','Excel Çalışma Kitabı (*.xlsx);;CSV Dosyası (*.csv)')
        if not path: return
        h=[self.table.horizontalHeaderItem(c).text() for c in range(self.table.columnCount())]; rows=[[self.table.item(r,c).text() if self.table.item(r,c) else '' for c in range(self.table.columnCount())] for r in range(self.table.rowCount())]
        try:
            if path.lower().endswith('.csv'):
                with open(path,'w',newline='',encoding='utf-8-sig') as f: csv.writer(f,delimiter=';').writerows([h]+rows)
            else:
                import xlsxwriter; wb=xlsxwriter.Workbook(path); ws=wb.add_worksheet('Oturum Log'); fmt=wb.add_format({'bold':True,'bg_color':'#D9E2F3','border':1})
                for c,v in enumerate(h): ws.write(0,c,v,fmt)
                for r,row in enumerate(rows,1):
                    for c,v in enumerate(row): ws.write(r,c,v)
                wb.close()
            QMessageBox.information(self,'Aktarım','Dosya kaydedildi.')
        except Exception as e: QMessageBox.critical(self,'Aktarım',str(e))
    def print_report(self):
        printer=QPrinter(QPrinter.HighResolution); d=QPrintDialog(printer,self)
        if d.exec_()!=QDialog.Accepted: return
        h=[self.table.horizontalHeaderItem(c).text() for c in range(self.table.columnCount())]; html=['<html><head><meta charset="utf-8"><style>body{font-family:Arial;font-size:8pt}table{width:100%;border-collapse:collapse}th,td{border:1px solid #777;padding:2px}</style></head><body><h2>OTURUM KAYITLARI</h2><table><tr>']+[f'<th>{x}</th>' for x in h]+['</tr>']
        for r in range(self.table.rowCount()): html.append('<tr>'+''.join(f'<td>{self.table.item(r,c).text() if self.table.item(r,c) else ""}</td>' for c in range(self.table.columnCount()))+'</tr>')
        html.append('</table></body></html>'); doc=QTextDocument(); doc.setHtml(''.join(html)); doc.print_(printer)




class AutoBackupSettingsDialog(QDialog):
    def __init__(self,parent,db):
        super().__init__(parent); self.db=db; self.setWindowTitle(f"Otomatik Yedekleme Ayarları - {APP_VERSION}"); self.resize(720,430); self.setMinimumSize(680,400)
        root=QVBoxLayout(self); root.addWidget(QLabel("OTOMATİK YEDEKLEME"))
        info=QLabel("Program açık olduğu sürece zamanlanan yedekleme kontrol edilir. Program açıldığında da son başarılı otomatik yedek tarihi kontrol edilir."); info.setWordWrap(True); root.addWidget(info)
        f=QFormLayout(); self.enabled=QCheckBox("Otomatik yedekleme aktif"); self.enabled.setChecked((APP_SETTINGS.value("backup/auto/enabled",False) or False) in (True,"true","1","True"))
        self.freq=QComboBox(); self.freq.addItems(["Her Gün","Haftada Bir"]); self.freq.setCurrentText(APP_SETTINGS.value("backup/auto/frequency","Her Gün") or "Her Gün")
        self.time=QTimeEdit(QTime.fromString(APP_SETTINGS.value("backup/auto/time","23:30"),"HH:mm")); self.time.setDisplayFormat("HH:mm")
        self.folder=QLineEdit(APP_SETTINGS.value("backup/auto/folder",str(Path.cwd()/"yedekler")) or str(Path.cwd()/"yedekler")); browse=QPushButton("Klasör Seç..."); browse.clicked.connect(self.choose_folder)
        h=QHBoxLayout(); h.addWidget(self.folder); h.addWidget(browse); w=QWidget(); w.setLayout(h)
        self.keep=QSpinBox(); self.keep.setRange(1,365); self.keep.setValue(int(APP_SETTINGS.value("backup/auto/keep",30) or 30))
        self.pgformat=QComboBox(); self.pgformat.addItems(["Custom (.dump)","Plain SQL (.sql)"]); self.pgformat.setCurrentText(APP_SETTINGS.value("backup/auto/pg_format","Custom (.dump)") or "Custom (.dump)")
        f.addRow(self.enabled); f.addRow("Sıklık",self.freq); f.addRow("Saat",self.time); f.addRow("Yedek klasörü",w); f.addRow("Son kaç yedek saklansın",self.keep); f.addRow("PostgreSQL formatı",self.pgformat); root.addLayout(f)
        row=QHBoxLayout(); row.addStretch(); save=QPushButton("Kaydet"); close=QPushButton("İptal"); save.clicked.connect(self.save); close.clicked.connect(self.reject); row.addWidget(save); row.addWidget(close); root.addLayout(row)
    def choose_folder(self):
        p=QFileDialog.getExistingDirectory(self,"Yedek Klasörü",self.folder.text() or str(Path.home()));
        if p:self.folder.setText(p)
    def save(self):
        try: t=self.time.time().toString("HH:mm")
        except Exception: t="23:30"
        APP_SETTINGS.setValue("backup/auto/enabled",self.enabled.isChecked()); APP_SETTINGS.setValue("backup/auto/frequency",self.freq.currentText()); APP_SETTINGS.setValue("backup/auto/time",t); APP_SETTINGS.setValue("backup/auto/folder",self.folder.text().strip()); APP_SETTINGS.setValue("backup/auto/keep",self.keep.value()); APP_SETTINGS.setValue("backup/auto/pg_format",self.pgformat.currentText()); APP_SETTINGS.sync(); QMessageBox.information(self,"Kaydedildi","Otomatik yedekleme ayarları kaydedildi. Değişiklikler program yeniden açıldığında ve zamanlayıcı döngüsünde uygulanır."); self.accept()


def find_pg_dump_exe():
    import shutil
    candidates=[]; found=shutil.which('pg_dump')
    if found:candidates.append(found)
    for root_dir in (Path(r'C:\Program Files\PostgreSQL'),Path(r'C:\Program Files (x86)\PostgreSQL')):
        if root_dir.exists():
            for x in root_dir.glob('*/bin/pg_dump.exe'): candidates.append(str(x))
    return candidates[0] if candidates else None


def perform_postgres_backup(target: Path, fmt: str):
    pg_dump=find_pg_dump_exe()
    if not pg_dump: raise FileNotFoundError("pg_dump.exe bulunamadı.")
    target=Path(target); target.parent.mkdir(parents=True,exist_ok=True)
    import os, tempfile, subprocess
    fd,tmp=tempfile.mkstemp(prefix='depo_stok_auto_pg_',suffix='.conf',text=True); os.close(fd); pgpass=Path(tmp)
    host=(APP_SETTINGS.value('postgres/host','localhost') or 'localhost').strip(); port=int(APP_SETTINGS.value('postgres/port',5432) or 5432); dbname=(APP_SETTINGS.value('postgres/dbname','depo_stok') or 'depo_stok').strip(); user=(APP_SETTINGS.value('postgres/user','postgres') or 'postgres').strip(); password=get_pg_password()
    try:
        pgpass.write_text(f"{host}:{port}:{dbname}:{user}:{password}\n",encoding='utf-8'); env=os.environ.copy(); env['PGPASSFILE']=str(pgpass)
        cmd=[pg_dump,'-h',host,'-p',str(port),'-U',user,'-d',dbname]
        if fmt.startswith('Custom'): cmd += ['-Fc','-f',str(target)]
        else: cmd += ['-Fp','-f',str(target),'--encoding=UTF8']
        proc=subprocess.run(cmd,env=env,capture_output=True,text=True,timeout=600)
        if proc.returncode!=0: raise RuntimeError((proc.stderr or proc.stdout or 'pg_dump hata kodu döndürdü.').strip())
        return target
    finally:
        try: pgpass.unlink(missing_ok=True)
        except Exception: pass



class StartupDatabaseRecoveryDialog(QDialog):
    """Program açılışında son kaydedilmiş veritabanına erişilemiyorsa kurtarma ekranı.
    Kullanıcı yeni SQLite yolunu veya PostgreSQL host/port/kimlik bilgilerini düzelterek
    programa devam edebilir. Ayarlar yalnızca başarılı bağlantı sonrası kalıcılaştırılır.
    """
    def __init__(self, parent=None, error_text=""):
        super().__init__(parent)
        self.setWindowTitle(f"Veritabanı Bağlantısı Kurtarma - {APP_VERSION}")
        self.setMinimumSize(820, 560)
        self.resize(900, 620)
        root = QVBoxLayout(self)
        title = QLabel("<b>VERİTABANI BAĞLANTISI KURULAMADI</b>")
        root.addWidget(title)
        info = QLabel(
            "Program son kaydedilen veritabanı ayarlarıyla bağlantı kuramadı. "
            "Aşağıdaki bilgilerden hatalı olanı düzelterek bağlantıyı test edin. "
            "Başarılı testten sonra program normal şekilde devam edecektir. "
            "Çalışma modu PostgreSQL ise SQLite yolu kullanılmaz."
        )
        info.setWordWrap(True)
        root.addWidget(info)
        err = QLabel(f"Son hata: {error_text}")
        err.setWordWrap(True)
        err.setTextInteractionFlags(Qt.TextSelectableByMouse)
        err.setStyleSheet("color:#8a1c1c;")
        root.addWidget(err)

        form = QFormLayout()
        self.mode = QComboBox(); self.mode.addItems(["SQLite", "PostgreSQL"])
        backend = (APP_SETTINGS.value("database/backend", "sqlite") or "sqlite").strip().lower()
        self.mode.setCurrentIndex(1 if backend == "postgresql" else 0)
        form.addRow("Çalışma modu", self.mode)

        self.sqlite_path = QLineEdit(str(get_configured_db_path()))
        browse = QPushButton("Gözat...")
        browse.clicked.connect(self.browse_sqlite)
        h = QHBoxLayout(); h.addWidget(self.sqlite_path, 1); h.addWidget(browse)
        w = QWidget(); w.setLayout(h)
        form.addRow("SQLite veritabanı", w)

        self.pg_host = QLineEdit(APP_SETTINGS.value("postgres/host", "localhost") or "localhost")
        self.pg_port = QLineEdit(str(APP_SETTINGS.value("postgres/port", 5432) or 5432))
        self.pg_db = QLineEdit(APP_SETTINGS.value("postgres/dbname", "depo_stok") or "depo_stok")
        self.pg_user = QLineEdit(APP_SETTINGS.value("postgres/user", "postgres") or "postgres")
        self.pg_password = QLineEdit(get_pg_password()); self.pg_password.setEchoMode(QLineEdit.Password)
        form.addRow("PostgreSQL Host", self.pg_host)
        form.addRow("PostgreSQL Port", self.pg_port)
        form.addRow("PostgreSQL Veritabanı", self.pg_db)
        form.addRow("PostgreSQL Kullanıcı", self.pg_user)
        form.addRow("PostgreSQL Şifre", self.pg_password)
        root.addLayout(form)

        self.status = QLabel("")
        self.status.setWordWrap(True)
        root.addWidget(self.status)
        root.addStretch()

        btnrow = QHBoxLayout()
        self.test_btn = QPushButton("Bağlantıyı Test Et")
        self.save_continue = QPushButton("Test Başarılı → Programa Devam Et")
        sqlite_btn = QPushButton("Yerel SQLite ile Devam Et")
        cancel_btn = QPushButton("Programdan Çık")
        self.save_continue.setDefault(True)
        self.save_continue.setEnabled(False)
        btnrow.addWidget(self.test_btn)
        btnrow.addWidget(self.save_continue)
        btnrow.addWidget(sqlite_btn)
        btnrow.addStretch()
        btnrow.addWidget(cancel_btn)
        root.addLayout(btnrow)

        self._validated = False
        self._validated_signature = None
        self.test_btn.clicked.connect(self.test_connection)
        self.save_continue.clicked.connect(self.accept_validated)
        sqlite_btn.clicked.connect(self.force_local_sqlite)
        cancel_btn.clicked.connect(self.reject)
        self.mode.currentIndexChanged.connect(self._invalidate_test)
        self.mode.currentIndexChanged.connect(self._update_mode_fields)
        self._update_mode_fields()
        for widget in (self.sqlite_path, self.pg_host, self.pg_port, self.pg_db, self.pg_user, self.pg_password):
            widget.textChanged.connect(self._invalidate_test)

    def _signature(self):
        return (
            self.mode.currentText(), self.sqlite_path.text().strip(),
            self.pg_host.text().strip(), self.pg_port.text().strip(),
            self.pg_db.text().strip(), self.pg_user.text().strip(), self.pg_password.text()
        )

    def _invalidate_test(self):
        self._validated = False
        self._validated_signature = None
        self.save_continue.setEnabled(False)
        self.status.setText("")

    def _update_mode_fields(self):
        is_pg = self.mode.currentText() == "PostgreSQL"
        self.sqlite_path.setEnabled(not is_pg)
        # Buton, SQLite yolu için anlamlıdır; PostgreSQL modunda karışıklığı önle.

    def browse_sqlite(self):
        p, _ = QFileDialog.getOpenFileName(
            self, "SQLite Veritabanını Seç", self.sqlite_path.text() or str(Path.home()),
            "SQLite DB (*.db *.sqlite *.sqlite3);;Tüm Dosyalar (*)"
        )
        if p:
            self.sqlite_path.setText(p)
            idx = self.mode.findText("SQLite")
            if idx >= 0 and self.mode.currentIndex() != idx:
                self.mode.setCurrentIndex(idx)

    def test_connection(self):
        self._invalidate_test()
        try:
            if self.mode.currentText() == "PostgreSQL":
                import psycopg2
                port = int(self.pg_port.text().strip() or "5432")
                conn = psycopg2.connect(
                    host=self.pg_host.text().strip() or "localhost",
                    port=port,
                    dbname=self.pg_db.text().strip() or "depo_stok",
                    user=self.pg_user.text().strip() or "postgres",
                    password=self.pg_password.text(),
                    connect_timeout=6,
                )
                cur = conn.cursor(); cur.execute("SELECT 1"); cur.fetchone(); cur.close(); conn.close()
                self.status.setText("✓ PostgreSQL bağlantısı başarılı.")
            else:
                raw = self.sqlite_path.text().strip()
                if not raw:
                    raise ValueError("SQLite veritabanı yolu boş olamaz.")
                path = Path(raw).expanduser()
                # Mevcut uzak/yasaklı bir klasörse doğrudan erişim hatası ver.
                path.parent.mkdir(parents=True, exist_ok=True)
                conn = sqlite3.connect(str(path), timeout=8)
                conn.execute("PRAGMA busy_timeout=8000")
                conn.execute("SELECT 1")
                conn.close()
                self.status.setText(f"✓ SQLite bağlantısı başarılı.\n{path}")
            self._validated = True
            self._validated_signature = self._signature()
            self.save_continue.setEnabled(True)
        except Exception as exc:
            self.status.setText(f"✗ Bağlantı başarısız: {exc}")
            QMessageBox.critical(self, "Bağlantı Testi Başarısız", str(exc))

    def _save_settings_for_current_selection(self):
        if self.mode.currentText() == "PostgreSQL":
            APP_SETTINGS.setValue("database/backend", "postgresql")
            APP_SETTINGS.setValue("postgres/host", self.pg_host.text().strip() or "localhost")
            APP_SETTINGS.setValue("postgres/port", int(self.pg_port.text().strip() or "5432"))
            APP_SETTINGS.setValue("postgres/dbname", self.pg_db.text().strip() or "depo_stok")
            APP_SETTINGS.setValue("postgres/user", self.pg_user.text().strip() or "postgres")
            save_pg_password(self.pg_password.text())
        else:
            path = Path(self.sqlite_path.text().strip()).expanduser()
            APP_SETTINGS.setValue("database/backend", "sqlite")
            APP_SETTINGS.setValue("database/path", str(path))
        APP_SETTINGS.sync()

    def accept_validated(self):
        if not self._validated or self._validated_signature != self._signature():
            self.test_connection()
            if not self._validated:
                return
        self._save_settings_for_current_selection()
        super().accept()

    def force_local_sqlite(self):
        # Son çalışan yerel yolu veya güvenli varsayılanı kullan.
        local = Path(r"C:\TUA_DepoStok") / "depo_stok.db" if getattr(sys, "frozen", False) else (Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "TUA Bilisim" / "DepoStok" / "depo_stok.db")
        current = Path(self.sqlite_path.text().strip()) if self.sqlite_path.text().strip() else local
        if current.as_posix().startswith("//") or str(current).startswith("\\\\"):
            current = local
        try:
            current.parent.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(str(current), timeout=8)
            conn.execute("PRAGMA busy_timeout=8000")
            conn.execute("SELECT 1")
            conn.close()
        except Exception as exc:
            QMessageBox.critical(self, "SQLite Hatası", f"Yerel SQLite'a geçilemedi:\n{exc}")
            return
        self.sqlite_path.setText(str(current))
        APP_SETTINGS.setValue("database/backend", "sqlite")
        APP_SETTINGS.setValue("database/path", str(current))
        APP_SETTINGS.sync()
        super().accept()


def create_database_with_startup_recovery():
    """Veritabanını oluşturur; bağlantı başarısızsa program kapanmak yerine kurtarma ekranı gösterir."""
    global DB_PATH
    while True:
        DB_PATH = get_configured_db_path()
        try:
            return Database(DB_PATH)
        except Exception as exc:
            dlg = StartupDatabaseRecoveryDialog(None, str(exc))
            result = dlg.exec_()
            if result != QDialog.Accepted:
                return None
            # Dialog ayarları güncelledi; döngüde DB yeniden oluşturulacak.


class FirstRunSetupWizard(QWizard):
    """Yeni kurulumlar için SQLite/PostgreSQL seçim ve bağlantı sihirbazı."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"İlk Kurulum Sihirbazı - {APP_VERSION}")
        self.setMinimumSize(760, 500)
        self.setOption(QWizard.IndependentPages, False)
        self._build_intro()
        self._build_backend()
        self._build_sqlite()
        self._build_postgres()
        self._build_finish()

    def _build_intro(self):
        p=QWizardPage(); p.setTitle("Depo & Stok Yönetim Programı – İlk Kurulum")
        lay=QVBoxLayout(p)
        info=QLabel(
            "Kurulum adımlarını tamamlamak veya mevcut veritabanı bağlantınızı doğrulamak için bu sihirbazı kullanın.\n\n"
            "• Mevcut SQLite/PostgreSQL çalışma modu ve bilinen veritabanı yolu önceden seçilir.\n"
            "• Küçük kurulumlarda SQLite kullanılabilir. Birden fazla bilgisayarın aynı anda kullanacağı sistemlerde PostgreSQL tercih edilir.\n"
            "• Mevcut verilerinize ulaşmak için daha önce kullandığınız veritabanını seçtiğinizden emin olun.\n"
            "• Yeni veritabanı gerekiyorsa program gerekli tabloları ve Yönetici hesabını oluşturur."
        ); info.setWordWrap(True); info.setMinimumHeight(180)
        lay.addWidget(info); lay.addStretch()
        self.addPage(p)

    def _build_backend(self):
        p=QWizardPage(); p.setTitle("Çalışma Veritabanı")
        lay=QVBoxLayout(p)
        self.rb_sqlite=QRadioButton("SQLite – yerel veya güvenli ağ paylaşımı")
        self.rb_pg=QRadioButton("PostgreSQL – merkezi sunucu / çok kullanıcılı kullanım")
        # Kurulum/güncelleme sihirbazı yeniden açıldığında mevcut çalışma modunu koru.
        # Böylece PostgreSQL kullanan bir kurulum, varsayılan SQLite seçimiyle yanlışlıkla değişmez.
        saved_backend = str(APP_SETTINGS.value('database/backend', 'sqlite') or 'sqlite').strip().lower()
        self.rb_pg.setChecked(saved_backend == 'postgresql')
        self.rb_sqlite.setChecked(saved_backend != 'postgresql')
        lay.addWidget(self.rb_sqlite); lay.addWidget(self.rb_pg)
        hint=QLabel("Seçiminizi daha sonra Ayarlar → Veritabanı / Ağ Kullanımı ekranından değiştirebilirsiniz.")
        hint.setWordWrap(True); lay.addWidget(hint); lay.addStretch()
        self.addPage(p)

    def _build_sqlite(self):
        p=QWizardPage(); p.setTitle("SQLite Veritabanı")
        lay=QVBoxLayout(p)
        f=QFormLayout()
        configured_sqlite_path = str(APP_SETTINGS.value('database/path', '') or '').strip()
        default_sqlite_path = (Path(r'C:\TUA_DepoStok') / 'depo_stok.db'
                               if getattr(sys, 'frozen', False)
                               else Path(__file__).resolve().with_name('depo_stok.db'))
        # Daha önce elle seçilen SQLite konumu varsa yeniden kurulumda aynen göster.
        self.sqlite_path=QLineEdit(configured_sqlite_path or str(default_sqlite_path))
        browse=QPushButton("Gözat..."); browse.clicked.connect(self._browse_sqlite)
        h=QHBoxLayout(); h.addWidget(self.sqlite_path,1); h.addWidget(browse)
        w=QWidget(); w.setLayout(h)
        f.addRow("Veritabanı yolu",w)
        lay.addLayout(f)
        self.sqlite_info=QLabel("Yeni dosya ise program gerekli tabloları ve Admin hesabını otomatik oluşturur.")
        self.sqlite_info.setWordWrap(True); lay.addWidget(self.sqlite_info); lay.addStretch()
        self.addPage(p)

    def _build_postgres(self):
        p=QWizardPage(); p.setTitle("PostgreSQL Bağlantısı")
        lay=QVBoxLayout(p)
        f=QFormLayout()
        self.pg_host=QLineEdit(APP_SETTINGS.value('postgres/host','localhost') or 'localhost')
        self.pg_port=QSpinBox(); self.pg_port.setRange(1,65535); self.pg_port.setValue(int(APP_SETTINGS.value('postgres/port',5432) or 5432))
        self.pg_db=QLineEdit(APP_SETTINGS.value('postgres/dbname','depo_stok') or 'depo_stok')
        self.pg_user=QLineEdit(APP_SETTINGS.value('postgres/user','postgres') or 'postgres')
        self.pg_pass=QLineEdit(); self.pg_pass.setEchoMode(QLineEdit.Password)
        self.pg_test=QPushButton("Bağlantıyı Test Et"); self.pg_test.clicked.connect(self._test_pg)
        self.pg_import=QPushButton("İstemci Profilini İçe Aktar..."); self.pg_import.clicked.connect(self._import_pg_profile)
        self.pg_result=QLabel("Test edilmedi."); self.pg_result.setWordWrap(True)
        f.addRow("Host",self.pg_host); f.addRow("Port",self.pg_port); f.addRow("Veritabanı",self.pg_db); f.addRow("Kullanıcı",self.pg_user); f.addRow("Şifre",self.pg_pass)
        lay.addLayout(f); lay.addWidget(self.pg_import); lay.addWidget(self.pg_test); lay.addWidget(self.pg_result); lay.addStretch()
        self.addPage(p)

    def _build_finish(self):
        p=QWizardPage(); p.setTitle("Kurulumu Tamamla")
        lay=QVBoxLayout(p)
        self.finish_info=QLabel(); self.finish_info.setWordWrap(True); lay.addWidget(self.finish_info); lay.addStretch()
        self.addPage(p)
        p.initializePage=lambda: self._update_finish()

    def _browse_sqlite(self):
        p,_=QFileDialog.getSaveFileName(self,'SQLite Veritabanı Yolu',self.sqlite_path.text() or str(Path.cwd()),'SQLite Database (*.db);;Tüm Dosyalar (*)')
        if p:
            self.sqlite_path.setText(p)
            self.rb_sqlite.setChecked(True)

    def _import_pg_profile(self):
        path,_=QFileDialog.getOpenFileName(self,"İstemci Profilini Seç",str(Path.home()),"JSON Profil (*.json);;Tüm Dosyalar (*)")
        if not path:
            return
        try:
            data=json.loads(Path(path).read_text(encoding="utf-8"))
            if int(data.get("profile_version",0)) != 1:
                raise ValueError("Desteklenmeyen profil sürümü.")
            self.pg_host.setText(str(data.get("host", "localhost")))
            self.pg_port.setValue(int(data.get("port", 5432)))
            self.pg_db.setText(str(data.get("dbname", "depo_stok")))
            self.pg_user.setText(str(data.get("user", "postgres")))
            ssl=str(data.get("sslmode", "prefer"))
            self.pg_result.setText(f"İstemci profili yüklendi: {self.pg_host.text()}:{self.pg_port.value()}/{self.pg_db.text()}\nŞifre güvenlik nedeniyle profil dosyasından alınmaz.")
        except Exception as exc:
            QMessageBox.critical(self,"Profil Hatası",f"Profil yüklenemedi:\n{exc}")

    def _test_pg(self):
        try:
            import psycopg2
            conn=psycopg2.connect(host=self.pg_host.text().strip() or 'localhost', port=self.pg_port.value(), dbname=self.pg_db.text().strip() or 'depo_stok', user=self.pg_user.text().strip() or 'postgres', password=self.pg_pass.text(), connect_timeout=5)
            conn.close()
            self.pg_result.setText("✓ PostgreSQL bağlantısı başarılı.")
        except Exception as exc:
            self.pg_result.setText(f"✗ PostgreSQL bağlantısı başarısız: {exc}")

    def _update_finish(self):
        if self.rb_sqlite.isChecked():
            self.finish_info.setText(
                f"SQLite seçildi.\n\nVeritabanı:\n{self.sqlite_path.text().strip()}\n\n"
                "İleri tamamlandığında bu veritabanı açılacak/oluşturulacak ve aktif kullanıcı yoksa Admin / 1234 hesabı hazırlanacaktır."
            )
        else:
            self.finish_info.setText(
                f"PostgreSQL seçildi.\n\nSunucu: {self.pg_host.text().strip()}:{self.pg_port.value()}\n"
                f"Veritabanı: {self.pg_db.text().strip()}\nKullanıcı: {self.pg_user.text().strip()}\n\n"
                "Kurulumun tamamlanması için PostgreSQL veritabanının erişilebilir olması gerekir."
            )

    def accept(self):
        if self.rb_sqlite.isChecked():
            p=Path(self.sqlite_path.text().strip()).expanduser()
            if not p:
                QMessageBox.warning(self,'Eksik Bilgi','SQLite veritabanı yolu seçin.'); return
            p.parent.mkdir(parents=True,exist_ok=True)
            APP_SETTINGS.setValue('database/backend','sqlite')
            APP_SETTINGS.setValue('database/path',str(p))
        else:
            if not self.pg_host.text().strip() or not self.pg_db.text().strip() or not self.pg_user.text().strip():
                QMessageBox.warning(self,'Eksik Bilgi','PostgreSQL Host, Veritabanı ve Kullanıcı alanları zorunludur.'); return
            if self.pg_pass.text() == '':
                if not (APP_SETTINGS.value('postgres/password_enc','') or APP_SETTINGS.value('postgres/password','')):
                    QMessageBox.warning(self,'Eksik Bilgi','PostgreSQL şifresini girin.'); return
            APP_SETTINGS.setValue('database/backend','postgresql')
            APP_SETTINGS.setValue('postgres/host',self.pg_host.text().strip())
            APP_SETTINGS.setValue('postgres/port',self.pg_port.value())
            APP_SETTINGS.setValue('postgres/dbname',self.pg_db.text().strip())
            APP_SETTINGS.setValue('postgres/user',self.pg_user.text().strip())
            if self.pg_pass.text(): save_pg_password(self.pg_pass.text())
        APP_SETTINGS.setValue('setup/completed',True)
        APP_SETTINGS.setValue('setup/version',APP_VERSION)
        APP_SETTINGS.setValue('setup/first_run_schema','1')
        APP_SETTINGS.sync()
        super().accept()


class LoginDialog(QDialog):
    def __init__(self, db):
        super().__init__(None)
        self.db = db
        self.user = None
        self.setWindowTitle("Depo & Stok Yönetim Programı - Kullanıcı Girişi")
        self.setFixedSize(430, 300)
        root = QVBoxLayout(self)
        title = QLabel("DEPO & STOK YÖNETİM PROGRAMI")
        title.setObjectName("dialogTitle")
        title.setAlignment(Qt.AlignCenter)
        root.addWidget(title)

        box = QGroupBox("Kullanıcı Girişi")
        f = QFormLayout(box)
        self.username = QLineEdit()
        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.Password)
        self.username.setPlaceholderText("Kullanıcı adınız")
        self.password.setPlaceholderText("Şifreniz")
        f.addRow("Kullanıcı Adı", self.username)
        f.addRow("Şifre", self.password)
        root.addWidget(box)

        self.info = QLabel("Aktif kullanıcı adı ve şifrenizi girin.")
        self.info.setWordWrap(True)
        root.addWidget(self.info)

        btns = QHBoxLayout()
        btns.addStretch()
        login = QPushButton("Giriş Yap")
        exit_btn = QPushButton("Çıkış")
        login.setDefault(True)
        btns.addWidget(login)
        btns.addWidget(exit_btn)
        root.addLayout(btns)

        login.clicked.connect(self.try_login)
        exit_btn.clicked.connect(self.reject)
        self.password.returnPressed.connect(self.try_login)
        self.username.setFocus()

    def try_login(self):
        username = self.username.text().strip()
        password = self.password.text()
        if not username or not password:
            self.info.setText("Kullanıcı adı ve şifre zorunludur.")
            return
        row = self.db.conn.execute("""
            SELECT k.*, r.ad AS rol_adi
            FROM kullanicilar k
            LEFT JOIN roller r ON r.id = k.rol_id
            WHERE k.kullanici_adi = ? AND k.aktif = 1
        """, (username,)).fetchone()
        if not row or row["sifre_hash"] != self.db.hash_password(password):
            self.db.log_session(None, username, "Giriş Başarısız", "Hatalı kullanıcı adı veya şifre")
            self.info.setText("Kullanıcı adı veya şifre hatalı.")
            self.password.clear()
            self.password.setFocus()
            return
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.db.conn.execute("UPDATE kullanicilar SET son_giris=? WHERE id=?", (now, row["id"]))
        self.db.conn.commit()
        self.db.log_session(row["id"], row["kullanici_adi"], "Giriş Başarılı", "Kullanıcı oturumu açtı")
        self.user = {
            "id": row["id"],
            "kullanici_adi": row["kullanici_adi"],
            "ad_soyad": row["ad_soyad"] or row["kullanici_adi"],
            "rol_id": row["rol_id"],
            "rol_adi": row["rol_adi"] or "",
        }
        self.accept()



class DatabaseDiagnosticsDialog(QDialog):
    """Veritabanı/ağ kullanımının sağlık kontrolü. Mevcut SQLite yapısını değiştirmez."""
    def __init__(self, parent, db):
        super().__init__(parent)
        self.db = db
        self.setWindowTitle(f"Veritabanı Bağlantı ve Sağlık Kontrolü - {APP_VERSION}")
        self.resize(820, 520)
        root = QVBoxLayout(self)
        title = QLabel("VERİTABANI / AĞ KULLANIMI SAĞLIK KONTROLÜ")
        title.setObjectName("dialogTitle")
        root.addWidget(title)
        info = QGroupBox("Bağlantı Bilgileri")
        form = QFormLayout(info)
        self.path_label = QLabel(str(db.path))
        self.path_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.mode_label = QLabel("Ağ paylaşımı / UNC" if str(db.path).startswith("\\\\") else "Yerel disk")
        self.size_label = QLabel("-")
        self.journal_label = QLabel("-")
        self.foreign_label = QLabel("-")
        self.busy_label = QLabel("-")
        form.addRow("Veritabanı", self.path_label)
        form.addRow("Kullanım modu", self.mode_label)
        form.addRow("Dosya boyutu", self.size_label)
        form.addRow("Journal modu", self.journal_label)
        form.addRow("Foreign Keys", self.foreign_label)
        form.addRow("Busy Timeout", self.busy_label)
        root.addWidget(info)

        self.table = QTableWidget(0, 3)
        self.table.setHorizontalHeaderLabels(["Kontrol", "Durum", "Açıklama"])
        configure_resizable_table(self.table, "database_diagnostics", [220, 120, 420])
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        root.addWidget(self.table, 1)

        self.result = QLabel()
        self.result.setWordWrap(True)
        root.addWidget(self.result)
        btns = QHBoxLayout()
        self.test_btn = QPushButton("Kontrolleri Yenile")
        self.integrity_btn = QPushButton("SQLite Bütünlük Testi")
        close_btn = QPushButton("Kapat")
        btns.addWidget(self.test_btn)
        btns.addWidget(self.integrity_btn)
        btns.addStretch()
        btns.addWidget(close_btn)
        root.addLayout(btns)
        self.test_btn.clicked.connect(self.run_checks)
        self.integrity_btn.clicked.connect(self.integrity_check)
        close_btn.clicked.connect(self.accept)
        self.run_checks()

    def add_result(self, name, ok, detail):
        r = self.table.rowCount(); self.table.insertRow(r)
        self.table.setItem(r, 0, QTableWidgetItem(name))
        self.table.setItem(r, 1, QTableWidgetItem("BAŞARILI" if ok else "DİKKAT"))
        self.table.setItem(r, 2, QTableWidgetItem(detail))

    def run_checks(self):
        self.table.setRowCount(0)
        if getattr(self.db, "backend", "sqlite") == "postgresql":
            try:
                self.path_label.setText(f"PostgreSQL: {APP_SETTINGS.value('postgres/host','localhost')}:{APP_SETTINGS.value('postgres/port',5432)}/{APP_SETTINGS.value('postgres/dbname','depo_stok')}")
                self.mode_label.setText("PostgreSQL sunucu modu")
                self.size_label.setText("Sunucu veritabanı")
                self.journal_label.setText("PostgreSQL")
                self.foreign_label.setText("Aktif")
                self.busy_label.setText("Sunucu tarafı")
                self.db.conn.execute("SELECT 1").fetchone()
                self.add_result("PostgreSQL bağlantısı", True, "SELECT 1 başarıyla çalıştı.")
                self.add_result("Sunucu", True, str(APP_SETTINGS.value('postgres/host','localhost')))
                self.add_result("Port", True, str(APP_SETTINGS.value('postgres/port',5432)))
                self.add_result("Veritabanı", True, str(APP_SETTINGS.value('postgres/dbname','depo_stok')))
                self.result.setText("PostgreSQL sunucu bağlantısı sağlıklı.")
            except Exception as exc:
                self.add_result("PostgreSQL bağlantısı", False, str(exc)); self.result.setText(f"Kontrol sırasında hata: {exc}")
            return
        try:
            exists = self.db.path.exists()
            self.size_label.setText(f"{self.db.path.stat().st_size:,} bayt" if exists else "Bulunamadı")
            self.add_result("Dosya erişimi", exists, "Veritabanı dosyasına erişilebiliyor." if exists else "Dosya mevcut değil.")
            rw = False
            try:
                self.db.conn.execute("SELECT 1").fetchone()
                self.db.conn.commit()
                rw = True
            except Exception as exc:
                self.add_result("Bağlantı", False, str(exc))
            if rw:
                self.add_result("SQLite bağlantısı", True, "SELECT 1 başarıyla çalıştı.")
            jm = self.db.conn.execute("PRAGMA journal_mode").fetchone()[0]
            fk = self.db.conn.execute("PRAGMA foreign_keys").fetchone()[0]
            bt = self.db.conn.execute("PRAGMA busy_timeout").fetchone()[0]
            self.journal_label.setText(str(jm)); self.foreign_label.setText("Açık" if fk else "Kapalı"); self.busy_label.setText(f"{bt} ms")
            self.add_result("Foreign key", bool(fk), "İlişkisel bütünlük koruması etkin." if fk else "Foreign key kontrolü kapalı!")
            self.add_result("Busy timeout", int(bt or 0) > 0, f"SQLite kilitlenmelerinde {bt} ms bekleme uygulanıyor.")
            unc = str(self.db.path).startswith("\\\\")
            self.add_result("Ağ yolu", True, "UNC ağ yolu algılandı." if unc else "Yerel yol kullanılıyor.")
            self.result.setText("Kontroller tamamlandı. Ağ üzerinde ortak SQLite kullanımında düzenli yedek alınması ve aynı veritabanı dosyasının çok yüksek eşzamanlı işlem için kullanılmaması önerilir.")
        except Exception as exc:
            self.result.setText(f"Kontrol sırasında hata: {exc}")

    def integrity_check(self):
        if getattr(self.db, "backend", "sqlite") == "postgresql":
            try:
                self.db.conn.execute("SELECT 1").fetchone()
                QMessageBox.information(self, "Bütünlük Testi", "PostgreSQL bağlantı ve sorgu testi başarılı.")
            except Exception as exc:
                QMessageBox.critical(self, "Bütünlük Testi", str(exc))
            return
        try:
            row = self.db.conn.execute("PRAGMA integrity_check").fetchone()
            ok = bool(row and str(row[0]).lower() == "ok")
            self.result.setText("SQLite bütünlük testi: BAŞARILI (ok)." if ok else f"SQLite bütünlük testi sonucu: {row[0] if row else 'sonuç yok'}")
            QMessageBox.information(self, "Bütünlük Testi", self.result.text()) if ok else QMessageBox.warning(self, "Bütünlük Testi", self.result.text())
        except Exception as exc:
            QMessageBox.critical(self, "Bütünlük Testi", f"Test yapılamadı:\n{exc}")



class PostgreSQLMigrationDialog(QDialog):
    """SQLite verisini PostgreSQL'e aktarmak için güvenli, tek seferlik yardımcı ekran."""
    def __init__(self, parent, db):
        super().__init__(parent); self.db=db; self.setWindowTitle(f"PostgreSQL Veri Aktarımı - {APP_VERSION}"); self.resize(760,620)
        root=QVBoxLayout(self)
        root.addWidget(QLabel('<b>SQLite → PostgreSQL Veri Aktarımı</b>'))
        root.addWidget(QLabel('Bu araç mevcut depo_stok.db verisini PostgreSQL sunucusuna kopyalar. Kaynak SQLite veritabanı değiştirilmez.'))
        form=QFormLayout()
        self.host=QLineEdit('localhost'); self.port=QLineEdit('5432'); self.dbname=QLineEdit('depo_stok'); self.user=QLineEdit('postgres'); self.password=QLineEdit(); self.password.setEchoMode(QLineEdit.Password)
        self.schema=QLineEdit('public')
        for w in (self.port,): w.setValidator(QIntValidator(1,65535,self))
        form.addRow('Sunucu (Host):',self.host); form.addRow('Port:',self.port); form.addRow('Veritabanı:',self.dbname); form.addRow('Kullanıcı:',self.user); form.addRow('Şifre:',self.password); form.addRow('Şema:',self.schema)
        root.addLayout(form)
        self.test_btn=QPushButton('Bağlantıyı Test Et'); self.test_btn.clicked.connect(self.test_connection); root.addWidget(self.test_btn)
        self.drop=QCheckBox('Hedef veritabanındaki mevcut program tablolarını aktarım öncesi sil ve yeniden oluştur')
        self.backup=QCheckBox('Aktarım öncesi yerel SQLite yedeği oluştur'); self.backup.setChecked(True)
        self.drop.setChecked(False)
        root.addWidget(self.drop); root.addWidget(self.backup)
        self.log=QPlainTextEdit(); self.log.setReadOnly(True); root.addWidget(self.log,1)
        self.progress=QProgressBar(); root.addWidget(self.progress)
        row=QHBoxLayout(); self.start_btn=QPushButton('Verileri Aktar'); self.start_btn.clicked.connect(self.migrate); close=QPushButton('Kapat'); close.clicked.connect(self.reject); row.addWidget(self.start_btn); row.addStretch(); row.addWidget(close); root.addLayout(row)
    def dsn(self):
        return dict(host=self.host.text().strip(),port=int(self.port.text() or 5432),dbname=self.dbname.text().strip(),user=self.user.text().strip(),password=self.password.text())
    def test_connection(self):
        try:
            import psycopg2
            conn=psycopg2.connect(connect_timeout=8,**self.dsn()); cur=conn.cursor(); cur.execute('SELECT version()'); v=cur.fetchone()[0]; conn.close()
            self.log.appendPlainText('✓ PostgreSQL bağlantısı başarılı.'); self.log.appendPlainText(v)
        except Exception as exc: QMessageBox.critical(self,'Bağlantı Hatası',str(exc))
    def sqlite_tables(self):
        return [r[0] for r in self.db.conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")]
    def topological_tables(self, tables):
        deps={t:set(r[2] for r in self.db.conn.execute(f'PRAGMA foreign_key_list("{t}")') if r[2] in tables) for t in tables}
        ordered=[]
        while deps:
            ready=[t for t,v in deps.items() if not v]
            if not ready: ordered.extend(sorted(deps)); break
            for t in sorted(ready): ordered.append(t); deps.pop(t)
            for v in deps.values(): v.difference_update(ready)
        return ordered
    @staticmethod
    def pg_type(decl, pk=False, autoinc=False):
        d=(decl or '').upper()
        if autoinc and pk and 'INTEGER' in d: return 'SERIAL'
        if 'INT' in d: return 'INTEGER'
        if 'CHAR' in d or 'CLOB' in d or 'TEXT' in d: return 'TEXT'
        if 'REAL' in d or 'FLOA' in d or 'DOUB' in d: return 'DOUBLE PRECISION'
        if 'BLOB' in d: return 'BYTEA'
        if 'BOOL' in d: return 'BOOLEAN'
        if 'DATE' in d and 'TIME' not in d: return 'DATE'
        if 'TIME' in d: return 'TIMESTAMP'
        if 'NUM' in d or 'DEC' in d: return 'NUMERIC'
        return 'TEXT'
    def quote_ident(self,x): return '"'+x.replace('"','""')+'"'
    def create_table_sql(self, table):
        cols=list(self.db.conn.execute(f'PRAGMA table_info("{table}")'))
        parts=[]; pkcols=[]
        autoinc=False
        for c in cols:
            cid,name,typ,notnull,default,pk=c
            if pk: pkcols.append(name)
            parts.append(f'{self.quote_ident(name)} {self.pg_type(typ, bool(pk), True)}'+(' NOT NULL' if notnull and not pk else '')+ (f' DEFAULT {default}' if default is not None else ''))
        if pkcols: parts.append('PRIMARY KEY ('+','.join(self.quote_ident(x) for x in pkcols)+')')
        return f'CREATE TABLE {self.quote_ident(table)} ('+', '.join(parts)+')'
    def unique_indexes(self, table):
        out=[]
        for r in self.db.conn.execute(f'PRAGMA index_list("{table}")'):
            # seq,name,unique,origin,partial
            name=r[1]; unique=r[2]; origin=r[3] if len(r)>3 else ''
            if not unique: continue
            cols=[x[2] for x in self.db.conn.execute(f'PRAGMA index_info("{name}")')]
            if cols: out.append((name,cols))
        return out
    def nonunique_indexes(self, table):
        out=[]
        for r in self.db.conn.execute(f'PRAGMA index_list("{table}")'):
            name=r[1]; unique=r[2]
            if unique: continue
            cols=[x[2] for x in self.db.conn.execute(f'PRAGMA index_info("{name}")')]
            if cols: out.append((name,cols))
        return out
    def foreign_keys(self, tables):
        f=[]
        for t in tables:
            for r in self.db.conn.execute(f'PRAGMA foreign_key_list("{t}")'):
                f.append((t,r[3],r[2],r[4],r[6]))
        return f
    def backup_sqlite(self):
        folder=self.db.path.parent/'yedekler'; folder.mkdir(exist_ok=True); target=folder/f"depo_stok_pre_pg_{datetime.now():%Y%m%d_%H%M%S}.db"; dest=sqlite3.connect(str(target)); self.db.conn.backup(dest); dest.close(); self.log.appendPlainText(f'✓ SQLite yedeği: {target}')
    def migrate(self):
        if QMessageBox.question(self,'Onay','PostgreSQL veritabanına mevcut tüm tablolar ve veriler aktarılacak. Devam edilsin mi?',QMessageBox.Yes|QMessageBox.No,QMessageBox.No)!=QMessageBox.Yes:return
        try:
            import psycopg2
        except ImportError:
            QMessageBox.critical(self,'Eksik Paket','psycopg2-binary kurulu değil.\n\n.venv içinde şu komutu çalıştırın:\npython -m pip install psycopg2-binary'); return
        try:
            if self.backup.isChecked(): self.backup_sqlite()
            conn=psycopg2.connect(connect_timeout=10,**self.dsn()); conn.autocommit=False; cur=conn.cursor(); schema=self.schema.text().strip() or 'public'
            cur.execute('CREATE SCHEMA IF NOT EXISTS '+self.quote_ident(schema))
            tables=self.sqlite_tables(); self.progress.setRange(0,max(1,len(tables))); self.progress.setValue(0)
            # Hedef program tablolarını isteğe bağlı temizle.
            if self.drop.isChecked():
                for t in reversed(self.topological_tables(tables)): cur.execute(f'DROP TABLE IF EXISTS {self.quote_ident(schema)}.{self.quote_ident(t)} CASCADE')
            for i,t in enumerate(self.topological_tables(tables),1):
                cur.execute(f'DROP TABLE IF EXISTS {self.quote_ident(schema)}.{self.quote_ident(t)} CASCADE') if self.drop.isChecked() else None
                cur.execute(f'CREATE TABLE IF NOT EXISTS {self.quote_ident(schema)}.{self.quote_ident(t)} ('+self.create_table_sql(t).split('(',1)[1].rsplit(')',1)[0]+')')
                cols=list(self.db.conn.execute(f'PRAGMA table_info("{t}")')); names=[c[1] for c in cols]
                if names:
                    ph=','.join(['%s']*len(names)); ins=f'INSERT INTO {self.quote_ident(schema)}.{self.quote_ident(t)} ('+','.join(self.quote_ident(n) for n in names)+f') VALUES ({ph}) ON CONFLICT DO NOTHING'
                    rows=self.db.conn.execute(f'SELECT {",".join(self.quote_ident(n) for n in names)} FROM {self.quote_ident(t)}').fetchall()
                    for row in rows: cur.execute(ins,tuple(row))
                for uname,ucols in self.unique_indexes(t):
                    # PK auto-indexleri PostgreSQL'de zaten karşılanır.
                    if set(ucols)==set(c[1] for c in cols if c[5]): continue
                    ixname='ux_'+re.sub(r'[^A-Za-z0-9_]+','_',t+'_'+uname)[:55]
                    cur.execute(f'CREATE UNIQUE INDEX IF NOT EXISTS {self.quote_ident(ixname)} ON {self.quote_ident(schema)}.{self.quote_ident(t)} ('+','.join(self.quote_ident(x) for x in ucols)+')')
                for nidx,icols in self.nonunique_indexes(t):
                    ixname='ix_'+re.sub(r'[^A-Za-z0-9_]+','_',t+'_'+nidx)[:55]
                    cur.execute(f'CREATE INDEX IF NOT EXISTS {self.quote_ident(ixname)} ON {self.quote_ident(schema)}.{self.quote_ident(t)} ('+','.join(self.quote_ident(x) for x in icols)+')')
                self.log.appendPlainText(f'✓ {t}: {len(rows)} kayıt aktarıldı'); self.progress.setValue(i); QApplication.processEvents()
            # FK'leri en sonda ekle
            for t,src,ref,rc,rule in self.foreign_keys(tables):
                cname=re.sub(r'[^A-Za-z0-9_]+','_',f'fk_{t}_{src}_{ref}_{rc}')[:60]
                try: cur.execute(f'ALTER TABLE {self.quote_ident(schema)}.{self.quote_ident(t)} ADD CONSTRAINT {self.quote_ident(cname)} FOREIGN KEY ({self.quote_ident(src)}) REFERENCES {self.quote_ident(schema)}.{self.quote_ident(ref)} ({self.quote_ident(rc)})')
                except Exception as exc: self.log.appendPlainText(f'! FK atlandı ({t}.{src}->{ref}.{rc}): {exc}')
            conn.commit(); cur.close(); conn.close(); self.progress.setValue(len(tables)); self.log.appendPlainText('✓ AKTARIM TAMAMLANDI.'); QMessageBox.information(self,'Aktarım Tamamlandı','SQLite verileriniz PostgreSQL veritabanına aktarıldı.\nKaynak SQLite veritabanı değiştirilmedi.')
        except Exception as exc:
            try: conn.rollback(); conn.close()
            except Exception: pass
            QMessageBox.critical(self,'Aktarım Hatası',str(exc))

class DatabaseSettingsDialog(QDialog):
    def __init__(self, parent, current_path):
        super().__init__(parent)
        self.setWindowTitle(f"Veritabanı / Ağ Kullanımı - {APP_VERSION}")
        self.resize(900, 700)
        self.setMinimumSize(900, 660)
        self.setMaximumWidth(900)
        root = QVBoxLayout(self)
        info = QLabel(
            "SQLite seçildiğinde SQLite veritabanı yolu kullanılır. PostgreSQL seçildiğinde SQLite yolu kullanılmaz; "
            "program Host + Port + Veritabanı bilgileriyle PostgreSQL sunucusuna bağlanır. "
            "Aşağıdaki 'PostgreSQL Veritabanı / Paylaşım Yolu' alanı merkezi veri konumunu kullanıcıya göstermek ve dağıtımda standartlaştırmak içindir; "
            "PostgreSQL bağlantısı bu klasör yolundan değil, Host/Port/Veritabanı bilgilerinden yapılır."
        )
        info.setWordWrap(True)
        root.addWidget(info)

        form = QFormLayout()
        self.mode = QComboBox(); self.mode.addItems(["SQLite", "PostgreSQL"])
        backend = (APP_SETTINGS.value("database/backend", "sqlite") or "sqlite").lower()
        self.mode.setCurrentIndex(1 if backend == "postgresql" else 0)
        form.addRow("Çalışma modu", self.mode)

        self.path_edit = QLineEdit(str(current_path))
        self.browse_btn = QPushButton("Gözat...")
        self.sqlite_test_btn = QPushButton("Bağlantıyı Test Et")
        row = QHBoxLayout(); row.addWidget(self.path_edit, 1); row.addWidget(self.browse_btn); row.addWidget(self.sqlite_test_btn)
        w = QWidget(); w.setLayout(row)
        form.addRow("SQLite veritabanı yolu", w)

        self.pg_host = QLineEdit(APP_SETTINGS.value("postgres/host", "localhost") or "localhost")
        self.pg_port = QLineEdit(str(APP_SETTINGS.value("postgres/port", 5432) or 5432))
        self.pg_db = QLineEdit(APP_SETTINGS.value("postgres/dbname", "depo_stok") or "depo_stok")
        self.pg_user = QLineEdit(APP_SETTINGS.value("postgres/user", "postgres") or "postgres")
        self.pg_password = QLineEdit(get_pg_password()); self.pg_password.setEchoMode(QLineEdit.Password)
        form.addRow("PostgreSQL Host", self.pg_host)
        form.addRow("PostgreSQL Port", self.pg_port)
        form.addRow("PostgreSQL Veritabanı", self.pg_db)
        form.addRow("PostgreSQL Kullanıcı", self.pg_user)
        form.addRow("PostgreSQL Şifre", self.pg_password)

        self.pg_target = QLineEdit(); self.pg_target.setReadOnly(True)
        self.pg_target.setToolTip("Programın PostgreSQL modunda bağlanacağı sunucu/veritabanı hedefi.")

        # PostgreSQL SQLite gibi tek bir .db dosyası kullanmaz. Kullanıcının
        # merkezi veri/paylaşım konumunu ayrıca gösterebilmesi için düzenlenebilir bilgi alanı.
        self.pg_share_path = QLineEdit(APP_SETTINGS.value("postgres/share_path", "") or "")
        self.pg_share_path.setPlaceholderText(r"Örn: C:\TUA_DepoStok veya \\SUNUCU\TUA_DepoStok\database")
        self.pg_share_browse = QPushButton("Klasör Seç...")
        self.pg_share_from_server = QPushButton("Sunucu yolunu doldur")
        share_row = QHBoxLayout(); share_row.addWidget(self.pg_share_path, 1); share_row.addWidget(self.pg_share_browse); share_row.addWidget(self.pg_share_from_server)
        share_w = QWidget(); share_w.setLayout(share_row)
        form.addRow("PostgreSQL Veritabanı / Paylaşım Yolu", share_w)

        self.pg_server_path = QLineEdit()
        self.pg_server_path.setReadOnly(True)
        self.pg_server_path.setToolTip("PostgreSQL sunucusunun data_directory değeri; sunucunun kendi dosya sistem yoludur.")
        self.pg_db_physical_path = QLineEdit()
        self.pg_db_physical_path.setReadOnly(True)
        self.pg_db_physical_path.setToolTip("Varsayılan tablespace kullanılıyorsa veritabanının fiziksel depolama konumu data_directory\\base\\OID altında bulunur.")
        self.pg_active_source = QLineEdit()
        self.pg_active_source.setReadOnly(True)
        self.pg_active_source.setToolTip("Programın gerçekten kullandığı PostgreSQL veritabanı: Host + Port + Veritabanı + Şema.")
        form.addRow("PostgreSQL Bağlantı Hedefi", self.pg_target)
        form.addRow("Aktif PostgreSQL Veri Kaynağı", self.pg_active_source)
        form.addRow("PostgreSQL Sunucu Veri Yolu", self.pg_server_path)
        form.addRow("PostgreSQL Veritabanı Fiziksel Yolu", self.pg_db_physical_path)
        root.addLayout(form)

        self.path_note = QLabel(
            "Not: PostgreSQL Veritabanı / Paylaşım Yolu alanı bir referans/paylaşım konumudur; PostgreSQL bu klasördeki bir .db dosyasını kullanmaz. "
            "Gerçek veri kaynağı aşağıdaki 'Aktif PostgreSQL Veri Kaynağı' ve 'PostgreSQL Sunucu Veri Yolu' alanlarında gösterilir. "
            "SQLite kullanmak istiyorsanız Çalışma modu olarak SQLite seçilmelidir."
        )
        self.path_note.setWordWrap(True)
        root.addWidget(self.path_note)

        self.result = QLabel("")
        self.result.setWordWrap(True)
        self.result.setMinimumHeight(70)
        self.result.setMaximumHeight(125)
        root.addWidget(self.result)

        action_row = QHBoxLayout()
        self.test_btn = QPushButton("PostgreSQL Bağlantısını Test Et")
        self.save_continue_btn = QPushButton("Test Başarılı → Programa Devam Et")
        self.local_sqlite_btn = QPushButton("Yerel SQLite ile Devam Et")
        self.save_continue_btn.setDefault(True)
        self.save_continue_btn.setEnabled(False)
        action_row.addWidget(self.test_btn)
        action_row.addWidget(self.save_continue_btn)
        action_row.addWidget(self.local_sqlite_btn)
        action_row.addStretch()
        root.addLayout(action_row)

        buttons = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.save)
        buttons.rejected.connect(self.reject)
        root.addWidget(buttons)

        self._validated = False
        self._validated_signature = None

        self.browse_btn.clicked.connect(self.choose)
        self.sqlite_test_btn.clicked.connect(self.test_connection)
        self.test_btn.clicked.connect(self.test_connection)
        self.save_continue_btn.clicked.connect(self.accept_validated)
        self.local_sqlite_btn.clicked.connect(self.force_local_sqlite)
        self.pg_share_browse.clicked.connect(self.choose_pg_share_path)
        self.pg_share_from_server.clicked.connect(self.copy_server_path_to_share)
        self.mode.currentIndexChanged.connect(self._update_mode_fields)
        for widget in (self.path_edit, self.pg_host, self.pg_port, self.pg_db, self.pg_user, self.pg_password):
            widget.textChanged.connect(self._invalidate_test)
        for widget in (self.pg_host, self.pg_port, self.pg_db):
            widget.textChanged.connect(lambda _=None: self._update_pg_target())
        self._update_mode_fields()

    def _signature(self):
        return (
            self.mode.currentText(), self.path_edit.text().strip(),
            self.pg_host.text().strip(), self.pg_port.text().strip(),
            self.pg_db.text().strip(), self.pg_user.text().strip(), self.pg_password.text()
        )

    def _invalidate_test(self):
        self._validated = False
        self._validated_signature = None
        self.save_continue_btn.setEnabled(False)

    def _update_pg_target(self):
        host = self.pg_host.text().strip() or "localhost"
        try:
            port = int(self.pg_port.text().strip() or 5432)
        except ValueError:
            port = 5432
        db = self.pg_db.text().strip() or "depo_stok"
        target = f"postgresql://{host}:{port}/{db}  |  Şema: public"
        self.pg_target.setText(target)
        self.pg_active_source.setText(f"Sunucu: {host}:{port} | Veritabanı: {db} | Şema: public")

    def _update_mode_fields(self):
        is_pg = self.mode.currentText() == "PostgreSQL"
        self.path_edit.setEnabled(not is_pg)
        self.browse_btn.setEnabled(not is_pg)
        self.sqlite_test_btn.setEnabled(not is_pg)
        self.pg_host.setEnabled(is_pg)
        self.pg_port.setEnabled(is_pg)
        self.pg_db.setEnabled(is_pg)
        self.pg_user.setEnabled(is_pg)
        self.pg_password.setEnabled(is_pg)
        self.pg_target.setEnabled(is_pg)
        self.pg_active_source.setEnabled(is_pg)
        self.pg_share_path.setEnabled(is_pg)
        self.pg_share_browse.setEnabled(is_pg)
        self.pg_share_from_server.setEnabled(is_pg and bool(self.pg_server_path.text().strip()))
        self.pg_server_path.setEnabled(is_pg)
        self.pg_db_physical_path.setEnabled(is_pg)
        self.test_btn.setText("PostgreSQL Bağlantısını Test Et" if is_pg else "Bağlantıyı Test Et")
        self._update_pg_target()
        if is_pg:
            self.result.setText("PostgreSQL çalışma modu seçili. Bağlantı Host + Port + Veritabanı bilgileriyle yapılır.")
        else:
            self.result.setText("SQLite çalışma modu seçili. Yalnızca SQLite yolu kullanılacaktır.")

    def choose(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "SQLite Veritabanını Seç", self.path_edit.text() or str(Path.home()),
            "SQLite DB (*.db *.sqlite *.sqlite3);;Tüm Dosyalar (*)"
        )
        if path:
            self.path_edit.setText(path)
            idx = self.mode.findText("SQLite")
            if idx >= 0 and self.mode.currentIndex() != idx:
                self.mode.setCurrentIndex(idx)

    def choose_pg_share_path(self):
        start = self.pg_share_path.text().strip() or self.pg_server_path.text().strip() or str(Path.home())
        p = QFileDialog.getExistingDirectory(self, "PostgreSQL Veritabanı / Paylaşım Klasörünü Seç", start)
        if p:
            self.pg_share_path.setText(p)

    def copy_server_path_to_share(self):
        server = self.pg_server_path.text().strip()
        if server and not server.startswith("Sunucu ") and "okunamadı" not in server.lower():
            self.pg_share_path.setText(server)

    def test_connection(self):
        self._invalidate_test()
        if self.mode.currentText() == "PostgreSQL":
            conn = None
            try:
                import psycopg2
                host = self.pg_host.text().strip() or "localhost"
                port = int(self.pg_port.text().strip() or 5432)
                dbname = self.pg_db.text().strip() or "depo_stok"
                user = self.pg_user.text().strip() or "postgres"
                conn = psycopg2.connect(host=host, port=port, dbname=dbname, user=user,
                                        password=self.pg_password.text(), connect_timeout=8)
                cur = conn.cursor()
                cur.execute("SELECT current_database(), current_user, current_schema(), (SELECT oid FROM pg_database WHERE datname = current_database())")
                db_name, current_user, schema, db_oid = cur.fetchone()
                schema = schema or "public"
                server_path = ""
                try:
                    cur.execute("SHOW data_directory")
                    server_path = cur.fetchone()[0] or ""
                except Exception:
                    server_path = ""
                physical = ""
                if server_path and db_oid is not None:
                    try:
                        cur.execute("SELECT COALESCE(pg_tablespace_location(dattablespace), ''), dattablespace FROM pg_database WHERE datname = current_database()")
                        ts_loc, _ts_oid = cur.fetchone()
                        physical = str(Path(ts_loc) / str(db_oid)) if ts_loc else str(Path(server_path) / "base" / str(db_oid))
                    except Exception:
                        physical = ""
                cur.close(); conn.close(); conn = None

                self.pg_target.setText(f"postgresql://{host}:{port}/{db_name}  |  Şema: {schema}")
                self.pg_active_source.setText(f"Sunucu: {host}:{port} | Veritabanı: {db_name} | Şema: {schema} | DB OID: {db_oid}")
                self.pg_server_path.setText(server_path if server_path else "Sunucu veri yolu okunamadı / yetki yok")
                self.pg_db_physical_path.setText(physical if physical else "Veritabanı fiziksel yolu okunamadı")
                self.pg_share_from_server.setEnabled(True)
                self.result.setText(
                    "✓ PostgreSQL bağlantısı başarılı.\n"
                    f"Hedef: {self.pg_target.text()}\n"
                    f"PostgreSQL Veritabanı / Paylaşım Yolu: {self.pg_share_path.text().strip() or 'Belirtilmedi'}\n"
                    f"Sunucu veri yolu: {self.pg_server_path.text()}"
                )
                self._validated = True
                self._validated_signature = self._signature()
                self.save_continue_btn.setEnabled(True)
                QMessageBox.information(self, "Başarılı", "PostgreSQL bağlantısı başarılı.")
            except Exception as exc:
                try:
                    if conn is not None:
                        conn.close()
                except Exception:
                    pass
                self.result.setText(f"✗ PostgreSQL bağlantısı başarısız.\n{exc}")
                QMessageBox.critical(self, "PostgreSQL Bağlantı Hatası", str(exc))
            return

        raw = self.path_edit.text().strip()
        if not raw:
            self.result.setText("✗ SQLite veritabanı yolu boş olamaz.")
            QMessageBox.warning(self, "Eksik Bilgi", "SQLite veritabanı yolu boş bırakılamaz.")
            return
        p = Path(raw).expanduser()
        try:
            p.parent.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(str(p), timeout=10)
            conn.execute("PRAGMA busy_timeout = 10000")
            conn.execute("SELECT 1")
            conn.close()
            self.result.setText(f"✓ SQLite bağlantısı başarılı.\n{p}")
            self._validated = True
            self._validated_signature = self._signature()
            self.save_continue_btn.setEnabled(True)
            QMessageBox.information(self, "Başarılı", "SQLite veritabanı erişim testi başarılı.")
        except Exception as exc:
            self.result.setText(f"✗ SQLite bağlantısı başarısız.\n{exc}")
            QMessageBox.critical(self, "SQLite Bağlantı Hatası", str(exc))

    def _save_settings_for_current_selection(self):
        if self.mode.currentText() == "PostgreSQL":
            APP_SETTINGS.setValue("database/backend", "postgresql")
            APP_SETTINGS.setValue("postgres/host", self.pg_host.text().strip() or "localhost")
            APP_SETTINGS.setValue("postgres/port", int(self.pg_port.text().strip() or 5432))
            APP_SETTINGS.setValue("postgres/dbname", self.pg_db.text().strip() or "depo_stok")
            APP_SETTINGS.setValue("postgres/user", self.pg_user.text().strip() or "postgres")
            APP_SETTINGS.setValue("postgres/share_path", self.pg_share_path.text().strip())
            save_pg_password(self.pg_password.text())
        else:
            path = Path(self.path_edit.text().strip()).expanduser()
            APP_SETTINGS.setValue("database/backend", "sqlite")
            APP_SETTINGS.setValue("database/path", str(path))
        APP_SETTINGS.sync()

    def accept_validated(self):
        if not self._validated or self._validated_signature != self._signature():
            self.test_connection()
            if not self._validated:
                return
        self._save_settings_for_current_selection()
        super().accept()

    def force_local_sqlite(self):
        current_text = self.path_edit.text().strip()
        current = Path(current_text).expanduser() if current_text else Path(r"C:\TUA_DepoStok") / "depo_stok.db"
        if current_text.startswith("\\\\") or current.as_posix().startswith("//"):
            current = Path(r"C:\TUA_DepoStok") / "depo_stok.db"
        try:
            current.parent.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(str(current), timeout=10)
            conn.execute("PRAGMA busy_timeout = 10000")
            conn.execute("SELECT 1")
            conn.close()
        except Exception as exc:
            QMessageBox.critical(self, "SQLite Hatası", f"Yerel SQLite'a geçilemedi:\n{exc}")
            return
        idx = self.mode.findText("SQLite")
        if idx >= 0:
            self.mode.setCurrentIndex(idx)
        self.path_edit.setText(str(current))
        APP_SETTINGS.setValue("database/backend", "sqlite")
        APP_SETTINGS.setValue("database/path", str(current))
        APP_SETTINGS.sync()
        QMessageBox.information(self, "Yerel SQLite", f"Program yerel SQLite ile devam edecek.\n\n{current}")
        super().accept()

    def save(self):
        self._save_settings_for_current_selection()
        QMessageBox.information(
            self,
            "Kaydedildi",
            f"{self.mode.currentText()} çalışma modu kaydedildi.\n\n"
            "Değişikliğin etkili olması için programı kapatıp yeniden açın."
        )
        self.accept()


def _current_user_is_admin(parent):
    user = getattr(parent, "current_user", None) or {}
    role = str(user.get("rol_adi") or "").strip().casefold()
    username = str(user.get("kullanici_adi") or "").strip().casefold()
    return role in {"yönetici", "yonetici"} or username == "admin"


def _restore_confirmation(parent, source_path, backend_name):
    return QMessageBox.question(
        parent,
        "DİKKAT: Yedek Geri Yüklenecek",
        f"{backend_name} veritabanı seçilen yedekten geri yüklenecek.\n\n"
        f"Kaynak: {source_path}\n\n"
        "Mevcut veritabanının üzerine yazılacaktır. Bu işlem geri alınamaz.\n"
        "İşlemden hemen önce mevcut veritabanının güvenlik yedeği alınacaktır.\n\n"
        "Devam etmek istiyor musunuz?",
        QMessageBox.Yes | QMessageBox.No,
        QMessageBox.No
    ) == QMessageBox.Yes


class PostgreSQLBackupDialog(QDialog):
    """PostgreSQL sunucu veritabanını pg_dump ile güvenli biçimde yedekler."""
    def __init__(self, parent, db):
        super().__init__(parent)
        self.db = db
        self.setWindowTitle(f"PostgreSQL Sunucu Yedekleme - {APP_VERSION}")
        self.resize(780, 520)
        self.setMinimumSize(720, 460)
        root = QVBoxLayout(self)
        title = QLabel("POSTGRESQL SUNUCU YEDEKLEME")
        title.setObjectName("dialogTitle")
        root.addWidget(title)
        info = QLabel(
            "Bu işlem PostgreSQL sunucusundaki aktif veritabanını pg_dump ile yedekler. "
            "Kaynak veritabanı değiştirilmez. Yedek dosyası programın SQLite yedeğinden bağımsızdır."
        )
        info.setWordWrap(True)
        root.addWidget(info)

        form = QFormLayout()
        self.host = QLineEdit(str(APP_SETTINGS.value('postgres/host','localhost') or 'localhost'))
        self.port = QLineEdit(str(APP_SETTINGS.value('postgres/port',5432) or 5432))
        self.dbname = QLineEdit(str(APP_SETTINGS.value('postgres/dbname','depo_stok') or 'depo_stok'))
        self.user = QLineEdit(str(APP_SETTINGS.value('postgres/user','postgres') or 'postgres'))
        self.password = QLineEdit(str(get_pg_password()))
        self.password.setEchoMode(QLineEdit.Password)
        self.path = QLineEdit(str(Path.cwd() / 'yedekler' / f"depo_stok_pg_{datetime.now():%Y%m%d_%H%M%S}.dump"))
        browse = QPushButton("Dosya Seç...")
        browse.clicked.connect(self.choose_path)
        pbox = QHBoxLayout(); pbox.addWidget(self.path); pbox.addWidget(browse)
        pw = QWidget(); pw.setLayout(pbox)
        for w in (self.port,): w.setValidator(QIntValidator(1,65535,self))
        form.addRow("Host", self.host)
        form.addRow("Port", self.port)
        form.addRow("Veritabanı", self.dbname)
        form.addRow("Kullanıcı", self.user)
        form.addRow("Şifre", self.password)
        form.addRow("Yedek dosyası", pw)
        root.addLayout(form)

        self.format = QComboBox(); self.format.addItems(["Custom (.dump)", "Plain SQL (.sql)"])
        form2 = QFormLayout(); form2.addRow("Yedek biçimi", self.format); root.addLayout(form2)

        self.status = QLabel("Hazır")
        self.status.setWordWrap(True)
        root.addWidget(self.status)
        self.log = QPlainTextEdit(); self.log.setReadOnly(True); root.addWidget(self.log,1)

        row = QHBoxLayout()
        self.test_btn = QPushButton("Bağlantıyı Test Et")
        self.backup_btn = QPushButton("Yedekle")
        self.restore_btn = QPushButton("Yedekten Geri Yükle")
        close = QPushButton("Kapat")
        self.test_btn.clicked.connect(self.test_connection)
        self.backup_btn.clicked.connect(self.backup)
        self.restore_btn.clicked.connect(self.restore_backup)
        close.clicked.connect(self.reject)
        if not _current_user_is_admin(parent):
            self.restore_btn.setEnabled(False)
            self.restore_btn.setToolTip("Yedekten geri yükleme yalnızca Yönetici kullanıcısına açıktır.")
        row.addWidget(self.test_btn); row.addWidget(self.backup_btn); row.addWidget(self.restore_btn); row.addStretch(); row.addWidget(close)
        root.addLayout(row)

    def choose_path(self):
        default = self.path.text().strip() or str(Path.cwd())
        filt = "PostgreSQL Custom Backup (*.dump);;SQL Dosyası (*.sql);;Tüm Dosyalar (*)"
        path, _ = QFileDialog.getSaveFileName(self, "PostgreSQL Yedek Dosyasını Seç", default, filt)
        if path:
            self.path.setText(path)
            if path.lower().endswith('.sql'):
                self.format.setCurrentIndex(1)
            elif path.lower().endswith('.dump'):
                self.format.setCurrentIndex(0)

    def dsn(self):
        return dict(
            host=self.host.text().strip() or 'localhost',
            port=int(self.port.text().strip() or '5432'),
            dbname=self.dbname.text().strip() or 'depo_stok',
            user=self.user.text().strip() or 'postgres',
            password=self.password.text()
        )

    def find_pg_dump(self):
        import shutil
        candidates = []
        found = shutil.which('pg_dump')
        if found: candidates.append(found)
        for root_dir in (Path(r'C:\Program Files\PostgreSQL'), Path(r'C:\Program Files (x86)\PostgreSQL')):
            if root_dir.exists():
                for p in root_dir.glob('*/bin/pg_dump.exe'):
                    candidates.append(str(p))
        return candidates[0] if candidates else None

    def test_connection(self):
        try:
            import psycopg2
            conn = psycopg2.connect(connect_timeout=8, **self.dsn())
            cur = conn.cursor(); cur.execute('SELECT current_database(), current_user, version()')
            row = cur.fetchone(); cur.close(); conn.close()
            ver = ' '.join(str(row[2]).split())
            if len(ver) > 150: ver = ver[:147] + '...'
            self.status.setText(f"Bağlantı başarılı: {row[0]} / {row[1]}")
            self.log.appendPlainText(f"✓ PostgreSQL bağlantısı başarılı. {ver}")
            QMessageBox.information(self, 'Başarılı', 'PostgreSQL sunucusuna bağlantı başarılı.')
        except Exception as exc:
            self.status.setText('Bağlantı başarısız.')
            self.log.appendPlainText(f'✗ {exc}')
            QMessageBox.critical(self, 'PostgreSQL Bağlantı Hatası', str(exc))

    def backup(self):
        pg_dump = self.find_pg_dump()
        if not pg_dump:
            QMessageBox.critical(
                self, 'pg_dump Bulunamadı',
                'pg_dump.exe bulunamadı. PostgreSQL kurulumunuzun bin klasörünün PATH ortam değişkenine eklenmesi gerekiyor.'
            )
            return
        target = Path(self.path.text().strip()).expanduser()
        if not target.suffix:
            target = target.with_suffix('.sql' if self.format.currentIndex() == 1 else '.dump')
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            if QMessageBox.question(self, 'Dosya Mevcut', f'{target}\n\nÜzerine yazılsın mı?', QMessageBox.Yes|QMessageBox.No, QMessageBox.No) != QMessageBox.Yes:
                return

        try:
            port = int(self.port.text().strip() or '5432')
        except ValueError:
            QMessageBox.warning(self, 'Geçersiz Port', 'PostgreSQL portu sayı olmalıdır.'); return

        import os, tempfile, subprocess
        pgpass = None
        try:
            # Şifreyi komut satırına yazmamak için geçici pgpass kullanıyoruz.
            fd, pgpass_name = tempfile.mkstemp(prefix='depo_stok_pg_', suffix='.conf', text=True)
            os.close(fd)
            pgpass = Path(pgpass_name)
            pgpass.write_text(
                f"{self.host.text().strip() or 'localhost'}:{port}:{self.dbname.text().strip() or 'depo_stok'}:{self.user.text().strip() or 'postgres'}:{self.password.text()}\n",
                encoding='utf-8'
            )
            env = os.environ.copy(); env['PGPASSFILE'] = str(pgpass)
            cmd = [
                pg_dump,
                '-h', self.host.text().strip() or 'localhost',
                '-p', str(port),
                '-U', self.user.text().strip() or 'postgres',
                '-d', self.dbname.text().strip() or 'depo_stok',
            ]
            if self.format.currentIndex() == 0:
                cmd += ['-Fc', '-f', str(target)]
            else:
                cmd += ['-Fp', '-f', str(target), '--encoding=UTF8']
            self.backup_btn.setEnabled(False); self.status.setText('Yedek alınıyor...'); QApplication.processEvents()
            proc = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=600)
            if proc.returncode != 0:
                msg = (proc.stderr or proc.stdout or 'pg_dump hata kodu döndürdü.').strip()
                self.status.setText('Yedekleme başarısız.')
                self.log.appendPlainText('✗ ' + msg)
                QMessageBox.critical(self, 'Yedekleme Hatası', msg)
                return
            size = target.stat().st_size if target.exists() else 0
            self.status.setText(f'Yedekleme tamamlandı: {target}')
            self.log.appendPlainText(f'✓ Yedek oluşturuldu: {target} ({size:,} bayt)')
            QMessageBox.information(self, 'Yedekleme Tamamlandı', f'PostgreSQL yedeği oluşturuldu:\n\n{target}')
        except subprocess.TimeoutExpired:
            self.status.setText('Yedekleme zaman aşımına uğradı.')
            QMessageBox.critical(self, 'Zaman Aşımı', 'pg_dump 10 dakika içinde tamamlanmadı.')
        except Exception as exc:
            self.status.setText('Yedekleme başarısız.')
            self.log.appendPlainText('✗ ' + str(exc))
            QMessageBox.critical(self, 'Yedekleme Hatası', str(exc))
        finally:
            self.backup_btn.setEnabled(True)
            if pgpass:
                try:
                    pgpass.unlink(missing_ok=True)
                except Exception:
                    pass

    def find_pg_tool(self, tool_name):
        import shutil
        found = shutil.which(tool_name)
        if found:
            return found
        exe_name = tool_name if tool_name.lower().endswith('.exe') else tool_name + '.exe'
        for root_dir in (Path(r'C:\Program Files\PostgreSQL'), Path(r'C:\Program Files (x86)\PostgreSQL')):
            if root_dir.exists():
                for p in root_dir.glob(f'*/bin/{exe_name}'):
                    return str(p)
        return None

    def restore_backup(self):
        if not _current_user_is_admin(self.parent()):
            QMessageBox.warning(self, "Yetki", "Yedekten geri yükleme yalnızca Yönetici kullanıcısına açıktır.")
            return
        path, _ = QFileDialog.getOpenFileName(
            self, "PostgreSQL Yedeğini Seç", str(Path.home()),
            "PostgreSQL Yedeği (*.dump *.backup *.sql);;Custom Backup (*.dump *.backup);;SQL Dosyası (*.sql);;Tüm Dosyalar (*)"
        )
        if not path:
            return
        source = Path(path)
        if not _restore_confirmation(self, source, "PostgreSQL"):
            return
        if source.suffix.lower() in {'.dump', '.backup'}:
            tool = self.find_pg_tool('pg_restore')
        elif source.suffix.lower() == '.sql':
            tool = self.find_pg_tool('psql')
        else:
            QMessageBox.warning(self, "Desteklenmeyen Dosya", "Yalnızca .dump/.backup veya .sql yedekleri geri yüklenebilir.")
            return
        if not tool:
            QMessageBox.critical(self, "PostgreSQL Aracı Bulunamadı", "Gerekli PostgreSQL istemci aracı (pg_restore veya psql) bulunamadı.")
            return

        # Aktif veritabanının mevcut halini zorunlu olarak yedekle.
        stamp=datetime.now().strftime('%Y%m%d_%H%M%S')
        pre_root=_migration_backup_root() / 'pre_restore'
        pre_root.mkdir(parents=True, exist_ok=True)
        pre_target=pre_root / f'depo_stok_pre_restore_{stamp}.dump'
        try:
            perform_postgres_backup(pre_target, 'Custom (.dump)')
        except Exception as exc:
            QMessageBox.critical(self, "Güvenlik Yedeği Başarısız", f"Mevcut veritabanının geri yükleme öncesi yedeği alınamadı.\n\n{exc}\n\nİşlem başlatılmadı.")
            return

        parent=self.parent()
        db=self.db
        try:
            # Mevcut uygulama bağlantısını kapat; böylece bağlantı sayımı yalnızca diğer istemcileri gösterir.
            try:
                db.close()
            except Exception:
                try: db.conn.close()
                except Exception: pass

            # Diğer istemcilerin bağlantıları varken restore edilmemesi için bağlantı durumunu kontrol et.
            import psycopg2
            maintenance=psycopg2.connect(
                host=self.host.text().strip() or 'localhost',
                port=int(self.port.text().strip() or 5432),
                dbname='postgres',
                user=self.user.text().strip() or 'postgres',
                password=self.password.text(),
                connect_timeout=8
            )
            mcur=maintenance.cursor()
            mcur.execute("SELECT count(*) FROM pg_stat_activity WHERE datname=%s AND pid<>pg_backend_pid()", (self.dbname.text().strip() or 'depo_stok',))
            others=int(mcur.fetchone()[0] or 0)
            mcur.close(); maintenance.close()
            if others>0:
                try: db.reconnect()
                except Exception: pass
                QMessageBox.warning(self, "Aktif Bağlantılar Var", f"Hedef PostgreSQL veritabanında {others} başka aktif bağlantı bulunuyor.\n\nÖnce diğer istemcilerde programı kapatın, sonra geri yükleme işlemini tekrar başlatın.")
                return

            dsn_file=None
            import os, tempfile, subprocess
            fd,tmp=tempfile.mkstemp(prefix='depo_stok_restore_',suffix='.conf',text=True); os.close(fd); dsn_file=Path(tmp)
            dsn_file.write_text(f"{self.host.text().strip() or 'localhost'}:{int(self.port.text().strip() or 5432)}:{self.dbname.text().strip() or 'depo_stok'}:{self.user.text().strip() or 'postgres'}:{self.password.text()}\n",encoding='utf-8')
            env=os.environ.copy(); env['PGPASSFILE']=str(dsn_file)
            host=self.host.text().strip() or 'localhost'; port=str(int(self.port.text().strip() or 5432)); dbname=self.dbname.text().strip() or 'depo_stok'; user=self.user.text().strip() or 'postgres'

            if source.suffix.lower() in {'.dump','.backup'}:
                cmd=[tool,'-h',host,'-p',port,'-U',user,'-d',dbname,'--clean','--if-exists','--no-owner','--exit-on-error',str(source)]
                proc=subprocess.run(cmd,env=env,capture_output=True,text=True,timeout=1200)
            else:
                # Plain SQL pg_dump çıktısında DROP ifadeleri varsayılan olarak bulunmayabilir.
                # Bu nedenle public şema temizlenir ve ardından SQL dosyası ON_ERROR_STOP ile yüklenir.
                import psycopg2
                prep=psycopg2.connect(host=host,port=int(port),dbname=dbname,user=user,password=self.password,connect_timeout=8)
                prep.autocommit=True; c=prep.cursor(); c.execute('DROP SCHEMA IF EXISTS public CASCADE'); c.execute('CREATE SCHEMA public'); c.execute('GRANT ALL ON SCHEMA public TO public'); c.close(); prep.close()
                cmd=[tool,'-h',host,'-p',port,'-U',user,'-d',dbname,'-v','ON_ERROR_STOP=1','-f',str(source)]
                proc=subprocess.run(cmd,env=env,capture_output=True,text=True,timeout=1200)
            if proc.returncode!=0:
                msg=(proc.stderr or proc.stdout or 'PostgreSQL geri yükleme hata kodu döndürdü.').strip()
                raise RuntimeError(msg)
            # Yeniden bağlan.
            db.reconnect()
            db.init_db()
            try: db._log_operation('PostgreSQL Yedekten Geri Yükleme',None,str(source),getattr(parent,'current_user',{}).get('id'),'Başarılı restore') ; db.conn.commit()
            except Exception: pass
            self.status.setText(f'Geri yükleme tamamlandı: {source}')
            self.log.appendPlainText(f'✓ Geri yükleme tamamlandı. Önceki veritabanı yedeği: {pre_target}')
            QMessageBox.information(self,'Geri Yükleme Tamamlandı',f'Yedek başarıyla geri yüklendi.\n\nKaynak: {source}\n\nGeri yükleme öncesi güvenlik yedeği: {pre_target}')
        except Exception as exc:
            try: db.reconnect()
            except Exception: pass
            self.status.setText('Geri yükleme başarısız.')
            self.log.appendPlainText('✗ ' + str(exc))
            QMessageBox.critical(self,'Geri Yükleme Hatası',str(exc))
        finally:
            try:
                if dsn_file: dsn_file.unlink(missing_ok=True)
            except Exception: pass



class UserDialog(QDialog):
    def __init__(self, parent, db):
        super().__init__(parent); self.db=db; self.selected_id=None
        self.setWindowTitle("Kullanıcılar / Yetkiler"); self.resize(900,560)
        root=QVBoxLayout(self)
        box=QGroupBox("Kullanıcı Tanımı"); f=QGridLayout(box)
        self.username=QLineEdit(); self.fullname=QLineEdit(); self.password=QLineEdit(); self.password.setEchoMode(QLineEdit.Password)
        self.role=QComboBox(); self.active=QCheckBox("Aktif"); self.active.setChecked(True)
        f.addWidget(QLabel("Kullanıcı Adı"),0,0); f.addWidget(self.username,0,1)
        f.addWidget(QLabel("Ad Soyad"),0,2); f.addWidget(self.fullname,0,3)
        f.addWidget(QLabel("Şifre"),1,0); f.addWidget(self.password,1,1)
        f.addWidget(QLabel("Rol"),1,2); f.addWidget(self.role,1,3)
        f.addWidget(self.active,2,0)
        save=QPushButton("Kaydet / Güncelle"); new=QPushButton("Yeni")
        f.addWidget(save,2,2); f.addWidget(new,2,3); root.addWidget(box)
        self.table=QTableWidget(0,6); self.table.setHorizontalHeaderLabels(["ID","Kullanıcı","Ad Soyad","Rol","Aktif","Son Giriş"])
        configure_resizable_table(self.table,"users/list",[55,180,220,150,80,180],2)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows); self.table.setEditTriggers(QAbstractItemView.NoEditTriggers); root.addWidget(self.table,1)
        row=QHBoxLayout(); edit=QPushButton("Seçileni Düzenle"); toggle=QPushButton("Aktif / Pasif"); delete=QPushButton("Sil"); close=QPushButton("Kapat")
        for b in (edit,toggle,delete): row.addWidget(b)
        row.addStretch(); row.addWidget(close); root.addLayout(row)
        save.clicked.connect(self.save); new.clicked.connect(self.clear_form); edit.clicked.connect(self.load_selected); toggle.clicked.connect(self.toggle); delete.clicked.connect(self.delete); close.clicked.connect(self.accept)
        self.load_roles(); self.refresh()
    def load_roles(self):
        self.role.clear()
        for r in self.db.roles(): self.role.addItem(r["ad"],r["id"])
    def clear_form(self):
        self.selected_id=None; self.username.clear(); self.fullname.clear(); self.password.clear(); self.active.setChecked(True)
    def row_index(self):
        rows=self.table.selectionModel().selectedRows(); return rows[0].row() if rows else -1
    def load_selected(self):
        r=self.row_index()
        if r<0:return
        uid=int(self.table.item(r,0).text()); row=self.db.conn.execute("SELECT * FROM kullanicilar WHERE id=?",(uid,)).fetchone()
        if not row:return
        self.selected_id=uid; self.username.setText(row["kullanici_adi"] or ""); self.fullname.setText(row["ad_soyad"] or ""); self.password.clear(); self.active.setChecked(bool(row["aktif"]))
        i=self.role.findData(row["rol_id"]);
        if i>=0:self.role.setCurrentIndex(i)
    def save(self):
        try:self.db.save_user(self.username.text(),self.fullname.text(),self.password.text(),self.role.currentData(),self.active.isChecked(),self.selected_id)
        except sqlite3.IntegrityError as e:
            msg = str(e) or "Bu kullanıcı adı zaten kayıtlı."
            if "kullanıcı" not in msg.lower():
                msg = "Bu kullanıcı adı zaten kayıtlı."
            QMessageBox.warning(self,"Kayıt Hatası",msg); return
        except ValueError as e:
            QMessageBox.warning(self,"Uyarı",str(e)); return
        self.clear_form(); self.refresh()
    def toggle(self):
        r=self.row_index()
        if r<0:return
        uid=int(self.table.item(r,0).text()); row=self.db.conn.execute("SELECT aktif FROM kullanicilar WHERE id=?",(uid,)).fetchone()
        if row:self.db.conn.execute("UPDATE kullanicilar SET aktif=? WHERE id=?",(0 if row["aktif"] else 1,uid)); self.db.conn.commit(); self.refresh()
    def delete(self):
        r=self.row_index()
        if r<0:return
        uid=int(self.table.item(r,0).text())
        if QMessageBox.question(self,"Kullanıcı Sil","Seçili kullanıcı silinsin mi?",QMessageBox.Yes|QMessageBox.No,QMessageBox.No)==QMessageBox.Yes:
            self.db.delete_user(uid); self.refresh()
    def refresh(self):
        self.table.setRowCount(0)
        for x in self.db.users():
            r=self.table.rowCount(); self.table.insertRow(r)
            vals=[x["id"],x["kullanici_adi"],x["ad_soyad"] or "",x["rol_adi"] or "", "Evet" if x["aktif"] else "Hayır",x["son_giris"] or ""]
            for c,v in enumerate(vals): self.table.setItem(r,c,QTableWidgetItem(str(v)))

class BackupDialog(QDialog):
    def __init__(self,parent,db):
        super().__init__(parent); self.db=db; self.setWindowTitle("Veritabanı Yedekleme"); self.resize(760,430)
        root=QVBoxLayout(self); root.addWidget(QLabel(f"Aktif veritabanı:\n{db.path}"))
        box=QGroupBox("Manuel Yedekleme"); g=QGridLayout(box)
        self.folder=QLineEdit(str(db.path.parent/"yedekler")); self.filename=QLineEdit(f"depo_stok_{datetime.now():%Y%m%d_%H%M%S}.db")
        browse=QPushButton("Klasör Seç"); save=QPushButton("Şimdi Yedekle")
        g.addWidget(QLabel("Yedek klasörü"),0,0); g.addWidget(self.folder,0,1); g.addWidget(browse,0,2)
        g.addWidget(QLabel("Dosya adı"),1,0); g.addWidget(self.filename,1,1,1,2); g.addWidget(save,2,1); root.addWidget(box)
        note=QLabel("Yedekleme SQLite'ın yerleşik backup API'si ile yapılır; açık program sırasında alınan yedek tutarlı veritabanı kopyasıdır."); note.setWordWrap(True); root.addWidget(note)
        restore=QPushButton("Yedekten Geri Yükle")
        close=QPushButton("Kapat"); row=QHBoxLayout(); row.addWidget(restore); row.addStretch(); row.addWidget(close); root.addLayout(row)
        if not _current_user_is_admin(parent):
            restore.setEnabled(False)
            restore.setToolTip("Yedekten geri yükleme yalnızca Yönetici kullanıcısına açıktır.")
        browse.clicked.connect(self.choose); save.clicked.connect(self.backup); restore.clicked.connect(self.restore_backup); close.clicked.connect(self.accept)
    def choose(self):
        p=QFileDialog.getExistingDirectory(self,"Yedek Klasörü",self.folder.text() or str(Path.home()))
        if p:self.folder.setText(p)
    def backup(self):
        folder=Path(self.folder.text().strip() or self.db.path.parent/"yedekler"); name=self.filename.text().strip() or f"depo_stok_{datetime.now():%Y%m%d_%H%M%S}.db"
        if not name.lower().endswith(".db"):name += ".db"
        try:
            out=self.db.backup_to(folder/name); QMessageBox.information(self,"Yedekleme","Yedek başarıyla oluşturuldu:\n\n"+str(out))
        except Exception as e: QMessageBox.critical(self,"Yedekleme Hatası",str(e))

    def restore_backup(self):
        if not _current_user_is_admin(self.parent()):
            QMessageBox.warning(self, "Yetki", "Yedekten geri yükleme yalnızca Yönetici kullanıcısına açıktır.")
            return
        path,_=QFileDialog.getOpenFileName(self,"SQLite Yedeğini Seç",self.folder.text() or str(Path.home()),"SQLite Yedeği (*.db *.sqlite *.sqlite3);;Tüm Dosyalar (*)")
        if not path:return
        source=Path(path)
        if not _restore_confirmation(self,source,"SQLite"):
            return
        if source.resolve()==Path(self.db.path).resolve():
            QMessageBox.warning(self,"Geçersiz Yedek","Aktif veritabanı dosyasının kendisini kaynak olarak seçemezsiniz.")
            return
        pre_root=Path(self.db.path).parent/'yedekler'/'pre_restore'; pre_root.mkdir(parents=True,exist_ok=True)
        pre_target=pre_root/f"depo_stok_pre_restore_{datetime.now():%Y%m%d_%H%M%S}.db"
        try:
            self.db.backup_to(pre_target)
            self.db.close()
            import shutil
            target=Path(self.db.path); target.parent.mkdir(parents=True,exist_ok=True)
            shutil.copy2(source,target)
            self.db.conn=sqlite3.connect(str(target),timeout=15)
            self.db.conn.row_factory=sqlite3.Row
            self.db.conn.execute("PRAGMA foreign_keys=ON")
            self.db.conn.execute("PRAGMA busy_timeout=15000")
            self.db.init_db()
            try: self.db._log_operation('SQLite Yedekten Geri Yükleme',None,str(source),getattr(self.parent(),'current_user',{}).get('id'),'Başarılı restore'); self.db.conn.commit()
            except Exception: pass
            QMessageBox.information(self,"Geri Yükleme Tamamlandı",f"Yedek başarıyla geri yüklendi.\n\nKaynak: {source}\n\nGeri yükleme öncesi güvenlik yedeği: {pre_target}")
            self.accept()
            try: self.parent().refresh_dashboard()
            except Exception: pass
        except Exception as exc:
            try:
                self.db.conn=sqlite3.connect(str(self.db.path),timeout=15); self.db.conn.row_factory=sqlite3.Row; self.db.init_db()
            except Exception: pass
            QMessageBox.critical(self,"Geri Yükleme Hatası",str(exc))


class ModulePlaceholder(QDialog):
    def __init__(self, parent, title, description):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.resize(520, 240)
        lay = QVBoxLayout(self)
        t = QLabel(title)
        t.setObjectName("dialogTitle")
        d = QLabel(description)
        d.setWordWrap(True)
        info = QLabel("Bu modül bir sonraki geliştirme aşamasında işlevsel hale getirilecektir.")
        info.setWordWrap(True)
        lay.addWidget(t)
        lay.addWidget(d)
        lay.addWidget(info)
        lay.addStretch()
        b = QDialogButtonBox(QDialogButtonBox.Close)
        b.rejected.connect(self.reject)
        lay.addWidget(b)



class DemirbasListDialog(QDialog):
    """Depodaki ve departman/alt birimlere teslim edilmiş demirbaşları raporlar."""
    COLUMNS = [
        ("kayit_turu", "Kayıt Türü", True), ("depo_adi", "Depo", True),
        ("departman", "Departman", True), ("alt_birim", "Alt Birim", True),
        ("kod", "Ürün Kodu", True), ("ad", "Ürün Adı", True),
        ("grup_adi", "Ürün Grubu", True), ("urun_turu_adi", "Ürün Türü", True),
        ("barkod", "Barkod Kodu", True), ("uretici_kodu", "Üretici Kodu", True),
        ("uretici", "Üretici", True), ("marka", "Marka", True),
        ("model", "Model", True), ("birim_adi", "Birim", True),
        ("mevcut", "Depo Mevcut", True), ("teslim_edilen_miktar", "Teslim Edilen Miktar", True),
        ("son_teslim_tarihi", "Son Teslim Tarihi", False),
        ("kdv", "KDV %", False), ("alis_fiyati", "Alış Fiyatı", False),
        ("satis_fiyati", "Satış Fiyatı", False), ("min_seviye", "Min. Seviye", False),
        ("max_seviye", "Max. Seviye", False), ("raf_bilgisi", "Raf / Lokasyon", True),
        ("aciklama", "Açıklama", False), ("notlar", "Notlar", False),
        ("resim_yolu", "Ürün Resmi Yolu", False), ("aktif", "Aktif", False),
    ]
    def __init__(self, parent, db):
        super().__init__(parent); self.db=db; self._last_rows=[]; self._last_columns=[]
        self.setWindowTitle("Demirbaş Listesi")
        self.setMinimumSize(1150, 680); self.resize(1450, 800)
        root=QVBoxLayout(self)
        title=QLabel("DEMİRBAŞ LİSTESİ"); title.setObjectName("dialogTitle"); root.addWidget(title)
        filters=QGroupBox("Demirbaş Filtresi"); g=QGridLayout(filters)
        self.depo=QComboBox(); self.depo.addItem("Tüm Depolar", None)
        default_depot=None
        for r in db.warehouses():
            if r["aktif"]:
                self.depo.addItem(f"{r['kod']} - {r['ad']}", r["id"])
                name=(r["ad"] or "").upper()
                if "DEMİRBAŞ" in name or "DEMIRBAS" in name: default_depot=r["id"]
        if default_depot is not None:
            self.depo.setCurrentIndex(self.depo.findData(default_depot))
        self.group=QComboBox(); self.group.addItem("Tüm Gruplar", None)
        default_group=None
        for r in db.groups():
            self.group.addItem(f"{r['kod']} - {r['ad']}", r["id"])
            name=(r["ad"] or "").upper()
            if "DEMİRBAŞ" in name or "DEMIRBAS" in name: default_group=r["id"]
        if default_group is not None: self.group.setCurrentIndex(self.group.findData(default_group))
        self.departman_filter=QComboBox(); self.departman_filter.addItem("Tüm Departmanlar", None)
        for r in db.departments():
            if r["aktif"]: self.departman_filter.addItem(f"{r['kod']} - {r['ad']}", r["id"])
        self.alt_birim_filter=QComboBox(); self.alt_birim_filter.addItem("Tüm Alt Birimler", None)
        self.search=QLineEdit(); self.search.setPlaceholderText("Kod, ad, barkod, üretici, marka, model veya raf...")
        self.zero=QCheckBox("Sıfır stokluları göster")
        q=QPushButton("Sorgula"); q.clicked.connect(self.refresh)
        g.addWidget(QLabel("Depo / Çıkış Deposu"),0,0); g.addWidget(self.depo,0,1,1,2)
        g.addWidget(QLabel("Ürün Grubu"),0,3); g.addWidget(self.group,0,4,1,2)
        g.addWidget(QLabel("Arama"),1,0); g.addWidget(self.search,1,1,1,4); g.addWidget(self.zero,1,5)
        g.addWidget(QLabel("Departman"),2,0); g.addWidget(self.departman_filter,2,1,1,2)
        g.addWidget(QLabel("Alt Birim"),2,3); g.addWidget(self.alt_birim_filter,2,4,1,2)
        g.addWidget(q,0,6,3,1)
        root.addWidget(filters)
        cols=QGroupBox("Demirbaş Listesinde Gösterilecek Kolonlar")
        cg=QGridLayout(cols); self.checks=[]
        for i,(_key,label,default) in enumerate(self.COLUMNS):
            cb=QCheckBox(label); cb.setChecked(default); self.checks.append(cb); cg.addWidget(cb,i//4,i%4)
        root.addWidget(cols)
        actions=QHBoxLayout(); ex=QPushButton("Excel'e Aktar"); ex.clicked.connect(self.export_excel); pr=QPushButton("Yazdır"); pr.clicked.connect(self.print_report); actions.addWidget(ex); actions.addWidget(pr); actions.addStretch(); self.info=QLabel("0 kayıt"); actions.addWidget(self.info); root.addLayout(actions)
        self.table=QTableWidget(0,1); self.table.setSelectionBehavior(QAbstractItemView.SelectRows); self.table.setEditTriggers(QAbstractItemView.NoEditTriggers); configure_resizable_table(self.table,"demirbas_listesi",[180]); root.addWidget(self.table,1)
        close=QPushButton("Kapat"); close.clicked.connect(self.accept); root.addWidget(close,0,Qt.AlignRight)
        self.load_department_subunits()
        self.refresh()
        connect_live_text_filter(self.search, self.refresh)
        for cb in self.checks: cb.stateChanged.connect(self.refresh)
        self.depo.currentIndexChanged.connect(self.refresh)
        self.group.currentIndexChanged.connect(self.refresh)
        self.zero.stateChanged.connect(self.refresh)
        self.departman_filter.currentIndexChanged.connect(self.on_department_filter_changed)
        self.alt_birim_filter.currentIndexChanged.connect(self.refresh)

    def load_department_subunits(self):
        selected_department = self.departman_filter.currentData()
        self.alt_birim_filter.blockSignals(True)
        self.alt_birim_filter.clear()
        self.alt_birim_filter.addItem("Tüm Alt Birimler", None)
        if selected_department is not None:
            subunits = self.db.subunits(selected_department, False)
            for row in subunits:
                self.alt_birim_filter.addItem(f"{row['kod']} - {row['ad']}", row['id'])
        else:
            rows = self.db.conn.execute(
                "SELECT a.id,a.kod,a.ad,d.kod AS departman_kodu,d.ad AS departman_adi "
                "FROM departman_alt_birimleri a JOIN departmanlar d ON d.id=a.departman_id "
                "WHERE a.aktif=1 AND d.aktif=1 ORDER BY d.ad,a.kod"
            ).fetchall()
            for row in rows:
                self.alt_birim_filter.addItem(
                    f"{row['departman_kodu']} - {row['departman_adi']} / {row['kod']} - {row['ad']}", row['id'])
        self.alt_birim_filter.blockSignals(False)

    def on_department_filter_changed(self):
        self.load_department_subunits()
        self.refresh()

    def selected_columns(self):
        return [(key,label) for (key,label,_),cb in zip(self.COLUMNS,self.checks) if cb.isChecked()]

    def refresh(self):
        cols=self.selected_columns() or [("kod","Ürün Kodu")]
        self.table.setColumnCount(len(cols)); self.table.setHorizontalHeaderLabels([label for _,label in cols])
        header=self.table.horizontalHeader(); header.setSectionResizeMode(QHeaderView.Interactive)
        for i,(key,_) in enumerate(cols): header.resizeSection(i,240 if key in ("ad","aciklama","notlar") else 150)
        rows=self.db.demirbas_rows(
            self.depo.currentData(), self.group.currentData(), self.search.text().strip(), self.zero.isChecked(),
            self.departman_filter.currentData(), self.alt_birim_filter.currentData())
        self.table.setRowCount(0)
        for rowdata in rows:
            r=self.table.rowCount(); self.table.insertRow(r)
            for c,(key,_label) in enumerate(cols):
                try:
                    v = rowdata[key] if key in rowdata.keys() else ""
                except (AttributeError, KeyError, TypeError):
                    v = ""
                if key == "kdv": txt=f"{float(v or 0):,.2f}".replace(',','X').replace('.',',').replace('X','.')
                elif key in ("alis_fiyati","satis_fiyati"): txt=fmt_money_tr(v)
                elif key in ("min_seviye","max_seviye","mevcut","teslim_edilen_miktar"): txt=fmt_qty_tr(v)
                elif key == "aktif": txt="Evet" if bool(v) else "Hayır"
                else: txt="" if v is None else str(v)
                self.table.setItem(r,c,QTableWidgetItem(txt))
            try:
                mevcut = float(rowdata["mevcut"] or 0)
            except (KeyError, TypeError, ValueError):
                mevcut = 0.0
            if mevcut < 0:
                brush=QColor(Qt.red).lighter(170)
                for c in range(self.table.columnCount()): self.table.item(r,c).setData(Qt.BackgroundRole,brush)
        self.info.setText(f"Toplam {len(rows)} kayıt")
        self._last_rows=rows; self._last_columns=cols

    def _export_rows(self):
        headers=[label for _,label in self._last_columns]
        rows=[[self.table.item(r,c).text() if self.table.item(r,c) else "" for c in range(self.table.columnCount())] for r in range(self.table.rowCount())]
        return headers,rows

    def export_excel(self):
        path,_=QFileDialog.getSaveFileName(self,"Demirbaş Listesini Kaydet",str(Path.home()/"Demirbas_Listesi.xlsx"),"Excel Çalışma Kitabı (*.xlsx);;Excel 97-2003 (*.xls);;CSV Dosyası (*.csv)")
        if not path:return
        headers,rows=self._export_rows()
        try:
            if path.lower().endswith('.csv'):
                with open(path,'w',encoding='utf-8-sig',newline='') as f:
                    w=csv.writer(f,delimiter=';'); w.writerow(headers); w.writerows(rows)
            elif path.lower().endswith('.xls'):
                import xlsxwriter, win32com.client
                tmp=Path(tempfile.NamedTemporaryFile(suffix='.xlsx',delete=False).name)
                wb=xlsxwriter.Workbook(str(tmp));ws=wb.add_worksheet('Demirbaş');hf=wb.add_format({'bold':True,'bg_color':'#D9EAF7','border':1});cf=wb.add_format({'border':1})
                for c,h in enumerate(headers):ws.write(0,c,h,hf)
                for r,row in enumerate(rows,1):
                    for c,v in enumerate(row):ws.write(r,c,v,cf)
                ws.freeze_panes(1,0);wb.close()
                excel=win32com.client.DispatchEx('Excel.Application');excel.Visible=False;excel.DisplayAlerts=False;book=excel.Workbooks.Open(str(tmp.resolve()));book.SaveAs(str(Path(path).resolve()),FileFormat=56);book.Close(False);excel.Quit();tmp.unlink(missing_ok=True)
            else:
                import xlsxwriter
                wb=xlsxwriter.Workbook(path);ws=wb.add_worksheet('Demirbaş');hf=wb.add_format({'bold':True,'bg_color':'#D9EAF7','border':1});cf=wb.add_format({'border':1})
                for c,h in enumerate(headers):ws.write(0,c,h,hf)
                for r,row in enumerate(rows,1):
                    for c,v in enumerate(row):ws.write(r,c,v,cf)
                ws.freeze_panes(1,0);ws.autofilter(0,0,len(rows),max(0,len(headers)-1));wb.close()
            QMessageBox.information(self,'Aktarım','Demirbaş listesi kaydedildi.\n\n'+path)
        except ImportError as exc:
            QMessageBox.critical(self,'Eksik Paket',f'Gerekli Excel paketi bulunamadı: {exc}\n\nXLSX için XlsxWriter, XLS için ayrıca pywin32 gerekir.')
        except Exception as exc: QMessageBox.critical(self,'Aktarım Hatası',str(exc))

    def print_report(self):
        headers,rows=self._export_rows()
        html=['<html><head><meta charset="utf-8"><style>body{font-family:Arial;font-size:8pt}h2{text-align:center}table{border-collapse:collapse;width:100%}th,td{border:1px solid #777;padding:3px}th{background:#e8edf2}</style></head><body>', '<h2>DEMİRBAŞ LİSTESİ</h2>', f'<p>Oluşturma: {datetime.now():%d.%m.%Y %H:%M}</p><table><tr>']
        html += [f'<th>{h}</th>' for h in headers] + ['</tr>']
        for row in rows: html.append('<tr>'+''.join(f'<td>{v}</td>' for v in row)+'</tr>')
        html.append('</table></body></html>')
        printer=QPrinter(QPrinter.HighResolution); printer.setDocName('Demirbaş Listesi'); dlg=QPrintDialog(printer,self)
        if dlg.exec_()!=QDialog.Accepted:return
        doc=QTextDocument();doc.setHtml(''.join(html));doc.print_(printer)

class KpiCard(QFrame):
    def __init__(self, title, value, subtitle, icon_char):
        super().__init__()
        self.setObjectName("kpiCard")
        lay = QVBoxLayout(self)
        top = QHBoxLayout()
        i = QLabel(icon_char)
        i.setObjectName("kpiIcon")
        t = QLabel(title)
        t.setObjectName("kpiTitle")
        top.addWidget(i)
        top.addWidget(t)
        top.addStretch()
        self.value = QLabel(str(value))
        self.value.setObjectName("kpiValue")
        s = QLabel(subtitle)
        s.setObjectName("kpiSub")
        lay.addLayout(top)
        lay.addWidget(self.value)
        lay.addWidget(s)

    def set_value(self, value):
        self.value.setText(str(value))



class InventoryHistoryDialog(QDialog):
    def __init__(self,parent,db):
        super().__init__(parent); self.db=db; self.setWindowTitle('Sayım Geçmişi'); self.resize(1250,720)
        root=QVBoxLayout(self); root.addWidget(QLabel('SAYIM GEÇMİŞİ')); f=QGridLayout()
        self.start=QDateEdit(QDate.currentDate().addMonths(-1)); self.end=QDateEdit(QDate.currentDate()); [x.setCalendarPopup(True) for x in (self.start,self.end)]
        self.depo=QComboBox(); self.depo.addItem('Tüm Depolar',None)
        for r in db.warehouses():
            if r['aktif']: self.depo.addItem(f"{r['kod']} - {r['ad']}",r['id'])
        self.search=QLineEdit(); self.search.setPlaceholderText('Sayım no, depo veya açıklama...')
        f.addWidget(QLabel('Başlangıç'),0,0);f.addWidget(self.start,0,1);f.addWidget(QLabel('Bitiş'),0,2);f.addWidget(self.end,0,3);f.addWidget(QLabel('Depo'),0,4);f.addWidget(self.depo,0,5);f.addWidget(self.search,0,6);b=QPushButton('Sorgula');b.clicked.connect(self.refresh);f.addWidget(b,0,7);root.addLayout(f)
        self.table=QTableWidget(0,10);self.table.setHorizontalHeaderLabels(['No','Sayım No','Tarih','Depo','Açıklama','Kullanıcı','Satır','Mutlak Fark','Eksik / Fazla','Durum']);configure_resizable_table(self.table,'sayim_gecmisi',[55,105,95,180,260,150,65,110,145,90]);self.table.setEditTriggers(QAbstractItemView.NoEditTriggers);root.addWidget(self.table,1)
        bb=QHBoxLayout(); det=QPushButton('Detay');det.clicked.connect(self.detail);ex=QPushButton("Excel'e Aktar");ex.clicked.connect(self.export);pr=QPushButton('Yazdır');pr.clicked.connect(self.print_report);cancel=QPushButton('Sayımı İptal Et');cancel.clicked.connect(self.cancel_selected);cancel.setEnabled(getattr(parent,'role_name','').casefold()=='yönetici');cl=QPushButton('Kapat');cl.clicked.connect(self.accept);bb.addWidget(det);bb.addWidget(ex);bb.addWidget(pr);bb.addWidget(cancel);bb.addStretch();bb.addWidget(cl);root.addLayout(bb);self.cancel_btn=cancel;self.refresh()
    def refresh(self):
        rows=self.db.list_inventory_counts(self.start.date().toString('yyyy-MM-dd'),self.end.date().toString('yyyy-MM-dd'),self.depo.currentData(),self.search.text().strip());self.table.setRowCount(0)
        for i,x in enumerate(rows,1):
            r=self.table.rowCount();self.table.insertRow(r);vals=[i,x['sayim_no'],x['tarih'],f"{x['depo_kodu']} - {x['depo_adi']}",x['aciklama'] or '',x['kullanici'] or '',x['satir_sayisi'],self.q(x['toplam_mutlak_fark']),f"Eksik {self.q(x['toplam_eksik'])} / Fazla {self.q(x['toplam_fazla'])}",x['durum']]
            for c,v in enumerate(vals):self.table.setItem(r,c,QTableWidgetItem(str(v)))
            self.table.item(r,1).setData(Qt.UserRole,x['id'])
    def cancel_selected(self):
        row=self.table.currentRow()
        if row<0: QMessageBox.information(self,'Seçim','İptal etmek için bir sayım seçin.'); return
        sayim_id=self.db.conn.execute('SELECT id FROM sayim_fisleri WHERE sayim_no=?',(self.table.item(row,1).text(),)).fetchone()
        if not sayim_id: return
        if self.table.item(row,9).text()=='İptal': QMessageBox.information(self,'Sayım','Bu sayım zaten iptal edilmiş.'); return
        reason,ok=QInputDialog.getText(self,'Sayım İptali','İptal nedeni:')
        if not ok:return
        if QMessageBox.question(self,'Sayım İptali','Seçilen sayımı iptal etmek istediğinizden emin misiniz?',QMessageBox.Yes|QMessageBox.No,QMessageBox.No)!=QMessageBox.Yes:return
        try:
            uid=getattr(self.parent(),'current_user',None)
            self.db.cancel_inventory_count(sayim_id['id'], uid['id'] if uid else None, reason.strip())
            self.refresh(); QMessageBox.information(self,'İptal','Sayım iptal edildi ve stok düzeltmesi tersine çevrildi.')
        except Exception as exc: QMessageBox.critical(self,'İptal Hatası',str(exc))

    def detail(self):
        it=self.table.currentItem();
        if not it: QMessageBox.information(self,'Sayım','Bir sayım seçin.'); return
        sid=self.table.item(it.row(),1).data(Qt.UserRole); rows=self.db.inventory_count_details(sid); d=QDialog(self);d.setWindowTitle('Sayım Detayı');d.resize(1100,650);l=QVBoxLayout(d);t=QTableWidget(0,8);t.setHorizontalHeaderLabels(['Ürün Kodu','Ürün Adı','Barkod','Birim','Sistem','Sayılan','Fark','Açıklama']);configure_resizable_table(t,'sayim_detay',[110,250,140,70,95,95,95,220])
        for x in rows:
            r=t.rowCount();t.insertRow(r);vals=[x['urun_kodu'],x['urun_adi'],x['barkod'] or '',x['birim'],self.q(x['sistem_miktari']),self.q(x['sayilan_miktar']),self.q(x['fark']),x['aciklama'] or '']
            for c,v in enumerate(vals):t.setItem(r,c,QTableWidgetItem(str(v)))
        l.addWidget(t);c=QPushButton('Kapat');c.clicked.connect(d.accept);l.addWidget(c,0,Qt.AlignRight);d.exec_()
    def export(self): self.simple_export('Sayım Geçmişi')
    def simple_export(self,title):
        path,_=QFileDialog.getSaveFileName(self,'Excel / CSV',title.replace(' ','_'),'Excel Çalışma Kitabı (*.xlsx);;CSV Dosyası (*.csv)');
        if not path:return
        h=[self.table.horizontalHeaderItem(c).text() for c in range(self.table.columnCount())];rows=[[self.table.item(r,c).text() if self.table.item(r,c) else '' for c in range(self.table.columnCount())] for r in range(self.table.rowCount())]
        try:
            if path.lower().endswith('.csv'):
                with open(path,'w',newline='',encoding='utf-8-sig') as f:csv.writer(f,delimiter=';').writerows([h]+rows)
            else:
                import xlsxwriter;wb=xlsxwriter.Workbook(path);ws=wb.add_worksheet('Sayım Geçmişi');fmt=wb.add_format({'bold':True,'bg_color':'#D9E2F3','border':1});
                for c,v in enumerate(h):ws.write(0,c,v,fmt)
                for r,row in enumerate(rows,1):
                    for c,v in enumerate(row):ws.write(r,c,v)
                wb.close()
            QMessageBox.information(self,'Aktarım','Dosya kaydedildi.')
        except Exception as e:QMessageBox.critical(self,'Aktarım',str(e))
    def print_report(self):
        printer=QPrinter(QPrinter.HighResolution);d=QPrintDialog(printer,self)
        if d.exec_()!=QDialog.Accepted:return
        h=[self.table.horizontalHeaderItem(c).text() for c in range(self.table.columnCount())];html=['<html><head><meta charset="utf-8"><style>body{font-family:Arial;font-size:8pt}table{width:100%;border-collapse:collapse}th,td{border:1px solid #777;padding:3px}th{background:#e8edf2}</style></head><body><h2>SAYIM GEÇMİŞİ</h2><table><tr>']+[f'<th>{x}</th>' for x in h]+['</tr>']
        for r in range(self.table.rowCount()):html.append('<tr>'+''.join(f"<td>{self.table.item(r,c).text() if self.table.item(r,c) else ''}</td>" for c in range(self.table.columnCount()))+'</tr>')
        html.append('</table></body></html>');doc=QTextDocument();doc.setHtml(''.join(html));doc.print_(printer)
    @staticmethod
    def q(v):return f"{float(v or 0):,.3f}".replace(',','X').replace('.',' ,').replace('X','.') .replace(' ,',',')

class InventoryDifferenceDialog(QDialog):
    def __init__(self,parent,db):
        super().__init__(parent);self.db=db;self.setWindowTitle('Sayım Fark Raporu');self.resize(1350,740);root=QVBoxLayout(self);root.addWidget(QLabel('SAYIM FARK RAPORU'));f=QGridLayout();self.start=QDateEdit(QDate.currentDate().addMonths(-1));self.end=QDateEdit(QDate.currentDate());self.start.setCalendarPopup(True);self.end.setCalendarPopup(True);self.depo=QComboBox();self.depo.addItem('Tüm Depolar',None);self.type=QComboBox();self.type.addItems(['Tümü','Eksik','Fazla','Eşit']);self.search=QLineEdit();self.search.setPlaceholderText('Ürün kodu, adı, barkod, marka veya model...')
        for x in db.warehouses():
            if x['aktif']:self.depo.addItem(f"{x['kod']} - {x['ad']}",x['id'])
        f.addWidget(QLabel('Başlangıç'),0,0);f.addWidget(self.start,0,1);f.addWidget(QLabel('Bitiş'),0,2);f.addWidget(self.end,0,3);f.addWidget(QLabel('Depo'),0,4);f.addWidget(self.depo,0,5);f.addWidget(QLabel('Durum'),0,6);f.addWidget(self.type,0,7);f.addWidget(self.search,1,0,1,4);b=QPushButton('Sorgula');b.clicked.connect(self.refresh);ex=QPushButton("Excel'e Aktar");ex.clicked.connect(self.export);pr=QPushButton('Yazdır');pr.clicked.connect(self.print_report);f.addWidget(b,1,4);f.addWidget(ex,1,5);f.addWidget(pr,1,6);root.addLayout(f)
        self.table=QTableWidget(0,13);self.table.setHorizontalHeaderLabels(['Sayım No','Tarih','Depo','Ürün Kodu','Ürün Adı','Barkod','Birim','Sistem','Sayılan','Fark','Durum','Kullanıcı','Açıklama']);configure_resizable_table(self.table,'sayim_fark_raporu',[100,95,170,110,240,130,70,95,95,95,90,130,220]);self.table.setEditTriggers(QAbstractItemView.NoEditTriggers);root.addWidget(self.table,1);connect_live_text_filter(self.search, self.refresh);self.refresh()
    def refresh(self):
        rows=self.db.inventory_difference_report(self.start.date().toString('yyyy-MM-dd'),self.end.date().toString('yyyy-MM-dd'),self.depo.currentData(),self.search.text().strip());flt=self.type.currentText();self.table.setRowCount(0)
        for x in rows:
            if flt!='Tümü' and x['durum']!=flt:continue
            r=self.table.rowCount();self.table.insertRow(r);vals=[x['sayim_no'],x['tarih'],f"{x['depo_kodu']} - {x['depo_adi']}",x['urun_kodu'],x['urun_adi'],x['barkod'] or '',x['birim'],self.q(x['sistem_miktari']),self.q(x['sayilan_miktar']),self.q(x['fark']),x['durum'],x['kullanici'] or '',x['aciklama'] or '']
            for c,v in enumerate(vals):self.table.setItem(r,c,QTableWidgetItem(str(v)))
    def export(self):
        path,_=QFileDialog.getSaveFileName(self,'Sayım Fark Raporu','sayim_fark_raporu','Excel Çalışma Kitabı (*.xlsx);;CSV Dosyası (*.csv)');
        if not path:return
        try:
            h=[self.table.horizontalHeaderItem(c).text() for c in range(self.table.columnCount())];rows=[[self.table.item(r,c).text() if self.table.item(r,c) else '' for c in range(self.table.columnCount())] for r in range(self.table.rowCount())]
            if path.lower().endswith('.csv'):
                with open(path,'w',newline='',encoding='utf-8-sig') as f:csv.writer(f,delimiter=';').writerows([h]+rows)
            else:
                import xlsxwriter;wb=xlsxwriter.Workbook(path);ws=wb.add_worksheet('Sayım Farkı');fmt=wb.add_format({'bold':True,'bg_color':'#D9E2F3','border':1});
                for c,v in enumerate(h):ws.write(0,c,v,fmt)
                for r,row in enumerate(rows,1):
                    for c,v in enumerate(row):ws.write(r,c,v)
                wb.close()
            QMessageBox.information(self,'Aktarım','Dosya kaydedildi.')
        except Exception as e:QMessageBox.critical(self,'Aktarım',str(e))
    def print_report(self):
        printer=QPrinter(QPrinter.HighResolution);d=QPrintDialog(printer,self)
        if d.exec_()!=QDialog.Accepted:return
        h=[self.table.horizontalHeaderItem(c).text() for c in range(self.table.columnCount())];html=['<html><head><meta charset="utf-8"><style>body{font-family:Arial;font-size:7pt}table{width:100%;border-collapse:collapse}th,td{border:1px solid #777;padding:2px}th{background:#e8edf2}</style></head><body><h2>SAYIM FARK RAPORU</h2><table><tr>']+[f'<th>{x}</th>' for x in h]+['</tr>']
        for r in range(self.table.rowCount()):html.append('<tr>'+''.join(f"<td>{self.table.item(r,c).text() if self.table.item(r,c) else ''}</td>" for c in range(self.table.columnCount()))+'</tr>')
        html.append('</table></body></html>');doc=QTextDocument();doc.setHtml(''.join(html));doc.print_(printer)
    @staticmethod
    def q(v):return f"{float(v or 0):,.3f}".replace(',','X').replace('.',',').replace('X','.')

class StockTransferDialog(QDialog):
    def __init__(self,parent,db,current_user=None):
        super().__init__(parent);self.db=db;self.current_user=current_user;self.lines=[];self.selected_product=None;self.setWindowTitle('Depolar Arası Stok Transferi');self.resize(1200,780);root=QVBoxLayout(self);root.addWidget(QLabel('DEPOLAR ARASI STOK TRANSFERİ'))
        g=QGridLayout();self.no=QLineEdit(db.ensure_transfer_no());self.no.setReadOnly(True);self.date=QDateEdit(QDate.currentDate());self.date.setCalendarPopup(True);self.source=QComboBox();self.target=QComboBox();self.desc=QLineEdit();self.desc.setPlaceholderText('Açıklama')
        g.addWidget(QLabel('Transfer No'),0,0);g.addWidget(self.no,0,1);g.addWidget(QLabel('Tarih'),0,2);g.addWidget(self.date,0,3);g.addWidget(QLabel('Kaynak Depo*'),0,4);g.addWidget(self.source,0,5);g.addWidget(QLabel('Hedef Depo*'),1,0);g.addWidget(self.target,1,1);g.addWidget(QLabel('Açıklama'),1,2);g.addWidget(self.desc,1,3,1,3);root.addLayout(g)

        # V1.37.3: Ürün arama artık yazarken canlı daralan liste sunar.
        h=QHBoxLayout();self.search=QLineEdit();self.search.setPlaceholderText('Barkod, ürün kodu veya ürün adı yazın...');self.qty=QLineEdit();self.qty.setPlaceholderText('Miktar');add=QPushButton('Ürün Ekle');add.clicked.connect(self.add_line);h.addWidget(self.search,1);h.addWidget(self.qty);h.addWidget(add);root.addLayout(h)
        self.product_list=QListWidget();self.product_list.setMinimumHeight(150);self.product_list.setMaximumHeight(210);self.product_list.setSelectionMode(QAbstractItemView.SingleSelection);self.product_list.setToolTip('Arama kutusuna barkod, ürün kodu veya ürün adı yazdıkça liste daralır. Ürünü listeden seçin.')
        root.addWidget(QLabel('Eşleşen Ürünler'));root.addWidget(self.product_list)
        self.table=QTableWidget(0,6);self.table.setHorizontalHeaderLabels(['Ürün Kodu','Ürün Adı','Barkod','Kaynak Stok','Transfer Miktarı','Birim']);configure_resizable_table(self.table,'depo_transfer_satirlari',[120,280,150,120,120,80]);root.addWidget(self.table,1)
        self.editing_line_index=None
        line_buttons=QHBoxLayout();self.edit_line_btn=QPushButton('Düzelt');self.delete_line_btn=QPushButton('Sil');self.cancel_edit_btn=QPushButton('Düzeltmeyi İptal Et');self.cancel_edit_btn.setVisible(False)
        self.edit_line_btn.clicked.connect(self.edit_selected_line);self.delete_line_btn.clicked.connect(self.delete_selected_line);self.cancel_edit_btn.clicked.connect(self.cancel_edit_line)
        line_buttons.addWidget(self.edit_line_btn);line_buttons.addWidget(self.delete_line_btn);line_buttons.addWidget(self.cancel_edit_btn);line_buttons.addStretch();root.addLayout(line_buttons)
        b=QDialogButtonBox(QDialogButtonBox.Save|QDialogButtonBox.Cancel);b.accepted.connect(self.save);b.rejected.connect(self.reject);root.addWidget(b)
        self.search.textChanged.connect(self.refresh_product_list);self.product_list.itemSelectionChanged.connect(self.select_product);self.product_list.itemDoubleClicked.connect(lambda _item:self._focus_quantity());self.source.currentIndexChanged.connect(lambda _=0:self.refresh_product_list());self.table.itemSelectionChanged.connect(self.update_line_buttons);self.load_depots();self.refresh_product_list();self.update_line_buttons()
    def load_depots(self):
        for c in (self.source,self.target):c.clear();c.addItem('-- Seçiniz --',None)
        for r in self.db.warehouses():
            if r['aktif']:
                self.source.addItem(f"{r['kod']} - {r['ad']}",r['id']);self.target.addItem(f"{r['kod']} - {r['ad']}",r['id'])
    def refresh_product_list(self):
        term=self.search.text().strip()
        self.selected_product=None
        self.product_list.blockSignals(True)
        try:
            self.product_list.clear()
            if term:
                like=f"%{term}%"
                rows=self.db.conn.execute(
                    "SELECT id,kod,ad,barkod,birim FROM urunler WHERE aktif=1 AND (kod LIKE ? OR ad LIKE ? OR COALESCE(barkod,'') LIKE ?) ORDER BY kod LIMIT 150",
                    (like,like,like)
                ).fetchall()
            else:
                rows=self.db.conn.execute(
                    "SELECT id,kod,ad,barkod,birim FROM urunler WHERE aktif=1 ORDER BY kod LIMIT 150"
                ).fetchall()
            for prod in rows:
                barkod=prod['barkod'] or ''
                text=f"{prod['kod']}  |  {prod['ad']}" + (f"  |  Barkod: {barkod}" if barkod else '')
                item=QListWidgetItem(text)
                item.setData(Qt.UserRole, {'id':prod['id'],'kod':prod['kod'],'ad':prod['ad'],'barkod':barkod,'birim':prod['birim'] or 'ADET'})
                self.product_list.addItem(item)
            if not rows:
                empty=QListWidgetItem('Eşleşen ürün bulunamadı.')
                empty.setFlags(Qt.NoItemFlags)
                self.product_list.addItem(empty)
            elif term:
                self.product_list.setCurrentRow(0)
        finally:
            self.product_list.blockSignals(False)
        if term and self.product_list.count() and self.product_list.item(0).data(Qt.UserRole):
            self.select_product()
        elif term and self.product_list.count() == 1 and self.product_list.item(0).flags() == Qt.NoItemFlags:
            self.selected_product=None

    def select_product(self):
        item=self.product_list.currentItem()
        data=item.data(Qt.UserRole) if item else None
        self.selected_product=data if isinstance(data,dict) else None

    def _focus_quantity(self):
        self.qty.setFocus()
        self.qty.selectAll()

    def add_line(self):
        src=self.source.currentData();key=self.search.text().strip()
        if not src:QMessageBox.warning(self,'Transfer','Önce kaynak depoyu seçin.');return
        if not key:QMessageBox.warning(self,'Transfer','Barkod, ürün kodu veya ürün adını girin.');return
        prod=self.selected_product
        if not prod:
            QMessageBox.warning(self,'Transfer','Lütfen aşağıdaki eşleşen ürünler listesinden bir ürün seçin.')
            self.product_list.setFocus()
            return
        try:qty=float(self.qty.text().replace('.','').replace(',','.'))
        except:QMessageBox.warning(self,'Transfer','Geçerli bir miktar girin.');return
        if qty<=0:QMessageBox.warning(self,'Transfer','Miktar sıfırdan büyük olmalıdır.');return
        bal=self.db.stock_balance(prod['id'],src)
        if self.editing_line_index is not None:
            idx=self.editing_line_index
            existing=sum(x['miktar'] for i,x in enumerate(self.lines) if i!=idx and x['urun_id']==prod['id'])
            if bal+1e-9 < existing+qty:
                QMessageBox.warning(self,'Transfer',f'Yetersiz stok. Mevcut: {bal:,.3f}');return
            other_idx=next((i for i,x in enumerate(self.lines) if i!=idx and x['urun_id']==prod['id']),None)
            if other_idx is not None:
                self.lines[other_idx]['miktar']+=qty
                self.lines.pop(idx)
            else:
                self.lines[idx]={'urun_id':prod['id'],'kod':prod['kod'],'ad':prod['ad'],'barkod':prod['barkod'] or '','miktar':qty,'birim':prod['birim'] or 'ADET','stok':bal}
            self.editing_line_index=None;self.edit_line_btn.setText('Düzelt');self.cancel_edit_btn.setVisible(False)
            self.clear_product_entry();self.rebuild();self.update_line_buttons();return
        existing=sum(x['miktar'] for x in self.lines if x['urun_id']==prod['id'])
        if bal+1e-9 < existing+qty:QMessageBox.warning(self,'Transfer',f'Yetersiz stok. Mevcut: {bal:,.3f}');return
        for x in self.lines:
            if x['urun_id']==prod['id']:
                x['miktar']+=qty
                self.clear_product_entry();self.rebuild();return
        self.lines.append({'urun_id':prod['id'],'kod':prod['kod'],'ad':prod['ad'],'barkod':prod['barkod'] or '','miktar':qty,'birim':prod['birim'] or 'ADET','stok':bal});self.clear_product_entry();self.rebuild()
    def clear_product_entry(self):
        self.search.blockSignals(True);self.search.clear();self.search.blockSignals(False);self.qty.clear();self.selected_product=None;self.editing_line_index=None;self.edit_line_btn.setText('Düzelt');self.cancel_edit_btn.setVisible(False);self.refresh_product_list();self.update_line_buttons()
    def update_line_buttons(self):
        has=0<=self.table.currentRow()<len(self.lines) and self.editing_line_index is None
        self.edit_line_btn.setEnabled(has);self.delete_line_btn.setEnabled(has)
    def edit_selected_line(self):
        row=self.table.currentRow()
        if row<0 or row>=len(self.lines):
            QMessageBox.information(self,'Transfer','Düzeltmek için listeden bir ürün satırı seçin.');return
        x=self.lines[row];self.editing_line_index=row
        self.search.setText(x['kod'])
        self.qty.setText(f"{float(x['miktar']):g}".replace('.',','))
        self.selected_product={'id':x['urun_id'],'kod':x['kod'],'ad':x['ad'],'barkod':x['barkod'] or '','birim':x['birim'] or 'ADET'}
        self.edit_line_btn.setText('Düzeltmeyi Kaydet');self.cancel_edit_btn.setVisible(True);self.delete_line_btn.setEnabled(False);self._focus_quantity()
    def cancel_edit_line(self):
        self.clear_product_entry()
    def delete_selected_line(self):
        row=self.table.currentRow()
        if row<0 or row>=len(self.lines):
            QMessageBox.information(self,'Transfer','Silmek için listeden bir ürün satırı seçin.');return
        x=self.lines[row]
        if QMessageBox.question(self,'Satır Sil','Seçilen ürün transfer listesinden silinsin mi?\n\n'+f"{x['kod']} - {x['ad']}",QMessageBox.Yes|QMessageBox.No,QMessageBox.No)!=QMessageBox.Yes:return
        self.lines.pop(row);self.rebuild();self.update_line_buttons()
    def rebuild(self):
        self.table.setRowCount(0)
        for x in self.lines:
            r=self.table.rowCount();self.table.insertRow(r);vals=[x['kod'],x['ad'],x['barkod'],self.q(x['stok']),self.q(x['miktar']),x['birim']]
            for c,v in enumerate(vals):self.table.setItem(r,c,QTableWidgetItem(str(v)))
    def save(self):
        src=self.source.currentData();dst=self.target.currentData()
        if not src or not dst:QMessageBox.warning(self,'Transfer','Kaynak ve hedef depoları seçin.');return
        try: _,no=self.db.save_stock_transfer(src,dst,self.date.date().toString('yyyy-MM-dd'),self.lines,self.current_user['id'] if self.current_user else None,self.desc.text().strip())
        except Exception as e:QMessageBox.critical(self,'Transfer',str(e));return
        QMessageBox.information(self,'Transfer Kaydedildi',f'{no} numaralı transfer kaydedildi.');self.accept()
    @staticmethod
    def q(v):return f"{float(v or 0):,.3f}".replace(',','X').replace('.',',').replace('X','.')

class StockTransferHistoryDialog(QDialog):
    def __init__(self,parent,db):
        super().__init__(parent);self.db=db;self.setWindowTitle('Transfer Geçmişi');self.resize(1150,650);root=QVBoxLayout(self);root.addWidget(QLabel('DEPO TRANSFER GEÇMİŞİ'));self.table=QTableWidget(0,9);self.table.setHorizontalHeaderLabels(['No','Transfer No','Tarih','Kaynak Depo','Hedef Depo','Satır','Toplam Miktar','Kullanıcı','Durum']);configure_resizable_table(self.table,'transfer_gecmisi',[55,110,95,190,190,70,120,150,90]);self.table.setEditTriggers(QAbstractItemView.NoEditTriggers);root.addWidget(self.table,1);b=QHBoxLayout();cancel=QPushButton('Transferi İptal Et');cancel.clicked.connect(self.cancel_selected);cancel.setEnabled(getattr(parent,'role_name','').casefold()=='yönetici');close=QPushButton('Kapat');close.clicked.connect(self.accept);b.addWidget(cancel);b.addStretch();b.addWidget(close);root.addLayout(b);self.refresh()
    def refresh(self):
        rows=self.db.list_stock_transfers();self.table.setRowCount(0)
        for i,x in enumerate(rows,1):
            r=self.table.rowCount();self.table.insertRow(r);vals=[i,x['transfer_no'],x['tarih'],f"{x['kaynak_kod']} - {x['kaynak_ad']}",f"{x['hedef_kod']} - {x['hedef_ad']}",x['satir_sayisi'],self.q(x['toplam_miktar']),x['kullanici'] or '',x['durum']]
            for c,v in enumerate(vals):self.table.setItem(r,c,QTableWidgetItem(str(v)))
    def cancel_selected(self):
        row=self.table.currentRow()
        if row<0: QMessageBox.information(self,'Seçim','İptal etmek için bir transfer seçin.'); return
        tr=self.db.conn.execute('SELECT id,durum FROM stok_transferleri WHERE transfer_no=?',(self.table.item(row,1).text(),)).fetchone()
        if not tr:return
        if tr['durum']=='İptal':QMessageBox.information(self,'Transfer','Bu transfer zaten iptal edilmiş.');return
        reason,ok=QInputDialog.getText(self,'Transfer İptali','İptal nedeni:')
        if not ok:return
        if QMessageBox.question(self,'Transfer İptali','Seçilen transferi iptal etmek istediğinizden emin misiniz?\nStok hareketi tersine çevrilecektir.',QMessageBox.Yes|QMessageBox.No,QMessageBox.No)!=QMessageBox.Yes:return
        try:
            uid=getattr(self.parent(),'current_user',None)
            self.db.cancel_stock_transfer(tr['id'], uid['id'] if uid else None, reason.strip())
            self.refresh();QMessageBox.information(self,'İptal','Transfer iptal edildi ve stok etkisi tersine çevrildi.')
        except Exception as exc: QMessageBox.critical(self,'İptal Hatası',str(exc))

    @staticmethod
    def q(v):return f"{float(v or 0):,.3f}".replace(',','X').replace('.',',').replace('X','.')

class OperationLogDialog(QDialog):
    def __init__(self,parent,db):
        super().__init__(parent); self.db=db; self.setWindowTitle('İşlem Logları / Denetim Kaydı'); self.resize(1100,650)
        root=QVBoxLayout(self); root.addWidget(QLabel('İŞLEM LOGLARI / DENETİM KAYDI'))
        self.table=QTableWidget(0,7); self.table.setHorizontalHeaderLabels(['No','İşlem','Referans No','Tarih','Kullanıcı','Açıklama','ID']); configure_resizable_table(self.table,'islem_loglari',[55,150,130,150,160,380,60]); self.table.setEditTriggers(QAbstractItemView.NoEditTriggers); root.addWidget(self.table,1)
        b=QHBoxLayout(); ex=QPushButton("Excel'e Aktar"); ex.clicked.connect(self.export); pr=QPushButton('Yazdır'); pr.clicked.connect(self.print_report); close=QPushButton('Kapat'); close.clicked.connect(self.accept); b.addWidget(ex);b.addWidget(pr);b.addStretch();b.addWidget(close);root.addLayout(b); self.refresh()
    def refresh(self):
        self.table.setRowCount(0)
        for i,x in enumerate(self.db.list_operation_logs(),1):
            r=self.table.rowCount();self.table.insertRow(r);vals=[i,x['islem_turu'],x['referans_no'] or '',x['tarih'],x['kullanici'] or '',x['aciklama'] or '',x['referans_id']]
            for c,v in enumerate(vals):self.table.setItem(r,c,QTableWidgetItem(str(v)))
    def export(self):
        path,_=QFileDialog.getSaveFileName(self,'İşlem Logları','islem_loglari','Excel Çalışma Kitabı (*.xlsx);;CSV Dosyası (*.csv)')
        if not path:return
        h=[self.table.horizontalHeaderItem(c).text() for c in range(self.table.columnCount())]; rows=[[self.table.item(r,c).text() if self.table.item(r,c) else '' for c in range(self.table.columnCount())] for r in range(self.table.rowCount())]
        try:
            if path.lower().endswith('.csv'):
                with open(path,'w',newline='',encoding='utf-8-sig') as f: csv.writer(f,delimiter=';').writerows([h]+rows)
            else:
                import xlsxwriter; wb=xlsxwriter.Workbook(path);ws=wb.add_worksheet('Log');fmt=wb.add_format({'bold':True,'bg_color':'#D9E2F3','border':1})
                for c,v in enumerate(h):ws.write(0,c,v,fmt)
                for r,row in enumerate(rows,1):
                    for c,v in enumerate(row):ws.write(r,c,v)
                wb.close()
            QMessageBox.information(self,'Aktarım','Dosya kaydedildi.')
        except Exception as exc: QMessageBox.critical(self,'Aktarım',str(exc))
    def print_report(self):
        printer=QPrinter(QPrinter.HighResolution);d=QPrintDialog(printer,self)
        if d.exec_()!=QDialog.Accepted:return
        h=[self.table.horizontalHeaderItem(c).text() for c in range(self.table.columnCount())];html=['<html><head><meta charset="utf-8"><style>body{font-family:Arial;font-size:7pt}table{width:100%;border-collapse:collapse}th,td{border:1px solid #777;padding:2px}</style></head><body><h2>İŞLEM LOGLARI / DENETİM KAYDI</h2><table><tr>']+[f'<th>{x}</th>' for x in h]+['</tr>']
        for r in range(self.table.rowCount()):html.append('<tr>'+''.join(f'<td>{self.table.item(r,c).text() if self.table.item(r,c) else ""}</td>' for c in range(self.table.columnCount()))+'</tr>')
        html.append('</table></body></html>');doc=QTextDocument();doc.setHtml(''.join(html));doc.print_(printer)

class ClientProfileDialog(QDialog):
    """PostgreSQL istemci bağlantı profilini parola olmadan dışa/içe aktarır."""
    def __init__(self, parent):
        super().__init__(parent)
        self.setWindowTitle(f"İstemci / Sunucu Profili - {APP_VERSION}")
        self.resize(760, 430)
        self.setMinimumSize(700, 400)
        root = QVBoxLayout(self)
        info = QLabel(
            "İstemci bilgisayarlarına dağıtmak için PostgreSQL bağlantı profilini dışa aktarabilir "
            "veya mevcut bir profili içe alabilirsiniz. Güvenlik nedeniyle PostgreSQL şifresi profil dosyasına yazılmaz."
        )
        info.setWordWrap(True)
        root.addWidget(info)
        form = QFormLayout()
        self.host = QLineEdit(str(APP_SETTINGS.value('postgres/host','localhost') or 'localhost'))
        self.port = QSpinBox(); self.port.setRange(1,65535); self.port.setValue(int(APP_SETTINGS.value('postgres/port',5432) or 5432))
        self.dbname = QLineEdit(str(APP_SETTINGS.value('postgres/dbname','depo_stok') or 'depo_stok'))
        self.user = QLineEdit(str(APP_SETTINGS.value('postgres/user','postgres') or 'postgres'))
        self.sslmode = QComboBox(); self.sslmode.addItems(['prefer','require','verify-ca','verify-full'])
        cur_ssl = str(APP_SETTINGS.value('postgres/sslmode','prefer') or 'prefer')
        idx = self.sslmode.findText(cur_ssl); self.sslmode.setCurrentIndex(idx if idx >= 0 else 0)
        form.addRow('PostgreSQL Host:', self.host)
        form.addRow('Port:', self.port)
        form.addRow('Veritabanı:', self.dbname)
        form.addRow('Kullanıcı:', self.user)
        form.addRow('SSL Mode:', self.sslmode)
        root.addLayout(form)
        self.status = QLabel('Parola profile dahil edilmez.')
        self.status.setWordWrap(True)
        root.addWidget(self.status)
        btns = QHBoxLayout()
        b_test = QPushButton('Bağlantıyı Test Et'); b_export = QPushButton('Profili Dışa Aktar...'); b_import = QPushButton('Profili İçe Al...')
        b_save = QPushButton('Kaydet'); b_close = QPushButton('Kapat')
        for b in (b_test,b_export,b_import,b_save,b_close): b.setMinimumWidth(130)
        btns.addWidget(b_test); btns.addWidget(b_export); btns.addWidget(b_import); btns.addStretch(1); btns.addWidget(b_save); btns.addWidget(b_close)
        root.addLayout(btns)
        b_test.clicked.connect(self.test_connection)
        b_export.clicked.connect(self.export_profile)
        b_import.clicked.connect(self.import_profile)
        b_save.clicked.connect(self.save)
        b_close.clicked.connect(self.reject)

    def profile_data(self):
        return {
            'profile_version': 1,
            'app_version': APP_VERSION,
            'backend': 'postgresql',
            'host': self.host.text().strip() or 'localhost',
            'port': int(self.port.value()),
            'dbname': self.dbname.text().strip() or 'depo_stok',
            'user': self.user.text().strip() or 'postgres',
            'sslmode': self.sslmode.currentText(),
            'password_included': False,
        }

    def export_profile(self):
        path, _ = QFileDialog.getSaveFileName(self, 'İstemci Profilini Kaydet', str(Path.home() / 'depo_stok_client_profile.json'), 'JSON Profil (*.json)')
        if not path: return
        try:
            Path(path).write_text(json.dumps(self.profile_data(), ensure_ascii=False, indent=2), encoding='utf-8')
            self.status.setText(f'Profil kaydedildi: {path}')
            QMessageBox.information(self, 'Başarılı', 'İstemci bağlantı profili kaydedildi.\nParola dosyaya dahil edilmedi.')
        except Exception as exc:
            QMessageBox.critical(self, 'Profil Hatası', str(exc))

    def import_profile(self):
        path, _ = QFileDialog.getOpenFileName(self, 'İstemci Profili Aç', str(Path.home()), 'JSON Profil (*.json)')
        if not path: return
        try:
            data = json.loads(Path(path).read_text(encoding='utf-8'))
            if str(data.get('backend','postgresql')).lower() != 'postgresql':
                raise ValueError('Seçilen profil PostgreSQL çalışma profili değil.')
            self.host.setText(str(data.get('host','localhost')))
            self.port.setValue(int(data.get('port',5432)))
            self.dbname.setText(str(data.get('dbname','depo_stok')))
            self.user.setText(str(data.get('user','postgres')))
            ssl = str(data.get('sslmode','prefer'))
            idx = self.sslmode.findText(ssl); self.sslmode.setCurrentIndex(idx if idx >= 0 else 0)
            self.status.setText('Profil içe alındı. Parola güvenlik nedeniyle alınmadı; mevcut kayıtlı parola korunur.')
            QMessageBox.information(self, 'Profil Alındı', 'Bağlantı bilgileri içe alındı. Kaydetmeden önce bağlantıyı test edebilirsiniz.')
        except Exception as exc:
            QMessageBox.critical(self, 'Profil Hatası', str(exc))

    def test_connection(self):
        try:
            import psycopg2
            password = get_pg_password()
            conn = psycopg2.connect(host=self.host.text().strip(), port=self.port.value(), dbname=self.dbname.text().strip(), user=self.user.text().strip(), password=password, sslmode=self.sslmode.currentText(), connect_timeout=8)
            cur = conn.cursor(); cur.execute('SELECT current_database(), current_user, version()'); row = cur.fetchone(); cur.close(); conn.close()
            ver = ' '.join(str(row[2]).split())
            if len(ver) > 160: ver = ver[:157] + '...'
            self.status.setText(f'Bağlantı başarılı: {row[0]} / {row[1]}\n{ver}')
            QMessageBox.information(self, 'Başarılı', 'PostgreSQL sunucusuna bağlantı başarılı.')
        except Exception as exc:
            self.status.setText('Bağlantı başarısız. Ayrıntı uyarı penceresinde gösterildi.')
            QMessageBox.critical(self, 'PostgreSQL Bağlantı Hatası', str(exc))

    def save(self):
        APP_SETTINGS.setValue('database/backend', 'postgresql')
        APP_SETTINGS.setValue('postgres/host', self.host.text().strip() or 'localhost')
        APP_SETTINGS.setValue('postgres/port', int(self.port.value()))
        APP_SETTINGS.setValue('postgres/dbname', self.dbname.text().strip() or 'depo_stok')
        APP_SETTINGS.setValue('postgres/user', self.user.text().strip() or 'postgres')
        APP_SETTINGS.setValue('postgres/sslmode', self.sslmode.currentText())
        APP_SETTINGS.sync()
        QMessageBox.information(self, 'Kaydedildi', 'PostgreSQL istemci bağlantı profili kaydedildi. Değişikliğin etkili olması için programı yeniden başlatın.')
        self.accept()



class DatabaseMigrationHistoryDialog(QDialog):
    """Uygulanmış veritabanı migration geçmişini gösterir."""
    def __init__(self, parent, db):
        super().__init__(parent)
        self.db = db
        self.setWindowTitle(f"Veritabanı Migration Geçmişi - {APP_VERSION}")
        self.resize(1080, 560)
        root = QVBoxLayout(self)
        title = QLabel("VERİTABANI MİGRATION GEÇMİŞİ")
        title.setObjectName("dialogTitle")
        root.addWidget(title)
        try:
            row = db.conn.execute("SELECT current_version FROM db_schema_version WHERE id=1").fetchone()
            schema = int(row[0]) if row else 1
        except Exception:
            schema = 1
        info = QLabel(f"Uygulama: {APP_VERSION}   •   Veritabanı şema sürümü: <b>V{schema}</b>   •   Hedef sürüm: <b>V{DB_SCHEMA_VERSION}</b>")
        info.setWordWrap(True); root.addWidget(info)
        self.table = QTableWidget(0, 8)
        self.table.setHorizontalHeaderLabels(["No", "Başlangıç", "Bitiş", "Geçiş", "Durum", "Uygulama", "Yedek", "Ayrıntı"])
        configure_resizable_table(self.table, "db_migration_history", [55,150,150,90,90,100,280,260])
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        root.addWidget(self.table, 1)
        b = QHBoxLayout()
        refresh = QPushButton("Yenile"); refresh.clicked.connect(self.refresh)
        close = QPushButton("Kapat"); close.clicked.connect(self.accept)
        b.addWidget(refresh); b.addStretch(); b.addWidget(close); root.addLayout(b)
        self.refresh()

    def refresh(self):
        self.table.setRowCount(0)
        try:
            rows = self.db.conn.execute("SELECT id,from_version,to_version,started_at,finished_at,status,app_version,backup_path,details FROM db_migration_history ORDER BY id DESC").fetchall()
        except Exception:
            rows = []
        for row in rows:
            rr=self.table.rowCount(); self.table.insertRow(rr)
            vals=[row['id'],row['started_at'] or '',row['finished_at'] or '',f"V{row['from_version']} → V{row['to_version']}",row['status'],row['app_version'] or '',row['backup_path'] or '',row['details'] or '']
            for c,v in enumerate(vals): self.table.setItem(rr,c,QTableWidgetItem(str(v)))


class UpdateSettingsDialog(QDialog):
    """İsteğe bağlı güncelleme kaynağı/manifest ayarları."""
    def __init__(self,parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"Güncelleme Ayarları - {APP_VERSION}")
        self.resize(760,420); self.setMinimumSize(700,380)
        root=QVBoxLayout(self)
        title=QLabel("UYGULAMA GÜNCELLEME AYARLARI"); title.setObjectName("dialogTitle"); root.addWidget(title)
        info=QLabel("Güncelleme kaynağı olarak HTTPS üzerinden JSON manifest adresi kullanılır. Kaynak adresi tanımlanmamışsa otomatik kontrol yapılmaz.")
        info.setWordWrap(True); root.addWidget(info)
        form=QFormLayout()
        self.url=QLineEdit(str(APP_SETTINGS.value("update/manifest_url","") or "")); self.url.setPlaceholderText("https://sunucu/adres/depostok-update.json")
        self.auto=QCheckBox("Program açılışında otomatik güncelleme kontrolü yap")
        self.auto.setChecked((APP_SETTINGS.value("update/auto_check",False) or False) in (True,"true","1","True"))
        form.addRow("Manifest URL",self.url); root.addLayout(form); root.addWidget(self.auto)
        self.status=QLabel(""); self.status.setWordWrap(True); root.addWidget(self.status); root.addStretch()
        b=QHBoxLayout(); save=QPushButton("Kaydet"); close=QPushButton("Kapat"); save.clicked.connect(self.save); close.clicked.connect(self.reject); b.addStretch(); b.addWidget(save); b.addWidget(close); root.addLayout(b)
    def save(self):
        url=self.url.text().strip()
        if url and not (url.lower().startswith("https://") or url.lower().startswith("http://")):
            QMessageBox.warning(self,"URL","Güncelleme manifest adresi http:// veya https:// ile başlamalıdır."); return
        APP_SETTINGS.setValue("update/manifest_url",url); APP_SETTINGS.setValue("update/auto_check",self.auto.isChecked()); APP_SETTINGS.sync()
        self.status.setText("Güncelleme ayarları kaydedildi."); QMessageBox.information(self,"Kaydedildi","Güncelleme ayarları kaydedildi."); self.accept()


class UpdateCheckWorker(QObject):
    finished = pyqtSignal(object, object)

    def __init__(self, url):
        super().__init__()
        self.url = url

    def run(self):
        import urllib.request
        try:
            req = urllib.request.Request(self.url, headers={"User-Agent": "TUA-DepoStok/" + APP_VERSION})
            with urllib.request.urlopen(req, timeout=UPDATE_CHECK_TIMEOUT) as r:
                data = json.loads(r.read().decode("utf-8"))
            if not data.get("version") or not data.get("download_url"):
                raise ValueError("Manifest içinde version ve download_url alanları zorunludur.")
            self.finished.emit(data, None)
        except Exception as exc:
            self.finished.emit(None, exc)


class UpdateDialog(QDialog):
    def __init__(self,parent=None,manifest=None):
        super().__init__(parent); self.manifest=manifest or {}
        self.setWindowTitle(f"Güncelleme - {APP_VERSION}"); self.resize(760,500)
        root=QVBoxLayout(self); title=QLabel("PROGRAM GÜNCELLEMESİ"); title.setObjectName("dialogTitle"); root.addWidget(title)
        ver=str(self.manifest.get("version","")); notes=str(self.manifest.get("notes","") or "")
        lbl=QLabel(f"Mevcut sürüm: <b>{APP_VERSION}</b><br>Yeni sürüm: <b>{ver}</b><br><br>{notes}"); lbl.setWordWrap(True); root.addWidget(lbl)
        self.status=QLabel("Güncelleme dosyası indirilmeye hazır."); self.status.setWordWrap(True); root.addWidget(self.status)
        row=QHBoxLayout(); self.download=QPushButton("Güncellemeyi İndir ve Kur"); close=QPushButton("Kapat"); self.download.clicked.connect(self.download_and_install); close.clicked.connect(self.reject); row.addStretch(); row.addWidget(self.download); row.addWidget(close); root.addLayout(row)
    def download_and_install(self):
        import urllib.request, hashlib, subprocess
        url=str(self.manifest.get("download_url","")).strip(); sha=str(self.manifest.get("sha256","")).strip().lower()
        if not url or not (url.lower().startswith("https://") or url.lower().startswith("http://")):
            QMessageBox.critical(self,"Güncelleme","Güvenilir bir HTTP/HTTPS indirme adresi bulunamadı."); return
        if not sha:
            QMessageBox.warning(self,"Güncelleme güvenliği","Manifest SHA-256 değeri içermediği için otomatik kurulum güvenlik nedeniyle durduruldu."); return
        target_dir=Path(os.environ.get("LOCALAPPDATA",str(Path.home()))) / "TUA Bilisim" / "DepoStok" / "updates"; target_dir.mkdir(parents=True,exist_ok=True)
        ver=re.sub(r"[^A-Za-z0-9_.-]","_",str(self.manifest.get("version")))
        target=target_dir/f"DepoStok_Setup_{ver}.exe"
        try:
            self.status.setText("Güncelleme indiriliyor..."); QApplication.processEvents()
            with urllib.request.urlopen(urllib.request.Request(url,headers={"User-Agent":"TUA-DepoStok/"+APP_VERSION}),timeout=30) as r, open(target,"wb") as f:
                while True:
                    chunk=r.read(1024*256)
                    if not chunk: break
                    f.write(chunk)
            h=hashlib.sha256(target.read_bytes()).hexdigest().lower()
            if h!=sha:
                target.unlink(missing_ok=True); raise ValueError("SHA-256 doğrulaması başarısız.")
            if QMessageBox.question(self,"Güncelleme Hazır",f"{target}\n\nGüncelleme doğrulandı. Program kapatılıp kurulum başlatılsın?",QMessageBox.Yes|QMessageBox.No,QMessageBox.Yes)!=QMessageBox.Yes:return
            subprocess.Popen([str(target)],close_fds=True); QApplication.quit()
        except Exception as exc:
            QMessageBox.critical(self,"Güncelleme Hatası",str(exc))


def check_for_updates(parent, interactive=True):
    url=str(APP_SETTINGS.value("update/manifest_url","") or "").strip()
    if not url:
        if interactive: QMessageBox.information(parent,"Güncelleme","Güncelleme kaynağı tanımlı değil. Ayarlar → Güncelleme Ayarları bölümünden manifest adresini tanımlayabilirsiniz.")
        return
    try:
        import urllib.request
        req=urllib.request.Request(url,headers={"User-Agent":"TUA-DepoStok/"+APP_VERSION})
        with urllib.request.urlopen(req,timeout=UPDATE_CHECK_TIMEOUT) as r:
            data=json.loads(r.read().decode("utf-8"))
        remote=str(data.get("version","")).strip()
        if remote and is_newer_version(remote):
            UpdateDialog(parent,data).exec_()
        elif interactive:
            QMessageBox.information(parent,"Güncelleme","Kullandığınız sürüm güncel. (%s)" % APP_VERSION)
    except Exception as exc:
        if interactive: QMessageBox.warning(parent,"Güncelleme Kontrolü",f"Güncelleme kontrolü yapılamadı:\n{exc}")



class PeriodStockReportsDialog(QDialog):
    """V1.37.0: Dönem bazlı stok karşılaştırma ve yıl hareket raporları."""
    def __init__(self, parent, db):
        super().__init__(parent)
        self.db = db
        self.setWindowTitle(f"Dönem ve Yıl Bazlı Stok Raporları - {APP_VERSION}")
        self.resize(1450, 780)
        self.setMinimumSize(1180, 680)
        root = QVBoxLayout(self)
        title = QLabel("DÖNEM / YIL BAZLI STOK RAPORLARI")
        title.setObjectName("dialogTitle")
        root.addWidget(title)
        info = QLabel(
            "Dönem açılış-kapanış bakiyelerini, dönemler arasındaki değişimleri ve seçilen yıl/dönemdeki "
            "giriş-çıkış hareketlerini karşılaştırır. Veriler mevcut stok hareketleri ve dönem devir snapshotlarından okunur."
        )
        info.setWordWrap(True)
        root.addWidget(info)

        self.tabs = QTabWidget()
        root.addWidget(self.tabs, 1)
        self._build_comparison_tab()
        self._build_year_tab()
        self._build_department_tab()
        self._load_periods()

    def _periods(self):
        try:
            return self.db.list_periods()
        except Exception:
            return []

    def _fmt_qty(self, value):
        try:
            return f"{float(value or 0):,.3f}".replace(',', 'X').replace('.', ',').replace('X', '.')
        except Exception:
            return str(value or '')

    def _fmt_money(self, value):
        try:
            return f"{float(value or 0):,.2f} TL".replace(',', 'X').replace('.', ',').replace('X', '.')
        except Exception:
            return str(value or '')

    def _fill_combo(self, combo, rows, label_fn):
        combo.clear(); combo.addItem("Tümü", None)
        for r in rows:
            combo.addItem(label_fn(r), r["id"])

    def _build_comparison_tab(self):
        tab = QWidget(); root = QVBoxLayout(tab)
        f = QGridLayout()
        self.c_period_a = QComboBox(); self.c_period_b = QComboBox(); self.c_depo = QComboBox()
        self.c_nonzero = QCheckBox("Sadece hareket/stok bulunanlar"); self.c_nonzero.setChecked(True)
        self.c_compare = QPushButton("Karşılaştır"); self.c_excel = QPushButton("Excel'e Aktar"); self.c_print = QPushButton("Yazdır")
        f.addWidget(QLabel("Dönem A"), 0, 0); f.addWidget(self.c_period_a, 0, 1)
        f.addWidget(QLabel("Dönem B"), 0, 2); f.addWidget(self.c_period_b, 0, 3)
        f.addWidget(QLabel("Depo"), 0, 4); f.addWidget(self.c_depo, 0, 5)
        f.addWidget(self.c_nonzero, 0, 6)
        f.addWidget(self.c_compare, 0, 7); f.addWidget(self.c_excel, 0, 8); f.addWidget(self.c_print, 0, 9)
        root.addLayout(f)
        self.c_table = QTableWidget(0, 10)
        self.c_table.setHorizontalHeaderLabels([
            "No", "Depo", "Ürün Kodu", "Ürün", "Birim",
            "A Açılış", "A Kapanış", "B Açılış", "B Kapanış", "Değişim"
        ])
        configure_resizable_table(self.c_table, "donem_karsilastirma", [55, 180, 110, 250, 80, 100, 100, 100, 100, 110])
        self.c_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        root.addWidget(self.c_table, 1)
        self.c_total = QLabel("Toplam kayıt: 0")
        root.addWidget(self.c_total)
        self.tabs.addTab(tab, "Açılış / Kapanış Karşılaştırma")
        self.c_compare.clicked.connect(self.refresh_comparison)
        self.c_excel.clicked.connect(lambda: self.export_table(self.c_table, "Donem_Karsilastirma"))
        self.c_print.clicked.connect(lambda: self.print_table(self.c_table, "Dönem Açılış / Kapanış Karşılaştırma"))

    def _build_year_tab(self):
        tab = QWidget(); root = QVBoxLayout(tab)
        f = QGridLayout()
        self.y_period = QComboBox(); self.y_depo = QComboBox(); self.y_type = QComboBox()
        self.y_type.addItems(["Tümü", "Giriş", "Çıkış", "İade"])
        self.y_search = QLineEdit(); self.y_search.setPlaceholderText("Ürün kodu / adı...")
        self.y_query = QPushButton("Sorgula"); self.y_excel = QPushButton("Excel'e Aktar"); self.y_print = QPushButton("Yazdır")
        f.addWidget(QLabel("Dönem"), 0, 0); f.addWidget(self.y_period, 0, 1)
        f.addWidget(QLabel("Depo"), 0, 2); f.addWidget(self.y_depo, 0, 3)
        f.addWidget(QLabel("İşlem"), 0, 4); f.addWidget(self.y_type, 0, 5)
        f.addWidget(QLabel("Ürün"), 0, 6); f.addWidget(self.y_search, 0, 7)
        f.addWidget(self.y_query, 0, 8); f.addWidget(self.y_excel, 0, 9); f.addWidget(self.y_print, 0, 10)
        root.addLayout(f)
        self.y_table = QTableWidget(0, 8)
        self.y_table.setHorizontalHeaderLabels(["No", "Depo", "Hareket", "Ürün Sayısı", "Toplam Miktar", "Net", "Ortalama Birim Fiyat", "Hareket Değeri"])
        configure_resizable_table(self.y_table, "yil_hareket_ozeti", [55, 220, 90, 110, 120, 120, 150, 140])
        self.y_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        root.addWidget(self.y_table, 1)
        self.y_total = QLabel("Toplam kayıt: 0")
        root.addWidget(self.y_total)
        self.tabs.addTab(tab, "Yıl / Dönem Hareket Özeti")
        connect_live_text_filter(self.y_search, self.refresh_year)
        self.y_query.clicked.connect(self.refresh_year)
        self.y_excel.clicked.connect(lambda: self.export_table(self.y_table, "Yil_Hareket_Ozeti"))
        self.y_print.clicked.connect(lambda: self.print_table(self.y_table, "Yıl / Dönem Hareket Özeti"))

    def _build_department_tab(self):
        tab = QWidget(); root = QVBoxLayout(tab)
        f = QGridLayout()
        self.d_period = QComboBox(); self.d_depo = QComboBox(); self.d_dep = QComboBox(); self.d_alt = QComboBox()
        self.d_query = QPushButton("Sorgula"); self.d_excel = QPushButton("Excel'e Aktar"); self.d_print = QPushButton("Yazdır")
        f.addWidget(QLabel("Dönem"), 0, 0); f.addWidget(self.d_period, 0, 1)
        f.addWidget(QLabel("Depo"), 0, 2); f.addWidget(self.d_depo, 0, 3)
        f.addWidget(QLabel("Departman"), 0, 4); f.addWidget(self.d_dep, 0, 5)
        f.addWidget(QLabel("Alt Birim"), 0, 6); f.addWidget(self.d_alt, 0, 7)
        f.addWidget(self.d_query, 0, 8); f.addWidget(self.d_excel, 0, 9); f.addWidget(self.d_print, 0, 10)
        root.addLayout(f)
        self.d_table = QTableWidget(0, 7)
        self.d_table.setHorizontalHeaderLabels(["No", "Depo", "Departman", "Alt Birim", "Çıkış Hareketi", "Çıkış Miktarı", "Yaklaşık Değer"])
        configure_resizable_table(self.d_table, "yil_departman_tuketim", [55, 200, 200, 180, 120, 120, 140])
        self.d_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        root.addWidget(self.d_table, 1)
        self.d_total = QLabel("Toplam kayıt: 0")
        root.addWidget(self.d_total)
        self.tabs.addTab(tab, "Departman / Alt Birim Tüketimi")
        self.d_query.clicked.connect(self.refresh_department)
        self.d_excel.clicked.connect(lambda: self.export_table(self.d_table, "Yil_Departman_Tuketim"))
        self.d_print.clicked.connect(lambda: self.print_table(self.d_table, "Yıl Departman / Alt Birim Tüketimi"))
        self.d_dep.currentIndexChanged.connect(self._load_report_alt_units)

    def _load_report_alt_units(self):
        self.d_alt.clear(); self.d_alt.addItem("Tümü", None)
        dep_id = self.d_dep.currentData()
        if dep_id:
            try:
                rows = self.db.subunits(dep_id, include_inactive=False)
            except Exception:
                rows = []
            for r in rows:
                self.d_alt.addItem(f"{r['kod']} - {r['ad']}", r['id'])

    def _load_periods(self):
        periods = self._periods()
        def label(r):
            return f"{r['kod']} - {r['ad']} ({r['baslangic_tarihi']} → {r['bitis_tarihi']})"
        for combo in (self.c_period_a, self.c_period_b, self.y_period, self.d_period):
            combo.clear()
            for r in periods:
                combo.addItem(label(r), r['id'])
        if periods:
            if len(periods) > 1:
                self.c_period_a.setCurrentIndex(min(1, len(periods)-1))
                self.c_period_b.setCurrentIndex(0)
            self.y_period.setCurrentIndex(0)
            self.d_period.setCurrentIndex(0)
        self._fill_combo(self.c_depo, self.db.warehouses(), lambda r: f"{r['kod']} - {r['ad']}")
        self._fill_combo(self.y_depo, self.db.warehouses(), lambda r: f"{r['kod']} - {r['ad']}")
        self._fill_combo(self.d_depo, self.db.warehouses(), lambda r: f"{r['kod']} - {r['ad']}")
        self._fill_combo(self.d_dep, self.db.departments(), lambda r: f"{r['kod']} - {r['ad']}")
        self._load_report_alt_units()
        if periods:
            self.refresh_comparison(); self.refresh_year(); self.refresh_department()

    def _period_by_id(self, pid):
        if not pid: return None
        for p in self._periods():
            if int(p['id']) == int(pid): return p
        return None

    def _opening_map(self, period_id, warehouse_id=None):
        params=[period_id]
        sql="SELECT depo_id,urun_id,miktar,birim_maliyet,stok_degeri FROM stok_donem_acilis_stoklari WHERE donem_id=?"
        if warehouse_id is not None:
            sql += " AND depo_id=?"; params.append(warehouse_id)
        rows=self.db.conn.execute(sql,params).fetchall()
        data={(int(r['depo_id']),int(r['urun_id'])): (float(r['miktar'] or 0), float(r['birim_maliyet'] or 0)) for r in rows}
        return data

    def _closing_map(self, period, warehouse_id=None):
        data={}
        if not period: return data
        close_id = period['kapanis_id']
        if close_id:
            params=[close_id]
            sql="SELECT depo_id,urun_id,miktar,birim_maliyet,stok_degeri FROM stok_devir_satirlari WHERE kapanis_id=?"
            if warehouse_id is not None:
                sql += " AND depo_id=?"; params.append(warehouse_id)
            rows=self.db.conn.execute(sql,params).fetchall()
            data={(int(r['depo_id']),int(r['urun_id'])): (float(r['miktar'] or 0), float(r['birim_maliyet'] or 0)) for r in rows}
            if rows:
                return data
        # Kapanış snapshotı yoksa hareketlerden dönem sonu bakiyesi hesapla.
        deps = self.db.warehouses()
        if warehouse_id is not None: deps=[d for d in deps if d['id']==warehouse_id]
        products=self.db.conn.execute("SELECT id,alis_fiyati FROM urunler WHERE aktif=1").fetchall()
        end=period['bitis_tarihi']
        for d in deps:
            for p in products:
                val=self.db.conn.execute("SELECT COALESCE(SUM(CASE WHEN islem_tipi IN ('Giriş','İade') THEN miktar ELSE -miktar END),0) FROM stok_hareketleri WHERE depo_id=? AND urun_id=? AND tarih<=?",(d['id'],p['id'],end)).fetchone()[0] or 0
                if abs(float(val)) > 1e-12:
                    data[(int(d['id']),int(p['id']))]=(float(val),float(p['alis_fiyati'] or 0))
        return data

    def _movement_balance_before(self, start_date, warehouse_id=None, product_id=None):
        q="SELECT depo_id,urun_id,COALESCE(SUM(CASE WHEN islem_tipi IN ('Giriş','İade') THEN miktar ELSE -miktar END),0) AS qty FROM stok_hareketleri WHERE tarih<?"
        params=[start_date]
        if warehouse_id is not None: q+=" AND depo_id=?"; params.append(warehouse_id)
        if product_id is not None: q+=" AND urun_id=?"; params.append(product_id)
        q+=" GROUP BY depo_id,urun_id"
        return {(int(r['depo_id']),int(r['urun_id'])):float(r['qty'] or 0) for r in self.db.conn.execute(q,params).fetchall()}

    def refresh_comparison(self):
        a=self._period_by_id(self.c_period_a.currentData()); b=self._period_by_id(self.c_period_b.currentData())
        self.c_table.setRowCount(0)
        if not a or not b:
            self.c_total.setText("Toplam kayıt: 0"); return
        wid=self.c_depo.currentData()
        oa=self._opening_map(a['id'],wid); ob=self._opening_map(b['id'],wid)
        ca=self._closing_map(a,wid); cb=self._closing_map(b,wid)
        keys=set(oa)|set(ob)|set(ca)|set(cb)
        dep_map={int(d['id']):d for d in self.db.warehouses()}
        prod_rows=self.db.conn.execute("SELECT id,kod,ad,birim,min_seviye,max_seviye FROM urunler WHERE aktif=1").fetchall()
        prod_map={int(p['id']):p for p in prod_rows}
        for key in sorted(keys):
            d_id,p_id=key; p=prod_map.get(p_id); d=dep_map.get(d_id)
            if not p or not d: continue
            a_open=oa.get(key,(0,0))[0]; a_close=ca.get(key,(0,0))[0]; b_open=ob.get(key,(0,0))[0]; b_close=cb.get(key,(0,0))[0]
            change=b_close-a_close
            if self.c_nonzero.isChecked() and all(abs(float(x))<1e-12 for x in (a_open,a_close,b_open,b_close,change)): continue
            row=self.c_table.rowCount(); self.c_table.insertRow(row)
            vals=[row+1,f"{d['kod']} - {d['ad']}",p['kod'],p['ad'],p['birim'] or '',self._fmt_qty(a_open),self._fmt_qty(a_close),self._fmt_qty(b_open),self._fmt_qty(b_close),self._fmt_qty(change)]
            for c,v in enumerate(vals): self.c_table.setItem(row,c,QTableWidgetItem(str(v)))
            if change < 0:
                brush=QColor(Qt.red).lighter(185)
            elif change > 0:
                brush=QColor(Qt.green).lighter(185)
            else:
                brush=None
            if brush:
                for c in range(self.c_table.columnCount()): self.c_table.item(row,c).setData(Qt.BackgroundRole,brush)
        self.c_total.setText(f"Toplam kayıt: {self.c_table.rowCount()}")

    def _period_dates(self, period):
        if period: return period['baslangic_tarihi'], period['bitis_tarihi']
        return None,None

    def refresh_year(self):
        p=self._period_by_id(self.y_period.currentData()); self.y_table.setRowCount(0)
        if not p: self.y_total.setText("Toplam kayıt: 0"); return
        start,end=self._period_dates(p); wid=self.y_depo.currentData(); typ=self.y_type.currentText(); search=self.y_search.text().strip()
        params=[start,end]; q="""SELECT sh.depo_id,d.kod AS depo_kod,d.ad AS depo_ad,
                   COUNT(*) AS hareket_sayisi,
                   COUNT(DISTINCT sh.urun_id) AS urun_sayisi,
                   COALESCE(SUM(sh.miktar),0) AS toplam_miktar,
                   COALESCE(SUM(CASE WHEN sh.islem_tipi IN ('Giriş','İade') THEN sh.miktar ELSE -sh.miktar END),0) AS net_miktar,
                   COALESCE(SUM(sh.miktar*COALESCE(sh.birim_fiyat,0)),0) AS hareket_degeri,
                   COALESCE(AVG(NULLIF(sh.birim_fiyat,0)),0) AS ort_fiyat
                FROM stok_hareketleri sh JOIN depolar d ON d.id=sh.depo_id
                LEFT JOIN urunler u ON u.id=sh.urun_id
                WHERE sh.tarih>=? AND sh.tarih<=?"""
        if wid is not None: q+=" AND sh.depo_id=?"; params.append(wid)
        if typ != 'Tümü': q+=" AND sh.islem_tipi=?"; params.append(typ)
        if search: q+=" AND (u.kod LIKE ? OR u.ad LIKE ?)"; params.extend([f"%{search}%",f"%{search}%"])
        q+=" GROUP BY sh.depo_id,d.kod,d.ad ORDER BY d.ad"
        rows=self.db.conn.execute(q,params).fetchall()
        for i,r in enumerate(rows,1):
            vals=[i,f"{r['depo_kod']} - {r['depo_ad']}",r['hareket_sayisi'],r['urun_sayisi'],self._fmt_qty(r['toplam_miktar']),self._fmt_qty(r['net_miktar']),self._fmt_money(r['ort_fiyat']),self._fmt_money(r['hareket_degeri'])]
            rr=self.y_table.rowCount(); self.y_table.insertRow(rr)
            for c,v in enumerate(vals): self.y_table.setItem(rr,c,QTableWidgetItem(str(v)))
        self.y_total.setText(f"Toplam kayıt: {self.y_table.rowCount()}")

    def refresh_department(self):
        p=self._period_by_id(self.d_period.currentData()); self.d_table.setRowCount(0)
        if not p: self.d_total.setText("Toplam kayıt: 0"); return
        start,end=self._period_dates(p); wid=self.d_depo.currentData(); depid=self.d_dep.currentData(); altid=self.d_alt.currentData()
        params=[start,end]
        q="""SELECT sh.depo_id,d.kod AS depo_kod,d.ad AS depo_ad,
                      sh.departman_id,dep.kod AS dep_kod,dep.ad AS dep_ad,
                      sh.alt_birim_id,alt.kod AS alt_kod,alt.ad AS alt_ad,
                      COUNT(*) AS hareket_sayisi,
                      COALESCE(SUM(sh.miktar),0) AS toplam_miktar,
                      COALESCE(SUM(sh.miktar*COALESCE(sh.birim_fiyat,0)),0) AS toplam_deger
               FROM stok_hareketleri sh
               JOIN depolar d ON d.id=sh.depo_id
               LEFT JOIN departmanlar dep ON dep.id=sh.departman_id
               LEFT JOIN departman_alt_birimleri alt ON alt.id=sh.alt_birim_id
               WHERE sh.tarih>=? AND sh.tarih<=? AND sh.islem_tipi='Çıkış'"""
        if wid is not None: q+=" AND sh.depo_id=?"; params.append(wid)
        if depid is not None: q+=" AND sh.departman_id=?"; params.append(depid)
        if altid is not None: q+=" AND sh.alt_birim_id=?"; params.append(altid)
        q+=" GROUP BY sh.depo_id,d.kod,d.ad,sh.departman_id,dep.kod,dep.ad,sh.alt_birim_id,alt.kod,alt.ad ORDER BY d.ad,dep.ad,alt.ad"
        rows=self.db.conn.execute(q,params).fetchall()
        for i,r in enumerate(rows,1):
            vals=[i,f"{r['depo_kod']} - {r['depo_ad']}",f"{r['dep_kod']} - {r['dep_ad']}" if r['dep_kod'] else '',f"{r['alt_kod']} - {r['alt_ad']}" if r['alt_kod'] else '',r['hareket_sayisi'],self._fmt_qty(r['toplam_miktar']),self._fmt_money(r['toplam_deger'])]
            rr=self.d_table.rowCount(); self.d_table.insertRow(rr)
            for c,v in enumerate(vals): self.d_table.setItem(rr,c,QTableWidgetItem(str(v)))
        self.d_total.setText(f"Toplam kayıt: {self.d_table.rowCount()}")

    def export_table(self, table, title):
        path,_=QFileDialog.getSaveFileName(self,"Excel'e Aktar",title.replace(' ','_').lower(),"Excel Çalışma Kitabı (*.xlsx);;CSV Dosyası (*.csv)")
        if not path:return
        try:
            headers=[table.horizontalHeaderItem(c).text() if table.horizontalHeaderItem(c) else f"Sütun {c+1}" for c in range(table.columnCount())]
            rows=[[table.item(r,c).text() if table.item(r,c) else '' for c in range(table.columnCount())] for r in range(table.rowCount())]
            if path.lower().endswith('.xlsx'):
                import xlsxwriter
                wb=xlsxwriter.Workbook(path); ws=wb.add_worksheet(title[:31]); fmt=wb.add_format({'bold':True,'bg_color':'#D9E2F3','border':1})
                for c,h in enumerate(headers): ws.write(0,c,h,fmt)
                for r,row in enumerate(rows,1):
                    for c,v in enumerate(row): ws.write(r,c,v)
                for c,h in enumerate(headers):
                    mx=max([len(str(h))]+[len(str(row[c])) for row in rows[:200]])
                    ws.set_column(c,c,max(10,min(38,mx+2)))
                ws.freeze_panes(1,0); ws.autofilter(0,0,len(rows),max(0,len(headers)-1)); wb.close()
            else:
                import csv
                with open(path,'w',newline='',encoding='utf-8-sig') as f:
                    w=csv.writer(f,delimiter=';'); w.writerow(headers); w.writerows(rows)
            QMessageBox.information(self,'Aktarım Tamamlandı',f"Rapor kaydedildi:\n{path}")
        except Exception as exc:
            QMessageBox.critical(self,'Aktarım Hatası',str(exc))

    def print_table(self, table, title):
        printer=QPrinter(QPrinter.HighResolution); dlg=QPrintDialog(printer,self)
        if dlg.exec_()!=QDialog.Accepted:return
        headers=[table.horizontalHeaderItem(c).text() if table.horizontalHeaderItem(c) else f"Sütun {c+1}" for c in range(table.columnCount())]
        html=f"<h2>{title}</h2><table border='1' cellspacing='0' cellpadding='3'><tr>" + ''.join(f"<th>{h}</th>" for h in headers) + '</tr>'
        for r in range(table.rowCount()):
            html+='<tr>'+''.join(f"<td>{table.item(r,c).text() if table.item(r,c) else ''}</td>" for c in range(table.columnCount()))+'</tr>'
        html+='</table>'
        doc=QTextDocument(); doc.setHtml(html); doc.print_(printer)

# ---------------------------------------------------------------------------
# Kullanıcı Yardımı / Program Kullanım Kılavuzu
# Ekran görselleri uygulama içinde çizilen örnek arayüzlerdir. Örnek kayıtlar
# temsili olup gerçek veritabanına yazılmaz.
# ---------------------------------------------------------------------------
def _help_topic(category, title, summary, steps, fields=None, tables=None, tip="", actions=None):
    return {
        "category": category,
        "title": title,
        "summary": summary,
        "steps": list(steps or []),
        "fields": list(fields or []),
        "tables": list(tables or []),
        "tip": tip,
        "actions": list(actions or ["Yeni", "Düzenle", "Sorgula", "Kapat"]),
    }


_HELP_TOPICS = [
    _help_topic("Başlangıç", "Giriş ve Ana Ekran",
        "Ana ekran; hızlı işlemlere, modüllere, sistem özetlerine ve üst menülerdeki tüm işlevlere ulaşmak için kullanılır.",
        ["Programı açın ve size tanımlanmış kullanıcı adı/şifreyle giriş yapın.", "Üst menülerden ilgili işlemi seçin. Araç çubuğu ve Hızlı İşlemler alanı sık kullanılan ekranlara kestirme sağlar.", "Toplam Ürün, Toplam Depo, Cari Hesap ve Stok Hareketi kartları genel durumu özetler.", "Ekranın altındaki sürüm ve veritabanı bağlantı bilgisini kontrol edin."],
        fields=[("Oturum", "Yönetici"), ("Program Sürümü", "V1.38.0"), ("Veritabanı", "Aktif bağlantı"), ("Hızlı İşlem", "Ürün Girişi")],
        tables=[{"title":"Örnek ana ekran özeti", "headers":["Gösterge", "Örnek değer", "Açıklama"], "rows":[["Toplam Ürün", "1.248", "Aktif ürün kartları"],["Toplam Depo", "4", "Aktif depolar"],["Cari Hesap", "36", "Aktif cari kayıtları"],["Stok Hareketi", "8.572", "Kaydedilmiş hareketler"]]}],
        tip="Kullanıcı yetkileri menüleri sınırlar. Görmediğiniz veya tıklayamadığınız bir işlem için yöneticinizle görüşün.", actions=["Ürün Tanımla", "Ürün Girişi", "Ürün Çıkışı", "Raporlar"]),

    _help_topic("Ürünler", "Ürün Kartları",
        "Ürün Kartları; stokta izlenecek her ürünün kod, ad, grup, barkod, marka/model, birim, fiyat ve min./maks. stok bilgilerini tanımlar.",
        ["Ürünler → Ürün Kartları ekranını açıp Yeni ürün seçin.", "Ürün Kodu ve Ürün Adı alanlarını doldurun; ürün grubu, ürün tipi ve birimi seçin.", "Barkod ve Üretici Kodu kullanılıyorsa doğru girin. Aynı barkod/üretici kodu başka üründe kullanılmamalıdır.", "Min. Seviye, Max. Seviye ve Raf/Lokasyon bilgilerini girin.", "Ürün grubu Demirbaş ise Demirbaş No alanını doldurun veya uyarıda Devam et seçeneğini kullanın.", "Kaydedin. Düzenlemek için listeden satırı seçip Düzenle'yi kullanın."],
        fields=[("Ürün Kodu", "SK000123"), ("Ürün Adı", "SSD 1 TB NVMe"), ("Ürün Grubu", "G004 - DEMİRBAŞ"), ("Barkod Kodu", "8691234567890"), ("Üretici Kodu", "SSD-1TB-01"), ("Üretici", "Örnek Teknoloji"), ("Ürün Tipi", "DEPOLAMA"), ("Marka", "Samsung"), ("Model", "990 EVO 1 TB"), ("Birim", "AD - ADET"), ("Alış Fiyatı", "2.450,00"), ("Satış Fiyatı", "2.890,00"), ("Min. Seviye", "2"), ("Max. Seviye", "25"), ("Raf / Lokasyon", "B-03-02"), ("Demirbaş No", "DEM-2026-0048"), ("Aktif", "Evet")],
        tables=[{"title":"Ürün kartları örneği", "headers":["Ürün Kodu", "Ürün Adı", "Grup", "Birim", "Durum"], "rows":[["SK000121", "Notebook", "BİLGİSAYAR", "ADET", "Aktif"],["SK000122", "Kablosuz Mouse", "AKSESUAR", "ADET", "Aktif"],["SK000123", "SSD 1 TB NVMe", "DEMİRBAŞ", "ADET", "Aktif"]]}],
        tip="Ürün kartı silmek yerine, stok hareketi olan kartlarda mümkünse Aktif/Pasif özelliğini kullanın; geçmiş kayıtlar korunur.", actions=["Yeni", "Düzenle", "Kopyala", "Sil", "Excel'e Aktar"]),

    _help_topic("Ürünler", "Ürün Grupları",
        "Ürün grupları, ürün kartlarını sınıflandırır ve rapor/filtrelerde kullanılmasını sağlar.",
        ["Ürünler → Ürün Grupları veya Tanımlar → Ürün Grupları ekranını açın.", "Grup Kodu ve Grup Adı alanlarını doldurun.", "Kaydet ile yeni grup ekleyin; listedeki satırı seçip Düzenle ile güncelleyin.", "Geçmiş hareketlerde kullanılan gruplar için fiziksel silme yerine pasifleştirme tercih edilir."],
        fields=[("Grup Kodu", "G004"), ("Grup Adı", "DEMİRBAŞ"), ("Durum", "Aktif")],
        tables=[{"title":"Örnek ürün grupları", "headers":["No", "Kod", "Ad", "Durum"], "rows":[["1", "G001", "SARF MALZEME", "AKTİF"],["2", "G002", "BİLGİSAYAR", "AKTİF"],["3", "G004", "DEMİRBAŞ", "AKTİF"]]}],
        tip="Ürün kartlarında kullanılan grup adlarını sonradan değiştirmek rapor filtrelerini etkileyebilir; değişiklikten önce kontrol edin."),

    _help_topic("Ürünler", "Barkodlu İşlemler",
        "Barkodlu İşlemler menüsü barkodla ürün bulup hızlı giriş/çıkış hareketi oluşturmak için kullanılır.",
        ["Barkodlu İşlemler ekranını açın ve işlem türünü seçin.", "İşlem yapılacak depoyu ve fiş tarihini belirleyin.", "Barkodu okuyucu ile okutun veya barkod alanına girin.", "Ürün bulununca miktarı kontrol edin; aynı fişe başka barkodlar ekleyebilirsiniz.", "Fişi kaydetmeden önce depo, ürün ve miktarları gözden geçirin."],
        fields=[("İşlem Türü", "Barkodlu Giriş"), ("Fiş No", "BG-2026-0042"), ("Tarih", "14.10.2026"), ("Depo", "Bilgi İşlem Depo"), ("Barkod", "8691234567890"), ("Ürün", "SSD 1 TB NVMe"), ("Miktar", "2"), ("Birim", "ADET")],
        tables=[{"title":"Fişe eklenen ürünler", "headers":["Barkod", "Ürün", "Miktar", "Birim"], "rows":[["8691234567890", "SSD 1 TB NVMe", "2", "ADET"],["8691234567807", "USB-C Adaptör", "5", "ADET"]]}],
        tip="Barkod okuyucu genellikle klavye gibi davranır. Barkod okutulunca ürünün ve miktarın doğru olduğundan emin olun.", actions=["Barkod Oku", "Ürün Ekle", "Satırı Sil", "Fişi Kaydet"]),

    _help_topic("Cari Hesaplar", "Cari Hesap Tanımları",
        "Cari hesaplar; tedarikçi, firma veya işlemle ilişkili diğer tarafların bilgilerinin tutulduğu tanımlardır.",
        ["Cari Hesaplar → Cari Hesap Tanımları ekranını açın ve Yeni kaydı seçin.", "Cari kodu program tarafından önerilebilir; ihtiyaç halinde kullanıcı tarafından düzenlenebilir.", "Cari Ünvan alanını ve gerekli iletişim/açıklama alanlarını doldurun.", "Kaydedin. Aynı ünvanın ikinci kez tanımlanması durumunda uyarıyı kontrol edin."],
        fields=[("Cari Kodu", "CRI0034"), ("Cari Ünvan", "Örnek Bilgisayar Ltd. Şti."), ("Yetkili", "Ayşe Yılmaz"), ("Telefon", "0212 555 12 34"), ("E-posta", "satinalma@ornek.com"), ("Vergi Dairesi", "Merkez"), ("Vergi No", "1234567890"), ("Durum", "Aktif")],
        tables=[{"title":"Cari kayıt örneği", "headers":["Cari Kodu", "Cari Ünvan", "Yetkili", "Durum"], "rows":[["CRI0032", "ABC Teknoloji", "Mehmet Demir", "AKTİF"],["CRI0033", "Örnek Kırtasiye", "Zeynep Kaya", "AKTİF"],["CRI0034", "Örnek Bilgisayar Ltd. Şti.", "Ayşe Yılmaz", "AKTİF"]]}],
        tip="Cari kodunu değiştirmeden önce eski fişlerin cari bağlantısını koruduğunuzdan emin olun."),

    _help_topic("İşlemler", "Ürün Giriş",
        "Ürün Giriş fişi, seçili depoya yeni stok ekler. Giriş kaydı miktar ve fiş bilgileriyle birlikte saklanır.",
        ["İşlemler → Ürün Giriş ekranını açın.", "Fiş No, tarih ve giriş yapılacak depoyu seçin; gerekiyorsa cari ve açıklamayı girin.", "Ürün alanına kod/adın bir bölümünü yazın; canlı filtrelenen listeden doğru ürünü seçin.", "Miktarı girip Ürün Ekle'ye basın. Fişe eklenecek diğer ürünler için tekrarlayın.", "Satırları kontrol edin ve fişi kaydedin."],
        fields=[("Fiş No", "GIR-2026-0148"), ("Tarih", "14.10.2026"), ("Depo", "Bilgi İşlem Depo"), ("Cari", "Örnek Bilgisayar Ltd. Şti."), ("Ürün Arama", "SSD 1 TB"), ("Seçilen Ürün", "SK000123 - SSD 1 TB NVMe"), ("Miktar", "2"), ("Teslim Eden", "Ahmet Kaya"), ("Açıklama", "Yeni alım")],
        tables=[{"title":"Giriş fişi satırları", "headers":["Kod", "Ürün", "Miktar", "Birim"], "rows":[["SK000123", "SSD 1 TB NVMe", "2", "ADET"],["SK000124", "USB-C Adaptör", "5", "ADET"]]}],
        tip="Fiş kaydedildikten sonra stok bakiyesi değişir. Yanlış depoya veya yanlış miktarla kayıt yapmamak için kaydetmeden önce son kontrol yapın.", actions=["Ürün Ekle", "Satırı Sil", "Fişi Kaydet", "İptal"]),

    _help_topic("İşlemler", "Ürün Çıkış",
        "Ürün Çıkış fişi, seçili depodan tüketim, teslim veya departmana kullanım amacıyla stok düşer.",
        ["İşlemler → Ürün Çıkış ekranını açın.", "Fiş No, tarih ve çıkış deposunu seçin.", "Malzeme bir departmana/alt birime teslim ediliyorsa ilgili alanları seçin; Teslim Eden ve Teslim Alan bilgilerini girin.", "Ürün ve miktarı ekleyin. Programın gösterdiği kullanılabilir stok miktarını kontrol edin.", "Fişi kaydedip fiş numarasını not edin."],
        fields=[("Fiş No", "CIK-2026-0089"), ("Tarih", "14.10.2026"), ("Çıkış Deposu", "Bilgi İşlem Depo"), ("Departman", "Bilgi İşlem"), ("Alt Birim", "DU01 - Sunucu Odası"), ("Teslim Eden", "Ahmet Kaya"), ("Teslim Alan", "Mehmet Demir"), ("Ürün", "SSD 1 TB NVMe"), ("Miktar", "1")],
        tables=[{"title":"Çıkış satırları", "headers":["Kod", "Ürün", "Mevcut", "Çıkış", "Kalan"], "rows":[["SK000123", "SSD 1 TB NVMe", "8", "1", "7"],["SK000124", "USB-C Adaptör", "20", "3", "17"]]}],
        tip="Çıkış fişi stok azaltır. Teslim bilgileri daha sonra departman tüketim ve demirbaş raporlarını etkileyebileceği için dikkatle girilmelidir.", actions=["Ürün Ekle", "Satırı Sil", "Fişi Kaydet", "İptal"]),

    _help_topic("İşlemler", "Barkodlu Giriş",
        "Barkodlu Giriş, barkodu okutularak depoya ürün kabul edilmesini sağlar.",
        ["Barkodlu Giriş ekranında tarih, depo ve fiş bilgilerini kontrol edin.", "Barkodu okutun. Ürün bulunmazsa ürün kartında barkod bilgisini kontrol edin.", "Miktarı girin; birden fazla ürün varsa yeni barkodu okutun.", "Satırları kontrol ederek fişi kaydedin."],
        fields=[("Fiş No", "BG-2026-0042"), ("Depo", "Sarf Depo"), ("Barkod", "8691234567890"), ("Ürün", "SSD 1 TB NVMe"), ("Miktar", "2"), ("Tarih", "14.10.2026")],
        tables=[{"title":"Barkod okutulan ürünler", "headers":["Barkod", "Ürün", "Miktar"], "rows":[["8691234567890", "SSD 1 TB NVMe", "2"],["8691234567807", "USB-C Adaptör", "5"]]}],
        tip="Yanlış barkod okutulduysa kaydetmeden önce yanlış satırı listeden kaldırın."),

    _help_topic("İşlemler", "Barkodlu Çıkış",
        "Barkodlu Çıkış, depodan ürün vermeyi barkod okutma yoluyla hızlandırır.",
        ["Barkodlu Çıkış ekranında çıkış deposunu ve tarih bilgilerini seçin.", "Ürünleri tek tek okutun; her satırda ürün adı ve miktarı kontrol edin.", "Departman/alt birime teslim yapılıyorsa uygun teslim alanlarını doldurun.", "Stok kontrolünden sonra fişi kaydedin."],
        fields=[("Fiş No", "BC-2026-0031"), ("Çıkış Deposu", "Bilgi İşlem Depo"), ("Barkod", "8691234567890"), ("Ürün", "SSD 1 TB NVMe"), ("Miktar", "1"), ("Departman", "Bilgi İşlem"), ("Alt Birim", "DU01 - Sunucu Odası"), ("Teslim Alan", "Mehmet Demir")],
        tables=[{"title":"Barkodlu çıkış satırları", "headers":["Ürün", "Mevcut Stok", "Çıkış"], "rows":[["SSD 1 TB NVMe", "8", "1"],["USB-C Adaptör", "20", "2"]]}],
        tip="Çıkış fişini kaydetmeden önce depo ve miktarları kontrol edin."),

    _help_topic("İşlemler", "Fiş Listesi / Fiş Yazdırma",
        "Kaydedilen stok fişlerini bulmak, incelemek, yazdırmak veya uygun fiş işlemlerini yönetmek için kullanılır.",
        ["Fiş Listesi / Fiş Yazdırma ekranını açın.", "Tarih, fiş numarası, depo veya hareket türü filtrelerini kullanarak fişi bulun.", "İlgili fişi seçin, detaylarını inceleyin.", "Yazdır seçeneğiyle fişi yazıcıya gönderin; yazdırmadan önce önizleme ve sayfa yönünü kontrol edin."],
        fields=[("Fiş Türü", "Ürün Giriş"), ("Fiş No", "GIR-2026-0148"), ("Başlangıç", "01.10.2026"), ("Bitiş", "14.10.2026"), ("Depo", "Tüm Depolar"), ("Durum", "Kaydedildi")],
        tables=[{"title":"Bulunan fişler", "headers":["Tarih", "Fiş No", "Tür", "Depo", "Durum"], "rows":[["14.10.2026", "GIR-2026-0148", "Giriş", "Bilgi İşlem Depo", "Kaydedildi"],["13.10.2026", "CIK-2026-0089", "Çıkış", "Bilgi İşlem Depo", "Kaydedildi"]]}],
        tip="Bir fişten emin değilseniz önce fiş numarası ve detayını doğrulayın. İptal/düzeltme imkânları fişin durumuna göre değişebilir.", actions=["Sorgula", "Detay", "Yazdır", "Kapat"]),

    _help_topic("Stok", "Depolar",
        "Depolar, stok miktarlarının ayrı ayrı izleneceği fiziksel veya mantıksal depolama yerlerini tanımlar.",
        ["Stok → Depolar ekranını açın.", "Depo Kodu ve Depo Adı girin; aktif olması gereken depoda Aktif kutusunu işaretleyin.", "Kaydet ile ekleyin. Düzenleme için listeden depo seçin.", "Stok hareketleri kullanmış olan depoları silmek yerine pasifleştirmeyi değerlendirin."],
        fields=[("Depo Kodu", "D001"), ("Depo Adı", "Bilgi İşlem Depo"), ("Durum", "Aktif")],
        tables=[{"title":"Örnek depo listesi", "headers":["No", "Kod", "Depo Adı", "Durum"], "rows":[["1", "D001", "Bilgi İşlem Depo", "AKTİF"],["2", "D002", "Sarf Depo", "AKTİF"],["3", "D003", "Arşiv Depo", "AKTİF"]]}],
        tip="Stok hareketleri depo bazında tutulur. Transfer işleminde kaynak ve hedef deponun doğru seçilmesi gerekir."),

    _help_topic("Stok", "Dönem Yönetimi",
        "Stok dönemleri, belirli tarih aralığındaki hareketlerin ve dönem kapanışlarının düzenli izlenmesine yardımcı olur.",
        ["Stok → Dönem Yönetimi ekranını açın.", "Dönem kodu/adı, başlangıç ve bitiş tarihlerini kontrol edin.", "Yeni dönemi oluştururken mevcut dönemlerle tarih çakışması olup olmadığını kontrol edin.", "Rapor ve devir işlemlerinde doğru dönemin seçildiğinden emin olun."],
        fields=[("Dönem Kodu", "2026"), ("Dönem Adı", "2026 Mali Yılı"), ("Başlangıç", "01.01.2026"), ("Bitiş", "31.12.2026"), ("Durum", "Açık")],
        tables=[{"title":"Dönem kayıtları", "headers":["Kod", "Dönem", "Başlangıç", "Bitiş", "Durum"], "rows":[["2025", "2025 Mali Yılı", "01.01.2025", "31.12.2025", "Kapalı"],["2026", "2026 Mali Yılı", "01.01.2026", "31.12.2026", "Açık"]]}],
        tip="Dönem kapanışı öncesinde veritabanı yedeği alın ve tarih aralığının doğru olduğunu doğrulayın."),

    _help_topic("Stok", "Stok Dönem Kapanışı / Devir",
        "Bu ekran seçilen dönem için kapanış/devir kontrolü yapar ve dönem sonu stok bakiyesini yeni döneme devretmeye yardımcı olur.",
        ["Kapanış öncesinde giriş/çıkış fişlerinin, transferlerin ve sayım farklarının tamamlandığını doğrulayın.", "Kaynak dönemi ve hedef dönemi seçin.", "Önce kontrol/önizleme çalıştırın; eksik veya tutarsız kayıtları düzeltin.", "Özet miktar ve değerleri kontrol ettikten sonra kapanışı/deviri kaydedin.", "Sonucu Kapanış / Devir Geçmişi ekranından doğrulayın."],
        fields=[("Kaynak Dönem", "2025 Mali Yılı"), ("Hedef Dönem", "2026 Mali Yılı"), ("İşlem", "Stok Devir"), ("Kontrol", "Tamamlandı"), ("Toplam Ürün", "1.248"), ("Onay", "Kaydetmeden önce önizleme")],
        tables=[{"title":"Örnek devir özeti", "headers":["Depo", "Ürün", "Kapanış Miktarı", "Devir Miktarı"], "rows":[["Bilgi İşlem Depo", "SSD 1 TB NVMe", "8", "8"],["Sarf Depo", "USB-C Adaptör", "24", "24"]]}],
        tip="Bu işlem stok dönem bakiyelerini etkiler. Önce yedek alın; önizleme ve hedef dönem doğru değilse kaydetmeyin.", actions=["Kontrol Et", "Önizleme", "Devir/Kapanış", "İptal"]),

    _help_topic("Stok", "Kapanış / Devir Geçmişi",
        "Daha önce yapılmış dönem kapanışı ve devir işlemlerinin listesi, ayrıntısı ve kullanılabilir iptal işlemlerini gösterir.",
        ["Kapanış / Devir Geçmişi ekranını açın.", "Dönem, tarih veya işlem numarasına göre ilgili kaydı bulun.", "Satırı seçip Detay ile işlem özetini kontrol edin.", "İptal seçeneği etkinse kapsamını ve uyarısını dikkatle okuyup ancak doğru olduğunda onaylayın."],
        fields=[("Dönem", "2025 → 2026"), ("İşlem Türü", "Stok Devir"), ("İşlem Tarihi", "31.12.2025"), ("İşlemi Yapan", "Yönetici"), ("Durum", "Tamamlandı")],
        tables=[{"title":"Kapanış/devir geçmişi", "headers":["Tarih", "Dönem", "İşlem", "Durum"], "rows":[["31.12.2025", "2025 → 2026", "Stok Devir", "Tamamlandı"],["31.12.2024", "2024 → 2025", "Yıl Sonu Kapanışı", "Tamamlandı"]]}],
        tip="Bir işlemi iptal etmeden önce stok bakiyelerinin ve ilişkili raporların nasıl etkileneceğini değerlendirin."),

    _help_topic("Stok", "Kapsamlı Stok Raporları",
        "Stok özeti, depo özeti ve departman tüketimi gibi kapsamlı analizleri aynı pencerede sunar.",
        ["Stok → Kapsamlı Stok Raporları ekranını açın.", "İlgili sekmeyi seçin: stok özeti, depo özeti veya departman tüketimi.", "Tarih/depo/departman filtrelerini doldurup Sorgula veya Yenile düğmesine basın.", "Sonuçları karşılaştırın; gerekirse Excel'e aktarın ya da yazdırın."],
        fields=[("Rapor", "Departman Tüketimi"), ("Başlangıç", "01.10.2026"), ("Bitiş", "14.10.2026"), ("Depo", "Tüm Depolar"), ("Departman", "Bilgi İşlem")],
        tables=[{"title":"Örnek departman tüketimi", "headers":["Departman", "Ürün", "Miktar", "Birim"], "rows":[["Bilgi İşlem", "SSD 1 TB NVMe", "3", "ADET"],["Bilgi İşlem", "USB-C Adaptör", "12", "ADET"],["D Kliniği", "Ethernet Kablosu", "20", "ADET"]]}],
        tip="Tarih aralığı ve rapor sekmesini kontrol edin. Departman tüketimi raporu, teslim/çıkış bilgilerinin doğruluğuna bağlıdır.", actions=["Sorgula", "Excel'e Aktar", "Yazdır", "Kapat"]),

    _help_topic("Stok", "Stok Sayım",
        "Stok Sayım, fiziksel sayılan miktarları sistem bakiyesiyle karşılaştırmak için sayım fişi oluşturur.",
        ["Stok → Stok Sayım ekranını açın ve sayım yapılacak depoyu seçin.", "Sayım tarihini girin; ürünleri listeye ekleyin veya arama ile bulun.", "Her satıra fiziksel olarak saydığınız miktarı yazın. Sayılan miktarı sistemde görünen miktarla karıştırmayın.", "Farkları kontrol edin ve sayım fişini kaydedin.", "Sayım farkı/otomatik stok düzeltmesi ile ilgili onayları dikkatli okuyun."],
        fields=[("Sayım No", "SAY-2026-0016"), ("Tarih", "14.10.2026"), ("Depo", "Sarf Depo"), ("Sayım Sorumlusu", "Mehmet Demir"), ("Durum", "Taslak / Kontrol ediliyor")],
        tables=[{"title":"Örnek sayım satırları", "headers":["Ürün", "Sistem", "Fiziksel Sayım", "Fark"], "rows":[["USB-C Adaptör", "24", "23", "-1"],["Ethernet Kablosu", "50", "52", "+2"],["SSD 1 TB NVMe", "8", "8", "0"]]}],
        tip="Sayım değerlerini kaydetmeden önce ikinci kez kontrol edin. Sayım farkları stok bakiyesini değiştirebileceği için kayıt öncesi yedek almak iyi uygulamadır.", actions=["Ürün Ekle", "Farkları Kontrol Et", "Sayımı Kaydet", "Kapat"]),

    _help_topic("Stok", "Sayım Geçmişi",
        "Kaydedilmiş sayımları, sayım numaralarını ve sonuç ayrıntılarını incelemek için kullanılır.",
        ["Sayım Geçmişi ekranını açın.", "Tarih, depo veya sayım numarası ile arama yapın.", "Satırı seçip Detay ile sayım satırlarını ve farkları inceleyin.", "Gerekirse geçmişi Excel'e aktarın veya yazdırın."],
        fields=[("Depo Filtresi", "Sarf Depo"), ("Tarih Aralığı", "01.10.2026 – 14.10.2026"), ("Sayım No", "SAY-2026-0016")],
        tables=[{"title":"Sayım geçmişi", "headers":["Sayım No", "Tarih", "Depo", "Ürün Sayısı", "Durum"], "rows":[["SAY-2026-0016", "14.10.2026", "Sarf Depo", "35", "Kaydedildi"],["SAY-2026-0015", "30.09.2026", "Bilgi İşlem Depo", "42", "Kaydedildi"]]}],
        tip="Geçmiş bir sayımın iptal/düzeltme işlemleri stok bakiyelerini etkileyebilir; önce ayrıntıyı inceleyin."),

    _help_topic("Stok", "Sayım Fark Raporu",
        "Sayım ile sistem miktarı arasında fark olan ürünleri bulur ve farkların incelenmesini sağlar.",
        ["Sayım Fark Raporu ekranını açın.", "Sayım numarası, depo veya tarih aralığını seçin.", "Sorgulayın; pozitif fark fazla sayılan, negatif fark eksik sayılan miktarı ifade eder.", "Farkları fiziksel kayıtlarla doğrulayın ve gerekiyorsa Excel'e aktarın."],
        fields=[("Sayım No", "SAY-2026-0016"), ("Depo", "Sarf Depo"), ("Fark Filtresi", "Sadece farklı satırlar")],
        tables=[{"title":"Örnek sayım farkı", "headers":["Ürün", "Sistem", "Sayım", "Fark"], "rows":[["USB-C Adaptör", "24", "23", "-1"],["Ethernet Kablosu", "50", "52", "+2"]]}],
        tip="Fark değerinin işaretini kontrol edin: eksi miktar sistem stokunun sayımdan fazla, artı miktar sayımın sistemden fazla olduğunu gösterir."),

    _help_topic("Stok", "Depolar Arası Transfer",
        "Transfer, ürün miktarını bir depodan diğerine taşır. Kaynak depoda stok azalırken hedef depoda artar.",
        ["Stok → Depolar Arası Transfer ekranını açın.", "Kaynak ve hedef depoyu seçin; aynı depo kaynak ve hedef olarak kullanılmamalıdır.", "Ürün arama alanına barkod, ürün kodu veya ürün adının bir bölümünü yazın. Liste her karakterle daralır.", "Listeden ürünü seçip miktarı ekleyin. Yanlış satır eklenirse seçerek Düzelt veya Sil kullanın.", "Tüm satırları kontrol edip transfer fişini kaydedin."],
        fields=[("Transfer No", "TRF-2026-0027"), ("Tarih", "14.10.2026"), ("Kaynak Depo", "Bilgi İşlem Depo"), ("Hedef Depo", "Sarf Depo"), ("Ürün Arama", "SSD"), ("Seçilen Ürün", "SK000123 - SSD 1 TB NVMe"), ("Miktar", "2")],
        tables=[{"title":"Transfer satırları", "headers":["Kod", "Ürün", "Miktar", "Birim"], "rows":[["SK000123", "SSD 1 TB NVMe", "2", "ADET"],["SK000124", "USB-C Adaptör", "4", "ADET"]]}],
        tip="Transferi kaydetmeden önce kaynak/hedef depo ve her ürün miktarını kontrol edin. Kaydedilen transferin geçmişini Transfer Geçmişi ekranından izleyebilirsiniz.", actions=["Ürün Ekle", "Düzelt", "Sil", "Transferi Kaydet"]),

    _help_topic("Stok", "Transfer Geçmişi",
        "Depolar arasında yapılmış transfer fişlerini ve satır detaylarını gösterir.",
        ["Transfer Geçmişi ekranını açın.", "Tarih, kaynak depo, hedef depo veya transfer numarasına göre filtreleyin.", "Satırı seçerek transfer ayrıntısını görüntüleyin.", "İptal işlemi sunuluyorsa onay mesajını ve stok etkisini okuyun."],
        fields=[("Transfer No", "TRF-2026-0027"), ("Kaynak Depo", "Bilgi İşlem Depo"), ("Hedef Depo", "Sarf Depo"), ("Tarih", "14.10.2026")],
        tables=[{"title":"Transfer geçmişi", "headers":["Tarih", "Transfer No", "Kaynak", "Hedef", "Durum"], "rows":[["14.10.2026", "TRF-2026-0027", "Bilgi İşlem Depo", "Sarf Depo", "Kaydedildi"],["13.10.2026", "TRF-2026-0026", "Arşiv Depo", "Bilgi İşlem Depo", "Kaydedildi"]]}],
        tip="Transferi yalnızca bir tarafta değil, hem kaynak hem hedef depo stoklarında kontrol edin."),

    _help_topic("Stok", "Stok Durumu",
        "Seçilen depodaki ürünlerin anlık stok miktarlarını ve ürün bilgilerini gösterir.",
        ["Stok → Stok Durumu ekranını açın.", "Depo ve gerekiyorsa ürün grubu seçin.", "Ürün kodu/adı, barkod veya marka/model bilgisiyle arama yapın.", "Sıfır stokluları göstermek istiyorsanız ilgili seçeneği işaretleyin.", "Sonuçları kontrol ederek raporlayın veya dışa aktarın."],
        fields=[("Depo", "Bilgi İşlem Depo"), ("Ürün Grubu", "Tüm Gruplar"), ("Arama", "SSD"), ("Sıfır Stoklular", "İşaretli değil")],
        tables=[{"title":"Stok durumu örneği", "headers":["Kod", "Ürün", "Depo", "Mevcut", "Birim"], "rows":[["SK000123", "SSD 1 TB NVMe", "Bilgi İşlem Depo", "8", "ADET"],["SK000124", "USB-C Adaptör", "Bilgi İşlem Depo", "20", "ADET"]]}],
        tip="Stoklar depo bazındadır. Tüm depoların toplamını arıyorsanız uygun rapor ekranını kullanın."),

    _help_topic("Stok", "Depo Raf / Lokasyonları",
        "Depo içindeki bölüm, koridor, raf, kat ve göz adreslerini tanımlar; ürün miktarlarını fiziksel lokasyonlara dağıtır ve lokasyonlar arası taşımayı kaydeder.",
        ["Tanımlar → Depo Raf / Lokasyonları ekranını açın.", "Lokasyon Tanımları sekmesinde depo seçin; lokasyon kodu ve adını girin. Bölüm, koridor, raf, kat, göz ve barkod alanlarını ihtiyaca göre doldurun.", "Kaydet ile lokasyonu oluşturun. Etiket Yazdır seçeneği lokasyon kodu ve adres bilgisini yazdırır (makine-okunur QR/barkod görseli bu sürümde henüz üretilmez).", "Ürün Yerleşimi sekmesinde depo ve ürünü seçin; dağıtılmamış stok miktarından hedef lokasyona miktar yerleştirin.", "Lokasyonlar arası taşıma için tablodan kaynak lokasyonu seçin, hedef lokasyonu ve miktarı girip Seçili Lokasyondan Taşı düğmesine basın. Lokasyondan Dağıtımı Kaldır seçeneği miktarı raf adresinden çıkarıp dağıtılmamış stok havuzuna alır.", "Lokasyon Hareket Geçmişi ekranından son yerleşim ve taşıma işlemlerini kontrol edin."],
        fields=[("Depo", "Bilgi İşlem Depo"), ("Lokasyon Kodu", "A-01-01"), ("Bölüm", "A Blok"), ("Koridor", "A"), ("Raf", "01"), ("Kat", "01"), ("Göz", "01"), ("Barkod", "A-01-01")],
        tables=[{"title":"Örnek lokasyon yerleşimi", "headers":["Ürün", "Lokasyon", "Yerleşik", "Depo Stoku", "Dağıtılmamış"], "rows":[["Klavye", "A-01-01", "20", "25", "5"],["Mouse", "A-01-02", "15", "15", "0"]]}],
        tip="Lokasyonlara dağıtılan miktar ana stok bakiyesinden ayrı bir fiziksel adresleme bilgisidir. Stok giriş/çıkış fişleri ana depo bakiyesini günceller; lokasyon yerleşimi otomatik değişmez. Çıkış veya transfer sonrasında yerleşim miktarlarını kontrol edin; gerekirse Lokasyondan Dağıtımı Kaldır ile dağıtılmamış havuza alın. Yerleşim toplamı depo stok bakiyesini aşmamalıdır.", actions=["Lokasyon Tanımla", "Stok Yerleştir", "Lokasyon Taşı", "Dağıtımı Kaldır", "Etiket Yazdır"]),

    _help_topic("Stok", "Stok Hareketleri",
        "Bir ürünün giriş, çıkış, transfer ve diğer stok hareketlerini tarih sırasıyla incelemeyi sağlar.",
        ["Stok → Stok Hareketleri ekranını açın.", "Ürün arama alanından ürün seçin veya ürün kod/adı girin.", "Tarih aralığı, depo ve hareket tipi filtrelerini kullanın.", "Sorgula ile sonuçları alın; ilgili satırın Detay seçeneğinden fiş bilgilerini inceleyin.", "Filtrelenmiş hareketleri Excel'e aktarabilir veya yazdırabilirsiniz."],
        fields=[("Ürün", "SK000123 - SSD 1 TB NVMe"), ("Başlangıç", "01.10.2026"), ("Bitiş", "14.10.2026"), ("Depo", "Tüm Depolar"), ("Hareket Türü", "Tümü")],
        tables=[{"title":"Hareket örneği", "headers":["Tarih", "Fiş No", "Tür", "Depo", "Giriş", "Çıkış"], "rows":[["14.10.2026", "GIR-0148", "Giriş", "Bilgi İşlem Depo", "5", "0"],["14.10.2026", "TRF-0027", "Transfer", "Bilgi İşlem Depo", "0", "2"],["13.10.2026", "CIK-0089", "Çıkış", "Bilgi İşlem Depo", "0", "1"]]}],
        tip="Ürün seçimi ve tarih filtresi boş kalırsa sonuçlar kapsamlı olabilir; aramayı daraltarak başlayın.", actions=["Sorgula", "Detay", "Excel'e Aktar", "Yazdır"]),

    _help_topic("Raporlar", "Rapor Merkezi",
        "Rapor Merkezi ürün, tarih aralığı ve hareket raporlarını tek yerde toplar; farklı sekmelerle stok analizini yapabilirsiniz.",
        ["Raporlar → Rapor Merkezi ekranını açın.", "Ürün Raporu, İki Tarih Arası Stok veya Ürün Hareket Raporu sekmesini seçin.", "Uygun ürün/depo/tarih filtrelerini belirleyin ve Sorgula düğmesine basın.", "Min/Max Uyarıları, Eksiye Düşenler ve Bakiyesiz Ürünler seçenekleriyle istisnai stokları inceleyin.", "Sonuçları Excel'e aktarın veya yazdırın."],
        fields=[("Rapor", "Ürün Hareket Raporu"), ("Ürün", "SK000123 - SSD 1 TB NVMe"), ("Başlangıç", "01.10.2026"), ("Bitiş", "14.10.2026"), ("Depo", "Tüm Depolar")],
        tables=[{"title":"Rapor Merkezi örnek sonuç", "headers":["Ürün Kodu", "Ürün Adı", "Giriş", "Çıkış", "Bakiye"], "rows":[["SK000123", "SSD 1 TB NVMe", "5", "3", "8"],["SK000124", "USB-C Adaptör", "10", "4", "20"]]}],
        tip="Raporun tarih aralığı, depo ve sekmesini dışa aktarmadan önce tekrar kontrol edin.", actions=["Sorgula", "Excel'e Aktar", "Yazdır", "Kapat"]),

    _help_topic("Raporlar", "Demirbaş Listesi",
        "Demirbaş Listesi, demirbaş grubundaki ürünleri depodaki bakiyeleriyle ve departman/alt birime teslim bilgileriyle inceler.",
        ["Raporlar → Demirbaş Listesi ekranını açın.", "Depo ve ürün grubu filtrelerini belirleyin; arama alanına ürün kodu, adı, barkod, marka veya model yazabilirsiniz.", "Departman seçildiğinde Alt Birim listesi o departmana göre daralır. İsterseniz tüm departmanları/alt birimleri seçili bırakın.", "Sıfır stokluları dahil edip etmeyeceğinizi belirleyin.", "Gösterilecek kolonları seçin; tabloda depo ve teslim kayıt türünü ayırt edin.", "Excel'e Aktar veya Yazdır ile aynı sütun seçimlerini rapora aktarın."],
        fields=[("Ürün Grubu", "G004 - DEMİRBAŞ"), ("Depo", "Tüm Depolar"), ("Departman", "Bilgi İşlem"), ("Alt Birim", "DU01 - Sunucu Odası"), ("Arama", "SSD"), ("Sıfır Stoklular", "Dahil değil")],
        tables=[{"title":"Örnek demirbaş listesi", "headers":["Ürün Kodu", "Ürün", "Kayıt Türü", "Depo", "Departman", "Alt Birim", "Miktar"], "rows":[["SK000123", "SSD 1 TB NVMe", "Depoda", "Bilgi İşlem Depo", "—", "—", "8"],["SK000130", "Masaüstü Bilgisayar", "Departmana Teslim", "Bilgi İşlem Depo", "Bilgi İşlem", "DU01 - Sunucu Odası", "1"]]}],
        tip="Teslim edilen miktarlar, departmana ilişkilendirilmiş çıkış kayıtlarından hesaplanır. İade departmanla ilişkilendirilmiyorsa teslim toplamından otomatik düşmeyebilir; tutarı fişlerle doğrulayın.", actions=["Sorgula", "Kolonları Seç", "Excel'e Aktar", "Yazdır"]),

    _help_topic("Raporlar", "Dönem Stok Raporları",
        "Dönem bazında stok karşılaştırması, yıl hareketleri ve departman tüketimi gibi dönem raporlarını gösterir.",
        ["Raporlar → Dönem Stok Raporları ekranını açın.", "Karşılaştırma, yıl özeti veya departman sekmesini seçin.", "Rapor dönemini ve varsa depo/departman/ürün filtrelerini belirleyin.", "Sorgulayın ve dönemler arasındaki miktar/değer farklarını kontrol edin.", "Gerekirse Excel'e aktarın veya yazdırın."],
        fields=[("Rapor Sekmesi", "Dönem Karşılaştırma"), ("Kaynak Dönem", "2025"), ("Karşılaştırılan Dönem", "2026"), ("Depo", "Tüm Depolar"), ("Departman", "Tüm Departmanlar")],
        tables=[{"title":"Dönem karşılaştırma örneği", "headers":["Ürün", "2025 Kapanış", "2026 Mevcut", "Fark"], "rows":[["SSD 1 TB NVMe", "6", "8", "+2"],["USB-C Adaptör", "28", "24", "-4"]]}],
        tip="Dönem tanımları ve kapanış/devir bilgileri doğru değilse karşılaştırma yanlış yorumlanabilir."),

    _help_topic("Raporlar", "Ürün Raporu",
        "Ürün Raporu, ürün kartları ile stok bilgilerini filtrelerle listelemek için kullanılır.",
        ["Rapor Merkezi içinden Ürün Raporu sekmesine geçin veya Raporlar → Ürün Raporu menüsünü kullanın.", "Ürün adı/kodu, grup, depo ya da stok seviyesi gibi filtreleri ayarlayın.", "Sorgula ile sonuçları listeleyin.", "Excel'e aktarmadan önce gereken sütunların görünür olduğunu kontrol edin."],
        fields=[("Ürün Arama", "SSD"), ("Grup", "DEMİRBAŞ"), ("Depo", "Bilgi İşlem Depo"), ("Stok Filtresi", "Tümü")],
        tables=[{"title":"Ürün raporu örneği", "headers":["Kod", "Ürün", "Grup", "Birim", "Mevcut"], "rows":[["SK000123", "SSD 1 TB NVMe", "DEMİRBAŞ", "ADET", "8"],["SK000130", "Masaüstü Bilgisayar", "DEMİRBAŞ", "ADET", "3"]]}],
        tip="Ürün Raporu ile stok hareket raporu farklıdır: bu rapor kart/bakiye odaklıdır."),

    _help_topic("Raporlar", "İki Tarih Arası Stok",
        "Seçilen iki tarih arasındaki stok durumunu ve hareketlerden oluşan farkları incelemeye yarar.",
        ["İki Tarih Arası Stok raporunu açın.", "Başlangıç ve bitiş tarihlerini girin.", "Ürün/depo filtrelerini seçin ve sorgulayın.", "Sonuçları seçilen tarih aralığı bağlamında yorumlayın; gerekiyorsa Excel'e aktarın."],
        fields=[("Başlangıç Tarihi", "01.10.2026"), ("Bitiş Tarihi", "14.10.2026"), ("Depo", "Sarf Depo"), ("Ürün Arama", "USB-C")],
        tables=[{"title":"Tarih aralığı örneği", "headers":["Ürün", "Açılış", "Giriş", "Çıkış", "Kapanış"], "rows":[["USB-C Adaptör", "18", "10", "4", "24"],["Ethernet Kablosu", "45", "12", "5", "52"]]}],
        tip="Başlangıç tarihi bitiş tarihinden sonra olmamalıdır. Tarih aralığını rapor başlığında da kontrol edin."),

    _help_topic("Raporlar", "Ürün Hareket Raporu",
        "Tek bir ürünün veya filtrelenen ürünlerin stok giriş/çıkış hareketlerini ayrıntılı olarak listeler.",
        ["Ürün Hareket Raporu sekmesini açın.", "Ürün seçin; arama kutusu ürün kodu/adına göre listeyi daraltır.", "Tarih aralığı ve depo filtresini uygulayıp sorgulayın.", "Fiş türü, tarih ve miktar bilgilerini kontrol edin; gerekirse detay veya dışa aktarma kullanın."],
        fields=[("Ürün", "SK000123 - SSD 1 TB NVMe"), ("Başlangıç", "01.10.2026"), ("Bitiş", "14.10.2026"), ("Depo", "Bilgi İşlem Depo")],
        tables=[{"title":"Ürün hareket raporu", "headers":["Tarih", "İşlem", "Fiş", "Giriş", "Çıkış", "Bakiye"], "rows":[["14.10.2026", "Giriş", "GIR-0148", "5", "0", "8"],["14.10.2026", "Transfer", "TRF-0027", "0", "2", "6"],["14.10.2026", "Çıkış", "CIK-0089", "0", "1", "5"]]}],
        tip="Aynı ürünün farklı depolardaki hareketlerini karşılaştırırken depo filtresini doğru ayarlayın."),

    _help_topic("Raporlar", "Min / Max Uyarıları",
        "Minimum stok altına düşen veya maksimum stok seviyesini aşan ürünleri görmeye yardımcı olur.",
        ["Rapor Merkezi'nden Min / Max Uyarıları seçeneğini açın.", "Depo ve ürün grubu filtresi varsa doldurun.", "Sorgulayın; mevcut miktarı ürün kartındaki min/max seviyeleriyle karşılaştırın.", "Satın alma veya fazla stok değerlendirmesi için listeyi Excel'e aktarabilirsiniz."],
        fields=[("Uyarı Türü", "Minimum altı"), ("Depo", "Sarf Depo"), ("Grup", "SARF MALZEME")],
        tables=[{"title":"Min/max uyarıları", "headers":["Ürün", "Mevcut", "Min.", "Max.", "Uyarı"], "rows":[["USB Bellek 32 GB", "1", "5", "30", "Min. altında"],["Ethernet Kablosu", "52", "10", "50", "Max. üstünde"]]}],
        tip="Uyarılar, ürün kartındaki min/max tanımları doğruysa anlamlıdır. Seviye tanımlı değilse kartı güncelleyin."),

    _help_topic("Raporlar", "Eksiye Düşenler",
        "Negatif bakiyeli ürünleri bulur; stok hareketlerinin sırası veya hatalı fişlerden doğan anormallikleri incelemek için kullanılır.",
        ["Eksiye Düşenler raporunu açın.", "Depo ve tarih/ürün filtresi mevcutsa ihtiyaca göre uygulayın.", "Negatif miktarlı satırı seçip Stok Hareketleri ekranında ilgili ürünün fişlerini kontrol edin.", "Hatalı depo, miktar, transfer veya iptal edilmemiş fişleri düzeltin."],
        fields=[("Rapor", "Eksiye Düşenler"), ("Depo", "Bilgi İşlem Depo"), ("Arama", "Kablo")],
        tables=[{"title":"Negatif stok örneği", "headers":["Ürün", "Depo", "Mevcut", "Kontrol"], "rows":[["Ethernet Kablosu", "Bilgi İşlem Depo", "-2", "Hareketleri inceleyin"],["USB Hub", "Sarf Depo", "-1", "Fiş/transfer kontrolü"]]}],
        tip="Negatif stok raporu bir düzeltme işlemi değildir; sebebi hareket detaylarından bulunmalı, ondan sonra kayıt düzeltilmelidir."),

    _help_topic("Raporlar", "Bakiyesiz Ürünler",
        "Stok bakiyesi sıfır olan ürünleri listeler; sıfır stoklu kartların kontrol edilmesine yardımcı olur.",
        ["Bakiyesiz Ürünler raporunu açın.", "Depo veya ürün grubu filtresini seçin.", "Sorgulayın ve gerçek stokla kayıtlı bakiyeyi karşılaştırın.", "Ürün kullanılmıyorsa kartın aktif/pasif durumunu yöneticinizle değerlendirin."],
        fields=[("Rapor", "Bakiyesiz Ürünler"), ("Depo", "Sarf Depo"), ("Grup", "Tüm Gruplar")],
        tables=[{"title":"Bakiyesiz ürün örneği", "headers":["Kod", "Ürün", "Depo", "Mevcut"], "rows":[["SK000219", "VGA Adaptör", "Sarf Depo", "0"],["SK000260", "Eski USB Kablo", "Sarf Depo", "0"]]}],
        tip="Sıfır bakiye, ürün kartının gereksiz olduğu anlamına gelmez; geçmiş hareket ve kullanım ihtiyacını değerlendirin."),

    _help_topic("Tanımlar", "Departman",
        "Departman tanımları, malzeme çıkışlarında teslimin hangi birime yapıldığını kaydetmek için kullanılır. Departman ekranında alt birimler de aynı pencereden yönetilir.",
        ["Tanımlar → Departman ekranını açın.", "Departman Kodu ve Departman Adı alanlarını doldurun; örneğin D001 / Bilgi İşlem.", "Kaydet'e basın; listeden departmanı seçtiğinizde ona bağlı alt birimler sağ tarafta görünür.", "Mevcut departmanı seçip Düzenle ile güncelleyin. Kullanılan tanımlarda silme yerine pasifleştirme gerekebilir.", "Yeni alt birim eklemek için sağ taraftaki Alt Birim Kodu/Adı alanlarını doldurun."],
        fields=[("Departman Kodu", "D001"), ("Departman Adı", "Bilgi İşlem"), ("Durum", "Aktif"), ("Seçili Departman", "D001 - Bilgi İşlem"), ("Alt Birim Kodu", "DU01"), ("Alt Birim Adı", "Sunucu Odası"), ("Alt Birim Durumu", "Aktif")],
        tables=[{"title":"Departman tanımları", "headers":["No", "Kod", "Ad", "Durum"], "rows":[["1", "D001", "Bilgi İşlem", "AKTİF"],["2", "D002", "D Kliniği", "AKTİF"],["3", "D003", "İdari İşler", "AKTİF"]]}, {"title":"Seçili departmanın alt birimleri", "headers":["No", "Kod", "Alt Birim Adı", "Durum"], "rows":[["1", "DU01", "Sunucu Odası", "AKTİF"],["2", "DU02", "Kullanıcı Destek", "AKTİF"],["3", "DU03", "Ağ / Sistem", "AKTİF"]]}],
        tip="Bu kılavuz görseli örnek bilgilerle doldurulmuş temsilî bir ekran görünümüdür; gerçek veritabanınıza kayıt eklemez.", actions=["Yeni / Temizle", "Kaydet", "Düzenle", "Aktif / Pasif", "Sil / Pasifleştir"]),

    _help_topic("Tanımlar", "Departman Alt Birimleri",
        "Alt birimler, bir departmanın içindeki teslim yerlerini veya çalışma birimlerini ayrı ayrı izlemeye yarar.",
        ["Tanımlar → Departman ekranında listeden departman seçin.", "Sağ tarafta seçili departman adının doğru olduğunu kontrol edin.", "Alt Birim Kodu ve Alt Birim Adı alanlarını doldurun; örnek: DU01 / Sunucu Odası.", "Alt Birimi Kaydet ile ekleyin. Var olan alt birimi seçerek Düzenle veya Aktif/Pasif kullanın.", "Alt birim bir stok fişinde kullanılmışsa fiziksel olarak silinemeyebilir; gerektiğinde pasif yapın."],
        fields=[("Departman", "D001 - Bilgi İşlem"), ("Alt Birim Kodu", "DU01"), ("Alt Birim Adı", "Sunucu Odası"), ("Durum", "Aktif")],
        tables=[{"title":"Alt birim örnekleri", "headers":["No", "Kod", "Alt Birim Adı", "Durum"], "rows":[["1", "DU01", "Sunucu Odası", "AKTİF"],["2", "DU02", "Kullanıcı Destek", "AKTİF"],["3", "DU03", "Ağ / Sistem", "AKTİF"],["4", "DU04", "Yedek Parça", "AKTİF"]]}],
        tip="Alt birim kodu aynı departman içinde benzersiz olmalıdır. Stok çıkışında doğru departmanla beraber seçilmelidir."),

    _help_topic("Tanımlar", "Ürün Grupları",
        "Tanımlar altındaki Ürün Grupları ekranı, Ürünler menüsündeki aynı grup tanımlama ekranına ulaşır.",
        ["Tanımlar → Ürün Grupları menüsünü açın.", "Grup Kodu ve Grup Adı yazıp Kaydet'e basın.", "Var olan grubu seçerek düzenleyin veya kullanım durumuna göre pasifleştirin.", "Ürün kartında doğru grup kullanıldığını kontrol edin."],
        fields=[("Grup Kodu", "G004"), ("Grup Adı", "DEMİRBAŞ"), ("Durum", "Aktif")],
        tables=[{"title":"Grup listesi", "headers":["No", "Kod", "Ad", "Durum"], "rows":[["1", "G001", "SARF MALZEME", "AKTİF"],["2", "G002", "BİLGİSAYAR", "AKTİF"],["3", "G004", "DEMİRBAŞ", "AKTİF"]]}],
        tip="Ürün kartındaki Demirbaş No alanını etkinleştiren grup, adı/kodu demirbaş olarak tanımlanmış gruptur."),

    _help_topic("Tanımlar", "Ürün Türleri",
        "Ürün Türleri, ürünleri daha ayrıntılı özellik veya cihaz sınıfına göre sınıflandırır.",
        ["Tanımlar → Ürün Türleri ekranını açın.", "Tür Kodu ve Tür Adı alanlarını doldurun.", "Kaydedin; ürün kartında Ürün Tipi listesinden seçin.", "Artık kullanılmayan türler için aktif/pasif durumunu değerlendirin."],
        fields=[("Tür Kodu", "DESK"), ("Tür Adı", "DESKTOP BİLGİSAYAR"), ("Durum", "Aktif")],
        tables=[{"title":"Ürün türleri örneği", "headers":["No", "Kod", "Tür Adı", "Durum"], "rows":[["1", "DESK", "DESKTOP BİLGİSAYAR", "AKTİF"],["2", "NOTE", "NOTEBOOK", "AKTİF"],["3", "MON", "MONİTÖR", "AKTİF"],["4", "PRN", "YAZICI", "AKTİF"]]}],
        tip="Tür tanımları ürün kartındaki seçim listesinde kullanılır; tür adını anlaşılır ve tutarlı tutun."),

    _help_topic("Tanımlar", "Birimler",
        "Birimler, ürün miktarlarının ADET, KUTU, METRE gibi ölçü birimleriyle saklanmasını sağlar.",
        ["Tanımlar → Birimler ekranını açın.", "Birim Kodu ve Birim Adı bilgilerini doldurun.", "Kaydedin, sonra ürün kartındaki Birim alanında seçin.", "Stok miktarlarını karşılaştırırken aynı ürün için uygun birim kullanıldığını doğrulayın."],
        fields=[("Birim Kodu", "AD"), ("Birim Adı", "ADET"), ("Durum", "Aktif")],
        tables=[{"title":"Birim listesi örneği", "headers":["No", "Kod", "Ad", "Durum"], "rows":[["1", "AD", "ADET", "AKTİF"],["2", "PK", "PAKET", "AKTİF"],["3", "MT", "METRE", "AKTİF"],["4", "KG", "KİLOGRAM", "AKTİF"]]}],
        tip="Birimi değiştirmek, stok miktarlarının yorumlanmasını etkiler. Ürün bazında doğru birim seçin."),

    _help_topic("Ayarlar", "İşlem Logları / Denetim Kaydı",
        "İşlem logları, programda gerçekleştirilen önemli işlemlerin kim tarafından ve ne zaman yapıldığını incelemeye yardımcı olur.",
        ["Ayarlar → İşlem Logları / Denetim Kaydı ekranını açın.", "Tarih, kullanıcı veya işlem türüne göre arama yapın.", "Kayıt detaylarında açıklama, kayıt kimliği ve işlem sonucunu inceleyin.", "İhtiyaç halinde logları Excel'e aktarın veya yazdırın."],
        fields=[("Başlangıç", "01.10.2026"), ("Bitiş", "14.10.2026"), ("Kullanıcı", "Yönetici"), ("İşlem", "Ürün Girişi")],
        tables=[{"title":"Denetim kaydı örneği", "headers":["Tarih/Saat", "Kullanıcı", "İşlem", "Açıklama"], "rows":[["14.10.2026 09:12", "yonetici", "Ürün Girişi", "GIR-2026-0148 kaydedildi"],["14.10.2026 09:25", "yonetici", "Ürün Kartı", "SK000123 güncellendi"]]}],
        tip="Loglar denetim amaçlıdır; bir log kaydını görmek ilgili hareketin kendisini otomatik olarak düzeltmez."),

    _help_topic("Ayarlar", "Oturum Kayıtları",
        "Kullanıcı giriş ve çıkışlarını, oturum zamanlarını ve oturum olaylarını görüntüler.",
        ["Ayarlar → Oturum Kayıtları ekranını açın.", "Tarih aralığı ya da kullanıcı filtresiyle arama yapın.", "Başarılı giriş, çıkış ve hata/oturum olaylarını inceleyin.", "Gerekliyse raporu dışa aktarın."],
        fields=[("Tarih Aralığı", "01.10.2026 – 14.10.2026"), ("Kullanıcı", "Tümü"), ("Olay", "Giriş / Çıkış")],
        tables=[{"title":"Oturum örnekleri", "headers":["Tarih/Saat", "Kullanıcı", "Olay", "Sonuç"], "rows":[["14.10.2026 08:55", "yonetici", "Giriş", "Başarılı"],["14.10.2026 12:53", "yonetici", "Oturum", "Aktif"]]}],
        tip="Bir kullanıcı artık çalışmıyorsa kullanıcı yetkileri ve oturum kayıtlarını yönetici birlikte kontrol etmelidir."),

    _help_topic("Ayarlar", "Otomatik Yedekleme",
        "Belirlenen aralıkta veritabanı yedeğinin otomatik oluşturulmasını ve eski yedeklerin saklama politikasını ayarlar.",
        ["Ayarlar → Otomatik Yedekleme ekranını açın.", "Otomatik yedeklemeyi etkinleştirin ve klasör yolunu seçin.", "Saat ve sıklığı belirleyin; günlük/haftalık seçenekleri ile saklanacak yedek sayısını ayarlayın.", "Ayarları kaydedin; hedef klasörün erişilebilir ve yeterli boş alana sahip olduğundan emin olun.", "İlk başarılı yedek dosyasının oluştuğunu ayrıca kontrol edin."],
        fields=[("Otomatik Yedekleme", "Etkin"), ("Klasör", "D:\\DepoYedekleri"), ("Saat", "23:30"), ("Sıklık", "Her Gün"), ("Saklanacak Yedek", "30"), ("Son Başarılı", "14.10.2026 23:30")],
        tables=[{"title":"Yedekleme planı", "headers":["Ayar", "Örnek değer"], "rows":[["Yedek tipi", "Aktif veritabanı"],["Plan", "Her gün 23:30"],["Saklama", "Son 30 yedek"]]}],
        tip="Yedeklemeyi ayarlamak tek başına yeterli değildir; ara sıra dosyanın oluştuğunu ve geri yüklemenin çalıştığını doğrulayın.", actions=["Klasör Seç", "Test / Kontrol", "Kaydet", "Kapat"]),

    _help_topic("Ayarlar", "Kullanıcılar / Yetkiler",
        "Kullanıcı hesapları oluşturur; rol ve yetkilerle hangi menülere erişilebileceğini belirler.",
        ["Ayarlar → Kullanıcılar / Yetkiler ekranını açın.", "Yeni kullanıcı için kullanıcı adı, ad-soyad, parola ve rol alanlarını doldurun.", "İş ihtiyacına uygun rolü seçin. Yönetici tüm ayarları yönetebilir; stok ve rapor kullanıcılarının erişimleri daha sınırlıdır.", "Kaydedin; kullanıcıya ilk giriş bilgilerini güvenli biçimde iletin.", "İşten ayrılan veya kullanılmayan hesapları silmek yerine durumunu pasifleştirmeyi değerlendirin."],
        fields=[("Kullanıcı Adı", "m.demir"), ("Ad Soyad", "Mehmet Demir"), ("Rol", "Stok Kullanıcısı"), ("Durum", "Aktif"), ("Parola", "••••••••")],
        tables=[{"title":"Kullanıcı örneği", "headers":["Kullanıcı", "Ad Soyad", "Rol", "Durum"], "rows":[["yonetici", "Sistem Yöneticisi", "Yönetici", "AKTİF"],["m.demir", "Mehmet Demir", "Stok Kullanıcısı", "AKTİF"],["rapor", "Rapor Yetkilisi", "Rapor Kullanıcısı", "AKTİF"]]}],
        tip="Gerçek parolayı Excel'e veya kılavuz notlarına yazmayın. İhtiyaç duyulmayan kullanıcıları devre dışı bırakın."),

    _help_topic("Ayarlar", "Veritabanı / Ağ Kullanımı",
        "Programın yerel SQLite veritabanıyla mı yoksa merkezi PostgreSQL sunucusuyla mı çalışacağını ve ilgili bağlantı ayarlarını yönetir.",
        ["Ayarlar → Veritabanı / Ağ Kullanımı ekranını açın.", "Kullanılacak veritabanı türünü seçin.", "SQLite kullanımında gerçek .db dosyasının yolunu; PostgreSQL kullanımında sunucu adresi, port, veritabanı ve kimlik bilgilerini girin.", "Bağlantıyı Test Et düğmesini kullanın; test başarılı olmadan ayarı kaydetmeyin.", "Kaydettikten sonra programı yeniden başlatıp bağlantı durumunu kontrol edin."],
        fields=[("Veritabanı Modu", "PostgreSQL"), ("Sunucu", "10.212.111.130"), ("Port", "5432"), ("Veritabanı", "depo_stok"), ("Şema", "public"), ("Bağlantı Testi", "Başarılı")],
        tables=[{"title":"Bağlantı özeti", "headers":["Alan", "Örnek değer"], "rows":[["Hedef", "10.212.111.130:5432/depo_stok"],["Şema", "public"],["Durum", "Bağlantı aktif"]]}],
        tip="PostgreSQL bir sunucu veritabanıdır; SQLite gibi tek bir .db dosyası değildir. Sunucu veri dizini ve paylaşım/referans yolu farklı kavramlardır. Gerçek parolaları başkalarıyla paylaşmayın.", actions=["Test Et", "Kaydet", "Kapat"]),

    _help_topic("Ayarlar", "İstemci / Sunucu Yapılandırması",
        "İstemcinin hangi merkezi sunucu profiline bağlanacağını ve paylaşım/dağıtım bilgilerini kontrol etmeye yarar.",
        ["Ayarlar → İstemci / Sunucu Yapılandırması menüsünü açın.", "Kuruluşunuzun verdiği sunucu host/port ve veritabanı adını kontrol edin.", "Ağ erişimi ve güvenlik duvarı kurallarını sistem yöneticisiyle doğrulayın.", "Bağlantı testini çalıştırın; birden çok istemcinin aynı veritabanını kullandığını doğrulayın."],
        fields=[("Rol", "İstemci"), ("Sunucu", "10.212.111.130"), ("Port", "5432"), ("Veritabanı", "depo_stok"), ("Şema", "public"), ("Durum", "Bağlanabilir")],
        tables=[{"title":"İstemci profili", "headers":["İstemci", "Bağlantı hedefi", "Durum"], "rows":[["DEPO-PC-01", "10.212.111.130:5432", "Aktif"],["MUHASEBE-PC", "10.212.111.130:5432", "Aktif"]]}],
        tip="Ağ paylaşımına sadece yedek dosyası yazabilmek PostgreSQL bağlantısının kurulduğu anlamına gelmez. Veritabanı bağlantısı ayrıca test edilmelidir."),

    _help_topic("Ayarlar", "Veritabanı Sağlık Kontrolü",
        "Veritabanına bağlanılabilirliği, temel tabloları ve bütünlük durumunu kontrol ederek arıza tespitini kolaylaştırır.",
        ["Ayarlar → Veritabanı Sağlık Kontrolü ekranını açın.", "Kontrolleri çalıştırın ve her testin sonucunu okuyun.", "Bağlantı veya bütünlük uyarısı varsa mesajı kaydedin; yedek almadan müdahale etmeyin.", "Ağ bağlantısı sorunuysa host/port, hizmet ve güvenlik duvarını sistem yöneticisiyle kontrol edin."],
        fields=[("Bağlantı", "Başarılı"), ("Veritabanı", "depo_stok"), ("Tablolar", "Kontrol edildi"), ("Bütünlük", "Sorun yok"), ("Son Kontrol", "14.10.2026 12:30")],
        tables=[{"title":"Örnek sağlık kontrolü", "headers":["Kontrol", "Sonuç", "Açıklama"], "rows":[["Veritabanı bağlantısı", "BAŞARILI", "Sunucuya erişiliyor"],["Temel tablolar", "BAŞARILI", "Tablolar erişilebilir"],["Bütünlük", "BAŞARILI", "Hata bulunmadı"]]}],
        tip="Sağlık kontrolü yedek yerine geçmez. Ciddi hata varsa veritabanı dosyasını elle değiştirmeyin; yedek ve loglarla destek alın."),

    _help_topic("Ayarlar", "Veritabanı Migration Geçmişi",
        "Veritabanı şema yükseltmelerinin ne zaman yapıldığını ve sonuçlarını görüntüler.",
        ["Ayarlar → Veritabanı Migration Geçmişi ekranını açın.", "Şema sürümü, işlem zamanı, sonucu ve varsa hata ayrıntısını inceleyin.", "Yükseltme hatası olduğunda otomatik alınan yedek yolunu not edin.", "Başarısız migration sonrası rastgele dosya/tablo silmeyin; kaydı destek için saklayın."],
        fields=[("Mevcut Şema", "5"), ("Uygulama Sürümü", "V1.38.0"), ("Son Migration", "Tamamlandı"), ("Yedek", "Migration öncesi yedek")],
        tables=[{"title":"Migration geçmişi örneği", "headers":["Tarih", "Önce", "Sonra", "Sonuç"], "rows":[["14.10.2026", "3", "4", "Başarılı"],["30.09.2026", "2", "3", "Başarılı"]]}],
        tip="Uygulama sürümü ile veritabanı şema sürümü aynı olmak zorunda değildir; migration geçmişinde şema yükseltmelerini izleyin."),

    _help_topic("Ayarlar", "PostgreSQL Veri Aktarımı",
        "Mevcut SQLite verisini merkezi PostgreSQL veritabanına aktarmak için kullanılan yönetici aracıdır.",
        ["Başlamadan önce SQLite veritabanının ve hedef PostgreSQL veritabanının yedeğini alın.", "Ayarlar → PostgreSQL Veri Aktarımı ekranında hedef bağlantı bilgilerini girin ve Test Et ile doğrulayın.", "Kaynak/hedef tabloları, aktarım uyarılarını ve varsa mevcut kayıtların üzerine yazılma riskini kontrol edin.", "Aktarımı çalıştırın; tamamlandığında kayıt sayılarını ve örnek ürün/cari/stok kayıtlarını doğrulayın.", "Normal çalışma modunda PostgreSQL seçildiyse bu tek seferlik aktarım aracına ihtiyaç olmayabilir."],
        fields=[("Kaynak", "SQLite depo_stok.db"), ("Hedef Sunucu", "10.212.111.130:5432"), ("Hedef Veritabanı", "depo_stok"), ("Aktarım Durumu", "Başlamadan önce test"), ("Yedek", "Alındı")],
        tables=[{"title":"Aktarım kontrol listesi", "headers":["Aşama", "Durum"], "rows":[["Kaynak yedeği", "Hazır"],["Hedef bağlantı testi", "Başarılı"],["Tablo/kayıt kontrolü", "Aktarım sonrası doğrulanacak"]]}],
        tip="Bu işlem sistem verilerini değiştirebilir. Üretim veritabanında çalıştırmadan önce hedefi ve yedekleri iki kez kontrol edin.", actions=["Bağlantı Testi", "Yedek Al", "Aktarımı Başlat", "Kapat"]),

    _help_topic("Ayarlar", "Güncelleme Ayarları",
        "Program güncelleme kontrolü için kullanılan manifest/adres ve güncelleme davranışını yapılandırır.",
        ["Ayarlar → Güncelleme Ayarları ekranını açın.", "Kurumunuzun belirlediği güncelleme kaynağını/adresini girin.", "Ayarları kaydedin ve Güncellemeleri Kontrol Et ile kaynağı test edin.", "Güncelleme dosyalarını yalnızca güvenilir ve yetkili kaynaktan alın; yükseltme öncesi veritabanı yedeği oluşturun."],
        fields=[("Güncelleme Kontrolü", "Etkin"), ("Kontrol Kaynağı", "Kurum güncelleme adresi"), ("Otomatik Kontrol", "Etkin"), ("Sonuç", "Güncel sürüm kontrol edilecek")],
        tables=[{"title":"Sürüm karşılaştırma örneği", "headers":["Alan", "Örnek"], "rows":[["Kurulu sürüm", "V1.38.0"],["Sunucudaki sürüm", "Kaynak sorgulanınca belirlenir"],["Yükseltme", "Kullanıcı onayıyla"]]}],
        tip="Bu kılavuz gerçek bir güncelleme sunucusuna bağlanmaz; örnek adres yerine sistem yöneticinizin sağladığı adresi kullanın."),

    _help_topic("Ayarlar", "İstemci Bağlantı Profili",
        "İstemci bilgisayarının bağlantı ve kurulum profil bilgilerini görüntülemeye, dışa aktarmaya veya içe almaya yardımcı olur.",
        ["Ayarlar → İstemci Bağlantı Profili ekranını açın.", "Makine adı, etkin veritabanı modu ve profil özetini kontrol edin.", "Sorun giderme için dışa aktarma seçeneğiyle profil özetini alın.", "Başka istemciye profil aktarırken sunucu ve güvenlik bilgilerini hedef ortam için doğrulayın."],
        fields=[("İstemci Adı", "DEPO-PC-01"), ("Çalışma Modu", "PostgreSQL istemcisi"), ("Hedef", "10.212.111.130:5432/depo_stok"), ("Profil", "Üretim"), ("Bağlantı", "Test edilebilir")],
        tables=[{"title":"Profil alanları", "headers":["Alan", "Örnek değer"], "rows":[["Uygulama sürümü", "V1.38.0"],["Veritabanı türü", "PostgreSQL"],["Şema", "public"]]}],
        tip="Profil dışa aktarımında parola veya hassas bağlantı bilgisi varsa dosyayı yalnızca yetkili kişilere iletin."),

    _help_topic("Ayarlar", "Yedekleme",
        "SQLite veritabanını dosyaya yedekleme ve yedekten geri yükleme; PostgreSQL modunda sunucu yedekleme/geri yükleme işlemlerini yönetir.",
        ["Ayarlar → Yedekleme ekranını açın.", "Yedek alınırken hedef klasörün dolu/erişilebilir olduğunu ve yeterli boş alan bulunduğunu doğrulayın.", "Geri yükleme öncesinde mevcut veritabanının ayrı yedeğini alın.", "Yedek dosyasının türü ve hedef veritabanı modunun doğru olduğunu kontrol ederek geri yüklemeyi başlatın.", "İşlem sonrası programı yeniden açın; ürün, cari, depolar ve stok bakiyelerinden örnekler kontrol edin."],
        fields=[("Veritabanı Modu", "PostgreSQL"), ("Yedek Dosyası", "depo_stok_20261014.dump"), ("Yedek Türü", "Custom (.dump)"), ("İşlem", "Yedek Al"), ("Sonuç", "İşlem sonrası doğrulanacak")],
        tables=[{"title":"Güvenli yedekleme adımları", "headers":["Adım", "Kontrol"], "rows":[["1", "Doğru kaynak/hedef"],["2", "Yedeğin oluştuğu"],["3", "Dosya boyutu ve tarih"],["4", "Geri yükleme testi"]]}],
        tip="Geri yükleme hedef verisinin üzerine yazabilir. İşlem öncesi dosya adını, veritabanını ve yedek tarihini kontrol edin.", actions=["Yedek Al", "Yedekten Geri Yükle", "Test", "Kapat"]),

    _help_topic("Excel", "Excel / CSV Aktarımı",
        "Rapor veya listelerde görünen verileri Excel uyumlu XLSX/XLS ya da CSV biçimlerine aktarmayı sağlar.",
        ["İlgili liste/raporda filtreleri uygulayıp sonucun doğru olduğunu kontrol edin.", "Excel'e Aktar veya CSV aktarımı seçeneğini kullanın.", "Dosya adı, klasör ve dosya türünü seçip kaydedin.", "Oluşan dosyayı açın; sütun başlıkları, tarih ve ondalık biçimlerini kontrol edin."],
        fields=[("Dosya Adı", "Stok_Raporu_20261014.xlsx"), ("Dosya Türü", "Excel çalışma kitabı (.xlsx)"), ("Sayfa", "Stok Raporu"), ("Filtre", "Mevcut ekran filtreleri")],
        tables=[{"title":"Aktarım önizleme", "headers":["Ürün Kodu", "Ürün Adı", "Miktar", "Birim"], "rows":[["SK000123", "SSD 1 TB NVMe", "8", "ADET"],["SK000124", "USB-C Adaptör", "24", "ADET"]]}],
        tip="CSV dosyaları bazı Excel bölgesel ayarlarında ayraç gerektirebilir. Türkçe karakterleri korumak için uygulamanın sunduğu UTF-8 uyumlu çıktıyı tercih edin."),

    _help_topic("Yardım", "Kullanıcı Yardımı / Program Kullanım Kılavuzu",
        "Bu ekran menülerin ne işe yaradığını, nasıl kullanılacağını, örnek alanları ve veri giriş adımlarını açıklar.",
        ["Sol listeden ana menü/alt menü konusunu seçin.", "Arama kutusuna örneğin 'departman', 'transfer', 'yedekleme' veya 'demirbaş' yazıp konuları daraltın.", "Sağ taraftaki açıklama ve adımları okuyun; alt bölümde doldurulmuş örnek ekran ve örnek tabloyu inceleyin.", "Kılavuzdaki görsel alanlar temsili veriler içerir; bu pencereden herhangi bir kayıt veritabanına yazılmaz."],
        fields=[("Konu", "Tanımlar › Departman"), ("Örnek Kod", "D001"), ("Örnek Ad", "Bilgi İşlem"), ("Örnek Alt Birim", "DU01 - Sunucu Odası")],
        tables=[{"title":"Bu kılavuzda anlatılan adımlar", "headers":["Sıra", "İşlem"], "rows":[["1", "Menü ve ekranı aç"],["2", "Alanları örneklerle doldur"],["3", "Gerekli kontrolleri yap"],["4", "Kaydetmeden önce son kontrol"]]}],
        tip="Ekran çizimleri kullanım amacıyla hazırlanmış örnek arayüz görselleridir; gerçek ekran tasarımınız ve veritabanı verileriniz farklı olabilir.", actions=["Konu Ara", "Başlığı Seç", "Kapat"]),

    _help_topic("Program", "Programdan Çıkış",
        "Programdan Çıkış menüsü uygulamayı kapatır. Kaydedilmemiş bir işlem penceresi varsa önce o ekranı kontrol edin.",
        ["Programdan Çıkış menüsüne tıklayın veya ana penceredeki Çıkış düğmesini kullanın.", "Kapatma onayı sorulduğunda, gerçekten bitirmek istiyorsanız Evet seçin; devam etmek için Hayır seçin.", "Programı kapatmadan önce açık fişlerin kaydedildiğini, rapor/aktarımı tamamladığınızı kontrol edin.", "Ağ ortamında çalışıyorsanız başka kullanıcıların işlemlerini etkilememek için yalnızca kendi oturumunuzu kapattığınızı doğrulayın."],
        fields=[("İşlem", "Programdan Çıkış"), ("Onay", "Evet / Hayır"), ("Etkin Oturum", "Yönetici"), ("Kaydedilmemiş İşlem", "Kapatmadan önce kontrol edin")],
        tables=[{"title":"Kapatma kontrolü", "headers":["Kontrol", "Öneri"], "rows":[["Açık fiş", "Kaydedildiğini doğrula"],["Rapor / Excel aktarımı", "Tamamlandığını doğrula"],["Veritabanı bağlantısı", "Program normal şekilde kapatılır"]]}],
        tip="Çıkış işlemi programı kapatır; yarım bırakılmış fiş verilerinin otomatik kaydedileceğini varsaymayın.", actions=["Evet", "Hayır"]),

    _help_topic("Yardım", "Program Hakkında",
        "Program sürümü, sürüm tarihi, firma ve destek iletişim bilgilerini gösterir.",
        ["Yardım → Program Hakkında menüsünü açın.", "Program sürümü ve sürüm tarihini not edin.", "Destek isterken hata mesajıyla birlikte sürüm bilgisini de paylaşın."],
        fields=[("Program", "Depo & Stok Yönetim Programı"), ("Sürüm", "V1.38.0"), ("Sürüm Tarihi", "30.10.2026"), ("Firma", "TUA Bilişim ve Yazılım Ltd. Şti."), ("Destek", "Ercan HAMZAOĞLU")],
        tables=[{"title":"Hakkında bilgileri", "headers":["Alan", "Bilgi"], "rows":[["Ürün", "Depo & Stok Yönetim Programı"],["Firma", "TUA Bilişim ve Yazılım Ltd. Şti."],["Haklar", "Tüm hakları saklıdır"]]}],
        tip="Destek mesajınıza kullandığınız sürümü, işlemi ve hata metnini ekleyin. Parola veya hassas veritabanı bilgisi paylaşmayın."),

    _help_topic("Yardım", "Güncellemeleri Kontrol Et",
        "Kullanılan sürümü güncelleme kaynağındaki sürümle karşılaştırır ve varsa yeni sürüm bilgisini gösterir.",
        ["Yardım → Güncellemeleri Kontrol Et menüsünü kullanın.", "İnternet ve güncelleme kaynağına erişimin açık olduğundan emin olun.", "Yeni sürüm bulunursa sürüm notlarını okuyun ve veri yedeği alın.", "Yükseltmeyi yalnızca güvenilir kaynaktan indirilen dosyayla yapın."],
        fields=[("Kurulu Sürüm", "V1.38.0"), ("Güncelleme Kaynağı", "Ayarlar'da tanımlı"), ("Kontrol Sonucu", "Kaynak sorgulandığında belirlenir")],
        tables=[{"title":"Güncelleme kontrol akışı", "headers":["Adım", "İşlem"], "rows":[["1", "Kaynağı kontrol et"],["2", "Sürüm numaralarını karşılaştır"],["3", "Notları incele ve yedek al"],["4", "Onaylı güncellemeyi uygula"]]}],
        tip="Güncelleme bulunmaması hata anlamına gelmez; güncelleme kaynağı tanımlı değilse veya erişilemiyorsa ayarları kontrol edin."),
]


class HelpScreenshotWidget(QFrame):
    """Kılavuz sayfasında görünen, örnek verilerle doldurulmuş temsilî ekran görseli."""
    def __init__(self, topic, parent=None):
        super().__init__(parent)
        self.setFrameShape(QFrame.StyledPanel)
        self.setStyleSheet("HelpScreenshotWidget { background: #f7f9fb; border: 1px solid #c4ced8; border-radius: 7px; }")
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        titlebar = QFrame()
        titlebar.setStyleSheet("background: #49677f; border-top-left-radius: 7px; border-top-right-radius: 7px;")
        th = QHBoxLayout(titlebar)
        th.setContentsMargins(12, 8, 12, 8)
        ttl = QLabel(topic.get("title", "Örnek ekran"))
        ttl.setStyleSheet("color: white; font-size: 13px; font-weight: 700; background: transparent; border: none;")
        th.addWidget(ttl)
        th.addStretch()
        sample = QLabel("ÖRNEK GÖRÜNÜM")
        sample.setStyleSheet("color: #e8f0f6; font-size: 9px; background: transparent; border: none;")
        th.addWidget(sample)
        root.addWidget(titlebar)

        content = QWidget()
        content.setStyleSheet("background: #f7f9fb; border: none;")
        cv = QVBoxLayout(content)
        cv.setContentsMargins(12, 10, 12, 10)
        cv.setSpacing(9)

        actionbar = QHBoxLayout()
        for label in topic.get("actions", ["Yeni", "Düzenle", "Sorgula", "Kapat"]):
            b = QPushButton(label)
            b.setEnabled(False)
            b.setMinimumHeight(25)
            b.setStyleSheet("QPushButton { background: #edf3f8; border: 1px solid #c6d1dc; border-radius: 4px; padding: 3px 8px; color: #40586b; font-size: 9px; }")
            actionbar.addWidget(b)
        actionbar.addStretch()
        cv.addLayout(actionbar)

        fields = topic.get("fields") or [("Kayıt Kodu", "ORNEK-001"), ("Kayıt Adı", "Örnek kayıt"), ("Durum", "Aktif")]
        formbox = QGroupBox("Örnek alanlar (doldurulmuş)")
        formbox.setStyleSheet("QGroupBox { background: white; border: 1px solid #d8e0e7; border-radius: 5px; margin-top: 8px; padding-top: 10px; color: #3d5265; font-weight: 600; } QGroupBox::title { subcontrol-origin: margin; left: 9px; padding: 0 5px; }")
        fg = QGridLayout(formbox)
        fg.setHorizontalSpacing(10)
        fg.setVerticalSpacing(7)
        for index, pair in enumerate(fields):
            label, value = pair
            row = index // 2
            col = (index % 2) * 2
            lab = QLabel(str(label))
            lab.setStyleSheet("color: #465b6d; font-size: 9px; background: transparent;")
            val = QLineEdit(str(value))
            val.setReadOnly(True)
            val.setMinimumHeight(24)
            val.setStyleSheet("QLineEdit { background: white; color: #17324a; border: 1px solid #becbd7; border-radius: 3px; padding: 3px 5px; font-size: 9px; }")
            fg.addWidget(lab, row, col)
            fg.addWidget(val, row, col + 1)
            fg.setColumnStretch(col + 1, 1)
        cv.addWidget(formbox)

        for table_spec in topic.get("tables", []):
            table_box = QGroupBox(table_spec.get("title", "Örnek kayıt listesi"))
            table_box.setStyleSheet("QGroupBox { background: white; border: 1px solid #d8e0e7; border-radius: 5px; margin-top: 8px; padding-top: 10px; color: #3d5265; font-weight: 600; } QGroupBox::title { subcontrol-origin: margin; left: 9px; padding: 0 5px; }")
            tv = QVBoxLayout(table_box)
            table = QTableWidget(len(table_spec.get("rows", [])), len(table_spec.get("headers", [])))
            table.setHorizontalHeaderLabels([str(x) for x in table_spec.get("headers", [])])
            table.setEditTriggers(QAbstractItemView.NoEditTriggers)
            table.setSelectionMode(QAbstractItemView.NoSelection)
            table.setFocusPolicy(Qt.NoFocus)
            table.verticalHeader().setVisible(False)
            table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
            table.setAlternatingRowColors(True)
            table.setStyleSheet("QTableWidget { background: white; gridline-color: #e1e7ed; border: 1px solid #dbe2e8; font-size: 9px; } QHeaderView::section { background: #dfe6ee; color: #304354; border: none; padding: 4px; font-weight: 700; font-size: 9px; }")
            for r, rowvals in enumerate(table_spec.get("rows", [])):
                for c, value in enumerate(rowvals[:table.columnCount()]):
                    table.setItem(r, c, QTableWidgetItem(str(value)))
            table.resizeRowsToContents()
            table.setMinimumHeight(max(72, min(145, 29 + 24 * max(1, table.rowCount()))))
            table.setMaximumHeight(155)
            tv.addWidget(table)
            cv.addWidget(table_box)

        note = QLabel("Not: Bu görseldeki kayıtlar örnektir. Kılavuz ekranı gerçek veritabanınıza kayıt yazmaz.")
        note.setWordWrap(True)
        note.setStyleSheet("color: #607284; font-size: 9px; background: transparent; padding: 3px;")
        cv.addWidget(note)
        root.addWidget(content)


class HelpManualDialog(QDialog):
    """Aranabilir, görselli kullanıcı yardım kılavuzu."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Kullanıcı Yardımı / Program Kullanım Kılavuzu")
        self.setMinimumSize(1080, 720)
        self.resize(1320, 850)
        self._building_list = False
        root = QVBoxLayout(self)
        root.setContentsMargins(12, 12, 12, 12)
        root.setSpacing(8)

        header = QFrame()
        header.setStyleSheet("background: #49677f; border-radius: 7px;")
        hh = QHBoxLayout(header)
        hh.setContentsMargins(14, 10, 14, 10)
        titlebox = QVBoxLayout()
        title = QLabel("KULLANICI YARDIMI / PROGRAM KULLANIM KILAVUZU")
        title.setStyleSheet("font-size: 17px; font-weight: 700; color: white; background: transparent;")
        subtitle = QLabel(f"{APP_TITLE}  •  Sürüm {APP_VERSION}  •  Menüler, veri girişi, işlemler ve raporlar")
        subtitle.setStyleSheet("font-size: 10px; color: #e4edf5; background: transparent;")
        titlebox.addWidget(title)
        titlebox.addWidget(subtitle)
        hh.addLayout(titlebox)
        hh.addStretch()
        root.addWidget(header)

        searchrow = QHBoxLayout()
        searchrow.addWidget(QLabel("Kılavuzda ara:"))
        self.search = QLineEdit()
        self.search.setPlaceholderText("Örn. departman, stok transferi, demirbaş no, yedekleme...")
        self.search.setClearButtonEnabled(True)
        searchrow.addWidget(self.search, 1)
        root.addLayout(searchrow)

        split = QSplitter(Qt.Horizontal)
        split.setChildrenCollapsible(False)
        self.topic_list = QListWidget()
        self.topic_list.setMinimumWidth(285)
        self.topic_list.setMaximumWidth(390)
        self.topic_list.setStyleSheet("QListWidget { background: white; border: 1px solid #cbd5de; border-radius: 5px; } QListWidget::item { padding: 7px 6px; border-bottom: 1px solid #edf0f3; } QListWidget::item:selected { background: #dce9f4; color: #203f58; }")
        split.addWidget(self.topic_list)

        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll.setFrameShape(QFrame.NoFrame)
        self.scroll.setStyleSheet("QScrollArea { background: #eef2f6; border: none; }")
        split.addWidget(self.scroll)
        split.setStretchFactor(0, 0)
        split.setStretchFactor(1, 1)
        root.addWidget(split, 1)

        footer = QHBoxLayout()
        info = QLabel(f"{len(_HELP_TOPICS)} konu • Örnek görsellerdeki veriler temsilidir; gerçek veritabanınıza yazılmaz.")
        info.setStyleSheet("color: #5e6d7a; font-size: 10px;")
        footer.addWidget(info)
        footer.addStretch()
        close = QPushButton("Kapat")
        close.clicked.connect(self.accept)
        footer.addWidget(close)
        root.addLayout(footer)

        self.search.textChanged.connect(self.filter_topics)
        self.topic_list.currentItemChanged.connect(self.topic_changed)
        self.filter_topics("")

    def filter_topics(self, text):
        query = str(text or "").strip().casefold()
        self._building_list = True
        self.topic_list.clear()
        for i, topic in enumerate(_HELP_TOPICS):
            haystack = " ".join([topic["category"], topic["title"], topic["summary"], " ".join(topic["steps"]), topic.get("tip", "")]).casefold()
            if query and query not in haystack:
                continue
            item = QListWidgetItem(f'{topic["category"]}  ›  {topic["title"]}')
            item.setData(Qt.UserRole, i)
            self.topic_list.addItem(item)
        self._building_list = False
        if self.topic_list.count():
            self.topic_list.setCurrentRow(0)
        else:
            self.show_no_results()

    def topic_changed(self, current, _previous=None):
        if self._building_list or current is None:
            return
        index = current.data(Qt.UserRole)
        if index is None or index < 0 or index >= len(_HELP_TOPICS):
            return
        self.render_topic(_HELP_TOPICS[index])

    def show_no_results(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        title = QLabel("Aramayla eşleşen konu bulunamadı")
        title.setStyleSheet("font-size: 18px; font-weight: 700; color: #2f465b;")
        layout.addWidget(title)
        msg = QLabel("Arama kelimesini kısaltın veya başka bir terim deneyin.")
        msg.setWordWrap(True)
        layout.addWidget(msg)
        layout.addStretch()
        self.scroll.setWidget(page)

    def render_topic(self, topic):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(12, 6, 12, 18)
        layout.setSpacing(10)

        title = QLabel(topic["title"])
        title.setWordWrap(True)
        title.setStyleSheet("font-size: 20px; font-weight: 700; color: #2f465b; padding: 2px 0;")
        layout.addWidget(title)
        crumb = QLabel(f'{topic["category"]}  ›  {topic["title"]}')
        crumb.setStyleSheet("font-size: 10px; color: #667887;")
        layout.addWidget(crumb)

        intro_box = QGroupBox("Ne işe yarar?")
        intro_box.setStyleSheet("QGroupBox { background: white; border: 1px solid #d4dde5; border-radius: 6px; margin-top: 8px; padding-top: 10px; color: #3c5366; font-weight: 700; } QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 5px; }")
        iv = QVBoxLayout(intro_box)
        intro = QLabel(topic["summary"])
        intro.setWordWrap(True)
        intro.setStyleSheet("color: #293f52; font-size: 11px; padding: 4px;")
        iv.addWidget(intro)
        layout.addWidget(intro_box)

        steps_box = QGroupBox("Nasıl kullanılır? Adım adım")
        steps_box.setStyleSheet("QGroupBox { background: white; border: 1px solid #d4dde5; border-radius: 6px; margin-top: 8px; padding-top: 10px; color: #3c5366; font-weight: 700; } QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 5px; }")
        sv = QVBoxLayout(steps_box)
        for number, instruction in enumerate(topic["steps"], 1):
            row = QHBoxLayout()
            num = QLabel(str(number))
            num.setAlignment(Qt.AlignCenter)
            num.setFixedSize(25, 25)
            num.setStyleSheet("background: #dce9f4; border-radius: 12px; color: #2b506d; font-weight: 700;")
            text = QLabel(instruction)
            text.setWordWrap(True)
            text.setStyleSheet("color: #293f52; font-size: 10px; padding: 2px;")
            row.addWidget(num, 0, Qt.AlignTop)
            row.addWidget(text, 1)
            sv.addLayout(row)
        layout.addWidget(steps_box)

        screenshot_label = QLabel("Örnek ekran görünümü — alanlar ve kayıt satırları örnek verilerle doldurulmuştur")
        screenshot_label.setWordWrap(True)
        screenshot_label.setStyleSheet("font-size: 12px; font-weight: 700; color: #2f465b; padding-top: 5px;")
        layout.addWidget(screenshot_label)
        layout.addWidget(HelpScreenshotWidget(topic))

        if topic.get("tip"):
            tip_box = QGroupBox("Önemli not")
            tip_box.setStyleSheet("QGroupBox { background: #fffdf6; border: 1px solid #e7d9ad; border-radius: 6px; margin-top: 8px; padding-top: 10px; color: #765d24; font-weight: 700; } QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 5px; }")
            tv = QVBoxLayout(tip_box)
            tip = QLabel(topic["tip"])
            tip.setWordWrap(True)
            tip.setStyleSheet("color: #665528; font-size: 10px; padding: 4px;")
            tv.addWidget(tip)
            layout.addWidget(tip_box)
        layout.addStretch()
        self.scroll.setWidget(page)


class WarehouseLocationDialog(QDialog):
    """Depo raf/lokasyon tanımları ve mevcut stok miktarlarının raflara dağıtımı.

    Yerleşim miktarları ana stok hareketlerinden ayrı bir fiziksel adresleme katmanıdır.
    Toplam yerleşim, ilgili depodaki gerçek stok bakiyesini aşamaz.
    """
    def __init__(self, parent, db, current_user=None):
        super().__init__(parent)
        self.db = db
        self.current_user = current_user or {}
        self.edit_location_id = None
        self.setWindowTitle(f"Depo Raf / Lokasyon Yönetimi - {APP_VERSION}")
        self.resize(1320, 820)
        self.setMinimumSize(1080, 680)
        root = QVBoxLayout(self)
        title = QLabel("DEPO RAF VE LOKASYON YÖNETİMİ")
        title.setObjectName("dialogTitle")
        root.addWidget(title)
        note = QLabel("Depo içindeki bölüm, koridor, raf, kat ve gözleri tanımlayın; ürün miktarlarını fiziksel lokasyonlara dağıtın.")
        note.setWordWrap(True)
        root.addWidget(note)
        self.tabs = QTabWidget()
        root.addWidget(self.tabs, 1)
        self._build_location_tab()
        self._build_placement_tab()
        close = QPushButton("Kapat")
        close.clicked.connect(self.accept)
        root.addWidget(close, 0, Qt.AlignRight)
        self.refresh_locations()
        self.refresh_placements()

    def _warehouse_combo(self, combo, include_all=False):
        combo.clear()
        if include_all:
            combo.addItem("Tüm Depolar", None)
        for row in self.db.warehouses():
            if row["aktif"]:
                combo.addItem(f"{row['kod']} - {row['ad']}", row["id"])

    def _build_location_tab(self):
        tab = QWidget()
        root = QVBoxLayout(tab)
        filters = QHBoxLayout()
        self.loc_warehouse = QComboBox()
        self._warehouse_combo(self.loc_warehouse)
        self.loc_warehouse.currentIndexChanged.connect(self.refresh_locations)
        filters.addWidget(QLabel("Depo"))
        filters.addWidget(self.loc_warehouse, 1)
        self.loc_search = QLineEdit()
        self.loc_search.setPlaceholderText("Lokasyon kodu / adı / raf / barkod ara...")
        self.loc_search.returnPressed.connect(self.refresh_locations)
        filters.addWidget(self.loc_search, 2)
        search_btn = QPushButton("Sorgula")
        search_btn.clicked.connect(self.refresh_locations)
        filters.addWidget(search_btn)
        root.addLayout(filters)

        form = QGroupBox("Lokasyon Bilgileri")
        grid = QGridLayout(form)
        self.loc_code = QLineEdit(); self.loc_code.setPlaceholderText("Örn. A-01-01")
        self.loc_name = QLineEdit(); self.loc_name.setPlaceholderText("Örn. Ağ cihazları rafı")
        self.loc_section = QLineEdit(); self.loc_aisle = QLineEdit()
        self.loc_rack = QLineEdit(); self.loc_level = QLineEdit(); self.loc_bin = QLineEdit()
        self.loc_barcode = QLineEdit(); self.loc_barcode.setPlaceholderText("Boş bırakılırsa lokasyon kodu kullanılır")
        self.loc_active = QCheckBox("Aktif"); self.loc_active.setChecked(True)
        self.loc_desc = QLineEdit(); self.loc_desc.setPlaceholderText("Açıklama")
        fields = [("Lokasyon Kodu",self.loc_code),("Lokasyon Adı",self.loc_name),("Bölüm",self.loc_section),("Koridor",self.loc_aisle),
                  ("Raf",self.loc_rack),("Kat",self.loc_level),("Göz",self.loc_bin),("Barkod",self.loc_barcode),("Açıklama",self.loc_desc)]
        for idx,(label,widget) in enumerate(fields):
            r=idx//3; c=(idx%3)*2
            grid.addWidget(QLabel(label),r,c); grid.addWidget(widget,r,c+1)
        grid.addWidget(self.loc_active,3,4)
        root.addWidget(form)

        buttons = QHBoxLayout()
        for text, slot in [("Yeni / Temizle",self.clear_location_form),("Kaydet",self.save_location),
                           ("Sil",self.delete_location),("Etiket Yazdır",self.print_location_label),("Yenile",self.refresh_locations)]:
            b=QPushButton(text); b.clicked.connect(slot); buttons.addWidget(b)
        buttons.addStretch()
        root.addLayout(buttons)
        self.loc_table = QTableWidget(0,11)
        self.loc_table.setHorizontalHeaderLabels(["ID","Depo","Lokasyon Kodu","Lokasyon Adı","Bölüm","Koridor","Raf","Kat","Göz","Barkod","Durum"])
        configure_resizable_table(self.loc_table,"depo_lokasyonlari_v138",[50,150,110,190,110,100,90,70,70,150,75])
        self.loc_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.loc_table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.loc_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.loc_table.doubleClicked.connect(self.load_selected_location)
        root.addWidget(self.loc_table,1)
        self.tabs.addTab(tab,"Lokasyon Tanımları")

    def _build_placement_tab(self):
        tab=QWidget(); root=QVBoxLayout(tab)
        filters=QHBoxLayout()
        self.place_warehouse=QComboBox(); self._warehouse_combo(self.place_warehouse)
        self.place_warehouse.currentIndexChanged.connect(self._reload_place_combos)
        self.place_product=QComboBox(); self.place_product.setEditable(True); self.place_product.setInsertPolicy(QComboBox.NoInsert)
        self.place_product.setMinimumWidth(280)
        self.place_product.setToolTip("Ürün kodu veya adının herhangi bir bölümünü yazın; eşleşen ürünler anında listelenir.")
        # V1.38.1: Ürün araması, önceki ekranlardaki gibi yazılan metnin
        # ürün kodu veya adının herhangi bir yerinde geçmesine göre filtrelenir.
        self.place_product_completer=QCompleter(self.place_product.model(),self.place_product)
        self.place_product_completer.setCaseSensitivity(Qt.CaseInsensitive)
        self.place_product_completer.setFilterMode(Qt.MatchContains)
        self.place_product_completer.setCompletionMode(QCompleter.PopupCompletion)
        self.place_product.setCompleter(self.place_product_completer)
        self.place_product_completer.activated[str].connect(self._select_place_product_completion)
        self.place_product.currentIndexChanged.connect(self.refresh_placements)
        self.place_location=QComboBox(); self.place_location.setMinimumWidth(220)
        filters.addWidget(QLabel("Depo")); filters.addWidget(self.place_warehouse,1)
        filters.addWidget(QLabel("Ürün")); filters.addWidget(self.place_product,2)
        filters.addWidget(QLabel("Hedef Lokasyon")); filters.addWidget(self.place_location,2)
        root.addLayout(filters)
        entry=QHBoxLayout()
        self.place_qty=QLineEdit(); self.place_qty.setPlaceholderText("Yerleştirilecek miktar")
        self.place_qty.setMaximumWidth(180)
        add_btn=QPushButton("Stoktan Lokasyona Yerleştir"); add_btn.clicked.connect(self.assign_stock)
        move_btn=QPushButton("Seçili Lokasyondan Taşı"); move_btn.clicked.connect(self.move_stock)
        unassign_btn=QPushButton("Lokasyondan Dağıtımı Kaldır"); unassign_btn.clicked.connect(self.unassign_stock)
        refresh_btn=QPushButton("Yenile"); refresh_btn.clicked.connect(self.refresh_placements)
        entry.addWidget(QLabel("Miktar")); entry.addWidget(self.place_qty); entry.addWidget(add_btn); entry.addWidget(move_btn); entry.addWidget(unassign_btn); entry.addWidget(refresh_btn); entry.addStretch()
        root.addLayout(entry)
        self.place_info=QLabel("Yerleşim toplamı, depodaki gerçek stok miktarını aşamaz. Henüz rafa dağıtılmamış miktar ayrıca gösterilir.")
        self.place_info.setWordWrap(True); root.addWidget(self.place_info)
        self.place_table=QTableWidget(0,8)
        self.place_table.setHorizontalHeaderLabels(["Depo","Ürün Kodu","Ürün Adı","Lokasyon","Barkod","Yerleşik Miktar","Depo Stoku","Rafa Dağıtılmamış"])
        configure_resizable_table(self.place_table,"stok_lokasyonlari_v138",[150,110,220,180,130,110,110,140])
        self.place_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.place_table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.place_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        root.addWidget(self.place_table,1)
        hist_btn=QPushButton("Lokasyon Hareket Geçmişi")
        hist_btn.clicked.connect(self.show_location_history)
        root.addWidget(hist_btn,0,Qt.AlignRight)
        self.tabs.addTab(tab,"Ürün Yerleşimi / Lokasyon Stokları")
        self._reload_place_combos()

    def _reload_place_combos(self):
        wid=self.place_warehouse.currentData()
        self.place_product.blockSignals(True); self.place_product.clear()
        rows=self.db.conn.execute("SELECT id,kod,ad,barkod FROM urunler WHERE aktif=1 ORDER BY kod").fetchall()
        for r in rows:
            self.place_product.addItem(f"{r['kod']} - {r['ad']}" + (f" [{r['barkod']}]" if r['barkod'] else ""),r['id'])
        self.place_product.blockSignals(False)
        # Ürün alanı her depo değişiminde boş başlar; kullanıcı listeden seçer.
        self.place_product.setCurrentIndex(-1)
        self.place_product.setEditText("")
        self.place_location.clear()
        if wid:
            locs=self.db.conn.execute("SELECT id,kod,ad,barkod FROM depo_lokasyonlari WHERE depo_id=? AND aktif=1 ORDER BY kod",(wid,)).fetchall()
            for r in locs:
                self.place_location.addItem(f"{r['kod']} - {r['ad']}",r['id'])
        self.refresh_placements()

    def _select_place_product_completion(self, text):
        """Tamamlayıcı listeden seçilen ürünü gerçek combo kaydına bağlar."""
        index=self.place_product.findText(text,Qt.MatchExactly)
        if index >= 0:
            self.place_product.setCurrentIndex(index)
            self.refresh_placements()

    def _clear_place_product(self):
        """İşlem tamamlanınca ürün seçimini temizleyip alanı yeniden boş bırakır."""
        self.place_product.blockSignals(True)
        self.place_product.setCurrentIndex(-1)
        self.place_product.setEditText("")
        self.place_product.blockSignals(False)
        self.refresh_placements()

    def _stock_balance(self, product_id, warehouse_id):
        row=self.db.conn.execute("""SELECT COALESCE(SUM(CASE WHEN islem_tipi IN ('Giriş','İade') THEN miktar ELSE -miktar END),0) AS bakiye
            FROM stok_hareketleri WHERE urun_id=? AND depo_id=?""",(product_id,warehouse_id)).fetchone()
        return float(row['bakiye'] or 0)

    def _allocated_total(self, product_id, warehouse_id):
        row=self.db.conn.execute("SELECT COALESCE(SUM(miktar),0) AS toplam FROM stok_lokasyonlari WHERE urun_id=? AND depo_id=?",(product_id,warehouse_id)).fetchone()
        return float(row['toplam'] or 0)

    @staticmethod
    def _parse_qty(text):
        value=str(text or '').strip().replace(' ','')
        if not value: raise ValueError("Miktar girin.")
        if ',' in value: value=value.replace('.','').replace(',','.')
        qty=float(value)
        if qty<=0: raise ValueError("Miktar sıfırdan büyük olmalıdır.")
        return qty

    def refresh_locations(self):
        if not hasattr(self,'loc_table'): return
        wid=self.loc_warehouse.currentData(); search=self.loc_search.text().strip()
        if not wid:
            self.loc_table.setRowCount(0); return
        sql="""SELECT l.*,d.kod AS depo_kod FROM depo_lokasyonlari l JOIN depolar d ON d.id=l.depo_id WHERE l.depo_id=?"""
        params=[wid]
        if search:
            sql += " AND (l.kod LIKE ? OR l.ad LIKE ? OR l.raf LIKE ? OR l.barkod LIKE ?)"
            params.extend([f"%{search}%"]*4)
        sql += " ORDER BY l.kod"
        rows=self.db.conn.execute(sql,params).fetchall(); self.loc_table.setRowCount(0)
        for row in rows:
            r=self.loc_table.rowCount(); self.loc_table.insertRow(r)
            vals=[row['id'],row['depo_kod'],row['kod'],row['ad'],row['bolum'] or '',row['koridor'] or '',row['raf'] or '',row['kat'] or '',row['goz'] or '',row['barkod'] or '', 'Aktif' if row['aktif'] else 'Pasif']
            for c,val in enumerate(vals): self.loc_table.setItem(r,c,QTableWidgetItem(str(val)))
        self._reload_place_combos()

    def clear_location_form(self):
        self.edit_location_id=None
        for w in (self.loc_code,self.loc_name,self.loc_section,self.loc_aisle,self.loc_rack,self.loc_level,self.loc_bin,self.loc_barcode,self.loc_desc): w.clear()
        self.loc_active.setChecked(True)
        self.loc_table.clearSelection()

    def load_selected_location(self):
        row=self.loc_table.currentRow()
        if row<0:return
        item=self.loc_table.item(row,0); lid=int(item.text())
        rec=self.db.conn.execute("SELECT * FROM depo_lokasyonlari WHERE id=?",(lid,)).fetchone()
        if not rec:return
        self.edit_location_id=lid
        for widget,key in [(self.loc_code,'kod'),(self.loc_name,'ad'),(self.loc_section,'bolum'),(self.loc_aisle,'koridor'),(self.loc_rack,'raf'),(self.loc_level,'kat'),(self.loc_bin,'goz'),(self.loc_barcode,'barkod'),(self.loc_desc,'aciklama')]: widget.setText(rec[key] or '')
        self.loc_active.setChecked(bool(rec['aktif']))

    def save_location(self):
        wid=self.loc_warehouse.currentData()
        if not wid: QMessageBox.warning(self,"Lokasyon","Önce depo tanımlayın ve seçin."); return
        code=self.loc_code.text().strip(); name=self.loc_name.text().strip()
        if not code or not name: QMessageBox.warning(self,"Lokasyon","Lokasyon kodu ve adı zorunludur."); return
        barcode=self.loc_barcode.text().strip() or code
        values=(wid,code,name,self.loc_section.text().strip(),self.loc_aisle.text().strip(),self.loc_rack.text().strip(),self.loc_level.text().strip(),self.loc_bin.text().strip(),barcode,1 if self.loc_active.isChecked() else 0,self.loc_desc.text().strip())
        try:
            if self.edit_location_id:
                current=self.db.conn.execute("SELECT depo_id FROM depo_lokasyonlari WHERE id=?",(self.edit_location_id,)).fetchone()
                if current and int(current['depo_id']) != int(wid):
                    QMessageBox.warning(self,"Depo Değişikliği","Mevcut bir lokasyon başka depoya taşınamaz. Yeni depoda yeni lokasyon tanımlayın."); return
                self.db.conn.execute("""UPDATE depo_lokasyonlari SET depo_id=?,kod=?,ad=?,bolum=?,koridor=?,raf=?,kat=?,goz=?,barkod=?,aktif=?,aciklama=? WHERE id=?""",values+(self.edit_location_id,))
                lid=self.edit_location_id; operation='Lokasyon Güncelleme'
            else:
                cur=self.db.conn.execute("""INSERT INTO depo_lokasyonlari(depo_id,kod,ad,bolum,koridor,raf,kat,goz,barkod,aktif,aciklama,olusturma_tarihi) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",values+(datetime.now().isoformat(timespec='seconds'),))
                lid=cur.lastrowid; operation='Lokasyon Tanımlama'
            self.db._log_operation(operation,lid,code,self.current_user.get('id'),f"{name} | {barcode}")
            self.db.conn.commit(); self.clear_location_form(); self.refresh_locations()
        except Exception as exc:
            self.db.conn.rollback(); QMessageBox.critical(self,"Lokasyon Kaydı",f"Lokasyon kaydedilemedi. Kod veya barkod başka bir kayıtta kullanılıyor olabilir.\n\n{exc}")

    def delete_location(self):
        row=self.loc_table.currentRow()
        if row<0: QMessageBox.warning(self,"Lokasyon","Silmek için bir lokasyon seçin."); return
        lid=int(self.loc_table.item(row,0).text())
        used=self.db.conn.execute("SELECT COUNT(*) FROM stok_lokasyonlari WHERE lokasyon_id=? AND miktar>0",(lid,)).fetchone()[0]
        history=self.db.conn.execute("SELECT COUNT(*) FROM stok_lokasyon_hareketleri WHERE kaynak_lokasyon_id=? OR hedef_lokasyon_id=?",(lid,lid)).fetchone()[0]
        if used or history:
            QMessageBox.warning(self,"Lokasyon Silinemez","Bu lokasyonda ürün miktarı veya geçmiş hareket kaydı bulunuyor. Önce ürünleri başka lokasyona taşıyın. Geçmiş kayıtların korunması için lokasyonu pasifleştirebilirsiniz."); return
        if QMessageBox.question(self,"Lokasyon Sil","Seçili lokasyon silinsin mi?")!=QMessageBox.Yes:return
        try:
            self.db.conn.execute("DELETE FROM depo_lokasyonlari WHERE id=?",(lid,)); self.db.conn.commit()
            self.clear_location_form(); self.refresh_locations()
        except Exception as exc:
            self.db.conn.rollback(); QMessageBox.critical(self,"Lokasyon",str(exc))

    def print_location_label(self):
        row=self.loc_table.currentRow()
        if row<0: QMessageBox.warning(self,"Etiket","Etiket yazdırmak için lokasyon seçin."); return
        lid=int(self.loc_table.item(row,0).text())
        rec=self.db.conn.execute("SELECT l.*,d.ad AS depo_adi FROM depo_lokasyonlari l JOIN depolar d ON d.id=l.depo_id WHERE l.id=?",(lid,)).fetchone()
        if not rec:return
        import html
        doc=QTextDocument(); doc.setHtml(f"<div style='text-align:center;font-family:Arial'><h2>{html.escape(rec['depo_adi'])}</h2><h1>{html.escape(rec['kod'])}</h1><h3>{html.escape(rec['ad'])}</h3><p>{html.escape(' / '.join(x for x in [rec['bolum'],rec['koridor'],rec['raf'],rec['kat'],rec['goz']] if x))}</p><h2>{html.escape(rec['barkod'] or rec['kod'])}</h2></div>")
        printer=QPrinter(QPrinter.HighResolution); printer.setDocName(f"Lokasyon_{rec['kod']}")
        dlg=QPrintDialog(printer,self)
        if dlg.exec_()==QDialog.Accepted: doc.print_(printer)

    def refresh_placements(self):
        if not hasattr(self,'place_table'):return
        wid=self.place_warehouse.currentData(); pid=self.place_product.currentData()
        self.place_table.setRowCount(0)
        if not wid:return
        params=[wid]; sql="""SELECT sl.id,sl.urun_id,sl.lokasyon_id,sl.miktar,u.kod AS urun_kod,u.ad AS urun_ad,
            l.kod AS lokasyon_kod,l.ad AS lokasyon_ad,l.barkod,u.barkod AS urun_barkod,d.kod AS depo_kod
            FROM stok_lokasyonlari sl JOIN urunler u ON u.id=sl.urun_id JOIN depo_lokasyonlari l ON l.id=sl.lokasyon_id JOIN depolar d ON d.id=sl.depo_id
            WHERE sl.depo_id=? AND sl.miktar>0"""
        if pid: sql+=" AND sl.urun_id=?"; params.append(pid)
        sql+=" ORDER BY u.kod,l.kod"
        rows=self.db.conn.execute(sql,params).fetchall()
        for row in rows:
            balance=self._stock_balance(row['urun_id'],wid); allocated=self._allocated_total(row['urun_id'],wid); unplaced=balance-allocated
            r=self.place_table.rowCount(); self.place_table.insertRow(r)
            vals=[row['depo_kod'],row['urun_kod'],row['urun_ad'],f"{row['lokasyon_kod']} - {row['lokasyon_ad']}",row['barkod'] or '',self._fmt_qty(row['miktar']),self._fmt_qty(balance),self._fmt_qty(unplaced)]
            for c,val in enumerate(vals):
                item=QTableWidgetItem(str(val))
                if c==0:item.setData(Qt.UserRole,{'product_id':row['urun_id'],'location_id':row['lokasyon_id'],'allocation_id':row['id']})
                self.place_table.setItem(r,c,item)
        if pid:
            balance=self._stock_balance(pid,wid); allocated=self._allocated_total(pid,wid)
            self.place_info.setText(f"Seçili ürün depo bakiyesi: {self._fmt_qty(balance)} | Lokasyonlara dağıtılan: {self._fmt_qty(allocated)} | Rafa dağıtılmamış: {self._fmt_qty(balance-allocated)}")
        else:
            self.place_info.setText("Ürün seçerek o ürünün lokasyon dağılımını görüntüleyebilirsiniz. Yerleşim toplamı, depo stok bakiyesini aşamaz.")

    @staticmethod
    def _fmt_qty(value):
        return f"{float(value or 0):,.3f}".replace(',','X').replace('.',',').replace('X','.')

    def assign_stock(self):
        wid=self.place_warehouse.currentData(); pid=self.place_product.currentData(); lid=self.place_location.currentData()
        if not all((wid,pid,lid)): QMessageBox.warning(self,"Ürün Yerleşimi","Depo, ürün ve hedef lokasyon seçin."); return
        try: qty=self._parse_qty(self.place_qty.text())
        except Exception as exc: QMessageBox.warning(self,"Miktar",str(exc)); return
        balance=self._stock_balance(pid,wid); allocated=self._allocated_total(pid,wid); unplaced=balance-allocated
        if qty>unplaced+1e-9:
            QMessageBox.warning(self,"Yetersiz Dağıtılmamış Stok",f"Yerleştirilebilir miktar: {self._fmt_qty(max(0,unplaced))}\nDepo bakiyesi: {self._fmt_qty(balance)}\nMevcut yerleşim: {self._fmt_qty(allocated)}"); return
        try:
            now=datetime.now().isoformat(timespec='seconds')
            self.db.conn.execute("""INSERT INTO stok_lokasyonlari(depo_id,lokasyon_id,urun_id,miktar,guncelleme_tarihi) VALUES(?,?,?,?,?)
                ON CONFLICT(lokasyon_id,urun_id) DO UPDATE SET miktar=stok_lokasyonlari.miktar+excluded.miktar,guncelleme_tarihi=excluded.guncelleme_tarihi""",(wid,lid,pid,qty,now))
            self.db.conn.execute("INSERT INTO stok_lokasyon_hareketleri(tarih,depo_id,urun_id,kaynak_lokasyon_id,hedef_lokasyon_id,miktar,kullanici_id,aciklama) VALUES(?,?,?,?,?,?,?,?)",
                (now,wid,pid,None,lid,qty,self.current_user.get('id'),'Depo stokundan lokasyona ilk yerleştirme'))
            self.db._log_operation('Stok Lokasyon Yerleşimi',pid,None,self.current_user.get('id'),f"Depo {wid}, lokasyon {lid}, miktar {qty}")
            self.db.conn.commit(); self.place_qty.clear(); self._clear_place_product()
        except Exception as exc:
            self.db.conn.rollback(); QMessageBox.critical(self,"Yerleşim",str(exc))

    def move_stock(self):
        row=self.place_table.currentRow(); wid=self.place_warehouse.currentData(); target=self.place_location.currentData()
        if row<0 or not target: QMessageBox.warning(self,"Lokasyon Taşıma","Taşınacak satırı ve hedef lokasyonu seçin."); return
        meta=self.place_table.item(row,0).data(Qt.UserRole); pid=meta['product_id']; source=meta['location_id']
        if source==target: QMessageBox.warning(self,"Lokasyon Taşıma","Kaynak ve hedef lokasyon aynı olamaz."); return
        try: qty=self._parse_qty(self.place_qty.text())
        except Exception as exc: QMessageBox.warning(self,"Miktar",str(exc)); return
        src=self.db.conn.execute("SELECT id,miktar FROM stok_lokasyonlari WHERE lokasyon_id=? AND urun_id=?",(source,pid)).fetchone()
        if not src or qty>float(src['miktar'])+1e-9: QMessageBox.warning(self,"Yetersiz Lokasyon Stoğu",f"Kaynak lokasyondaki miktar: {self._fmt_qty(src['miktar'] if src else 0)}"); return
        now=datetime.now().isoformat(timespec='seconds')
        try:
            remaining=float(src['miktar'])-qty
            if remaining<=1e-9:self.db.conn.execute("DELETE FROM stok_lokasyonlari WHERE id=?",(src['id'],))
            else:self.db.conn.execute("UPDATE stok_lokasyonlari SET miktar=?,guncelleme_tarihi=? WHERE id=?",(remaining,now,src['id']))
            self.db.conn.execute("""INSERT INTO stok_lokasyonlari(depo_id,lokasyon_id,urun_id,miktar,guncelleme_tarihi) VALUES(?,?,?,?,?)
                ON CONFLICT(lokasyon_id,urun_id) DO UPDATE SET miktar=stok_lokasyonlari.miktar+excluded.miktar,guncelleme_tarihi=excluded.guncelleme_tarihi""",(wid,target,pid,qty,now))
            self.db.conn.execute("INSERT INTO stok_lokasyon_hareketleri(tarih,depo_id,urun_id,kaynak_lokasyon_id,hedef_lokasyon_id,miktar,kullanici_id,aciklama) VALUES(?,?,?,?,?,?,?,?)",
                (now,wid,pid,source,target,qty,self.current_user.get('id'),'Lokasyonlar arası taşıma'))
            self.db._log_operation('Lokasyonlar Arası Taşıma',pid,None,self.current_user.get('id'),f"Kaynak {source} → Hedef {target}, miktar {qty}")
            self.db.conn.commit(); self.place_qty.clear(); self._clear_place_product()
        except Exception as exc:
            self.db.conn.rollback(); QMessageBox.critical(self,"Lokasyon Taşıma",str(exc))

    def unassign_stock(self):
        """Seçili lokasyondaki miktarı raf adresinden çıkarıp dağıtılmamış havuza alır."""
        row=self.place_table.currentRow(); wid=self.place_warehouse.currentData()
        if row<0:
            QMessageBox.warning(self,"Lokasyon Stoku","Dağıtımı kaldırılacak lokasyon satırını seçin."); return
        meta=self.place_table.item(row,0).data(Qt.UserRole); pid=meta['product_id']; source=meta['location_id']
        try: qty=self._parse_qty(self.place_qty.text())
        except Exception as exc: QMessageBox.warning(self,"Miktar",str(exc)); return
        src=self.db.conn.execute("SELECT id,miktar FROM stok_lokasyonlari WHERE lokasyon_id=? AND urun_id=?",(source,pid)).fetchone()
        if not src or qty>float(src['miktar'])+1e-9:
            QMessageBox.warning(self,"Yetersiz Lokasyon Stoğu",f"Kaynak lokasyondaki miktar: {self._fmt_qty(src['miktar'] if src else 0)}"); return
        now=datetime.now().isoformat(timespec='seconds')
        try:
            remaining=float(src['miktar'])-qty
            if remaining<=1e-9:self.db.conn.execute("DELETE FROM stok_lokasyonlari WHERE id=?",(src['id'],))
            else:self.db.conn.execute("UPDATE stok_lokasyonlari SET miktar=?,guncelleme_tarihi=? WHERE id=?",(remaining,now,src['id']))
            self.db.conn.execute("INSERT INTO stok_lokasyon_hareketleri(tarih,depo_id,urun_id,kaynak_lokasyon_id,hedef_lokasyon_id,miktar,kullanici_id,aciklama) VALUES(?,?,?,?,?,?,?,?)",
                (now,wid,pid,source,None,qty,self.current_user.get('id'),'Lokasyondan dağıtılmamış stok havuzuna alındı'))
            self.db._log_operation('Lokasyon Dağıtımını Kaldırma',pid,None,self.current_user.get('id'),f"Lokasyon {source}, miktar {qty}")
            self.db.conn.commit(); self.place_qty.clear(); self._clear_place_product()
        except Exception as exc:
            self.db.conn.rollback(); QMessageBox.critical(self,"Lokasyon",str(exc))

    def show_location_history(self):
        dlg=QDialog(self); dlg.setWindowTitle("Lokasyon Hareket Geçmişi"); dlg.resize(1050,560); root=QVBoxLayout(dlg)
        table=QTableWidget(0,8); table.setHorizontalHeaderLabels(["Tarih","Depo","Ürün Kodu","Ürün Adı","Kaynak","Hedef","Miktar","Kullanıcı ID"])
        configure_resizable_table(table,"lokasyon_hareket_gecmisi_v138",[150,140,110,200,130,130,100,90])
        rows=self.db.conn.execute("""SELECT h.*,d.ad AS depo_adi,u.kod AS urun_kod,u.ad AS urun_ad,ls.kod AS kaynak_kod,lt.kod AS hedef_kod
            FROM stok_lokasyon_hareketleri h LEFT JOIN depolar d ON d.id=h.depo_id LEFT JOIN urunler u ON u.id=h.urun_id
            LEFT JOIN depo_lokasyonlari ls ON ls.id=h.kaynak_lokasyon_id LEFT JOIN depo_lokasyonlari lt ON lt.id=h.hedef_lokasyon_id ORDER BY h.id DESC LIMIT 1000""").fetchall()
        for row in rows:
            r=table.rowCount(); table.insertRow(r)
            vals=[row['tarih'],row['depo_adi'] or '',row['urun_kod'] or '',row['urun_ad'] or '',row['kaynak_kod'] or 'Depo stoku',row['hedef_kod'] or '—',self._fmt_qty(row['miktar']),row['kullanici_id'] or '']
            for c,val in enumerate(vals):table.setItem(r,c,QTableWidgetItem(str(val)))
        root.addWidget(table,1); close=QPushButton("Kapat"); close.clicked.connect(dlg.accept); root.addWidget(close,0,Qt.AlignRight); dlg.exec_()


class MainWindow(QMainWindow):
    def __init__(self, user):
        super().__init__()
        self.db = Database(DB_PATH)
        self.current_user = user
        self.role_name = (user.get("rol_adi") or "").strip()
        self.setWindowTitle(f"{APP_TITLE} - {APP_VERSION} - {user.get('ad_soyad','')} [{self.role_name}]")
        self.setMinimumSize(1120, 720)
        self.resize(1300, 820)
        self.setWindowIcon(self.style().standardIcon(QStyle.SP_ComputerIcon))
        self.build_menu()
        self.build_toolbar()
        self.build_ui()
        self.apply_style()
        self.apply_permissions()
        self.refresh_dashboard()
        self.start_auto_backup_scheduler()
        self.start_database_health_monitor()
        if (APP_SETTINGS.value("update/auto_check",False) or False) in (True,"true","1","True"):
            QTimer.singleShot(8000, self.start_background_update_check)

    def start_database_health_monitor(self):
        self._db_health_busy = False
        self._db_recovery_open = False
        self._db_health_timer = QTimer(self)
        self._db_health_timer.setInterval(30000)
        self._db_health_timer.timeout.connect(self.check_database_health)
        self._db_health_timer.start()
        QTimer.singleShot(5000, self.check_database_health)
        self.update_connection_status()

    def update_connection_status(self, extra=""):
        try:
            status = self.db.connection_info()
            suffix = f" | {extra}" if extra else ""
            self.statusBar().showMessage(f"{status}{suffix}", 10000)
        except Exception:
            pass

    def check_database_health(self):
        if self._db_health_busy or getattr(self.db, "backend", "sqlite") != "postgresql":
            return
        self._db_health_busy = True
        try:
            self.db.ping()
            self.update_connection_status("Bağlantı: AKTİF")
        except Exception as exc:
            self.update_connection_status("Bağlantı: KESİLDİ")
            if not self._db_recovery_open:
                self._db_recovery_open = True
                try:
                    QMessageBox.warning(self, "Veritabanı Bağlantısı", "Merkezi PostgreSQL bağlantısı kesildi. Bağlantı kurtarma ekranından sunucu bilgilerini kontrol edin.")
                    dlg = StartupDatabaseRecoveryDialog(self, str(exc))
                    if dlg.exec_() == QDialog.Accepted:
                        try:
                            self.db.close()
                        except Exception:
                            pass
                        global DB_PATH
                        DB_PATH = get_configured_db_path()
                        self.db = Database(DB_PATH)
                        self.refresh_dashboard()
                        self.apply_permissions()
                        self.update_connection_status("Bağlantı: AKTİF")
                except Exception as recovery_exc:
                    QMessageBox.critical(self, "Bağlantı Kurtarma", f"Yeni bağlantı kurulamadı:\n{recovery_exc}")
                finally:
                    self._db_recovery_open = False
        finally:
            self._db_health_busy = False

    def start_background_update_check(self):
        url = str(APP_SETTINGS.value("update/manifest_url","") or "").strip()
        if not url:
            return
        self._update_thread = QThread(self)
        self._update_worker = UpdateCheckWorker(url)
        self._update_worker.moveToThread(self._update_thread)
        self._update_thread.started.connect(self._update_worker.run)
        self._update_worker.finished.connect(self._background_update_result)
        self._update_worker.finished.connect(self._update_thread.quit)
        self._update_worker.finished.connect(self._update_worker.deleteLater)
        self._update_thread.finished.connect(self._update_thread.deleteLater)
        self._update_thread.start()

    def _background_update_result(self, data, error):
        if error or not data:
            return
        remote = str(data.get("version","")).strip()
        if remote and is_newer_version(remote):
            UpdateDialog(self, data).exec_()

    def open_update_settings(self):
        UpdateSettingsDialog(self).exec_()

    def open_client_profile(self):
        ClientProfileDialog(self).exec_()

    def build_menu(self):
        mb = self.menuBar()
        menus = {
            "Ürünler": [
                ("Ürün Kartları", self.open_products),
                ("Ürün Grupları", self.open_groups),
                ("Barkodlu İşlemler", self.open_barcode),
            ],
            "Cari Hesaplar": [
                ("Cari Hesap Tanımları", self.open_cari),
            ],
            "İşlemler": [
                ("Ürün Giriş", self.open_stock_in),
                ("Ürün Çıkış", self.open_stock_out),
                ("Barkodlu Giriş", self.open_barcode_in),
                ("Barkodlu Çıkış", self.open_barcode_out),
                ("Fiş Listesi / Fiş Yazdırma", self.open_slips),
            ],
            "Stok": [
                ("Depolar", self.open_warehouses),
                ("Dönem Yönetimi", self.open_period_management),
                ("Stok Dönem Kapanışı / Devir", self.open_period_close),
                ("Kapanış / Devir Geçmişi", self.open_period_close_history),
                ("Kapsamlı Stok Raporları", self.open_comprehensive_reports),
                ("Stok Sayım", self.open_inventory_count),
                ("Sayım Geçmişi", self.open_inventory_history),
                ("Sayım Fark Raporu", self.open_inventory_difference),
                ("Depolar Arası Transfer", self.open_stock_transfer),
                ("Transfer Geçmişi", self.open_transfer_history),
                ("Stok Durumu", self.open_stock_status),
                ("Stok Hareketleri", self.open_stock_movements),
            ],
            "Raporlar": [
                ("Rapor Merkezi", self.open_reports),
                ("Demirbaş Listesi", self.open_demirbas),
                ("Dönem Stok Raporları", self.open_period_reports),
                ("Ürün Raporu", lambda: self.open_reports(0)),
                ("İki Tarih Arası Stok", lambda: self.open_reports(1)),
                ("Ürün Hareket Raporu", lambda: self.open_reports(2)),
                ("Min / Max Uyarıları", lambda: self.open_reports(0)),
                ("Eksiye Düşenler", lambda: self.open_reports(0)),
                ("Bakiyesiz Ürünler", lambda: self.open_reports(0)),
            ],
            "Tanımlar": [
                ("Departman", self.open_departments),
                ("Departman Alt Birimleri", self.open_departments),
                ("Ürün Grupları", self.open_groups),
                ("Ürün Türleri", self.open_product_types),
                ("Birimler", self.open_units),
                ("Depo Raf / Lokasyonları", self.open_warehouse_locations),
            ],
            "Ayarlar": [
                ("İşlem Logları / Denetim Kaydı", self.open_operation_logs),
                ("Oturum Kayıtları", self.open_session_logs),
                ("Otomatik Yedekleme", self.open_auto_backup_settings),
                ("Kullanıcılar / Yetkiler", self.open_users),
                ("Veritabanı / Ağ Kullanımı", self.open_database_settings),
                ("İstemci / Sunucu Yapılandırması", self.open_database_settings),
                ("Veritabanı Sağlık Kontrolü", self.open_database_diagnostics),
                ("Veritabanı Migration Geçmişi", self.open_database_migration_history),
                ("PostgreSQL Veri Aktarımı", self.open_postgresql_migration),
                ("Güncelleme Ayarları", self.open_update_settings),
                ("İstemci Bağlantı Profili", self.open_client_profile),
                ("Yedekleme", self.open_backup),
            ],
        }
        self.menu_actions = {}
        self.top_menus = {}
        for menu_name, items in menus.items():
            m = mb.addMenu(menu_name)
            self.top_menus[menu_name] = m
            self.menu_actions.setdefault(menu_name, [])
            for text, slot in sorted(items, key=lambda pair: turkish_sort_key(pair[0])):
                a = QAction(text, self)
                a.triggered.connect(slot)
                m.addAction(a)
                self.menu_actions[menu_name].append((text, a))
        excel = mb.addMenu("Excel")
        a = QAction("Excel / CSV Aktarımı", self)
        a.triggered.connect(self.open_reports)
        excel.addAction(a)
        yardım = mb.addMenu("Yardım")
        help_items = [
            ("Kullanıcı Yardımı / Program Kullanım Kılavuzu", self.open_user_manual),
            ("Program Hakkında", self.show_about),
            ("Güncellemeleri Kontrol Et", lambda: check_for_updates(self, True)),
        ]
        for text, slot in sorted(help_items, key=lambda pair: turkish_sort_key(pair[0])):
            action = QAction(text, self)
            action.triggered.connect(slot)
            yardım.addAction(action)
        mb.addAction(QAction("Programdan Çıkış", self, triggered=self.close))

    def build_toolbar(self):
        tb = self.addToolBar("Ana İşlemler")
        tb.setMovable(False)
        tb.setToolButtonStyle(Qt.ToolButtonTextUnderIcon)
        items = [
            ("Ürünler", QStyle.SP_FileIcon, self.open_products),
            ("Cari Hesaplar", QStyle.SP_DirHomeIcon, self.open_cari),
            ("Ürün Giriş", QStyle.SP_ArrowDown, self.open_stock_in),
            ("Ürün Çıkış", QStyle.SP_ArrowUp, self.open_stock_out),
            ("Giriş / Çıkış", QStyle.SP_DialogApplyButton, self.open_barcode),
            ("Hareketler", QStyle.SP_FileDialogDetailedView, self.open_stock_movements),
            ("Stok Sayım", QStyle.SP_FileDialogListView, self.open_inventory_count),
            ("Stok Transfer", QStyle.SP_ArrowRight, self.open_stock_transfer),
            ("Fişler", QStyle.SP_FileDialogDetailedView, self.open_slips),
            ("Rapor", QStyle.SP_FileDialogContentsView, self.open_reports),
        ]
        self.toolbar_buttons = {}
        for text, icon, slot in items:
            b = QToolButton()
            b.setText(text)
            b.setIcon(self.style().standardIcon(icon))
            b.setToolButtonStyle(Qt.ToolButtonTextUnderIcon)
            b.setAutoRaise(True)
            b.clicked.connect(slot)
            tb.addWidget(b)
            self.toolbar_buttons[text] = b

        # Ayarlar düğmesi, üst menüdeki gerçek ayar ekranlarının tamamını açan menüyü gösterir.
        settings_button = QToolButton()
        settings_button.setText("Ayarlar")
        settings_button.setIcon(self.style().standardIcon(QStyle.SP_FileDialogListView))
        settings_button.setToolButtonStyle(Qt.ToolButtonTextUnderIcon)
        settings_button.setAutoRaise(True)
        settings_menu = QMenu(settings_button)
        settings_items = [
            ("İşlem Logları / Denetim Kaydı", self.open_operation_logs),
            ("Oturum Kayıtları", self.open_session_logs),
            ("Otomatik Yedekleme", self.open_auto_backup_settings),
            ("Kullanıcılar / Yetkiler", self.open_users),
            ("Veritabanı / Ağ Kullanımı", self.open_database_settings),
            ("İstemci / Sunucu Yapılandırması", self.open_database_settings),
            ("Veritabanı Sağlık Kontrolü", self.open_database_diagnostics),
            ("Veritabanı Migration Geçmişi", self.open_database_migration_history),
            ("PostgreSQL Veri Aktarımı", self.open_postgresql_migration),
            ("Güncelleme Ayarları", self.open_update_settings),
            ("Yedekleme", self.open_backup),
        ]
        for text, slot in sorted(settings_items, key=lambda pair: turkish_sort_key(pair[0])):
            act = QAction(text, settings_menu)
            act.triggered.connect(slot)
            settings_menu.addAction(act)
        settings_button.setMenu(settings_menu)
        settings_button.setPopupMode(QToolButton.InstantPopup)
        tb.addWidget(settings_button)
        self.toolbar_buttons["Ayarlar"] = settings_button

        # Sarı klasör simgeli "Tanımlar" düğmesi artık placeholder değildir;
        # ana menüdeki Tanımlar ile aynı çalışan açılır menüyü gösterir.
        definition_button = QToolButton()
        definition_button.setText("Tanımlar")
        definition_button.setIcon(self.style().standardIcon(QStyle.SP_FileDialogNewFolder))
        definition_button.setToolButtonStyle(Qt.ToolButtonTextUnderIcon)
        definition_button.setAutoRaise(True)
        definition_menu = QMenu(definition_button)
        definition_items = [
            ("Departman", self.open_departments),
            ("Departman Alt Birimleri", self.open_departments),
            ("Ürün Grupları", self.open_groups),
            ("Ürün Türleri", self.open_product_types),
            ("Birimler", self.open_units),
            ("Depo Raf / Lokasyonları", self.open_warehouse_locations),
        ]
        for text, slot in sorted(definition_items, key=lambda pair: turkish_sort_key(pair[0])):
            act = QAction(text, definition_menu)
            act.triggered.connect(slot)
            definition_menu.addAction(act)
        definition_button.setMenu(definition_menu)
        definition_button.setPopupMode(QToolButton.InstantPopup)
        tb.addWidget(definition_button)
        self.toolbar_buttons["Tanımlar"] = definition_button
        tb.addSeparator()
        out = QToolButton()
        out.setText("Çıkış")
        out.setIcon(self.style().standardIcon(QStyle.SP_DialogCloseButton))
        out.setToolButtonStyle(Qt.ToolButtonTextUnderIcon)
        out.clicked.connect(self.close)
        tb.addWidget(out)

    def build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(14, 12, 14, 12)
        root.setSpacing(12)
        header = QFrame()
        header.setObjectName("header")
        h = QHBoxLayout(header)
        titlebox = QVBoxLayout()
        t = QLabel(f"DEPO & STOK YÖNETİMİ  •  {APP_VERSION}")
        t.setObjectName("appTitle")
        st = QLabel("Ürün, depo, cari ve stok hareketlerini tek merkezden yönetin.")
        st.setObjectName("appSubtitle")
        titlebox.addWidget(t)
        titlebox.addWidget(st)
        h.addLayout(titlebox)
        h.addStretch()
        h.addWidget(QLabel(QDate.currentDate().toString("dd.MM.yyyy")))
        root.addWidget(header)

        quick = QGroupBox("Hızlı İşlemler")
        q = QGridLayout(quick)
        quicks = [
            ("＋ Ürün Tanımla", self.open_new_product),
            ("↓ Ürün Girişi", self.open_stock_in),
            ("↑ Ürün Çıkışı", self.open_stock_out),
            ("▣ Barkodlu İşlem", self.open_barcode),
            ("▤ Stok Sorgula", self.open_stock_status),
            ("▥ Raporlar", self.open_reports),
        ]
        for i, (text, slot) in enumerate(quicks):
            b = QPushButton(text)
            b.setMinimumHeight(44)
            b.clicked.connect(slot)
            q.addWidget(b, i // 3, i % 3)
        root.addWidget(quick)

        cards = QHBoxLayout()
        self.card_urun = KpiCard("Toplam Ürün", 0, "Aktif ürün kartları", "▦")
        self.card_depo = KpiCard("Toplam Depo", 0, "Aktif depo", "⌂")
        self.card_cari = KpiCard("Cari Hesap", 0, "Aktif cari", "◉")
        self.card_hareket = KpiCard("Stok Hareketi", 0, "Toplam stok hareketi", "↕")
        for c in (self.card_urun, self.card_depo, self.card_cari, self.card_hareket):
            cards.addWidget(c)
        root.addLayout(cards)

        lower = QHBoxLayout()
        left = QGroupBox("Program Modülleri")
        ll = QVBoxLayout(left)
        lst = QListWidget()
        mods = [
            "Ürün Kartları — ürün tanımları, barkod, grup, birim, min/max",
            "Giriş - Çıkış — stok fişleri",
            "Barkodlu İşlemler — hızlı depo hareketleri",
            "Çoklu Depo — depo bazlı stok",
            "Departmanlar — malzeme çıkışları",
            "Stok Sayım — sayım fişi, fark ve otomatik stok düzeltme",
            "Raporlar — stok, iki tarih arası, hareket, min/max ve negatif/sıfır stok",
        ]
        for x in mods:
            lst.addItem(x)
        # Ana ekrandaki Program Modülleri artık gerçek modülleri açar.
        module_actions = {
            "Ürün Kartları": self.open_products,
            "Giriş - Çıkış": self.open_slips,
            "Barkodlu İşlemler": self.open_barcode,
            "Çoklu Depo": self.open_stock_status,
            "Departmanlar": self.open_departments,
            "Stok Sayım": self.open_inventory_count,
            "Raporlar": self.open_reports,
        }
        def open_program_module(item):
            key = item.text().split(" — ")[0].strip()
            action = module_actions.get(key)
            if action:
                action()
        # Tek tıklamada açılır; ayrıca çift tıklama da aynı işlemi tetikler.
        lst.itemClicked.connect(open_program_module)
        lst.itemDoubleClicked.connect(open_program_module)
        ll.addWidget(lst)
        right = QGroupBox("Geliştirme Sırası")
        rl = QVBoxLayout(right)
        inf = QLabel(
            f"Mevcut sürüm: {APP_VERSION}\n1. Ürün Kartları ✓\n2. Depo / Departman / Grup / Birim tanımları ✓\n3. Cari hesaplar ✓\n4. Ürün giriş / çıkış fişleri ✓\n5. Barkodlu giriş / çıkış ✓\n6. Gerçek stok kontrolü ✓\n7. Raporlar + Excel ✓\n8. Kullanıcı/yetki ✓\n9. Ağ kullanımı altyapısı ✓\n10. Stok sayım + fark düzeltme ✓\n11. Veritabanı bağlantı/sağlık kontrolü ✓\n12. PostgreSQL sunucu yedekleme ✓\n13. Demirbaş listesi ✓\n14. Sistem yönetimi / otomatik yedekleme ✓\n15. Oturum kayıtları ✓\n16. İstemci bağlantı profili / dağıtım desteği ✓\n17. Güvenli veritabanı migration / güncelleme altyapısı ✓\n18. Depo raf / lokasyon tanımları ve ürün yerleşimi ✓"
        )
        inf.setWordWrap(True)
        rl.addWidget(inf)
        rl.addStretch()
        lower.addWidget(left, 3)
        lower.addWidget(right, 2)
        root.addLayout(lower, 1)
        self.setStatusBar(QStatusBar())
        self.version_label = QLabel(f"Sürüm: {APP_VERSION}")
        self.version_label.setToolTip(f"{APP_TITLE} | Sürüm: {APP_VERSION} | Tarih: {APP_VERSION_DATE}")
        self.statusBar().addPermanentWidget(self.version_label)
        self.statusBar().showMessage(f"Hoş geldiniz: {self.current_user.get('ad_soyad', '')} | {self.role_name}", 5000)

    def open_user_manual(self):
        HelpManualDialog(self).exec_()

    def show_about(self):
        QMessageBox.information(
            self,
            "Program Hakkında",
            f"<h3>{APP_TITLE}</h3>"
            f"<p><b>Sürüm:</b> {APP_VERSION}</p>"
            f"<p><b>Sürüm tarihi:</b> {APP_VERSION_DATE}</p>"
            "<p>Depo, stok, cari, sayım, transfer, demirbaş ve raporlama işlemlerinin yönetimi için geliştirilmiştir. SQLite ve merkezi PostgreSQL istemci/sunucu mimarisini destekler.</p>"
            "<p><b>Firma:</b> TUA Bilişim ve Yazılım Ltd. Şti.</p>"
            "<p><b>Haklar:</b> Programın tüm hakları TUA Bilişim ve Yazılım Ltd. Şti.'ye aittir.</p>"
            "<p><b>İletişim:</b><br>"
            "Ercan HAMZAOĞLU<br>"
            "ercanhamzaoglu@tuabilisim.com<br>"
            "ercanh@msn.com<br>"
            "Instagram: @ercan.hamzaoglu<br>"
            "X: @hamzaoglu_ercan</p>"
        )

    def apply_style(self):
        self.setStyleSheet("""
            QMainWindow { background: #eef2f6; }
            QMenuBar { background: #e8edf3; padding: 4px; }
            QMenuBar::item { padding: 7px 12px; border-radius: 4px; }
            QMenuBar::item:selected { background: #d3deea; }
            QMenu { background: white; border: 1px solid #c9d2dc; }
            QMenu::item { padding: 7px 26px; }
            QMenu::item:selected { background: #e9f1f8; }
            QToolBar { background: #dfe6ee; border: 0; spacing: 4px; padding: 4px; }
            QToolButton { min-width: 80px; min-height: 56px; padding: 5px; border-radius: 6px; }
            QToolButton:hover { background: #cad7e4; }
            #header { background: #49677f; border-radius: 9px; }
            #appTitle { color: white; font-size: 21px; font-weight: 700; }
            #appSubtitle { color: #e4edf5; font-size: 11px; }
            QGroupBox { background: white; border: 1px solid #ccd5df; border-radius: 8px; margin-top: 9px; padding-top: 12px; font-weight: 600; color: #33475b; }
            QGroupBox::title { subcontrol-origin: margin; left: 12px; padding: 0 6px; background: white; }
            QPushButton { background: #edf3f8; border: 1px solid #c3ced9; border-radius: 6px; padding: 7px 12px; color: #263a4d; font-weight: 600; }
            QPushButton:hover { background: #dde8f1; }
            QLineEdit, QComboBox, QTextEdit { background: white; border: 1px solid #bfcbd6; border-radius: 4px; padding: 5px; }
            QLineEdit:focus, QComboBox:focus, QTextEdit:focus { border: 1px solid #5c88ad; }
            QTableWidget { background: white; border: 1px solid #c8d2dc; gridline-color: #e5e9ee; alternate-background-color: #f6f8fa; }
            QHeaderView::section { background: #dfe6ee; color: #304354; border: 0; border-right: 1px solid #c7d1db; border-bottom: 1px solid #bfcbd6; padding: 6px; font-weight: 700; }
            #kpiCard { background: white; border: 1px solid #cfd8e1; border-radius: 8px; }
            #kpiIcon { font-size: 20px; color: #55738c; }
            #kpiTitle { color: #596b7c; font-size: 11px; font-weight: 600; }
            #kpiValue { color: #24394d; font-size: 24px; font-weight: 700; }
            #kpiSub { color: #5f6f7d; font-size: 11px; font-weight: 700; }
            #productHeader { background: #566f83; border-radius: 6px; }
            #productTitle { color: white; font-size: 17px; font-weight: 700; }
            #dialogTitle { font-size: 18px; font-weight: 700; color: #2f465b; }
            #stockInfo { font-weight: 700; color: #355d7a; padding: 4px 8px; }
            QTabBar::tab { padding: 7px 16px; }
            QStatusBar { background: #e3e9ef; color: #475968; }
        """)

    def refresh_dashboard(self):
        d = self.db.counts()
        self.card_urun.set_value(d["urun"])
        self.card_depo.set_value(d["depo"])
        self.card_cari.set_value(d["cari"])
        self.card_hareket.set_value(d["hareket"])
        self.statusBar().showMessage(f"Hazır | Ürün: {d['urun']} | Depo: {d['depo']} | Cari: {d['cari']} | Hareket: {d['hareket']} | DB: {self.db.path}")

    def apply_permissions(self):
        role = self.role_name.casefold()
        is_admin = role == "yönetici".casefold()
        is_stock = role == "stok kullanıcısı".casefold()
        is_report = role == "rapor kullanıcısı".casefold()

        # Menu bazlı erişim
        menu_enable = {
            "Ürünler": is_admin or is_stock,
            "Cari Hesaplar": is_admin or is_stock,
            "İşlemler": is_admin or is_stock,
            "Stok": is_admin or is_stock or is_report,
            "Raporlar": is_admin or is_stock or is_report,
            "Tanımlar": is_admin or is_stock,
            "Ayarlar": is_admin,
            "Excel": is_admin or is_stock or is_report,
        }
        for name, enabled in menu_enable.items():
            if name in self.top_menus:
                self.top_menus[name].setEnabled(enabled)

        # Daha ince yetki: Rapor Kullanıcısı Stok menüsünde sadece görüntüleme ekranlarına erişsin.
        if is_report and "Stok" in self.menu_actions:
            for text, action in self.menu_actions["Stok"]:
                action.setEnabled(text in ("Stok Durumu", "Stok Hareketleri", "Kapsamlı Stok Raporları", "Kapanış / Devir Geçmişi"))

        # Araç çubuğu
        for text, btn in self.toolbar_buttons.items():
            enabled = True
            if text in ("Ürünler", "Cari Hesaplar", "Ürün Giriş", "Ürün Çıkış", "Giriş / Çıkış", "Tanımlar", "Stok Transfer"):
                enabled = is_admin or is_stock
            elif text in ("Hareketler", "Rapor", "Fişler"):
                enabled = is_admin or is_stock or is_report
            elif text == "Ayarlar":
                enabled = is_admin
            btn.setEnabled(enabled)

        if "Ayarlar" in self.menu_actions and "İşlem Logları / Denetim Kaydı" in [t for t,_ in self.menu_actions["Ayarlar"]]:
            is_log_admin = is_admin
            for text, action in self.menu_actions["Ayarlar"]:
                if text == "İşlem Logları / Denetim Kaydı": action.setEnabled(is_log_admin)

        # Kullanıcı sadece Yönetici tarafından değiştirilebilir.
        if is_admin:
            self.statusBar().showMessage(f"Giriş yapan: {self.current_user['ad_soyad']} | Rol: {self.role_name}", 10000)
        else:
            self.statusBar().showMessage(f"Giriş yapan: {self.current_user['ad_soyad']} | Rol: {self.role_name}", 10000)

    def open_products(self):
        dlg = ProductCardsDialog(self, self.db)
        dlg.exec_()
        self.refresh_dashboard()

    def open_new_product(self):
        dlg = ProductDialog(self, self.db)
        if dlg.exec_() == QDialog.Accepted:
            self.refresh_dashboard()

    def open_groups(self):
        DefinitionDialog(self, self.db, 'urun_gruplari').exec_()

    def open_warehouses(self):
        DefinitionDialog(self, self.db, 'depolar').exec_()
        self.refresh_dashboard()

    def open_departments(self):
        DefinitionDialog(self, self.db, 'departmanlar').exec_()

    def open_units(self):
        DefinitionDialog(self, self.db, 'birimler').exec_()

    def open_product_types(self):
        DefinitionDialog(self, self.db, 'urun_turleri').exec_()

    def open_warehouse_locations(self):
        WarehouseLocationDialog(self, self.db, self.current_user).exec_()

    def open_cari(self):
        dlg = CariDialog(self, self.db)
        dlg.exec_()
        self.refresh_dashboard()

    def open_stock_in(self):
        dlg = StockSlipDialog(self, self.db, "Giriş")
        if dlg.exec_() == QDialog.Accepted:
            self.refresh_dashboard()

    def open_stock_out(self):
        dlg = StockSlipDialog(self, self.db, "Çıkış")
        if dlg.exec_() == QDialog.Accepted:
            self.refresh_dashboard()

    def open_barcode(self):
        dlg = BarcodeTransactionDialog(self, self.db, None)
        if dlg.exec_() == QDialog.Accepted:
            self.refresh_dashboard()

    def open_barcode_in(self):
        dlg = BarcodeTransactionDialog(self, self.db, "Giriş")
        if dlg.exec_() == QDialog.Accepted:
            self.refresh_dashboard()

    def open_barcode_out(self):
        dlg = BarcodeTransactionDialog(self, self.db, "Çıkış")
        if dlg.exec_() == QDialog.Accepted:
            self.refresh_dashboard()

    def open_slips(self):
        dlg = StockSlipListDialog(self, self.db)
        dlg.exec_()
        self.refresh_dashboard()

    def open_reports(self, start_tab=0):
        dlg = ReportCenterDialog(self, self.db, start_tab)
        dlg.exec_()
        self.refresh_dashboard()

    def open_demirbas(self):
        DemirbasListDialog(self, self.db).exec_()

    def open_period_reports(self):
        PeriodStockReportsDialog(self, self.db).exec_()

    def open_period_management(self):
        PeriodManagementDialog(self,self.db,self.current_user).exec_()

    def open_period_close(self):
        dlg=PeriodCloseDialog(self,self.db,self.current_user)
        if dlg.exec_()==QDialog.Accepted:self.refresh_dashboard()

    def open_period_close_history(self):
        PeriodCloseHistoryDialog(self,self.db).exec_()

    def open_comprehensive_reports(self):
        ComprehensiveStockReportDialog(self,self.db).exec_()

    def open_inventory_count(self):
        dlg=InventoryCountDialog(self,self.db,self.current_user)
        if dlg.exec_()==QDialog.Accepted:
            self.refresh_dashboard()

    def open_inventory_history(self):
        InventoryHistoryDialog(self,self.db).exec_()

    def open_inventory_difference(self):
        InventoryDifferenceDialog(self,self.db).exec_()

    def open_stock_transfer(self):
        dlg=StockTransferDialog(self,self.db,self.current_user)
        if dlg.exec_()==QDialog.Accepted: self.refresh_dashboard()

    def open_transfer_history(self):
        StockTransferHistoryDialog(self,self.db).exec_()

    def open_stock_status(self):
        dlg = StockStatusDialog(self, self.db)
        dlg.exec_()
        self.refresh_dashboard()

    def open_stock_movements(self):
        dlg = StockMovementDialog(self, self.db)
        dlg.exec_()
        self.refresh_dashboard()

    def open_database_settings(self):
        dlg = DatabaseSettingsDialog(self, DB_PATH)
        dlg.exec_()

    def open_database_migration_history(self):
        DatabaseMigrationHistoryDialog(self, self.db).exec_()

    def open_database_diagnostics(self):
        DatabaseDiagnosticsDialog(self, self.db).exec_()

    def open_postgresql_migration(self):
        if getattr(self.db, "backend", "sqlite") == "postgresql":
            QMessageBox.information(self, "PostgreSQL Aktif", "Program şu anda doğrudan PostgreSQL çalışma modunda. SQLite → PostgreSQL veri aktarım aracı bu modda gerekli değildir.")
            return
        PostgreSQLMigrationDialog(self, self.db).exec_()

    def open_operation_logs(self):
        OperationLogDialog(self,self.db).exec_()

    def open_session_logs(self):
        SessionLogDialog(self,self.db).exec_()

    def open_auto_backup_settings(self):
        AutoBackupSettingsDialog(self,self.db).exec_()

    def start_auto_backup_scheduler(self):
        self._auto_backup_timer=QTimer(self); self._auto_backup_timer.setInterval(60000); self._auto_backup_timer.timeout.connect(self.run_scheduled_backup); self._auto_backup_timer.start(); QTimer.singleShot(2500,self.run_scheduled_backup)

    def run_scheduled_backup(self):
        enabled=(APP_SETTINGS.value("backup/auto/enabled",False) or False) in (True,"true","1","True")
        if not enabled:return
        now=datetime.now(); tstr=APP_SETTINGS.value("backup/auto/time","23:30") or "23:30"
        try: target_time=datetime.strptime(tstr,"%H:%M").time()
        except ValueError: target_time=datetime.strptime("23:30","%H:%M").time()
        # Son başarılı yedek kaydı (ISO formatında)
        last=APP_SETTINGS.value("backup/auto/last_success","") or ""
        last_dt=None
        if last:
            try:last_dt=datetime.fromisoformat(last)
            except Exception: last_dt=None
        due=last_dt is None
        if last_dt:
            days=(now.date()-last_dt.date()).days
            freq=APP_SETTINGS.value("backup/auto/frequency","Her Gün") or "Her Gün"
            due=(days>=7 if freq=="Haftada Bir" else days>=1)
        if not due:return
        # İlk kurulumda da planlanan saatten önce yedek alma.
        if now.time() < target_time:return
        folder=Path(APP_SETTINGS.value("backup/auto/folder",str(Path.cwd()/"yedekler")) or str(Path.cwd()/"yedekler")); folder.mkdir(parents=True,exist_ok=True)
        stamp=now.strftime("%Y%m%d_%H%M%S"); backend=getattr(self.db,"backend","sqlite")
        try:
            if backend=="postgresql":
                fmt=APP_SETTINGS.value("backup/auto/pg_format","Custom (.dump)") or "Custom (.dump)"; ext='.dump' if fmt.startswith('Custom') else '.sql'; target=folder/f"depo_stok_auto_{stamp}{ext}"; out=perform_postgres_backup(target,fmt)
            else:
                target=folder/f"depo_stok_auto_{stamp}.db"; out=self.db.backup_to(target)
            APP_SETTINGS.setValue("backup/auto/last_success",now.isoformat(timespec='seconds')); APP_SETTINGS.sync()
            try:self.db._log_operation("Otomatik Yedekleme",None,None,self.current_user.get('id'),f"Başarılı: {out}") ; self.db.conn.commit()
            except Exception: pass
            self.statusBar().showMessage(f"Otomatik yedekleme tamamlandı: {out}",10000)
            self.cleanup_auto_backups(folder)
        except Exception as exc:
            self.statusBar().showMessage(f"Otomatik yedekleme başarısız: {exc}",10000)

    def cleanup_auto_backups(self, folder):
        keep=int(APP_SETTINGS.value("backup/auto/keep",30) or 30); files=[]
        for pattern in ("depo_stok_auto_*.db","depo_stok_auto_*.dump","depo_stok_auto_*.sql"):
            files.extend(folder.glob(pattern))
        files=sorted({x for x in files if x.is_file()}, key=lambda x:x.stat().st_mtime, reverse=True)
        for old in files[keep:]:
            try:old.unlink()
            except Exception:pass

    def open_users(self):
        UserDialog(self,self.db).exec_()

    def open_backup(self):
        if getattr(self.db, "backend", "sqlite") == "postgresql":
            PostgreSQLBackupDialog(self, self.db).exec_()
            return
        BackupDialog(self,self.db).exec_()

    def open_module(self, title, description):
        dlg = ModulePlaceholder(self, title, description)
        dlg.exec_()
        self.refresh_dashboard()

    def logout(self):
        QMessageBox.information(self, "Çıkış", "Kullanıcı oturumunu kapatmak için program yeniden giriş ekranına dönecektir.")
        self.close()

    def closeEvent(self, event):
        if QMessageBox.question(self, "Programdan Çıkış", "Programdan çıkmak istiyor musunuz?", QMessageBox.Yes | QMessageBox.No, QMessageBox.No) == QMessageBox.Yes:
            try:
                self.db.log_session(self.current_user.get("id"), self.current_user.get("kullanici_adi"), "Çıkış", "Program kapatıldı")
            except Exception:
                pass
            self.db.close()
            event.accept()
        else:
            event.ignore()


def main():
    app = QApplication(sys.argv)
    app.setApplicationName(APP_TITLE)
    app.setOrganizationName("DepoStok")
    app.setFont(QFont("Segoe UI", 9))

    # V1.34.1: Yeni kurulum/yeniden kurulumlarda eski QSettings kalmış olsa bile
    # ilk kurulum sihirbazı en az bir kez gösterilir.
    # first_run_schema, V1.34.1 ile eklenen kalıcı kurulum işaretidir.
    setup_done=(APP_SETTINGS.value("setup/completed",False) or False) in (True,"true","1","True")
    setup_schema=str(APP_SETTINGS.value("setup/first_run_schema","") or "").strip()
    first_run_required = setup_schema != "1"
    if first_run_required:
        wizard=FirstRunSetupWizard()
        if wizard.exec_()!=QDialog.Accepted:
            return 0
    try:
        db = create_database_with_startup_recovery()
    except MigrationError as exc:
        msg = "Veritabanı güvenli sürüm yükseltmesi sırasında hata oluştu.\n\n" + str(exc)
        if exc.backup_path:
            msg += f"\n\nMigration öncesi yedek:\n{exc.backup_path}"
        QMessageBox.critical(None, "Veritabanı Güncelleme Hatası", msg)
        return 1
    if db is None:
        return 0
    if getattr(db, "migration_performed", False):
        backup = getattr(db, "last_migration_backup", None)
        info = f"Veritabanı otomatik olarak V{getattr(db,'last_migration_from',1)} → V{getattr(db,'last_migration_to',DB_SCHEMA_VERSION)} şema sürümüne yükseltildi."
        if backup:
            info += f"\n\nMigration öncesi güvenlik yedeği:\n{backup}"
        backup_warning = getattr(db, "last_migration_backup_warning", None)
        if backup_warning:
            info += f"\n\nUYARI:\n{backup_warning}"
        QMessageBox.information(None, "Veritabanı Güncellemesi", info)
    active_users = db.conn.execute("SELECT COUNT(*) FROM kullanicilar WHERE aktif=1").fetchone()[0]
    if active_users == 0:
        # Eski veya özel bir veritabanında kullanıcılar pasif hale getirilmiş olabilir.
        # Yeni kurulumlarda Database.init_db() zaten Admin oluşturur; bu koruma
        # yalnızca veritabanı gerçekten kullanıcı barındırmıyorsa son bir güvenlik ağıdır.
        try:
            admin_role = db.conn.execute("SELECT id FROM roller WHERE ad=? LIMIT 1", ("Yönetici",)).fetchone()
            if admin_role:
                db.conn.execute(
                    "INSERT OR IGNORE INTO kullanicilar(kullanici_adi, ad_soyad, sifre_hash, rol_id, aktif) "
                    "VALUES (?, ?, ?, ?, 1)",
                    ("Admin", "Sistem Yöneticisi", db.hash_password("1234"), admin_role[0]),
                )
                db.conn.commit()
                active_users = db.conn.execute("SELECT COUNT(*) FROM kullanicilar WHERE aktif=1").fetchone()[0]
        except sqlite3.DatabaseError:
            pass

    if active_users == 0:
        QMessageBox.critical(None, "Kullanıcı Tanımlı Değil", "Aktif kullanıcı bulunamadı.")
        db.close()
        return 1

    login = LoginDialog(db)
    if login.exec_() != QDialog.Accepted:
        db.close()
        return 0

    user = login.user
    db.close()
    window = MainWindow(user)
    window.show()
    return app.exec_()


if __name__ == "__main__":
    main()
