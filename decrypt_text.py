#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""批量还原被 IP-Guard / DLP 驱动加密的文本与 Office 文件为明文。

用法::

    python decrypt_text.py [文件夹] [-r] [-n] [--no-backup]

    -r, --recursive   递归处理子目录（默认只处理当前这一层）
    -n, --dry-run     只检测不修改
    --no-backup       不保留密文备份（默认备份到 _enc_backup 子目录）

覆盖范围
--------
文本类：.txt .json .csv .tsv .py .xml .ini .log .md .bat .ps1 .js .ts
        .css .html .yml .yaml .sql .toml .reg …
Office：.pptx .pptm .docx .docm .xlsx .xlsm（OOXML，文件头 PK\\x03\\x04）
        .ppt .doc .xls（97-2003，OLE 复合文档）
        .zip

检测原理
--------
受信任的解释器读盘时会被 DLP 驱动透明解密，``open()`` 永远看到明文，
所以程序自己无法判断磁盘上是否加密。这里借 ``cmd.exe``（不在白名单）
把原始字节复制成 ``.bin``，再判断是否含 ``%TSD-Header`` 魔数。

写回同理：Python 读出明文 -> 写无扩展名中转文件 -> 由 ``cmd.exe`` 复制
回目标文件，确保落盘字节不再被重新加密。
"""
from __future__ import annotations

import argparse
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
from pathlib import Path

MAGIC = b"%TSD-Header"
BACKUP_DIR_NAME = "_enc_backup"
TAR_EXE = r"C:\Windows\System32\tar.exe"

TEXT_EXTS = {
    ".txt", ".json", ".csv", ".tsv", ".py", ".xml", ".ini", ".cfg", ".conf",
    ".log", ".md", ".bat", ".cmd", ".ps1", ".js", ".cjs", ".mjs", ".ts",
    ".css", ".html", ".htm", ".yml", ".yaml", ".sql", ".properties",
    ".spec", ".toml", ".vbs", ".reg",
}

# 二进制格式：只校验文件头，不做文本编码校验。
# OOXML（docx/xlsx/pptx）与 zip 都是 PK\x03\x04；Office 97-2003 是 OLE 复合文档。
OOXML_SIG = b"PK\x03\x04"
OLE_SIG = b"\xd0\xcf\x11\xe0"

BINARY_EXTS = {
    ".pptx": (OOXML_SIG,),
    ".pptm": (OOXML_SIG,),
    ".docx": (OOXML_SIG,),
    ".docm": (OOXML_SIG,),
    ".xlsx": (OOXML_SIG,),
    ".xlsm": (OOXML_SIG,),
    ".zip": (OOXML_SIG,),
    ".ppt": (OLE_SIG,),
    ".doc": (OLE_SIG,),
    ".xls": (OLE_SIG,),
}


# --------------------------------------------------------------------------- #
#  外部进程：以非白名单身份读取 / 写入原始字节
# --------------------------------------------------------------------------- #
def _cmd(args: list[str]) -> bool:
    """调用 cmd.exe 执行内置命令，返回是否成功。"""
    try:
        res = subprocess.run(
            ["cmd", "/c"] + args,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
            shell=False,
        )
    except OSError:
        return False
    return res.returncode == 0


def copy_raw(src: Path, dest_dir: Path, dest_name: str = "probe.bin") -> Path | None:
    """用 cmd.exe 把 src 的原始字节复制到 dest_dir。

    只走 ``copy``：它不在 DLP 白名单，读到的是磁盘密文。含 ``+`` 号的路径
    会失败（``copy`` 把 + 当多文件连接符），由调用方回退到 tar。

    🔴 ``dest_name`` 必须使用**不可被 DLP 解密**的扩展名（如 ``.bin``）。
    若沿用原文件名（如 ``x.json``），Python 随后读取该副本时会被驱动透明解密，
    拿到的就是明文——用“已解密的证据”判断“是否加密”，必然误报为明文。
    """
    dest = dest_dir / dest_name
    try:
        dest_dir.mkdir(parents=True, exist_ok=True)
        if dest.exists():
            dest.unlink()
    except OSError:
        pass

    try:
        src_size = src.stat().st_size
    except OSError:
        src_size = -1

    if _cmd(["copy", "/y", str(src), str(dest)]) and dest.exists():
        if src_size < 0 or dest.stat().st_size == src_size:
            return dest
    return None


def _tar_read_head(path: Path, workspace: Path) -> bytes | None:
    """用 bsdtar 打包后读取条目字节。

    tar 不在 DLP 白名单（读到的是密文），且支持 ``+`` 号与长路径，
    因此作为 ``cmd copy`` 失败时的兜底探测手段。
    """
    if not os.path.isfile(TAR_EXE):
        return None
    pkg = workspace / "probe.tar"
    try:
        if pkg.exists():
            pkg.unlink()
    except OSError:
        pass
    try:
        res = subprocess.run(
            [TAR_EXE, "-c", "-f", str(pkg), "-C", str(path.parent), path.name],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
            shell=False,
        )
    except OSError:
        return None
    if res.returncode != 0 or not pkg.exists():
        return None

    try:
        with tarfile.open(pkg, "r:") as tf:
            for member in tf.getmembers():
                if not member.isfile():
                    continue
                handle = tf.extractfile(member)
                if handle is not None:
                    with handle:
                        return handle.read(96)
    except (tarfile.TarError, OSError):
        return None
    return None


def _tar_write_bytes(raw: bytes, name: str, dest_dir: Path, workspace: Path) -> bool:
    """把明文以 ``name`` 为文件名解包进 dest_dir。

    关键：**绝不能先写成临时名再 os.replace 改名**。实测发现文件被改名为
    ``.txt`` / ``.json`` 的瞬间就会被 IP-Guard 加密（改名前是明文，改名后
    立刻变成 ``%TSD-Header`` 密文）。因此这里直接在内存里构造一个 tar，
    成员名就是目标文件名，交给 bsdtar 落盘——tar 不在白名单，写出的就是明文。
    """
    if not os.path.isfile(TAR_EXE):
        return False

    info = tarfile.TarInfo(name=name)
    info.size = len(raw)
    info.mtime = int(time.time())
    info.mode = 0o644
    buf = io.BytesIO()
    try:
        with tarfile.open(fileobj=buf, mode="w") as tf:
            tf.addfile(info, io.BytesIO(raw))
    except (tarfile.TarError, OSError):
        return False

    pkg = workspace / "__out.tar"
    try:
        pkg.write_bytes(buf.getvalue())
    except OSError:
        return False

    try:
        dest_dir.mkdir(parents=True, exist_ok=True)
        res = subprocess.run(
            [TAR_EXE, "-x", "-f", str(pkg), "-C", str(dest_dir)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
            shell=False,
        )
    except OSError:
        return False
    finally:
        try:
            pkg.unlink()
        except OSError:
            pass
    return res.returncode == 0 and (dest_dir / name).exists()


def read_raw_head(path: Path, workspace: Path) -> bytes | None:
    """用非白名单进程读取原始字节，返回文件头 96 字节；失败返回 None。

    副本一律落成 ``probe.bin``：扩展名一旦与被探测文件相同，Python 读取副本
    时会被 DLP 透明解密，检测就失效了。
    """
    probe = copy_raw(path, workspace, "probe.bin")
    if probe is not None:
        try:
            return probe.read_bytes()[:96]
        except OSError:
            return None
        finally:
            try:
                probe.unlink()
            except OSError:
                pass
    return _tar_read_head(path, workspace)


# --------------------------------------------------------------------------- #
#  内容校验
# --------------------------------------------------------------------------- #
def validate_payload(path: Path, raw: bytes) -> tuple[bool, str]:
    """确认读到的是可靠明文，避免把密文写回去。"""
    if raw.startswith(MAGIC):
        return False, "Python 对该类型无解密权限（DLP 按扩展名授权），未改动"
    if not raw:
        return False, "文件为空"

    ext = path.suffix.lower()
    signatures = BINARY_EXTS.get(ext)
    if signatures is not None:
        if any(raw.startswith(sig) for sig in signatures):
            return True, ""
        return False, f"文件头不符合 {ext} 格式，可能已损坏"

    if not raw.strip():
        return False, "内容为空"

    if ext == ".json":
        try:
            json.loads(raw.decode("utf-8-sig"))
        except UnicodeDecodeError as exc:
            return False, f"JSON 编码异常：{exc}"
        except ValueError as exc:
            return False, f"JSON 解析异常：{exc}"
        return True, ""

    try:
        raw.decode("utf-8")
        return True, ""
    except UnicodeDecodeError:
        pass
    try:
        raw.decode("gbk")
        return True, ""
    except UnicodeDecodeError:
        return False, "既非 UTF-8 也非 GBK 文本"
    return True, ""


# --------------------------------------------------------------------------- #
#  单文件解密
# --------------------------------------------------------------------------- #
def _fmt_size(n: int) -> str:
    if n >= 1024 * 1024:
        return f"{n:,} 字节 ({n / 1048576:.1f} MB)"
    return f"{n:,} 字节"


def decrypt_file(path: Path, workspace: Path, backup_root: Path | None) -> tuple[bool, str]:
    try:
        raw = path.read_bytes()          # 驱动透明解密后的明文
    except OSError as exc:
        return False, f"读取失败：{exc}"

    ok, reason = validate_payload(path, raw)
    if not ok:
        return False, reason

    backup: Path | None = None
    if backup_root is not None:
        backup_root.mkdir(parents=True, exist_ok=True)
        candidate = backup_root / path.name
        idx = 1
        while candidate.exists():
            candidate = backup_root / f"{path.stem}~{idx}{path.suffix}"
            idx += 1
        try:
            os.replace(path, candidate)          # 同盘重命名，字节不变
            backup = candidate
        except OSError as exc:
            return False, f"备份失败：{exc}"
    else:
        try:
            path.unlink()
        except OSError as exc:
            return False, f"删除原件失败：{exc}"

    if not _tar_write_bytes(raw, path.name, path.parent, workspace):
        _rollback(backup, path)
        return False, "写回失败，已回滚"

    head = read_raw_head(path, workspace)
    if head is None:
        _rollback(backup, path)
        return False, "写回后无法复验，已回滚"
    if MAGIC in head:
        _rollback(backup, path)
        return False, "写回后仍被加密，已回滚"

    return True, _fmt_size(path.stat().st_size)


def _rollback(backup: Path | None, path: Path) -> None:
    if backup is None or not backup.exists():
        return
    try:
        if path.exists():
            path.unlink()
        os.replace(backup, path)
    except OSError:
        pass


# --------------------------------------------------------------------------- #
#  目录遍历
# --------------------------------------------------------------------------- #
def _scan_dir(root: Path, recursive: bool):
    entries = root.rglob("*") if recursive else root.iterdir()
    found = []
    for p in entries:
        if not p.is_file():
            continue
        if BACKUP_DIR_NAME in p.parts:
            continue
        ext = p.suffix.lower()
        if ext in TEXT_EXTS or ext in BINARY_EXTS:
            found.append(p)
    return found


def collect_targets(paths: list[str], recursive: bool) -> list[Path]:
    """把「文件 / 文件夹」混合输入展开为去重后的文件列表。"""
    found: list[Path] = []
    for raw in paths:
        p = Path(raw).expanduser()
        if not p.is_absolute():
            p = Path.cwd() / p
        try:
            p = p.resolve()
        except OSError:
            continue
        if p.is_dir():
            found.extend(_scan_dir(p, recursive))
        elif p.is_file():
            found.append(p)

    seen: set[Path] = set()
    unique: list[Path] = []
    for p in sorted(found):
        if p not in seen:
            seen.add(p)
            unique.append(p)
    return unique


# --------------------------------------------------------------------------- #
#  入口
# --------------------------------------------------------------------------- #
def main(argv: list[str] | None = None) -> int:
    if sys.platform == "win32":
        for stream in (sys.stdout, sys.stderr):
            try:
                stream.reconfigure(encoding="utf-8")
            except Exception:
                pass

    parser = argparse.ArgumentParser(
        description="把被 IP-Guard 加密的文本 / Office 文件还原为明文",
    )
    parser.add_argument("paths", nargs="*", help="文件或文件夹，可传多个；默认为当前目录")
    parser.add_argument("-r", "--recursive", action="store_true", help="递归子目录")
    parser.add_argument("-n", "--dry-run", action="store_true", help="只检测不修改")
    parser.add_argument("--no-backup", action="store_true", help="不保留密文备份")
    args = parser.parse_args(argv)

    raw_paths = args.paths or ["."]
    bases: list[Path] = []
    for raw in raw_paths:
        p = Path(raw).expanduser()
        if not p.is_absolute():
            p = Path.cwd() / p
        try:
            p = p.resolve()
        except OSError:
            pass
        if p.is_dir():
            bases.append(p)

    if not bases and not any(Path(x).exists() for x in raw_paths):
        print(f"[错误] 路径不存在：{raw_paths[0]}")
        return 2

    targets = collect_targets(raw_paths, args.recursive)

    def _disp(path: Path) -> str:
        for base in bases:
            try:
                return str(path.relative_to(base))
            except ValueError:
                continue
        return path.name

    print(f"输入：{len(raw_paths)} 项")
    if bases:
        print(f"扫描范围：{'含子目录' if args.recursive else '仅当前层'}")
    print(f"候选文件：{len(targets)} 个（文本 + Office 二进制）")
    print("-" * 66)

    if not targets:
        print("没有可处理的文件。")
        return 0

    workspace = Path(tempfile.mkdtemp(prefix="vcm_dec_"))

    encrypted = 0
    decrypted = 0
    failed = 0
    skipped = 0

    try:
        for path in targets:
            head = read_raw_head(path, workspace)
            label = _disp(path)
            if head is None:
                failed += 1
                print(f"  [失败] {label}  （无法读取原始字节，可能被占用或路径过长）")
                continue
            if MAGIC not in head:
                skipped += 1
                continue

            encrypted += 1
            if args.dry_run:
                print(f"  [密文] {label}")
                continue

            backup_root = None if args.no_backup else path.parent / BACKUP_DIR_NAME
            ok, info = decrypt_file(path, workspace, backup_root)
            if ok:
                decrypted += 1
                print(f"  [解密] {label}  -> {info}")
            else:
                failed += 1
                print(f"  [失败] {label}  {info}")
    finally:
        shutil.rmtree(workspace, ignore_errors=True)

    print("-" * 66)
    if encrypted == 0:
        if failed:
            print(f"结论：{len(targets)} 个候选文件中 {failed} 个无法读取，其余均为明文。")
            return 1
        print(f"结论：{len(targets)} 个候选文件全部是明文，无需处理。")
        return 0

    if args.dry_run:
        print(f"结论：发现 {encrypted} 个密文文件（试运行，未修改）。")
        return 0

    print(f"结论：发现 {encrypted} 个密文，成功 {decrypted} 个，失败 {failed} 个。")
    if not args.no_backup:
        print(f"密文备份：各文件同级的 {BACKUP_DIR_NAME} 目录")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
