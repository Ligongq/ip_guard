#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""DLP 解密工具（图形界面）。

为什么需要「外壳 + 子进程」
--------------------------
PyInstaller 打出来的 exe 是一个新进程，不在 IP-Guard 白名单里，它自己
open() 读到的永远是密文。真正有透明解密权限的是 python.exe，所以本程序
只负责界面与调度，实际的文件读写交给 python.exe 执行 decrypt_text.py。

用法
----
双击：打开界面，手动选择文件或文件夹。
拖拽：把若干文件 / 文件夹直接拖到 exe 图标上，打开时自动填入。
"""
from __future__ import annotations

import os
import queue
import shutil
import subprocess
import sys
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

APP_TITLE = "DLP 文件解密工具"
SCRIPT_NAME = "decrypt_text.py"
CREATE_NO_WINDOW = 0x08000000

PY_CANDIDATES = [
    r"C:\Users\ligongqiang\AppData\Local\Programs\Python\Python310\python.exe",
    os.path.expandvars(r"%LOCALAPPDATA%\Programs\Python\Python310\python.exe"),
    os.path.expandvars(r"%LOCALAPPDATA%\Programs\Python\Python311\python.exe"),
    os.path.expandvars(r"%LOCALAPPDATA%\Programs\Python\Python312\python.exe"),
    os.path.expandvars(r"%PROGRAMFILES%\Python310\python.exe"),
    r"C:\Python310\python.exe",
]


def resource_path(name: str) -> str:
    base = getattr(sys, "_MEIPASS", None) or os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base, name)


def find_python() -> str | None:
    for cand in PY_CANDIDATES:
        if cand and os.path.isfile(cand):
            return cand
    found = shutil.which("python.exe")
    if found:
        return found
    return None


class App:
    def __init__(self, root: tk.Tk, initial: list[str]):
        self.root = root
        self.paths: list[str] = []
        self.running = False
        self.log_queue: queue.Queue[str] = queue.Queue()

        self.py_exe = find_python()
        self.script = resource_path(SCRIPT_NAME)

        root.title(APP_TITLE)
        root.geometry("820x640")
        root.minsize(700, 540)

        self._build_ui()
        for p in initial:
            self._add_path(p)

        self.root.after(80, self._drain_log)
        self._update_status()

    # ------------------------------------------------------------------ UI
    def _build_ui(self) -> None:
        style = ttk.Style()
        try:
            style.theme_use("vista")
        except tk.TclError:
            pass
        style.configure("Title.TLabel", font=("Microsoft YaHei UI", 13, "bold"))
        style.configure("Hint.TLabel", font=("Microsoft YaHei UI", 9), foreground="#666666")
        style.configure("Go.TButton", font=("Microsoft YaHei UI", 10, "bold"))

        outer = ttk.Frame(self.root, padding=12)
        outer.pack(fill="both", expand=True)

        head = ttk.Frame(outer)
        head.pack(fill="x")
        ttk.Label(head, text="IP-Guard 密文 → 明文", style="Title.TLabel").pack(side="left")
        ttk.Label(
            head,
            text="  支持 txt / json / py / csv / doc 等，逐个检测，只处理真正的密文",
            style="Hint.TLabel",
        ).pack(side="left", pady=(6, 0))

        bar = ttk.Frame(outer)
        bar.pack(fill="x", pady=(10, 6))
        ttk.Button(bar, text="选择文件…", command=self.pick_files, width=12).pack(side="left")
        ttk.Button(bar, text="选择文件夹…", command=self.pick_folder, width=13).pack(side="left", padx=6)
        ttk.Button(bar, text="清空列表", command=self.clear_list, width=10).pack(side="left")
        self.count_label = ttk.Label(bar, text="", style="Hint.TLabel")
        self.count_label.pack(side="right")

        listbox_frame = ttk.Frame(outer)
        listbox_frame.pack(fill="both", expand=True)
        self.listbox = tk.Listbox(
            listbox_frame,
            height=8,
            font=("Consolas", 9),
            activestyle="none",
            selectmode="extended",
        )
        yscroll = ttk.Scrollbar(listbox_frame, orient="vertical", command=self.listbox.yview)
        self.listbox.configure(yscrollcommand=yscroll.set)
        self.listbox.pack(side="left", fill="both", expand=True)
        yscroll.pack(side="right", fill="y")

        opts = ttk.Frame(outer)
        opts.pack(fill="x", pady=(8, 6))
        self.recursive = tk.BooleanVar(value=True)
        self.backup = tk.BooleanVar(value=True)
        ttk.Checkbutton(opts, text="递归子目录", variable=self.recursive).pack(side="left")
        ttk.Checkbutton(opts, text="保留密文备份（_enc_backup）", variable=self.backup).pack(
            side="left", padx=14
        )

        actions = ttk.Frame(outer)
        actions.pack(fill="x", pady=(2, 8))
        self.btn_run = ttk.Button(actions, text="开始解密", command=self.run_decrypt, style="Go.TButton", width=14)
        self.btn_run.pack(side="left")
        self.btn_dry = ttk.Button(actions, text="仅检测", command=self.run_dry, width=10)
        self.btn_dry.pack(side="left", padx=8)
        ttk.Button(actions, text="打开备份目录", command=self.open_backup, width=14).pack(side="left")

        log_frame = ttk.LabelFrame(outer, text=" 运行日志 ", padding=6)
        log_frame.pack(fill="both", expand=True)
        self.log = tk.Text(
            log_frame,
            height=10,
            wrap="none",
            font=("Consolas", 9),
            state="disabled",
            background="#1e1e1e",
            foreground="#d4d4d4",
            insertbackground="#d4d4d4",
        )
        log_scroll = ttk.Scrollbar(log_frame, orient="vertical", command=self.log.yview)
        self.log.configure(yscrollcommand=log_scroll.set)
        self.log.pack(side="left", fill="both", expand=True)
        log_scroll.pack(side="right", fill="y")

        self.status = ttk.Label(outer, text="", style="Hint.TLabel")
        self.status.pack(fill="x", pady=(6, 0))

    # -------------------------------------------------------------- 列表
    def _add_path(self, path: str) -> None:
        path = os.path.abspath(path)
        if not os.path.exists(path):
            return
        if path in self.paths:
            return
        self.paths.append(path)
        prefix = "[目录] " if os.path.isdir(path) else ""
        self.listbox.insert("end", prefix + path)
        self._update_status()

    def pick_files(self) -> None:
        files = filedialog.askopenfilenames(title="选择要解密的文件")
        for f in files:
            self._add_path(f)

    def pick_folder(self) -> None:
        folder = filedialog.askdirectory(title="选择要解密的文件夹")
        if folder:
            self._add_path(folder)

    def clear_list(self) -> None:
        self.paths.clear()
        self.listbox.delete(0, "end")
        self._update_status()

    def _update_status(self) -> None:
        self.count_label.configure(text=f"待处理 {len(self.paths)} 项")
        if self.py_exe:
            self.status.configure(text=f"解释器：{self.py_exe}")
        else:
            self.status.configure(text="未找到 python.exe —— 无法执行解密（见下方说明）")

    # -------------------------------------------------------------- 运行
    def _build_cmd(self, dry: bool) -> list[str] | None:
        if not self.py_exe:
            messagebox.showerror(
                "缺少 Python",
                "未找到 python.exe。\n\n"
                "IP-Guard 只对白名单进程透明解密，本工具必须借 python.exe 读取文件。\n"
                "请安装 Python 3.10，或把它的安装路径加入 PATH。",
            )
            return None
        if not os.path.isfile(self.script):
            messagebox.showerror("文件缺失", f"缺少配套脚本：\n{self.script}")
            return None
        cmd = [self.py_exe, self.script] + self.paths
        if self.recursive.get():
            cmd.append("-r")
        if dry:
            cmd.append("-n")
        if not self.backup.get():
            cmd.append("--no-backup")
        return cmd

    def run_decrypt(self) -> None:
        self._start(dry=False)

    def run_dry(self) -> None:
        self._start(dry=True)

    def _start(self, dry: bool) -> None:
        if self.running:
            return
        if not self.paths:
            messagebox.showinfo("提示", "请先选择文件或文件夹。")
            return
        cmd = self._build_cmd(dry)
        if cmd is None:
            return

        self.running = True
        self._set_busy(True)
        self._append_log("=" * 62)
        self._append_log(("检测模式（不修改文件）" if dry else "开始解密") + f"，共 {len(self.paths)} 项")
        self._append_log("=" * 62)

        threading.Thread(target=self._worker, args=(cmd,), daemon=True).start()

    def open_backup(self) -> None:
        """打开第一个存在的 _enc_backup 目录。"""
        for p in self.paths:
            base = Path(p if os.path.isdir(p) else os.path.dirname(p))
            cand = base / "_enc_backup"
            if cand.is_dir():
                os.startfile(str(cand))
                return
        messagebox.showinfo("提示", "还没有备份目录。\n（备份在解密时自动创建）")

    def _worker(self, cmd: list[str]) -> None:
        env = dict(os.environ)
        env["PYTHONIOENCODING"] = "utf-8"
        env["PYTHONUTF8"] = "1"
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                env=env,
                creationflags=CREATE_NO_WINDOW,
            )
        except OSError as exc:
            self.log_queue.put(f"[错误] 无法启动解释器：{exc}")
            self.log_queue.put("__DONE__:1")
            return

        self._proc = proc
        assert proc.stdout is not None
        for raw in proc.stdout:
            line = raw.decode("utf-8", "replace").rstrip("\r\n")
            self.log_queue.put(line)
        code = proc.wait()
        self.log_queue.put(f"\n完成，退出码 {code}。")
        self.log_queue.put(f"__DONE__:{code}")

    def _set_busy(self, busy: bool) -> None:
        state = "disabled" if busy else "normal"
        self.btn_run.configure(state=state)
        self.btn_dry.configure(state=state)

    # -------------------------------------------------------------- 日志
    def _append_log(self, text: str) -> None:
        self.log.configure(state="normal")
        self.log.insert("end", text + "\n")
        self.log.see("end")
        self.log.configure(state="disabled")

    def _drain_log(self) -> None:
        try:
            while True:
                item = self.log_queue.get_nowait()
                if item.startswith("__DONE__:"):
                    code = int(item.split(":", 1)[1])
                    self.running = False
                    self._set_busy(False)
                    continue
                self._append_log(item)
        except queue.Empty:
            pass
        self.root.after(80, self._drain_log)


def run_selftest() -> int:
    """无界面自检：把关键路径写进 %TEMP%\\dlp_selftest.log，便于排障。"""
    lines = [
        f"exe        = {sys.executable}",
        f"frozen     = {getattr(sys, 'frozen', False)}",
        f"meipass    = {getattr(sys, '_MEIPASS', None)}",
    ]
    py = find_python()
    script = resource_path(SCRIPT_NAME)
    lines.append(f"python     = {py}")
    lines.append(f"script     = {script}")
    lines.append(f"script_ok  = {os.path.isfile(script)}")

    if py and os.path.isfile(script):
        env = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONUTF8="1")
        try:
            r = subprocess.run(
                [py, script, "--help"],
                capture_output=True,
                env=env,
                creationflags=CREATE_NO_WINDOW,
                timeout=60,
            )
            lines.append(f"help_rc    = {r.returncode}")
            lines.append("--- stdout ---")
            lines.append(r.stdout.decode("utf-8", "replace")[:900])
            err = r.stderr.decode("utf-8", "replace").strip()
            if err:
                lines.append("--- stderr ---")
                lines.append(err[:900])
        except Exception as exc:                     # noqa: BLE001
            lines.append(f"spawn_fail = {exc}")

    out = Path(os.environ.get("TEMP", ".")) / "dlp_selftest.log"
    out.write_text("\n".join(lines), encoding="utf-8")
    return 0


def run_cli(args: list[str]) -> int:
    """无人值守模式：把参数原样转给 decrypt_text.py，结果写入 %TEMP%\\dlp_cli.log。"""
    py = find_python()
    script = resource_path(SCRIPT_NAME)
    if not py or not os.path.isfile(script):
        return 3
    env = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONUTF8="1")
    try:
        r = subprocess.run(
            [py, script] + args,
            capture_output=True,
            env=env,
            creationflags=CREATE_NO_WINDOW,
        )
    except OSError as exc:
        (Path(os.environ.get("TEMP", ".")) / "dlp_cli.log").write_text(
            f"spawn_fail: {exc}", encoding="utf-8"
        )
        return 4

    text = r.stdout.decode("utf-8", "replace")
    err = r.stderr.decode("utf-8", "replace").strip()
    if err:
        text += "\n--- stderr ---\n" + err
    (Path(os.environ.get("TEMP", ".")) / "dlp_cli.log").write_text(text, encoding="utf-8")
    return r.returncode


def main() -> None:
    if "--selftest" in sys.argv:
        raise SystemExit(run_selftest())
    if sys.argv[1:2] == ["--cli"]:
        raise SystemExit(run_cli(sys.argv[2:]))
    initial = [a for a in sys.argv[1:] if os.path.exists(a)]
    root = tk.Tk()
    App(root, initial)
    root.mainloop()


if __name__ == "__main__":
    main()
