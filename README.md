# DLP 解密工具（IP-Guard 密文 → 明文）

批量把被 IP-Guard 透明加密的文本文件还原成明文，支持图形界面与命令行两种用法。

```
DLP-Decrypt.exe        GUI 单文件（9.4 MB），可选择文件 / 文件夹 / 拖拽
decrypt_text.py        核心逻辑，可独立运行
decrypt_gui.py         GUI 源码
解密文本文件.bat       轻量入口（命令行场景）
```

---

## 一、为什么需要这个工具

IP-Guard 这类 DLP 会把文件在磁盘上整体加密（文件头为 `%TSD-Header-###%`）。
被授权的应用（Office、白名单里的解释器）读取时由驱动透明解密，用户无感知；
但**不在白名单的进程**（打包后的 exe、其他工具、第三方脚本）读到的是密文，
表现为：

- 程序解析 JSON 报 `UnicodeDecodeError: 'utf-8' codec can't decode byte 0x.. in position 16`
- 后端接口直接 500
- 资源管理器里文件带锁图标

本工具负责把这类文件还原成真正的明文，让任意程序都能读取。

---

## 二、原理（三个必须知道的事实）

### 1. 判断「是否加密」不能用会解密的进程

同一批密文文件，不同工具读到的内容完全不同：

| 工具 | 读到的字节 | 能否用于判断 |
|---|---|---|
| `cmd copy` | 密文 `%TSD-Header` | ✅ 但含 `+` 号路径必失败 |
| `tar`（bsdtar） | 密文 | ✅ 支持 `+` 号与长路径 |
| `robocopy` | **明文** | ❌ 被 DLP 授权解密 |
| `PowerShell Copy-Item` | **明文** | ❌ 同样被授权解密 |

用 `robocopy` 去判断「有没有加密」，等于用已经解密的证据来证明文件没被加密，
结果永远是「全部是明文」。这是本工具第一版最严重的 bug。

**同源陷阱：探测副本不能沿用原扩展名。**

`cmd copy` 虽然读的是密文，但如果把副本写成 `probe.json`，随后 Python 再读这个
副本时，驱动**照样会透明解密**——检测环节又变成「用明文判断是否加密」。
实测：`Config/MPTestConfig/Profiles/*.json` 五个文件全是 `%TSD-Header` 密文，
工具却报告「6 个候选文件全部是明文」。

修正：探测副本一律固定命名为 `probe.bin`，用不可被解密的扩展名，绕开透明解密。

### 2. `cmd copy` 会把 `+` 号当文件名连接符

`copy` 支持 `copy a.txt+b.txt dest` 的多文件合并语法，所以源路径里出现 `+`
时——**即使加了引号**——会报「系统找不到指定的文件」。

实测文件名 `..._Z+_X_ClosedFRA_...txt`：`plain_name.txt` 成功，`with_Z+_mark.txt` 失败。

替代方案对比：

| 方案 | 结果 |
|---|---|
| `xcopy` | 目标文件不存在时停在 F/D 交互确认，脚本卡死 |
| 8.3 短名 | Windows 10+ 默认禁用，拿不到短名 |
| `robocopy` | 能复制，但会解密（见上） |
| **`tar`** | **可用**，且同时支持长路径 |

### 3. 改名成 `.txt` / `.json` 的瞬间就被加密

实测证据：

```
写 plain.tmp（无扩展名）   → tar 视角：plain
os.replace 改名 xxx.txt    → tar 视角：CIPHER   ← 改名即加密
```

所以「先写临时文件、再改名成目标名」的写回方案从根上不可行。

**正确的写回方式**：在内存里用 `tarfile` 构造一个 tar，成员名**直接就是目标
文件名**，再交给 `bsdtar -x` 解包到目标目录。tar 不在白名单，落盘即明文。

### 4. exe 为什么还要依赖 `python.exe`

PyInstaller 打出的 exe 是**新进程**，不在 DLP 白名单，它自己 `open()` 同样只能
拿到密文。因此 GUI 只负责界面与调度，真正的读写交给 `python.exe` 子进程执行
`decrypt_text.py`（脚本用 `--add-data` 打包进 exe，运行时解压到 `_MEIPASS`）。

代价：目标机器必须安装 Python 3.10。这是原理限制，无法绕开。

---

## 三、用法

### GUI

双击 `DLP-Decrypt.exe`：

- **选择文件…** — 多选
- **选择文件夹…** — 按需勾选「递归子目录」
- 也可以把文件 / 文件夹直接拖到 exe 图标上
- **开始解密** / **仅检测**（只报告不修改）
- **打开备份目录** — 打开第一个存在的 `_enc_backup`

勾选「保留密文备份」时，原件会移到同目录的 `_enc_backup/`，可随时回滚。

### 命令行

```bat
:: 处理整个目录（含子目录）
DLP-Decrypt.exe --cli "D:\path\to\dir" -r

:: 结果写入 %TEMP%\dlp_cli.log
```

```bat
:: 直接用 Python 脚本（等价，参数更全）
python decrypt_text.py "D:\path\to\dir" -r
python decrypt_text.py a.json b.txt -n
python decrypt_text.py "D:\dir" --no-backup
```

| 参数 | 说明 |
|---|---|
| `-r, --recursive` | 递归子目录（默认只处理当前层） |
| `-n, --dry-run` | 只检测不修改 |
| `--no-backup` | 不保留密文备份 |

### 排障

```bat
DLP-Decrypt.exe --selftest      :: 自检，输出 %TEMP%\dlp_selftest.log
```

自检会记录：是否 frozen、`_MEIPASS` 路径、找到的 python.exe、脚本是否就位、
子进程调用返回码。首次启动若窗口出现很慢，通常是杀软在扫描新 exe，等几秒即可。

---

## 四、支持范围

| 类型 | 能否解密 | 说明 |
|---|---|---|
| `.txt` `.json` `.py` | ✅ | Python 有解密权限 |
| `.csv` `.md` `.html` `.log` `.xml` `.bat` 等 | 视情况 | 逐个探测：是密文才处理，不是则跳过 |
| `.pptx` `.docx` `.xlsx` `.doc` `.xls` | ❌ | Python 无该类型解密权限 |
| `.png` `.jpg` | ❌ | 同上 |

**判断逻辑**：不预设白名单。工具对每个文件先探测磁盘字节，只有确实是
`%TSD-Header` 密文才尝试解密；读不出明文就报「Python 对该类型无解密权限」并
**跳过，不改动原文件**。

所以「某个类型能不能解」不需要查表——直接跑一次就能得到答案。

---

## 五、安全性

- **备份**：默认把密文原件移到同目录 `_enc_backup/`，文件名冲突时自动加 `~1` 后缀
- **内容校验**：写回前校验明文（`.json` 走 `json.loads`，文本按 UTF-8 → GBK 兜底），
  校验不过直接放弃，不动原文件
- **写回复验**：写回后再用 tar 视角探测一次，仍是密文则自动从备份回滚
- **幂等**：明文文件不做任何改动，重复运行输出「全部是明文，无需处理」

---

## 六、从源码构建

```bat
pip install pyinstaller
cd tools

python -m PyInstaller --onefile --windowed --name "DLP-Decrypt" ^
    --add-data "decrypt_text.py;." --noconfirm ^
    --distpath dist --workpath build decrypt_gui.py
```

产物：`dist\DLP-Decrypt.exe`

注意两点：

1. 若 `dist\DLP-Decrypt.exe` 已存在且被占用，先改名再打包
2. 打包机的 Python 版本建议 3.10（与本机白名单一致）

---

## 七、已知限制

- 路径超过 260 字符的文件：`cmd copy` 不支持，会回退到 `tar`，通常可处理
- 目标机器必须装 Python 3.10，且该解释器在 DLP 白名单内
- 只有 Python 被授权的类型才能解；`.pptx` / `.png` 这类需要 Office 或走 DLP 外发审批
- 批量处理大量文件时每个文件约 0.1–0.3 秒（tar 调用开销）
