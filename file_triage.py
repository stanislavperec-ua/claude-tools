#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
file_triage.py v1.0 (07.09.2026) - карантин-триаж файлов из почты.
Второй слой скилла injection-guard: не закладки для ИИ, а вредоносная начинка.

Запуск:
    python3 file_triage.py файл [файл2 ...]
    python3 file_triage.py --json файл        # машинный вывод (для watch_downloads.py)
    python3 file_triage.py --defender файл    # + прогон Windows Defender (только Windows)

Что ищет (без запуска файла, только чтение байтов):
  1. Опасные типы и двойные расширения ("Матеріали.pdf.exe"), несовпадение
     сигнатуры и расширения, ярлыки .lnk, образы .iso/.img, .hta/.js/.vbs/.wsf.
  2. Архивы zip: опасные файлы внутри, вложенные архивы, шифрование
     (классика: пароль в письме, чтобы обойти антивирус). rar/7z/lzh - через 7z,
     если установлен, иначе флаг "не разобран".
  3. OOXML (docx/xlsx/pptx и *m/*t): макросы (vbaProject.bin, XLM-макролисты),
     внешние связи (attachedTemplate -> template injection, oleObject по http),
     DDE в полях, OLE-вложения, ссылки на опасные домены/TLD и на архивы/exe.
  4. Старый Office (doc/xls/ppt) и RTF: макросы через olevba (если установлен
     oletools), \\objdata / \\objupdate в RTF (эксплойты Equation Editor).
  5. PDF: /JavaScript, /JS, /OpenAction, /AA, /Launch, /EmbeddedFile, /RichMedia,
     ссылки (/URI) - с проверкой TLD и файлообменников; одностраничный PDF с одной
     ссылкой на архив = типовая приманка CERT-UA 2026.
  6. SHA256 - для ручной проверки хеша на virustotal.com (сам файл НЕ загружать:
     документы КНП и судебные материалы конфиденциальны).

Выход: код 0 - ЧИСТО, 1 - есть находки (УВАГА или НЕБЕЗПЕЧНО), 2 - ошибка.
Скрипт ничего не открывает "по-настоящему": Office, PDF-ридер, архиватор не вызываются.
"""

import sys
import os
import re
import io
import json
import zlib
import hashlib
import zipfile
import subprocess
import xml.etree.ElementTree as ET

# ----------------------------------------------------------------- справочники

DANGEROUS_EXT = {
    ".exe", ".scr", ".com", ".pif", ".bat", ".cmd", ".msi", ".msp", ".dll",
    ".js", ".jse", ".vbs", ".vbe", ".wsf", ".wsh", ".hta", ".ps1", ".psm1",
    ".lnk", ".url", ".reg", ".chm", ".cpl", ".inf", ".scf", ".jar",
    ".iso", ".img", ".vhd", ".vhdx", ".one", ".application", ".appref-ms",
}
MACRO_EXT = {".docm", ".dotm", ".xlsm", ".xltm", ".xlam", ".pptm", ".potm", ".ppam", ".ppsm"}
LEGACY_OFFICE = {".doc", ".dot", ".xls", ".xlt", ".ppt", ".pps", ".pot"}
OOXML_EXT = {".docx", ".dotx", ".xlsx", ".xltx", ".pptx", ".potx", ".ppsx"} | MACRO_EXT
ARCHIVE_EXT = {".zip", ".rar", ".7z", ".lzh", ".lha", ".arj", ".cab", ".gz", ".tgz", ".tar", ".bz2", ".xz", ".ace"}
DOC_LIKE_EXT = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".rtf", ".txt", ".jpg", ".jpeg", ".png", ".odt", ".ods"}

# TLD, которые в украинских кампаниях 2025-2026 почти не встречаются легитимно
BAD_TLD = {
    ".icu", ".top", ".xyz", ".cfd", ".sbs", ".click", ".monster", ".rest", ".cyou",
    ".buzz", ".quest", ".zip", ".mov", ".lol", ".pw", ".tk", ".ml", ".ga", ".cf", ".gq",
    ".shop", ".bond", ".fun", ".site", ".website", ".online", ".space", ".live",
}
FILE_SHARE = (
    "mega.nz", "gofile.io", "anonfiles", "dropbox.com", "drive.google.com", "docs.google.com",
    "wetransfer.com", "we.tl", "sendspace", "filetransfer", "transfer.sh", "pixeldrain",
    "1fichier", "mediafire.com", "files.fm", "fex.net", "ufile.io", "dropmefiles",
    "onedrive.live.com", "1drv.ms", "sharepoint.com", "bit.ly", "tinyurl.com", "cutt.ly",
    "t.ly", "rb.gy", "is.gd", "clck.ru", "goo.su",
)
DOWNLOAD_EXT_RE = re.compile(r"\.(zip|rar|7z|exe|scr|js|vbs|hta|lnk|iso|img|msi|lzh)(\?|$)", re.I)
URL_RE = re.compile(r"(?:https?|ftp|file)://[^\s\"'<>)\]]{4,300}", re.I)

MAGIC = [
    (b"MZ", "exe/dll (PE)"),
    (b"\x7fELF", "elf"),
    (b"PK\x03\x04", "zip-контейнер (zip/ooxml/jar/apk)"),
    (b"%PDF", "pdf"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole2 (старый Office/msi/lnk-подобные)"),
    (b"{\\rtf", "rtf"),
    (b"Rar!\x1a\x07", "rar"),
    (b"7z\xbc\xaf\x27\x1c", "7z"),
    (b"\x1f\x8b", "gzip"),
    (b"MSCF", "cab"),
    (b"\x4c\x00\x00\x00\x01\x14\x02\x00", "lnk (ярлык Windows)"),
    (b"CD001", "iso"),
    (b"\xff\xd8\xff", "jpeg"),
    (b"\x89PNG", "png"),
]
MAGIC_FAMILY = {  # какое расширение какой сигнатуре соответствует
    "pdf": {".pdf"},
    "zip-контейнер (zip/ooxml/jar/apk)": OOXML_EXT | {".zip", ".jar", ".odt", ".ods", ".odp", ".xps", ".apk", ".epub"},
    "ole2 (старый Office/msi/lnk-подобные)": LEGACY_OFFICE | {".msi", ".msg"},
    "rtf": {".rtf", ".doc"},
    "rar": {".rar"}, "7z": {".7z"}, "gzip": {".gz", ".tgz"}, "cab": {".cab"},
    "jpeg": {".jpg", ".jpeg"}, "png": {".png"},
    "exe/dll (PE)": {".exe", ".dll", ".scr", ".com", ".sys", ".cpl", ".ocx", ".pif"},
    "lnk (ярлык Windows)": {".lnk"},
}

SEV = {"НЕБЕЗПЕЧНО": 3, "УВАГА": 2, "ІНФО": 1}


class Triage:
    def __init__(self, path):
        self.path = path
        self.name = os.path.basename(path)
        self.findings = []      # (severity, where, reason, sample)
        self.urls = set()

    def add(self, sev, where, reason, sample=""):
        self.findings.append((sev, where, reason, (sample or "").strip()[:240]))

    # ------------------------------------------------------------- имя и магия
    def check_name(self, name=None, where=None):
        name = name or self.name
        where = where or "имя файла"
        low = name.lower()
        parts = low.split(".")
        ext = "." + parts[-1] if len(parts) > 1 else ""
        if ext in DANGEROUS_EXT:
            self.add("НЕБЕЗПЕЧНО", where, "исполняемый/скриптовый тип %s - в почте таким документам делать нечего" % ext, name)
        if len(parts) >= 3 and ("." + parts[-2]) in DOC_LIKE_EXT and ext not in DOC_LIKE_EXT:
            self.add("НЕБЕЗПЕЧНО", where, "двойное расширение: маскировка %s под документ .%s" % (ext, parts[-2]), name)
        if ext in MACRO_EXT:
            self.add("УВАГА", where, "формат с макросами %s" % ext, name)
        if re.search(r"[\u202a-\u202e\u2066-\u2069]", name):
            self.add("НЕБЕЗПЕЧНО", where, "bidi-оверрайд в имени файла (RLO-трюк: 'exe' показывается как 'doc')", repr(name))
        if re.search(r" {6,}", name):
            self.add("УВАГА", where, "длинная серия пробелов в имени - прячет настоящее расширение", name)
        return ext

    def check_magic(self, head, ext, where="сигнатура"):
        kind = None
        for sig, label in MAGIC:
            if head.startswith(sig):
                kind = label
                break
        if kind is None:
            return None
        fam = MAGIC_FAMILY.get(kind)
        if fam is not None and ext and ext not in fam:
            sev = "НЕБЕЗПЕЧНО" if kind in ("exe/dll (PE)", "lnk (ярлык Windows)", "elf") else "УВАГА"
            self.add(sev, where, "содержимое = %s, а расширение %s - файл притворяется" % (kind, ext))
        elif kind in ("exe/dll (PE)", "lnk (ярлык Windows)", "elf"):
            self.add("НЕБЕЗПЕЧНО", where, "исполняемое содержимое (%s)" % kind)
        return kind

    # ---------------------------------------------------------------- ссылки
    def check_urls(self, urls, where):
        for u in urls:
            self.urls.add(u)
            low = u.lower()
            host = re.sub(r"^[a-z]+://", "", low).split("/")[0].split("?")[0].split(":")[0]
            if low.startswith("file://") or low.startswith("\\\\"):
                self.add("НЕБЕЗПЕЧНО", where, "ссылка на файловый ресурс (file:// / UNC) - утечка NTLM или загрузка кода", u)
                continue
            for tld in BAD_TLD:
                if host.endswith(tld):
                    self.add("НЕБЕЗПЕЧНО", where, "домен в зоне %s (типовая зона фишинга 2025-2026)" % tld, u)
                    break
            if any(fs in host for fs in FILE_SHARE):
                self.add("УВАГА", where, "ссылка на файлообменник/укорачиватель - классическая доставка архива", u)
            if DOWNLOAD_EXT_RE.search(low):
                self.add("НЕБЕЗПЕЧНО", where, "ссылка ведёт прямо на архив/исполняемый файл", u)
            if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
                self.add("НЕБЕЗПЕЧНО", where, "ссылка на голый IP-адрес", u)
            if re.search(r"(gov|court|nszu|prozorro|rada|dsp|tax|mil)[-.]?ua[a-z0-9-]*\.(?!gov\.ua)[a-z]{2,}", host):
                self.add("НЕБЕЗПЕЧНО", where, "домен имитирует государственный (gov.ua-двойник)", u)
            if re.search(r"(prometheus|diia|дія|certua|cert-ua|derzhspetszvyazok)", host) and not host.endswith((".gov.ua", "prometheus.org.ua")):
                self.add("НЕБЕЗПЕЧНО", where, "домен имитирует известный украинский сервис", u)

    # ------------------------------------------------------------------ zip
    def scan_zip(self, path_or_bytes, where="архив", depth=0):
        try:
            zf = zipfile.ZipFile(path_or_bytes)
        except Exception as e:
            self.add("УВАГА", where, "zip не читается (%s) - возможна порча для обхода антивируса" % e)
            return
        names = zf.namelist()
        if not names:
            self.add("УВАГА", where, "пустой архив")
        for info in zf.infolist():
            n = info.filename
            if info.flag_bits & 0x1:
                self.add("НЕБЕЗПЕЧНО", where, "зашифрованный элемент архива (пароль в письме = обход антивируса)", n)
            base = n.split("/")[-1]
            if not base:
                continue
            ext = self.check_name(base, where + " -> " + n)
            if n.startswith("/") or ".." in n.split("/"):
                self.add("НЕБЕЗПЕЧНО", where, "zip-slip: путь выходит за пределы папки", n)
            if info.file_size > 200 * 1024 * 1024 and info.compress_size < 2 * 1024 * 1024:
                self.add("НЕБЕЗПЕЧНО", where, "zip-бомба: %d МБ из %d КБ" % (info.file_size // 2**20, info.compress_size // 1024), n)
            if ext in ARCHIVE_EXT and depth < 2 and info.file_size < 50 * 2**20 and not (info.flag_bits & 0x1):
                try:
                    data = zf.read(n)
                    self.add("УВАГА", where, "вложенный архив (матрёшка - приём обхода почтовых фильтров)", n)
                    if ext == ".zip":
                        self.scan_zip(io.BytesIO(data), where + " -> " + n, depth + 1)
                except Exception:
                    pass
            elif not (info.flag_bits & 0x1) and info.file_size < 30 * 2**20:
                try:
                    with zf.open(n) as fh:
                        head = fh.read(16)
                    self.check_magic(head, ext, where + " -> " + n)
                except Exception:
                    pass
        # одиночный опасный файл в zip - главный признак приманки
        bases = [n.split("/")[-1] for n in names if not n.endswith("/")]
        if len(bases) == 1 and bases[0].lower().endswith(tuple(DANGEROUS_EXT)):
            self.add("НЕБЕЗПЕЧНО", where, "архив с единственным исполняемым файлом - схема CERT-UA (PDF -> ссылка -> ZIP -> exe)", bases[0])

    def scan_other_archive(self, path, ext):
        exe = None
        for cand in ("7z", "7za", "7zz"):
            try:
                subprocess.run([cand], capture_output=True, timeout=5)
                exe = cand
                break
            except Exception:
                continue
        if not exe:
            self.add("УВАГА", "архив", "формат %s не разобран (нет 7z) - НЕ распаковывать на рабочем ПК" % ext)
            return
        try:
            out = subprocess.run([exe, "l", "-slt", "-p", path], capture_output=True, text=True, timeout=60).stdout
        except Exception as e:
            self.add("УВАГА", "архив", "7z не смог прочитать архив: %s" % e)
            return
        if "Encrypted = +" in out:
            self.add("НЕБЕЗПЕЧНО", "архив", "зашифрованный элемент архива (пароль в письме = обход антивируса)")
        paths = re.findall(r"^Path = (.+)$", out, re.M)[1:]
        for p in paths:
            self.check_name(p.split("/")[-1].split("\\")[-1], "архив -> " + p)
        if len(paths) == 1 and paths[0].lower().endswith(tuple(DANGEROUS_EXT)):
            self.add("НЕБЕЗПЕЧНО", "архив", "архив с единственным исполняемым файлом", paths[0])

    # ---------------------------------------------------------------- ooxml
    def scan_ooxml(self, path):
        try:
            zf = zipfile.ZipFile(path)
        except Exception as e:
            self.add("УВАГА", "ooxml", "не открывается как zip: %s" % e)
            return
        names = zf.namelist()
        low = [n.lower() for n in names]
        # макросы
        for n in names:
            nl = n.lower()
            if nl.endswith("vbaproject.bin"):
                self.add("НЕБЕЗПЕЧНО", n, "VBA-макросы внутри документа")
            if "/macrosheets/" in nl or "intlmacrosheets" in nl:
                self.add("НЕБЕЗПЕЧНО", n, "XLM-макролист Excel 4.0 (старые макросы, любимы вредоносами)")
            if nl.startswith(("word/embeddings/", "xl/embeddings/", "ppt/embeddings/")):
                sev = "НЕБЕЗПЕЧНО" if nl.endswith((".exe", ".bin", ".ole", ".msi", ".lnk", ".js", ".vbs", ".hta", ".bat", ".cmd", ".ps1")) else "УВАГА"
                self.add(sev, n, "встроенный OLE-объект/вложение (двойной клик = запуск)")
            if nl.startswith("customxml/") or nl.endswith(".xml.rels"):
                pass
        # Content_Types: макро-типы
        try:
            ct = zf.read("[Content_Types].xml").decode("utf-8", "replace")
            if "macroEnabled" in ct or "vbaProject" in ct:
                self.add("НЕБЕЗПЕЧНО", "[Content_Types].xml", "объявлен макро-контент", re.search(r"[^\"]*macroEnabled[^\"]*|vbaProject[^\"]*", ct).group(0))
        except KeyError:
            self.add("УВАГА", "[Content_Types].xml", "нет Content_Types - нестандартный OOXML")
        # внешние связи (.rels)
        for n in names:
            if not n.lower().endswith(".rels"):
                continue
            try:
                root = ET.fromstring(zf.read(n))
            except ET.ParseError:
                self.add("УВАГА", n, "битый XML связей")
                continue
            for rel in root.iter():
                if not rel.tag.endswith("Relationship"):
                    continue
                target = rel.get("Target", "")
                rtype = rel.get("Type", "").rsplit("/", 1)[-1]
                mode = rel.get("TargetMode", "")
                if mode == "External" or re.match(r"^(https?|file|ftp|\\\\)", target, re.I):
                    if rtype in ("attachedTemplate", "oleObject", "package", "frame", "subDocument", "vmlDrawing", "image", "oleObject"):
                        self.add("НЕБЕЗПЕЧНО", n, "внешняя связь типа %s -> загрузка кода при открытии (template injection / CVE-2021-40444-style)" % rtype, target)
                    elif rtype == "hyperlink":
                        self.check_urls([target], n + " (гиперссылка)")
                    else:
                        self.add("УВАГА", n, "внешняя связь типа %s" % rtype, target)
                        self.check_urls([target], n)
            # externalLinks в Excel
            if "externallink" in n.lower():
                self.add("УВАГА", n, "внешние ссылки книги Excel")
        # DDE и опасные поля
        for n in names:
            nl = n.lower()
            if not (nl.endswith(".xml") and (nl.startswith("word/") or nl.startswith("xl/") or nl.startswith("ppt/"))):
                continue
            try:
                data = zf.read(n).decode("utf-8", "replace")
            except Exception:
                continue
            for m in re.finditer(r"<w:instrText[^>]*>([^<]*)</w:instrText>|w:instr=\"([^\"]*)\"", data):
                instr = (m.group(1) or m.group(2) or "").strip()
                if re.search(r"\bDDE(AUTO)?\b", instr, re.I):
                    self.add("НЕБЕЗПЕЧНО", n, "DDE-поле - запуск команд при открытии", instr)
                elif re.search(r"\b(INCLUDEPICTURE|INCLUDETEXT|IMPORT|LINK)\b", instr, re.I) and re.search(r"(https?|file|\\\\)", instr, re.I):
                    self.add("НЕБЕЗПЕЧНО", n, "поле %s с внешним адресом" % instr.split()[0], instr)
            if nl.startswith("xl/") and re.search(r"<f>[^<]*(cmd|powershell|mshta|rundll32|regsvr32|EXEC\(|=CALL\()", data, re.I):
                self.add("НЕБЕЗПЕЧНО", n, "формула Excel с вызовом команды/EXEC/CALL")
            # видимые url в тексте
            self.check_urls(URL_RE.findall(data), n + " (текст)")
            if re.search(r"(?<![\\\w])\\\\[a-z0-9.\-]+\\[a-z0-9$]", data, re.I):
                self.add("УВАГА", n, "UNC-путь в тексте документа (возможна утечка NTLM)")
        # settings.xml: автозапуск, attachedTemplate без rels
        if "word/settings.xml" in names:
            s = zf.read("word/settings.xml").decode("utf-8", "replace")
            if "attachedTemplate" in s:
                self.add("УВАГА", "word/settings.xml", "подключён внешний шаблон (проверить связь в settings.xml.rels)")
            if "w:updateFields" in s:
                self.add("УВАГА", "word/settings.xml", "updateFields=true: поля обновятся при открытии (сочетание с DDE/INCLUDE = запуск)")

    # ------------------------------------------------------ старый Office, rtf
    def scan_legacy(self, path, ext):
        try:
            from oletools.olevba import VBA_Parser  # noqa
            vp = VBA_Parser(path)
            if vp.detect_vba_macros():
                self.add("НЕБЕЗПЕЧНО", "olevba", "найдены VBA-макросы")
                try:
                    res = vp.analyze_macros()
                    for kind, kw, desc in res or []:
                        if kind in ("AutoExec", "Suspicious", "IOC"):
                            self.add("НЕБЕЗПЕЧНО" if kind != "IOC" else "УВАГА", "olevba/" + kind, desc, kw)
                except Exception:
                    pass
            if hasattr(vp, "detect_xlm_macros") and vp.detect_xlm_macros():
                self.add("НЕБЕЗПЕЧНО", "olevba", "XLM-макросы Excel 4.0")
            vp.close()
        except ImportError:
            self.add("УВАГА", "olevba", "формат %s может нести макросы, oletools не установлен (pip install oletools) - проверка не выполнена" % ext)
        except Exception as e:
            self.add("УВАГА", "olevba", "olevba не смог разобрать файл: %s" % e)
        if ext in (".doc", ".xls", ".ppt"):
            self.add("ІНФО", "формат", "устаревший бинарный формат %s - сам по себе повод для осторожности" % ext)

    def scan_rtf(self, data):
        low = data.lower()
        if b"\\objdata" in low or b"\\objupdate" in low or b"\\objemb" in low:
            self.add("НЕБЕЗПЕЧНО", "rtf", "встроенный OLE-объект (\\objdata/\\objupdate) - типовой носитель эксплойтов Equation Editor")
        if re.search(rb"\\object[^\\]*\\objautlink", low):
            self.add("НЕБЕЗПЕЧНО", "rtf", "автоссылка на внешний объект")
        if b"\\dde" in low:
            self.add("НЕБЕЗПЕЧНО", "rtf", "DDE в RTF")
        if b"http" in low:
            self.check_urls(URL_RE.findall(data.decode("latin-1", "replace")), "rtf (текст)")
        if len(data) > 100000 and low.count(b"\\bin") > 20:
            self.add("УВАГА", "rtf", "много \\bin-блоков - обфускация")
        try:
            from oletools import rtfobj  # noqa
            objs = list(rtfobj.rtf_iter_objects(self.path))
            for idx, orig_len, obj in objs:
                self.add("НЕБЕЗПЕЧНО", "rtfobj", "OLE-объект #%d, %d байт" % (idx, len(obj)))
        except ImportError:
            pass
        except Exception:
            pass

    # -------------------------------------------------------------------- pdf
    def scan_pdf(self, path):
        raw = open(path, "rb").read()
        # распаковать потоки, чтобы видеть скрытое в object streams
        text = raw
        try:
            out = subprocess.run(["qpdf", "--qdf", "--object-streams=disable", path, "-"],
                                 capture_output=True, timeout=60).stdout
            if out and len(out) > 100:
                text = out
        except Exception:
            # fallback: расжать FlateDecode вручную
            chunks = []
            for m in re.finditer(rb"stream\r?\n(.*?)\r?\nendstream", raw, re.S):
                try:
                    chunks.append(zlib.decompress(m.group(1)))
                except Exception:
                    pass
            text = raw + b"\n".join(chunks)
        # /Name с hex-обфускацией (#4A#53 = JS)
        def deobf(b):
            return re.sub(rb"#([0-9A-Fa-f]{2})", lambda m: bytes([int(m.group(1), 16)]), b)
        t = deobf(text)
        checks = [
            (rb"/JavaScript|/JS\b", "НЕБЕЗПЕЧНО", "JavaScript внутри PDF"),
            (rb"/OpenAction", "ІНФО", "действие при открытии (/OpenAction) - само по себе обычно переход на 1-ю страницу"),
            (rb"/AA\b", "УВАГА", "автоматические действия (/AA)"),
            (rb"/Launch", "НЕБЕЗПЕЧНО", "запуск внешней программы (/Launch)"),
            (rb"/EmbeddedFile", "НЕБЕЗПЕЧНО", "встроенный файл в PDF (вложение-контейнер)"),
            (rb"/RichMedia|/Flash", "НЕБЕЗПЕЧНО", "RichMedia/Flash"),
            (rb"/XFA", "УВАГА", "XFA-формы (старый вектор уязвимостей Adobe)"),
            (rb"/SubmitForm", "УВАГА", "отправка формы наружу (/SubmitForm)"),
            (rb"/GoToR|/GoToE", "УВАГА", "переход во внешний документ"),
            (rb"/AcroForm", "ІНФО", "интерактивная форма"),
        ]
        for pat, sev, why in checks:
            n = len(re.findall(pat, t))
            if n:
                self.add(sev, "pdf", "%s (x%d)" % (why, n))
        if len(re.findall(rb"/ObjStm", raw)) and text is raw:
            self.add("УВАГА", "pdf", "object streams не распакованы (нет qpdf) - часть структуры не видна")
        # ссылки
        uris = set()
        for m in re.finditer(rb"/URI\s*\(([^)]{4,400})\)", t):
            uris.add(m.group(1).decode("latin-1", "replace"))
        for m in re.finditer(rb"/URI\s*<([0-9A-Fa-f\s]+)>", t):
            try:
                uris.add(bytes.fromhex(re.sub(rb"\s", b"", m.group(1)).decode()).decode("latin-1"))
            except Exception:
                pass
        try:
            plain = subprocess.run(["pdftotext", "-q", path, "-"], capture_output=True, timeout=60).stdout.decode("utf-8", "replace")
        except Exception:
            plain = ""
        for u in URL_RE.findall(plain):
            uris.add(u)
        self.check_urls(sorted(uris), "pdf (ссылки)")
        pages = len(re.findall(rb"/Type\s*/Page\b", t)) or 1
        untrusted = [u for u in uris if not re.search(r"://([\w.-]+\.)?(gov\.ua|rada\.gov\.ua|court\.gov\.ua|prozorro\.gov\.ua|nszu\.gov\.ua|ligazakon\.net|zakononline\.com\.ua|reyestr\.court\.gov\.ua|opendatabot\.ua|youcontrol\.com\.ua|clarity-project\.info|prometheus\.org\.ua)(/|$)", u, re.I)]
        if pages <= 2 and 1 <= len(untrusted) <= 3 and len(plain.strip()) < 2500:
            self.add("УВАГА", "pdf", "короткий PDF с %d внешней ссылкой(ами) - формат приманки 'документ по ссылке'" % len(untrusted))
        if pages <= 1 and not plain.strip() and b"/Image" in t:
            self.add("УВАГА", "pdf", "PDF = одна картинка без текстового слоя (обход текстовых фильтров), проверьте ссылку/QR на ней")

    # ------------------------------------------------------------- defender
    def defender(self):
        if os.name != "nt":
            return
        exe = None
        for base in (os.environ.get("ProgramFiles", r"C:\Program Files"), os.environ.get("ProgramW6432", r"C:\Program Files")):
            p = os.path.join(base, "Windows Defender", "MpCmdRun.exe")
            if os.path.isfile(p):
                exe = p
                break
        if not exe:
            self.add("ІНФО", "defender", "MpCmdRun.exe не найден")
            return
        try:
            r = subprocess.run([exe, "-Scan", "-ScanType", "3", "-File", os.path.abspath(self.path), "-DisableRemediation"],
                               capture_output=True, text=True, timeout=300)
            if r.returncode == 2:
                self.add("НЕБЕЗПЕЧНО", "defender", "Windows Defender нашёл угрозу", r.stdout[-400:])
            elif r.returncode == 0:
                self.add("ІНФО", "defender", "Defender: чисто (по сигнатурам на сегодня)")
            else:
                self.add("ІНФО", "defender", "Defender вернул код %d" % r.returncode)
        except Exception as e:
            self.add("ІНФО", "defender", "Defender не запустился: %s" % e)

    # ------------------------------------------------------------------ run
    def run(self, use_defender=False):
        p = self.path
        ext = self.check_name()
        with open(p, "rb") as f:
            head = f.read(16)
        kind = self.check_magic(head, ext)
        size = os.path.getsize(p)
        if size == 0:
            self.add("УВАГА", "размер", "пустой файл")
        if kind == "zip-контейнер (zip/ooxml/jar/apk)":
            if ext in OOXML_EXT:
                self.scan_ooxml(p)
            elif ext in (".odt", ".ods", ".odp"):
                self.scan_ooxml(p)
            else:
                self.scan_zip(p)
        elif kind == "pdf":
            self.scan_pdf(p)
        elif kind == "ole2 (старый Office/msi/lnk-подобные)":
            self.scan_legacy(p, ext or ".doc")
        elif kind == "rtf":
            self.scan_rtf(open(p, "rb").read())
        elif kind in ("rar", "7z", "cab", "gzip") or ext in ARCHIVE_EXT:
            self.scan_other_archive(p, ext or kind)
        elif kind is None and ext in (".txt", ".csv", ".htm", ".html", ".eml", ".msg", ".md", ""):
            data = open(p, "rb").read()
            txt = data.decode("utf-8", "replace")
            self.check_urls(URL_RE.findall(txt), "текст")
            if ext in (".htm", ".html") and re.search(r"<script|javascript:|data:text/html", txt, re.I):
                self.add("НЕБЕЗПЕЧНО", "html", "скрипт/data-URI в HTML-вложении (HTML-smuggling)")
            if ext == ".eml" or txt.startswith(("Received:", "Return-Path:", "From:")):
                self.scan_eml_headers(txt)
        if use_defender:
            self.defender()
        return self.verdict()

    def scan_eml_headers(self, txt):
        hdr = txt.split("\n\n", 1)[0]
        ar = re.search(r"Authentication-Results:.*?(?=\n\S)", hdr, re.S | re.I)
        if ar:
            a = ar.group(0).lower()
            for k in ("spf", "dkim", "dmarc"):
                m = re.search(k + r"=(\w+)", a)
                if m and m.group(1) not in ("pass",):
                    self.add("УВАГА", "eml", "%s=%s" % (k, m.group(1)))
        frm = re.search(r"^From:\s*(.*)$", hdr, re.M | re.I)
        rt = re.search(r"^Reply-To:\s*(.*)$", hdr, re.M | re.I)
        if frm and rt:
            d1 = re.search(r"@([\w.\-]+)", frm.group(1))
            d2 = re.search(r"@([\w.\-]+)", rt.group(1))
            if d1 and d2 and d1.group(1).lower() != d2.group(1).lower():
                self.add("УВАГА", "eml", "Reply-To ведёт на другой домен, чем From", "%s -> %s" % (d1.group(1), d2.group(1)))

    def verdict(self):
        top = max((SEV[s] for s, *_ in self.findings), default=0)
        return {3: "НЕБЕЗПЕЧНО", 2: "УВАГА", 1: "ЧИСТО", 0: "ЧИСТО"}[top]


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def report(t, verdict, as_json=False):
    rank = {"НЕБЕЗПЕЧНО": 0, "УВАГА": 1, "ІНФО": 2}
    fnd = sorted(t.findings, key=lambda x: rank[x[0]])
    if as_json:
        return {"file": t.path, "verdict": verdict, "sha256": sha256(t.path),
                "findings": [{"severity": s, "where": w, "reason": r, "sample": smp} for s, w, r, smp in fnd],
                "urls": sorted(t.urls)}
    print("=" * 78)
    print("ФАЙЛ: %s  (%d байт)" % (t.path, os.path.getsize(t.path)))
    print("SHA256: %s   <- проверить хеш на virustotal.com, файл НЕ загружать" % sha256(t.path))
    print("=" * 78)
    print("ВЕРДИКТ: %s" % verdict)
    real = [f for f in fnd if f[0] != "ІНФО"]
    if not real:
        print("[OK] Вредоносных конструкций по структуре не найдено. Это не гарантия: эксплойт без макросов и ссылок скрипт не увидит.")
    for i, (s, w, r, smp) in enumerate(fnd, 1):
        print("%2d. [%s] [%s] %s" % (i, s, w, r))
        if smp:
            print("    -> %s" % smp)
    if verdict == "НЕБЕЗПЕЧНО":
        print("\nДЕЙСТВИЕ: не открывать, не распаковывать, не запускать. Удалить или отдать на разбор.")
    elif verdict == "УВАГА":
        print("\nДЕЙСТВИЕ: открывать только в песочнице / через конвертацию в PDF-картинки, ссылки не нажимать.")
    print()


def main(argv):
    as_json = "--json" in argv
    use_def = "--defender" in argv
    files = [a for a in argv[1:] if not a.startswith("--")]
    if not files:
        print(__doc__)
        return 2
    rc = 0
    results = []
    for path in files:
        if not os.path.isfile(path):
            print("нет файла: %s" % path, file=sys.stderr)
            rc = 2
            continue
        t = Triage(path)
        try:
            v = t.run(use_def)
        except Exception as e:
            t.add("УВАГА", "triage", "ошибка разбора: %r - файл считать подозрительным" % e)
            v = "УВАГА"
        results.append(report(t, v, as_json))
        if v != "ЧИСТО":
            rc = max(rc, 1)
    if as_json:
        print(json.dumps(results if len(results) > 1 else results[0], ensure_ascii=False, indent=1))
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv))
