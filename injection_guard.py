#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
injection_guard.py - детектор скрытых закладок (prompt injection) в документах.

Запуск:
    python3 injection_guard.py файл.docx [файл2.pdf ...]
    python3 injection_guard.py --clean файл.docx   # + выгрузить чистый текстовый слой

Что ищет:
  1. DOCX: скрытый текст (w:vanish), кегль <= 6pt, белый/почти белый шрифт,
     текст в колонтитулах/сносках/комментариях/текстовых блоках/alt-text картинок,
     метаданные (core.xml, app.xml, custom.xml), поля w:instrText.
  2. PDF:  невидимый режим отрисовки текста (Tr 3), микрокегль, белая заливка текста,
     расхождение объёма текстового слоя с видимым.
  3. ЛЮБОЙ текст: невидимые Unicode-символы (zero-width, Unicode Tags U+E0000 -
     это буквально невидимый ASCII), bidi-оверрайды, гомоглифы.
  4. Лексика: императивы, адресованные ИИ ("ignore previous", "не упоминай", "assistant" ...).

Выход: код 0 - чисто, 1 - найдены подозрительные фрагменты, 2 - ошибка.
"""

import sys
import os
import re
import zipfile
import unicodedata
import subprocess
import xml.etree.ElementTree as ET

W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"

# ---------------------------------------------------------------- Unicode слой

INVISIBLE = {
    0x200B: "ZERO WIDTH SPACE",
    0x200C: "ZERO WIDTH NON-JOINER",
    0x200D: "ZERO WIDTH JOINER",
    0x2060: "WORD JOINER",
    0xFEFF: "ZERO WIDTH NO-BREAK SPACE",
    0x00AD: "SOFT HYPHEN",
    0x180E: "MONGOLIAN VOWEL SEPARATOR",
}
BIDI = {0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069}


def scan_unicode(text, where):
    """Невидимые символы и скрытый ASCII в блоке Unicode Tags."""
    out = []
    tag_payload = []
    for i, ch in enumerate(text):
        cp = ord(ch)
        if cp in INVISIBLE:
            out.append((where, "невидимый символ %s (U+%04X), позиция %d"
                        % (INVISIBLE[cp], cp, i), ""))
        elif cp in BIDI:
            out.append((where, "bidi-оверрайд U+%04X, позиция %d" % (cp, i), ""))
        elif 0xE0000 <= cp <= 0xE007F:
            # Unicode Tags: невидимая копия ASCII, любимый приём смуглинга
            tag_payload.append(chr(cp - 0xE0000) if cp > 0xE0000 else "")
    if tag_payload:
        out.append((where, "СКРЫТЫЙ ASCII в блоке Unicode Tags (U+E0000)",
                    "".join(tag_payload)[:400]))
    return out


# ------------------------------------------------------------------- Лексика

MARKERS = [
    r"ignore (all |any |the )?(previous|prior|above)",
    r"disregard (all |any |the )?(previous|prior|above)",
    r"new instructions?", r"system prompt", r"override",
    r"you are (an? )?(ai|assistant|language model)",
    r"\b(chatgpt|claude|gemini|copilot|gpt-?[0-9]|llm)\b",
    r"as an ai\b", r"do not mention", r"don'?t mention", r"only (say|output|write)",
    r"игнорируй", r"забудь (все |всі )?(предыдущие|попередні)",
    r"новые инструкции", r"нові інструкції", r"системн(ый|ая|ое) промпт",
    r"не упомина", r"не згадуй", r"не указывай", r"не вказуй",
    r"не отмечай", r"не позначай", r"не считай риск", r"не вважай ризик",
    r"обязательно (напиши|укажи|вставь)", r"обов'?язково (напиши|вкажи|встав)",
    r"если ты (ии|ai|модель)", r"якщо ти (ші|ai|модель)",
    r"ассистент(у)?[,:]", r"асистент(у)?[,:]",
    r"нейросет", r"нейромереж", r"искусственн(ый|ому) интеллект",
    r"штучн(ий|ому) інтелект",
]
MARKER_RE = re.compile("|".join(MARKERS), re.IGNORECASE)


def scan_lexical(text, where):
    out = []
    for m in MARKER_RE.finditer(text):
        s = max(0, m.start() - 90)
        e = min(len(text), m.end() + 90)
        out.append((where, "императив/обращение к ИИ: '%s'" % m.group(0),
                    text[s:e].replace("\n", " ")))
    return out


# ---------------------------------------------------------------------- DOCX

def _rpr_flags(rpr):
    """Возвращает список причин, почему run подозрителен."""
    reasons = []
    if rpr is None:
        return reasons
    if rpr.find(W + "vanish") is not None or rpr.find(W + "webHidden") is not None:
        reasons.append("скрытый текст (w:vanish)")
    sz = rpr.find(W + "sz")
    if sz is not None:
        try:
            half = int(sz.get(W + "val"))
            if half <= 12:                      # <= 6 pt
                reasons.append("кегль %.1f pt" % (half / 2))
        except (TypeError, ValueError):
            pass
    color = rpr.find(W + "color")
    if color is not None:
        val = (color.get(W + "val") or "").upper()
        if re.fullmatch(r"[0-9A-F]{6}", val):
            r, g, b = int(val[0:2], 16), int(val[2:4], 16), int(val[4:6], 16)
            if min(r, g, b) >= 0xF0:
                reasons.append("белый/почти белый шрифт #%s" % val)
    return reasons


def _text_of(run):
    return "".join(t.text or "" for t in run.iter(W + "t"))


def scan_docx(path):
    findings = []
    all_text = []
    with zipfile.ZipFile(path) as z:
        names = z.namelist()

        # 1. Основные части + колонтитулы + сноски + комментарии
        parts = [n for n in names
                 if n.startswith("word/") and n.endswith(".xml")
                 and not n.startswith("word/theme")]
        for part in parts:
            try:
                root = ET.fromstring(z.read(part))
            except ET.ParseError:
                continue
            label = part.replace("word/", "")
            for run in root.iter(W + "r"):
                txt = _text_of(run)
                if not txt.strip():
                    continue
                all_text.append(txt)
                for reason in _rpr_flags(run.find(W + "rPr")):
                    findings.append((label, reason, txt[:300]))
            # поля (могут прятать инструкции)
            for it in root.iter(W + "instrText"):
                if it.text and len(it.text.strip()) > 40:
                    findings.append((label, "длинное поле w:instrText", it.text[:300]))
            # alt-text картинок и фигур
            for el in root.iter():
                descr = el.get("descr") or el.get("title")
                if descr and len(descr.strip()) > 25:
                    findings.append((label, "alt-text объекта", descr[:300]))
                    all_text.append(descr)
            # текстовые рамки / надписи
            if label not in ("document.xml",):
                pass

        # 2. Метаданные
        for meta in ("docProps/core.xml", "docProps/app.xml", "docProps/custom.xml"):
            if meta in names:
                try:
                    root = ET.fromstring(z.read(meta))
                except ET.ParseError:
                    continue
                for el in root.iter():
                    if el.text and len(el.text.strip()) > 40:
                        findings.append((meta, "длинный текст в метаданных",
                                         el.text.strip()[:300]))
                        all_text.append(el.text)

        # 3. Посторонние объекты
        for n in names:
            if n.endswith((".bin", ".vbaProject.bin")) or "vbaProject" in n:
                findings.append((n, "внедрённый бинарный объект / макросы", ""))

    joined = "\n".join(all_text)
    findings += scan_unicode(joined, "docx:текст")
    findings += scan_lexical(joined, "docx:текст")
    return findings, joined


# ----------------------------------------------------------------------- PDF

def scan_pdf(path):
    findings = []
    text = ""
    try:
        text = subprocess.run(["pdftotext", "-layout", path, "-"],
                              capture_output=True, text=True, timeout=120).stdout
    except Exception as e:
        findings.append(("pdf", "pdftotext не отработал: %s" % e, ""))

    # Распаковываем потоки и смотрим операторы отрисовки
    try:
        qdf = subprocess.run(["qpdf", "--qdf", "--object-streams=disable",
                              path, "-"], capture_output=True, timeout=120).stdout
        raw = qdf.decode("latin-1", "ignore")
        if re.search(r"\b3\s+Tr\b", raw):
            findings.append(("pdf", "режим отрисовки текста Tr 3 = НЕВИДИМЫЙ ТЕКСТ",
                             "используется в OCR-слоях, но и для закладок"))
        if re.search(r"\b7\s+Tr\b", raw):
            findings.append(("pdf", "режим Tr 7 (текст только как clip) - невидим", ""))
        for m in re.finditer(r"/[A-Za-z0-9.+-]+\s+([0-9.]+)\s+Tf", raw):
            try:
                if 0 < float(m.group(1)) <= 3.0:
                    findings.append(("pdf", "микрокегль %s pt" % m.group(1), ""))
                    break
            except ValueError:
                pass
        if re.search(r"\b1\s+1\s+1\s+rg\b", raw):
            findings.append(("pdf", "белая заливка (1 1 1 rg) - возможен белый по белому",
                             "проверить визуально"))
    except Exception as e:
        findings.append(("pdf", "qpdf не отработал: %s" % e, ""))

    findings += scan_unicode(text, "pdf:текст")
    findings += scan_lexical(text, "pdf:текст")
    return findings, text


# ---------------------------------------------------------------------- Вывод

def report(path, findings, clean_text, dump_clean=False):
    print("=" * 78)
    print("ФАЙЛ: %s  (%d байт)" % (path, os.path.getsize(path)))
    print("=" * 78)
    if not findings:
        print("[OK] Явных закладок не найдено.")
    else:
        crit = [f for f in findings
                if any(k in f[1] for k in ("vanish", "белый", "Tr 3", "Tr 7",
                                           "Unicode Tags", "кегль", "микрокегль",
                                           "макросы"))]
        print("[!] Находок: %d (из них структурно критичных: %d)\n"
              % (len(findings), len(crit)))
        for i, (where, reason, sample) in enumerate(findings, 1):
            print("%2d. [%s] %s" % (i, where, reason))
            if sample:
                print("    -> %s" % sample.strip()[:280])
        print("\nВЕРДИКТ: НЕ загружать документ в чат до ручного разбора находок.")
    if dump_clean:
        out = os.path.splitext(path)[0] + ".clean.txt"
        with open(out, "w", encoding="utf-8") as f:
            f.write(clean_text)
        print("\nЧистый текстовый слой выгружен: %s" % out)
    print()
    return 1 if findings else 0


def main(argv):
    dump = "--clean" in argv
    files = [a for a in argv[1:] if not a.startswith("--")]
    if not files:
        print(__doc__)
        return 2
    rc = 0
    for path in files:
        if not os.path.isfile(path):
            print("нет файла: %s" % path)
            rc = 2
            continue
        ext = os.path.splitext(path)[1].lower()
        if ext in (".docx", ".dotx", ".docm"):
            f, t = scan_docx(path)
        elif ext == ".pdf":
            f, t = scan_pdf(path)
        else:
            t = open(path, encoding="utf-8", errors="replace").read()
            f = scan_unicode(t, path) + scan_lexical(t, path)
        rc = max(rc, report(path, f, t, dump))
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv))
