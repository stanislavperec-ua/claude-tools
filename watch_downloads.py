#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
watch_downloads.py v1.0 (07.09.2026) - карантин-лаборатория для папки Загрузки.
Следит за папкой, каждый новый файл прогоняет через file_triage.py (лежит рядом)
и, если вердикт УВАГА/НЕБЕЗПЕЧНО, показывает окно с находками, пишет в лог,
при желании переносит файл в карантин и шлёт сообщение в Telegram.

Запуск (Windows, без зависимостей кроме Python; oletools - по желанию):
    python watch_downloads.py                       # следит за %USERPROFILE%\\Downloads
    python watch_downloads.py "D:\\Почта\\Вложения"   # другая папка
Ключи:
    --quarantine   опасные файлы переносить в Downloads\\_КАРАНТИН\\ с суффиксом .blocked
    --defender     дополнительно вызывать Windows Defender (MpCmdRun) на каждый файл
    --all          показывать окно и на ЧИСТО (по умолчанию - только УВАГА/НЕБЕЗПЕЧНО)
    --telegram     слать вердикт в Telegram; токен и chat_id берутся из переменных
                   окружения TRIAGE_TG_TOKEN и TRIAGE_TG_CHAT
Автозапуск: Планировщик заданий -> "При входе в систему" -> pythonw.exe watch_downloads.py --quarantine
Остановить: Ctrl+C в консоли или завершить pythonw.exe.

Что НЕ делает: не открывает файлы, не лечит, не подменяет антивирус. Это второй глаз.
"""

import os
import sys
import time
import json
import shutil
import threading
import datetime
import urllib.request
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
try:
    import file_triage
except ImportError:
    print("Рядом с watch_downloads.py должен лежать file_triage.py")
    sys.exit(2)

PARTIAL = (".crdownload", ".part", ".partial", ".tmp", ".download", ".opdownload", ".!ut")
SKIP_DIRS = ("_КАРАНТИН",)


def log(folder, msg):
    line = "%s  %s" % (datetime.datetime.now().strftime("%d.%m.%Y %H:%M:%S"), msg)
    print(line, flush=True)
    try:
        with open(os.path.join(folder, "_triage.log"), "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass


def popup(title, text):
    if os.name == "nt":
        import ctypes
        icon = 0x30 if "НЕБЕЗПЕЧНО" in title else 0x40  # warning / info
        threading.Thread(target=ctypes.windll.user32.MessageBoxW,
                         args=(0, text, title, icon | 0x1000), daemon=True).start()  # 0x1000 = topmost
    else:
        print("[POPUP] %s\n%s" % (title, text))


def telegram(text):
    tok = os.environ.get("TRIAGE_TG_TOKEN")
    chat = os.environ.get("TRIAGE_TG_CHAT")
    if not tok or not chat:
        return
    try:
        data = urllib.parse.urlencode({"chat_id": chat, "text": text[:3900]}).encode()
        urllib.request.urlopen("https://api.telegram.org/bot%s/sendMessage" % tok, data, timeout=15)
    except Exception as e:
        print("telegram: %s" % e)


def stable(path, wait=2.0):
    """Файл дописан: размер не меняется wait секунд и его можно открыть на чтение."""
    try:
        s1 = os.path.getsize(path)
        time.sleep(wait)
        s2 = os.path.getsize(path)
        if s1 != s2 or s2 == 0:
            return False
        with open(path, "rb"):
            pass
        return True
    except (OSError, PermissionError):
        return False


def handle(folder, path, opts):
    name = os.path.basename(path)
    t = file_triage.Triage(path)
    try:
        verdict = t.run(opts["defender"])
    except Exception as e:
        verdict = "УВАГА"
        t.add("УВАГА", "triage", "ошибка разбора %r - считать подозрительным" % e)
    res = file_triage.report(t, verdict, as_json=True)
    real = [f for f in res["findings"] if f["severity"] != "ІНФО"]
    log(folder, "%s | %s | %d находок" % (verdict, name, len(real)))
    if verdict == "ЧИСТО" and not opts["all"]:
        return
    lines = ["%s\n" % name]
    for f in real[:12]:
        lines.append("[%s] %s: %s" % (f["severity"], f["where"], f["reason"]))
        if f["sample"]:
            lines.append("    -> %s" % f["sample"][:120])
    if len(real) > 12:
        lines.append("... ещё %d" % (len(real) - 12))
    lines.append("\nSHA256: %s" % res["sha256"])
    moved = ""
    if verdict == "НЕБЕЗПЕЧНО" and opts["quarantine"]:
        qdir = os.path.join(folder, "_КАРАНТИН")
        os.makedirs(qdir, exist_ok=True)
        dst = os.path.join(qdir, name + ".blocked")
        try:
            shutil.move(path, dst)
            moved = "\nФайл перенесён в карантин:\n%s" % dst
            log(folder, "карантин: %s" % dst)
        except Exception as e:
            moved = "\nПеренести в карантин не удалось: %s" % e
    action = {"НЕБЕЗПЕЧНО": "НЕ ОТКРЫВАТЬ. Проверить хеш на virustotal.com или отдать файл Клоду на разбор.",
              "УВАГА": "Открывать только через конвертацию в PDF-картинки / в песочнице. Ссылки не нажимать.",
              "ЧИСТО": "По структуре чисто. Антивирус и здравый смысл не отменяются."}[verdict]
    text = "\n".join(lines) + "\n\n" + action + moved
    popup("Карантин-триаж: %s" % verdict, text)
    if opts["telegram"]:
        telegram("Карантин-триаж: %s\n%s" % (verdict, text))


def main(argv):
    opts = {"quarantine": "--quarantine" in argv, "defender": "--defender" in argv,
            "all": "--all" in argv, "telegram": "--telegram" in argv}
    args = [a for a in argv[1:] if not a.startswith("--")]
    folder = args[0] if args else os.path.join(os.path.expanduser("~"), "Downloads")
    if not os.path.isdir(folder):
        print("нет папки: %s" % folder)
        return 2
    log(folder, "старт слежения: %s (карантин=%s, defender=%s, telegram=%s)" %
        (folder, opts["quarantine"], opts["defender"], opts["telegram"]))
    seen = set(os.listdir(folder))
    pending = {}
    while True:
        try:
            now = set(os.listdir(folder))
            for name in now - seen:
                if name.lower().endswith(PARTIAL) or name.startswith(("~$", "_triage")) or name in SKIP_DIRS:
                    continue
                p = os.path.join(folder, name)
                if os.path.isfile(p):
                    pending[p] = time.time()
            seen = now
            for p in list(pending):
                if not os.path.exists(p):
                    pending.pop(p, None)
                    continue
                if stable(p):
                    pending.pop(p, None)
                    handle(folder, p, opts)
                elif time.time() - pending[p] > 600:
                    pending.pop(p, None)
        except KeyboardInterrupt:
            log(folder, "остановлено")
            return 0
        except Exception as e:
            log(folder, "ошибка цикла: %r" % e)
        time.sleep(3)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
