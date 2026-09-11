#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
watch_downloads.py v1.0 (07.09.2026) - карантин-лаборатория для папки Загрузки.
Следит за папкой, каждый новый файл прогоняет через file_triage.py (лежит рядом)
и, если вердикт УВАГА/НЕБЕЗПЕЧНО, показывает окно с находками, пишет в лог
(C:\\Tools\\triage.log, на уровень выше папки скрипта),
при желании переносит файл в карантин и шлёт сообщение в Telegram.

Запуск (Windows, без зависимостей кроме Python; oletools - по желанию):
    python watch_downloads.py                       # следит за %USERPROFILE%\\Downloads
                                                    # и за подпапками из EXTRA_SUBDIRS (Telegram Desktop)
    python watch_downloads.py "D:\\Почта\\Вложения"   # другая папка (можно перечислить несколько)
Ключи:
    --quarantine   опасные файлы переносить в _КАРАНТИН\\ первой (главной) папки с суффиксом .blocked
    --defender     дополнительно вызывать Windows Defender (MpCmdRun) на каждый файл
    --all          показывать окно и на ЧИСТО (по умолчанию - только УВАГА/НЕБЕЗПЕЧНО)
    --telegram     слать вердикт в Telegram; токен и chat_id берутся из переменных
                   окружения TRIAGE_TG_TOKEN и TRIAGE_TG_CHAT
Автозапуск: Планировщик заданий -> "При входе в систему" -> pythonw.exe watch_downloads.py --quarantine
Страховка: второе задание раз в 3 часа запускает ту же команду; если сторож жив, новый экземпляр
сразу выходит (именованный mutex), если упал - поднимается заново. Оба задания ставит install_watch.bat.
Остановить: Ctrl+C в консоли или завершить pythonw.exe (см. remove_watch.bat).

Белый список: allow.txt рядом со скриптом. Файл из списка пропускается без окна и карантина.
Строка = SHA256 файла (точечно) или «издатель: Имя» (любая программа с действительной подписью
этого издателя). В окне предупреждения есть кнопка «Так»: она вносит файл в белый список и тут же
возвращает его из карантина, без папок и перетаскиваний. Если окно закрыто, то же самое делает
разрешить.bat (двойной щелчок покажет карантин списком).

Что НЕ делает: не открывает файлы, не лечит, не подменяет антивирус. Это второй глаз.
"""

import os
import re
import sys
import time
import json
import shutil
import hashlib
import threading
import datetime
import subprocess
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
# подпапки главной папки, за которыми следим дополнительно (если существуют).
# Telegram Desktop сохраняет вложения в Downloads\Telegram Desktop, корень Downloads их не видит.
EXTRA_SUBDIRS = ("Telegram Desktop",)


# лог лежит НЕ в наблюдаемой папке, а на уровень выше папки скрипта: C:\Tools\triage.log
LOG_PATH = os.path.join(os.path.dirname(HERE), "triage.log")

# белый список доверенных файлов: C:\Tools\triage\allow.txt (см. шапку самого файла).
# Читается заново на каждый файл, поэтому правки применяются без перезапуска сторожа.
ALLOW_PATH = os.path.join(HERE, "allow.txt")
# расширения, у которых вообще бывает цифровая подпись Authenticode: только их проверяем на подпись
SIGNED_EXT = (".exe", ".dll", ".msi", ".msp", ".cab", ".sys", ".ocx", ".ps1", ".appx", ".msix", ".cat")


def load_allow(path=None):
    """Читает allow.txt. Возвращает (хеши SHA256, издатели, нераспознанные строки)."""
    hashes, publishers, junk = set(), set(), []
    try:
        with open(path or ALLOW_PATH, encoding="utf-8-sig") as f:
            for raw in f:
                line = raw.split("#", 1)[0].strip()
                if not line:
                    continue
                low = line.lower()
                key = next((k for k in ("издатель:", "видавець:", "publisher:") if low.startswith(k)), None)
                if key:
                    name = line[len(key):].strip().strip('"')
                    if name:
                        publishers.add(name.lower())
                    continue
                if re.fullmatch(r"[0-9a-fA-F]{64}", line):
                    hashes.add(low)
                else:
                    junk.append(line[:80])
    except FileNotFoundError:
        pass
    except Exception as e:
        junk.append("файл не прочитан: %r" % e)
    return hashes, publishers, junk


def sha256_file(path):
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
    except Exception:
        return None
    return h.hexdigest()


def signature_cn(path):
    """Имя издателя из ДЕЙСТВИТЕЛЬНОЙ цифровой подписи файла или None.
    Файл при этом не запускается: Windows только читает его байты и проверяет сертификат.
    Путь передаётся через переменную окружения, чтобы кавычки в имени файла ничего не сломали."""
    if os.name != "nt":
        return None
    ps = ("$ErrorActionPreference='SilentlyContinue';"
          "$s = Get-AuthenticodeSignature -LiteralPath $env:TRIAGE_SIG_FILE;"
          "if ($s.Status -eq 'Valid') { $s.SignerCertificate.Subject }")
    try:
        env = dict(os.environ, TRIAGE_SIG_FILE=os.path.abspath(path))
        out = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
                             capture_output=True, text=True, timeout=90, env=env).stdout
    except Exception:
        return None
    m = re.search(r"CN=([^,]+)", out or "")
    return m.group(1).strip().strip('"') if m else None


def may_be_signed(path):
    """Бывает ли у такого файла подпись. Суффикс карантина .blocked не мешает: подпись лежит
    внутри самого файла, а не в его имени, поэтому смотрим расширение под суффиксом."""
    low = path.lower()
    if low.endswith(".blocked"):
        low = low[:-len(".blocked")]
    return low.endswith(SIGNED_EXT)


def allowed(path, allow_path=None):
    """(True, причина), если файл в белом списке. Сначала точный хеш, затем издатель подписи."""
    hashes, publishers, _ = load_allow(allow_path)
    if hashes:
        h = sha256_file(path)
        if h and h in hashes:
            return True, "белый список: SHA256"
    if publishers and may_be_signed(path):
        cn = signature_cn(path)
        if cn and cn.lower() in publishers:
            return True, "белый список: подпись %s" % cn
    return False, ""


def allow_add_hash(sha, note=""):
    """Дописывает SHA256 в allow.txt. Возвращает True, если строка добавлена."""
    if not re.fullmatch(r"[0-9a-fA-F]{64}", sha or ""):
        return False
    if sha.lower() in load_allow()[0]:
        return True
    tail = b""
    try:
        with open(ALLOW_PATH, "rb") as f:
            tail = f.read()[-1:]
    except FileNotFoundError:
        pass
    try:
        with open(ALLOW_PATH, "a", encoding="utf-8") as f:
            if tail and tail != b"\n":
                f.write("\n")
            f.write("%s%s\n" % (sha.lower(), ("  # " + note) if note else ""))
    except Exception:
        return False
    return True


ORIGIN_DB = "_откуда.json"   # реестр в папке карантина: из какой папки изъят каждый файл


def _origin_load(qdir):
    try:
        with open(os.path.join(qdir, ORIGIN_DB), encoding="utf-8") as f:
            db = json.load(f)
        return db if isinstance(db, dict) else {}
    except Exception:
        return {}


def _origin_save(qdir, db):
    # заодно выбрасываем записи про файлы, которых в карантине уже нет
    db = {k: v for k, v in db.items() if os.path.exists(os.path.join(qdir, k))}
    try:
        with open(os.path.join(qdir, ORIGIN_DB), "w", encoding="utf-8") as f:
            json.dump(db, f, ensure_ascii=False, indent=1)
    except Exception as e:
        print("реестр карантина: %r" % e, flush=True)


def remember_origin(qdir, blocked_name, folder, sha=None):
    """Запоминает, откуда изъят файл, чтобы вернуть его в ту же папку, а не в корень Загрузок."""
    db = _origin_load(qdir)
    db[blocked_name] = {"folder": folder, "sha256": sha,
                        "when": datetime.datetime.now().strftime("%d.%m.%Y %H:%M:%S")}
    _origin_save(qdir, db)


def origin_folder(qdir, name, sha=None):
    """Папка, куда возвращать файл. Ищем по имени в карантине, затем по хешу (имя могли изменить
    вручную, сняв пометку). Если записи нет или папка исчезла, возвращаем папку над карантином."""
    db = _origin_load(qdir)
    rec = db.get(name) or db.get(name + ".blocked")
    if not rec and sha:
        rec = next((r for r in db.values() if r.get("sha256") == sha), None)
    folder = (rec or {}).get("folder")
    if folder and os.path.isdir(folder):
        return folder
    return os.path.dirname(qdir)


def yes_no_labels():
    """Подписи кнопок окна. Их рисует сама Windows на языке системы, поэтому в тексте окна
    надо называть их теми же словами, иначе выйдет «нажмите Так», а на кнопке «Да»."""
    try:
        import ctypes
        lang = ctypes.windll.kernel32.GetUserDefaultUILanguage() & 0x3FF
    except Exception:
        lang = 0
    return {0x19: ("Да", "Нет"), 0x22: ("Так", "Ні")}.get(lang, ("Yes", "No"))


def restore_from_quarantine(path, sha=None):
    """Возвращает файл из карантина ТУДА, ОТКУДА ОН БЫЛ ИЗЪЯТ (файл из подпапки Telegram вернётся
    в неё, а не в корень Загрузок), снимая суффикс .blocked, если он есть.
    Возвращает новый путь или None, если файл лежит не в карантине."""
    qdir, name = os.path.split(path)
    if os.path.basename(qdir) != SKIP_DIRS[0]:
        return None
    base = name[:-len(".blocked")] if name.lower().endswith(".blocked") else name
    target_dir = origin_folder(qdir, name, sha)
    dst = os.path.join(target_dir, base)
    stem, ext = os.path.splitext(base)
    n = 1
    while os.path.exists(dst):  # одноимённый файл в папке не затираем
        dst = os.path.join(target_dir, "%s (%d)%s" % (stem, n, ext))
        n += 1
    shutil.move(path, dst)
    db = _origin_load(qdir)
    db.pop(name, None)
    db.pop(name + ".blocked", None)
    _origin_save(qdir, db)
    return dst


def trust_now(root, path, sha, name):
    """Реакция на кнопку «Доверять» в окне: сперва запись в белый список, только потом возврат
    файла, иначе сторож увидит его раньше, чем прочитает список, и снова унесёт в карантин."""
    if not allow_add_hash(sha, "%s, разрешено из окна %s" % (name, datetime.datetime.now().strftime("%d.%m.%Y"))):
        log(root, "не удалось записать в белый список: %s" % name)
        popup("Карантин-триаж", "Не удалось записать в белый список:\n%s\n\nФайл оставлен в карантине." % ALLOW_PATH)
        return
    where = path
    try:
        restored = restore_from_quarantine(path, sha)
        if restored:
            where = restored
    except Exception as e:
        log(root, "не удалось вернуть из карантина (%r): %s" % (e, name))
        popup("Карантин-триаж", "Файл внесён в доверенные, но вернуть его из карантина не вышло:\n%s" % e)
        return
    log(root, "ДОВІРЕНО вручную | %s | %s" % (name, where))
    popup("Карантин-триаж: файл доверен", "%s\n\nФайл возвращён:\n%s\n\nБольше про него не спрошу." % (name, where))


def log(folder, msg):
    line = "%s  %s" % (datetime.datetime.now().strftime("%d.%m.%Y %H:%M:%S"), msg)
    print(line, flush=True)
    try:
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass


_MUTEX = None


def single_instance():
    """True, если это единственный экземпляр сторожа. Второй (например, из задания-keepalive,
    которое раз в 3 часа пытается запустить сторож заново) тихо выходит. Именованный mutex
    Windows освобождается системой при смерти процесса, поэтому после падения новый стартует."""
    global _MUTEX
    if os.name != "nt":
        return True
    import ctypes
    k32 = ctypes.windll.kernel32
    _MUTEX = k32.CreateMutexW(None, False, "Global\\Triage-Downloads-Watch")
    return k32.GetLastError() != 183  # 183 = ERROR_ALREADY_EXISTS


def popup(title, text):
    """Окно с одной кнопкой ОК. Не ждёт ответа, работа сторожа не останавливается."""
    if os.name == "nt":
        import ctypes
        icon = 0x30 if "НЕБЕЗПЕЧНО" in title else 0x40  # warning / info
        threading.Thread(target=ctypes.windll.user32.MessageBoxW,
                         args=(0, text, title, icon | 0x1000), daemon=True).start()  # 0x1000 = topmost
    else:
        print("[POPUP] %s\n%s" % (title, text))


def popup_ask(title, text, on_yes, on_no=None):
    """Окно с кнопками «Да» и «Нет» (подписи ставит Windows, см. yes_no_labels).
    Кнопка по умолчанию – вторая (0x100), чтобы случайный Enter ничего не разрешил.
    Окно живёт в отдельном потоке: сторож продолжает следить за папками, пока оно открыто."""
    if os.name != "nt":
        print("[POPUP?] %s\n%s" % (title, text))
        return

    def run():
        import ctypes
        # 0x4 = кнопки Да/Нет, 0x30 = знак предупреждения, 0x100 = по умолчанию вторая кнопка,
        # 0x1000 = поверх всех окон, 0x10000 = вывести окно на передний план
        answer = ctypes.windll.user32.MessageBoxW(0, text, title, 0x4 | 0x30 | 0x100 | 0x1000 | 0x10000)
        try:
            if answer == 6:      # IDYES
                on_yes()
            elif on_no:          # IDNO или закрытое окно
                on_no()
        except Exception as e:
            print("окно с вопросом: %r" % e, flush=True)

    threading.Thread(target=run, daemon=True).start()


def reblock(root, path):
    """Возвращает файлу в карантине пометку .blocked (ответ «Нет» на вопрос о доверии)."""
    dst = path + ".blocked"
    n = 1
    while os.path.exists(dst):
        dst = "%s.%d.blocked" % (path, n)
        n += 1
    try:
        shutil.move(path, dst)
        log(root, "пометка .blocked возвращена | %s" % os.path.basename(dst))
    except Exception as e:
        log(root, "не удалось вернуть пометку .blocked (%r) | %s" % (e, os.path.basename(path)))


def handle_unblocked(root, path):
    """Пользователь снял пометку .blocked с файла прямо в карантине. Спрашиваем подтверждение:
    «Да» – доверять и вернуть в Загрузки, «Нет» – вернуть пометку обратно."""
    name = os.path.basename(path)
    yes, no = yes_no_labels()
    sha = sha256_file(path)
    log(root, "снята пометка в карантине | %s | жду ответа" % name)
    text = ("%s\n\n"
            "Вы сняли пометку .blocked с файла, который лежит в карантине.\n"
            "Сторож считает этот файл опасным.\n\n"
            "«%s» = доверять файлу: вернуть его в Загрузки и больше не проверять.\n"
            "«%s» = вернуть пометку .blocked, файл останется в карантине.\n\n"
            "SHA256: %s\n\n"
            "Нажимайте «%s», только если вы сами скачали этот файл с сайта производителя.\n"
            "Файл из письма или из Telegram доверенным не делать." % (name, yes, no, sha or "не прочитан", yes))
    popup_ask("Карантин-триаж: подтвердите доверие", text,
              on_yes=lambda: trust_now(root, path, sha, name),
              on_no=lambda: reblock(root, path))


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


def handle(root, path, opts):
    """root - главная папка: в ней лежит _КАРАНТИН; path может быть и в её подпапке."""
    name = os.path.basename(path)
    shown = os.path.relpath(path, root) if path.startswith(root) else path  # "Telegram Desktop\имя" для подпапки
    ok, why = allowed(path)
    if ok:
        log(root, "ДОВІРЕНО | %s | %s" % (shown, why))
        return
    t = file_triage.Triage(path)
    try:
        verdict = t.run(opts["defender"])
    except Exception as e:
        verdict = "УВАГА"
        t.add("УВАГА", "triage", "ошибка разбора %r - считать подозрительным" % e)
    res = file_triage.report(t, verdict, as_json=True)
    real = [f for f in res["findings"] if f["severity"] != "ІНФО"]
    log(root, "%s | %s | %d находок" % (verdict, shown, len(real)))
    if verdict == "ЧИСТО" and not opts["all"]:
        return
    lines = ["%s\n" % shown]
    for f in real[:12]:
        lines.append("[%s] %s: %s" % (f["severity"], f["where"], f["reason"]))
        if f["sample"]:
            lines.append("    -> %s" % f["sample"][:120])
    if len(real) > 12:
        lines.append("... ещё %d" % (len(real) - 12))
    lines.append("\nSHA256: %s" % res["sha256"])
    moved = ""
    now = path  # где файл лежит после разбора: на месте или в карантине
    if verdict == "НЕБЕЗПЕЧНО" and opts["quarantine"]:
        qdir = os.path.join(root, "_КАРАНТИН")
        os.makedirs(qdir, exist_ok=True)
        dst = os.path.join(qdir, name + ".blocked")
        if os.path.exists(dst):  # одноимённый файл уже в карантине - не затирать
            dst = os.path.join(qdir, "%s.%s.blocked" % (name, datetime.datetime.now().strftime("%Y%m%d_%H%M%S")))
        try:
            shutil.move(path, dst)
            now = dst
            remember_origin(qdir, os.path.basename(dst), os.path.dirname(path), res["sha256"])
            moved = "\nФайл перенесён в карантин:\n%s" % dst
            log(root, "карантин: %s" % dst)
        except Exception as e:
            moved = "\nПеренести в карантин не удалось: %s" % e
    action = {"НЕБЕЗПЕЧНО": "НЕ ОТКРЫВАТЬ. Проверить хеш на virustotal.com или отдать файл Клоду на разбор.",
              "УВАГА": "Открывать только через конвертацию в PDF-картинки / в песочнице. Ссылки не нажимать.",
              "ЧИСТО": "По структуре чисто. Антивирус и здравый смысл не отменяются."}[verdict]
    text = "\n".join(lines) + "\n\n" + action + moved
    if opts["telegram"]:
        telegram("Карантин-триаж: %s\n%s" % (verdict, text))
    if verdict == "ЧИСТО":
        popup("Карантин-триаж: %s" % verdict, text)
        return
    # кнопка «Да» = файл свой, вернуть и больше про него не спрашивать
    yes, no = yes_no_labels()
    question = ("\n\nЭто ваша программа или ваш документ?\n"
                "«%s» = вернуть файл%s и внести в доверенные (%s).\n"
                "«%s» = оставить как есть.\n"
                "Нажимайте «%s», только если вы сами скачали этот файл с сайта производителя.\n"
                "Файл из письма или из Telegram доверенным не делать." %
                (yes, " из карантина" if now != path else "", os.path.basename(ALLOW_PATH), no, yes))
    popup_ask("Карантин-триаж: %s" % verdict, text + question,
              lambda: trust_now(root, now, res["sha256"], shown))


def main(argv):
    opts = {"quarantine": "--quarantine" in argv, "defender": "--defender" in argv,
            "all": "--all" in argv, "telegram": "--telegram" in argv}
    args = [a for a in argv[1:] if not a.startswith("--")]
    if not single_instance():
        return 0  # сторож уже работает - молча уходим, в лог не пишем, чтобы не засорять
    if args:
        folders = [os.path.abspath(a) for a in args]
    else:
        root = os.path.join(os.path.expanduser("~"), "Downloads")
        folders = [root] + [os.path.join(root, sub) for sub in EXTRA_SUBDIRS if os.path.isdir(os.path.join(root, sub))]
    root = folders[0]  # главная папка: карантин лежит в ней
    missing = [f for f in folders if not os.path.isdir(f)]
    if missing:
        print("нет папки: %s" % "; ".join(missing))
        return 2
    log(root, "старт слежения: %s (карантин=%s, defender=%s, telegram=%s)" %
        ("; ".join(folders), opts["quarantine"], opts["defender"], opts["telegram"]))
    hashes, publishers, junk = load_allow()
    log(root, "белый список %s: хешей %d, издателей %d%s" %
        (ALLOW_PATH, len(hashes), len(publishers),
         (", НЕ РАЗОБРАНО строк %d (первая: %s)" % (len(junk), junk[0])) if junk else ""))
    seen = {f: set(os.listdir(f)) for f in folders}
    # за карантином следим отдельно: файл БЕЗ пометки .blocked означает, что пометку сняли вручную
    qdirs = [os.path.join(f, SKIP_DIRS[0]) for f in folders]
    seen_q = {d: (set(os.listdir(d)) if os.path.isdir(d) else set()) for d in qdirs}
    pending = {}
    while True:
        try:
            for folder in folders:
                try:
                    now = set(os.listdir(folder))
                except FileNotFoundError:  # папку удалили/переименовали - ждём, пока вернётся
                    continue
                for name in now - seen[folder]:
                    if name.lower().endswith(PARTIAL) or name.startswith(("~$", "_triage")) or name in SKIP_DIRS:
                        continue
                    p = os.path.join(folder, name)
                    if os.path.isfile(p):
                        pending[p] = time.time()
                seen[folder] = now
            for qdir in qdirs:
                if not os.path.isdir(qdir):
                    seen_q[qdir] = set()
                    continue
                now_q = set(os.listdir(qdir))
                for name in now_q - seen_q[qdir]:
                    low = name.lower()
                    if low.endswith(".blocked") or low.endswith(PARTIAL) or name.startswith("~$") or name == ORIGIN_DB:
                        continue  # пометка на месте, файл ещё дописывается или это служебный реестр
                    p = os.path.join(qdir, name)
                    if os.path.isfile(p):
                        handle_unblocked(root, p)
                seen_q[qdir] = now_q
            for p in list(pending):
                if not os.path.exists(p):
                    pending.pop(p, None)
                    continue
                if stable(p):
                    pending.pop(p, None)
                    handle(root, p, opts)
                elif time.time() - pending[p] > 600:
                    pending.pop(p, None)
        except KeyboardInterrupt:
            log(root, "остановлено")
            return 0
        except Exception as e:
            log(root, "ошибка цикла: %r" % e)
        time.sleep(3)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
