#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
npa_tool.py – єдиний інструмент роботи з НПА із zakon.rada.gov.ua
(завантаження повного тексту + витяг статті + пошук + детектор чинності).

Замінює npa_status_check.py (детектор збережено як команду `check`).

КОМАНДИ
    python3 npa_tool.py fetch   <ID>                    завантажити /print, зберегти <ID>.txt,
                                                        вивести редакцію і кількість статей
    python3 npa_tool.py article <ID|файл.txt> "Стаття 23"   ціла стаття + вердикт детектора
    python3 npa_tool.py grep    <ID|файл.txt> "<regex>"      пошук по тексту з контекстом
                                                        (для ПОШУКУ статті, не для цитування)
    python3 npa_tool.py check   <ID|файл.txt> "Стаття 23"   лише вердикт детектора чинності
    python3 npa_tool.py check   <ID|файл.txt> all            вердикти по всіх статтях
    python3 npa_tool.py point   <ID|файл.txt> "9-2"          цілий ПУНКТ акта без статей
                                                        (постанови, порядки) + вердикт
    python3 npa_tool.py toc     <ID|файл.txt>                перелік статей / розділів

Якщо другим аргументом дано ID акта (напр. 2456-17, 1404-19, 76-2023-п), а файлу
<ID>.txt ще немає – скрипт сам його завантажить.

ЧОМУ РАНІШЕ «НЕ ВИХОДИЛО» (провал 26.08.2026, Бюджетний кодекс, три спроби)
    zakon.rada.gov.ua віддає відповідь у gzip НАВІТЬ без заголовка Accept-Encoding.
    `curl -sL .../print -o akt.html` без `--compressed` записує gzip-блоб: HTTP 200,
    файл ~250 КБ, grep «Стаття» = 0. Модель вирішує, що завантаження провалилося
    або сайт блокує, і йде по колу обхідними шляхами. Тут декомпресія примусова.

ДІАГНОСТИКА ЗБОЮ (порядок дій, якщо fetch не дав [OK])
    1. HTTP ≠ 200 або таймаут  → зовнішні конектори: Tavily → Firecrawl scrape (1 кредит)
    2. [OK], але статей 0       → акт без структури «Стаття N.» (постанова/порядок з пунктами):
                                  користуватися grep по «^\\d+[\\-\\d]*\\.» і ключових словах
    3. Ніколи не тягнути кодекс через web_fetch (обрізає) і ніколи не читати
       весь .txt у контекст – тільки article / grep / toc.

ВЕРДИКТИ ДЕТЕКТОРА ЧИННОСТІ
    [СТОП]   критичний маркер (неконституційність, втрата чинності, виключення,
             зупинення, спецрежим) – цитувати ЗАБОРОНЕНО до ручного розбору примітки
    [УВАГА]  редакції/зміни – звірити дату останньої зміни, читати статтю цілком
    [ЧИСТО]  приміток немає (спецрежими поза статтею перевіряти окремо)

ЖОРСТКЕ ПРАВИЛО: норма береться ТІЛЬКИ цілою статтею (команда article),
фрагмент навколо ключового слова (grep) – лише щоб знайти номер статті.
"""
import gzip
import html
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

BASE = "https://zakon.rada.gov.ua/laws/show/{id}/print"
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/126.0 Safari/537.36")

CRIT = [
    (r'визнан[оі][^{}]{0,200}неконституційн', 'НЕКОНСТИТУЦІЙНІСТЬ (рішення КСУ)'),
    (r'Рішенням Конституційного Суду', 'згадка рішення КСУ'),
    (r'втрача[єю]ть чинність|втратив чинність|втратила чинність', 'ВТРАТА ЧИННОСТІ'),
    (r'виключено на підставі|статтю\s+\d+[^{}]{0,80}виключено|частину[^{}]{0,80}виключено'
     r'|пункт[^{}]{0,80}виключено|абзац[^{}]{0,80}виключено', 'ВИКЛЮЧЕННЯ положення'),
    (r'зупин[еи]но[^{}]{0,120}(дію|чинність)|дію[^{}]{0,120}зупинено', 'ЗУПИНЕННЯ дії'),
    (r'не застосовується', 'НЕЗАСТОСУВАННЯ (обмеження дії)'),
    (r'на період[^{}]{0,120}(воєнного стану|карантину)', 'СПЕЦРЕЖИМ (війна/карантин)'),
]
WARN = [
    (r'в редакції Закону', 'нова редакція – звірити дату'),
    (r'із змінами, внесеними', 'зміни – звірити дату останньої'),
    (r'доповнено', 'доповнення'),
    (r'[Щщ]одо (введення в дію|доповнення|перенумерації)', 'перехідне застереження'),
    (r'[Дд]ив\. (Закон|пункт)', 'відсилання до перехідних положень'),
]

ART_RE = re.compile(r'^\s*Стаття\s+(\d+[\-\d]*)[\.\u00b9\u00b2\u00b3]', re.M)
BREAK_RE = re.compile(r'^\s*(Стаття\s+\d+[\-\d]*[\.\u00b9\u00b2\u00b3]|Розділ\s+[IVXLC\d]+|Глава\s+\d+)', re.M)


# ---------------------------------------------------------------- fetch
HEADERS = {
    "User-Agent": UA,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "uk-UA,uk;q=0.9,ru;q=0.8,en;q=0.7",
    "Accept-Encoding": "gzip",
}


def fetch_html(npa_id: str) -> tuple[int, bytes]:
    """Завантажує /print. Сайт без «браузерних» заголовків ганяє по колу
    302 (/laws/show → /go → /laws/show …) і після серії запитів дає 429.
    Тому: повний набір заголовків + Referer на картку акта + до 4 спроб
    з паузою."""
    import time
    qid = urllib.parse.quote(npa_id, safe='')
    url = BASE.format(id=qid)
    hdrs = dict(HEADERS, Referer=f"https://zakon.rada.gov.ua/laws/show/{qid}")
    last = None
    for attempt in range(4):
        req = urllib.request.Request(url, headers=hdrs)
        try:
            with urllib.request.urlopen(req, timeout=90) as r:
                raw = r.read()
                code = r.status
            if raw[:2] == b"\x1f\x8b":            # gzip magic – незалежно від заголовків
                raw = gzip.decompress(raw)
            return code, raw
        except urllib.error.HTTPError as e:
            last = f"HTTP {e.code}"
            if e.code == 429 or e.code in (301, 302):
                wait = 20 * (attempt + 1)
                print(f"[ЧЕКАЮ] {last} (спроба {attempt + 1}/4), пауза {wait} с …", file=sys.stderr)
                time.sleep(wait)
                continue
            raise
        except urllib.error.URLError as e:
            last = f"мережа: {e.reason}"
            time.sleep(10)
    print(f"[ПОМИЛКА] zakon.rada не віддав /print після 4 спроб ({last}) – "
          f"переходити до конекторів: Tavily → Firecrawl scrape (1 кредит) → Chrome",
          file=sys.stderr)
    sys.exit(3)


def html_to_text(page: str) -> str:
    t = re.sub(r"<script.*?</script>|<style.*?</style>", "", page, flags=re.S | re.I)
    t = re.sub(r"<br\s*/?>|</p>|</div>|</tr>|</h\d>|</li>", "\n", t, flags=re.I)
    t = html.unescape(re.sub(r"<[^>]+>", "", t))
    t = re.sub(r"[ \t\xa0]+", " ", t)
    return re.sub(r"\n\s*\n+", "\n", t).strip()


def txt_name(npa_id: str) -> str:
    return npa_id.replace("/", "_") + ".txt"


def do_fetch(npa_id: str) -> str:
    code, raw = fetch_html(npa_id)
    page = raw.decode("utf-8", errors="ignore")
    if code != 200 or "<html" not in page[:2000].lower():
        print(f"[ПОМИЛКА] HTTP {code}, це не HTML – переходити до конекторів (Tavily → Firecrawl scrape)")
        sys.exit(3)
    text = html_to_text(page)
    out = txt_name(npa_id)
    with open(out, "w", encoding="utf-8") as f:
        f.write(text)
    report(text, out)
    return out


def report(text: str, out: str) -> None:
    red = re.search(r"Редакція від [^\n]{0,120}", text)
    arts = ART_RE.findall(text)
    title = text.split("\n", 1)[0][:120]
    print(f"[OK] {out}: {len(text):,} символів, статей: {len(arts)} | {title}")
    print(f"[РЕДАКЦІЯ] {red.group(0).strip() if red else 'рядок редакції не знайдено – звірити вручну в шапці'}")
    if not arts:
        print("[ПРИМІТКА] структури «Стаття N.» немає – акт з пунктами; шукати через grep")


def load(src: str) -> str:
    """src – або шлях до .txt, або ID акта (тоді файл <ID>.txt, за потреби завантажити)."""
    path = src if os.path.isfile(src) else txt_name(src)
    if not os.path.isfile(path):
        path = do_fetch(src)
    with open(path, encoding="utf-8") as f:
        return f.read()


# ---------------------------------------------------------------- article
def norm_art_no(target: str) -> str:
    return target.replace("Стаття", "").strip().rstrip(".").strip()


def split_article(text: str, art_no: str):
    m = re.search(r'^\s*Стаття\s+%s[\.\u00b9\u00b2\u00b3]' % re.escape(art_no), text, flags=re.M)
    if not m:
        return None
    start = m.start()
    rest = text[m.end():]
    m2 = BREAK_RE.search(rest)
    end = m.end() + (m2.start() if m2 else len(rest))
    return text[start:end].strip()


def split_point(text: str, pt_no: str):
    """Пункт «N.» або «N-M.» на початку рядка – до наступного пункту того самого рівня.
    Примітки {...} після тексту пункту входять у витяг."""
    m = re.search(r'^\s*%s\.\s' % re.escape(pt_no), text, flags=re.M)
    if not m:
        return None
    rest = text[m.end():]
    m2 = re.search(r'^\s*\d+(-\d+)?\.\s', rest, flags=re.M)
    end = m.end() + (m2.start() if m2 else len(rest))
    return text[m.start():end].strip()


# ---------------------------------------------------------------- check
def check(seg: str, label: str) -> bool:
    flat = seg.replace("\n", " ")
    notes = re.findall(r'\{[^}]+\}', flat)
    crit_hits, warn_hits = [], []
    for note in notes:
        hit = False
        for pat, name in CRIT:
            if re.search(pat, note):
                crit_hits.append((name, note.strip()[:240]))
                hit = True
                break
        if not hit:
            for pat, name in WARN:
                if re.search(pat, note):
                    warn_hits.append((name, note.strip()[:160]))
                    break
    print("=" * 74)
    print("НОРМА:", label, "| приміток у фігурних дужках:", len(notes))
    if crit_hits:
        print("ВЕРДИКТ: [СТОП] – критичних маркерів:", len(crit_hits))
        for name, note in crit_hits:
            print("  !!", name)
            print("     ", note)
        print("  ЦИТУВАТИ ЗАБОРОНЕНО до ручного розбору кожної примітки вище.")
    elif warn_hits:
        print("ВЕРДИКТ: [УВАГА] – редакційних маркерів:", len(warn_hits))
        for name, note in warn_hits[:6]:
            print("  ~", name, "|", note)
        print("  Звірити дату останньої зміни; текст норми читати повністю.")
    else:
        print("ВЕРДИКТ: [ЧИСТО] – приміток немає.")
        print("  Окремо перевірити спецрежими поза текстом статті (перехідні положення, воєнний стан).")
    return bool(crit_hits)


# ---------------------------------------------------------------- main
def main(argv):
    if len(argv) < 3:
        sys.exit(__doc__)
    cmd, src = argv[1], argv[2]

    if cmd == "fetch":
        do_fetch(src)
        return

    text = load(src)

    if cmd == "toc":
        for m in re.finditer(r'^\s*(Розділ\s+[IVXLC\d]+[^\n]{0,80}|Глава\s+\d+[^\n]{0,80}|Стаття\s+\d+[\-\d]*\.[^\n]{0,90})', text, flags=re.M):
            print(m.group(1).strip())
        return

    if cmd == "grep":
        if len(argv) < 4:
            sys.exit("grep потребує шаблон")
        pat = re.compile(argv[3], flags=re.I)
        lines = text.split("\n")
        cur = "?"
        n = 0
        for i, ln in enumerate(lines):
            am = ART_RE.match(ln)
            if am:
                cur = "Стаття " + am.group(1)
            if pat.search(ln):
                n += 1
                print(f"--- [{cur}] рядок {i}:")
                print("\n".join(lines[max(0, i - 1): i + 2]))
        print(f"\nЗбігів: {n}. Для цитування – витягти статтю цілком: article <джерело> \"<Стаття N>\"")
        return

    if cmd == "point":
        if len(argv) < 4:
            sys.exit("потрібен номер пункту, напр. 9-2")
        pt = argv[3].replace("п.", "").replace("пункт", "").strip().rstrip(".")
        seg = split_point(text, pt)
        if not seg:
            sys.exit(f"Пункт {pt} не знайдено. Увага: у постанові кілька додатків з власною нумерацією – "
                     f"перевір через grep, який саме додаток потрібен.")
        print(seg)
        print()
        check(seg, "Пункт " + pt)
        return

    if cmd in ("article", "check"):
        if len(argv) < 4:
            sys.exit("потрібен номер статті або all")
        target = argv[3]
        if target == "all":
            arts = sorted(set(ART_RE.findall(text)), key=lambda x: [int(p) for p in x.split("-")])
            stops = 0
            for a in arts:
                seg = split_article(text, a)
                if seg and check(seg, "Стаття " + a):
                    stops += 1
            print("\nРАЗОМ [СТОП]:", stops, "з", len(arts))
            return
        art_no = norm_art_no(target)
        seg = split_article(text, art_no)
        if not seg:
            sys.exit(f"Статтю не знайдено: {target}. Перевір toc або grep.")
        if cmd == "article":
            print(seg)
            print()
        check(seg, "Стаття " + art_no)
        return

    sys.exit(f"Невідома команда: {cmd}\n{__doc__}")


if __name__ == "__main__":
    main(sys.argv)
