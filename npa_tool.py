#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
npa_tool.py – єдиний інструмент роботи з НПА із zakon.rada.gov.ua
(завантаження повного тексту + витяг статті + пошук + детектор чинності + радар змін).

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
    python3 npa_tool.py status  <ID> [ID …]                  редакція і статус чинності кількох актів
    python3 npa_tool.py radar   <watch.json> [--fresh]       РАДАР ЗМІН скіла: акти з watch.json проти
                                                        еталона (редакція, статус, рішення КСУ, нові акти
                                                        змін у примітках, вік еталона, строкові норми)
    python3 npa_tool.py changes <watch.json> [ID] [ДД.ММ.РРРР]   що саме змінилося (пункти/статті)
                                                        і які місця скіла (SKILL.md, modules/*.md) на це
                                                        посилаються; з датою – акти змін після неї
    python3 npa_tool.py snapshot <watch.json> [--write]      новий еталон (оновлення скіла в Claude Code)
    Ключ --fresh у будь-якій команді: завантажити акт заново, навіть якщо кеш свіжий.
    Ключ --nth K у point: K-те входження номера пункту (додатки з власною нумерацією).

Якщо другим аргументом дано ID акта (напр. 2456-17, 1404-19, 76-2023-п), а файлу
<ID>.txt ще немає – скрипт сам його завантажить.
ID зі слешем передавати як є: fetch 280/97-вр (файл 280_97-вр.txt). Слеш не кодується
(до 29.09.2026 кодувався як %2F → HTTP 404).

ЧИННІСТЬ АКТА ЦІЛКОМ (додано 29.09.2026): fetch/report читає шапку акта; примітка
«{Закон/Кодекс/Постанова/Наказ … втратив(-ла) чинність …}» → рядок [СТОП] АКТ ВТРАТИВ
ЧИННІСТЬ. Такий акт не цитувати – шукати акт, що його замінив (зазначений у примітці).

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

КЕШ (змінено 20.10.2026): <ID>.txt і <ID>.html старші за 24 год завантажуються заново
автоматично; кожне читання друкує [РЕДАКЦІЯ], [СТАТУС] і вік кешу. Раніше кеш жив безстроково.

СТАТУС ЧИННОСТІ (додано 20.10.2026): з рядка «Законодавство України станом на … <статус>»
у хвості /print. «втратив чинність», «не набрав чинності», «зупинено» → [!!]; «попередня
редакція» → [!?]: zakon віддав НЕ чинний текст (так буває з КУпАП 80731-10), цитувати за цим
ID не можна, звіряти іншим шляхом. Рішення КСУ («Визнання неконституційними окремих положень
від …») друкується окремим рядком.

ДЕТЕКТОР (посилено 20.10.2026): «в редакції Постанови/Указу/Наказу» і «згідно з …» → [УВАГА];
«набирає чинності / вводиться в дію з <дата>» у майбутньому → [СТОП] «ще не набрало чинності»;
примітки про ІНШИЙ пункт чи статтю не впливають на вердикт; примітки, яких детектор не впізнав,
дають [УВАГА] «некласифіковані», а не [ЧИСТО].

РАДАР (додано 20.10.2026): watch.json скіла містить акти, на які скіл спирається, з еталоном
(дата редакції, перелік актів змін із приміток zakon на день знімка) і строкові норми.
radar показує, що змінилося після еталона; changes – які пункти і які місця скіла зачеплено;
snapshot --write оновлює еталон після того, як скіл виправлено.
"""
import gzip
import html
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta

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
    (r'в редакції (Закон|Постанов|Указ|Наказ|Рішенн|Розпорядженн)', 'нова редакція – звірити дату'),
    (r'із змінами, внесеними', 'зміни – звірити дату останньої'),
    (r'доповнено', 'доповнення'),
    (r'[Щщ]одо (введення в дію|доповнення|перенумерації)', 'перехідне застереження'),
    (r'[Дд]ив\. (Закон|пункт)', 'відсилання до перехідних положень'),
    (r'згідно (з|із) (Закон|Постанов|Указ|Наказ|Рішенн|Розпорядженн)', 'зміни – звірити дату'),
]
CACHE_HOURS = 24        # <ID>.txt / <ID>.html старші за це – завантажити заново
RADAR_HOURS = 6         # radar у межах однієї розмови не качає акт повторно частіше
MONTHS = {"січня": 1, "лютого": 2, "березня": 3, "квітня": 4, "травня": 5, "червня": 6, "липня": 7,
          "серпня": 8, "вересня": 9, "жовтня": 10, "листопада": 11, "грудня": 12}
FRESH = "--fresh" in sys.argv

ART_RE = re.compile(r'^\s*Стаття\s+(\d+[\-\d]*)[\.\u00b9\u00b2\u00b3]', re.M)
BREAK_RE = re.compile(r'^\s*(Стаття\s+\d+[\-\d]*[\.\u00b9\u00b2\u00b3]|Розділ\s+[IVXLC\d]+|Глава\s+\d+)', re.M)


# ---------------------------------------------------------------- fetch
HEADERS = {
    "User-Agent": UA,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "uk-UA,uk;q=0.9,ru;q=0.8,en;q=0.7",
    "Accept-Encoding": "gzip",
}


class FetchError(Exception):
    pass


def _fetch_raw(npa_id: str) -> tuple[int, bytes]:
    """Завантажує /print. Сайт без «браузерних» заголовків ганяє по колу
    302 (/laws/show → /go → /laws/show …) і після серії запитів дає 429.
    Тому: повний набір заголовків + Referer на картку акта + до 4 спроб
    з паузою. Помилка → FetchError з текстом для користувача."""
    qid = urllib.parse.quote(npa_id, safe='/')   # слеш в ID (280/97-вр) не кодувати
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
                print(f"[ЧЕКАЮ] {npa_id}: {last} (спроба {attempt + 1}/4), пауза {wait} с …", file=sys.stderr)
                time.sleep(wait)
                continue
            if e.code == 404:
                raise FetchError(f"[ПОМИЛКА] HTTP 404 – акт «{npa_id}» не знайдено: звірити ID на zakon.rada "
                                 f"(формат: 2456-17, 280/97-вр, 76-2023-п)")
            raise FetchError(f"[ПОМИЛКА] {npa_id}: {last}")
        except urllib.error.URLError as e:
            last = f"мережа: {e.reason}"
            time.sleep(10)
        except OSError as e:
            last = f"мережа: {e}"
            time.sleep(10)
    raise FetchError(f"[ПОМИЛКА] zakon.rada не віддав /print для {npa_id} після 4 спроб ({last}) – "
                     f"переходити до конекторів: Tavily → Firecrawl scrape (1 кредит) → Chrome")


def fetch_html(npa_id: str) -> tuple[int, bytes]:
    try:
        return _fetch_raw(npa_id)
    except FetchError as e:
        print(str(e), file=sys.stderr)
        sys.exit(3)


def html_to_text(page: str) -> str:
    t = re.sub(r"<script.*?</script>|<style.*?</style>", "", page, flags=re.S | re.I)
    # складені номери (9-2, 11-1, ст. 164-14) інколи позначені верхнім індексом: 9<sup>2</sup>
    t = re.sub(r"<sup[^>]*>\s*([\d,\s-]+?)\s*</sup>", r"-\1", t, flags=re.I)
    t = re.sub(r"<br\s*/?>|</p>|</div>|</tr>|</h\d>|</li>", "\n", t, flags=re.I)
    t = html.unescape(re.sub(r"<[^>]+>", "", t))
    t = re.sub(r"[ \t\xa0]+", " ", t)
    return re.sub(r"\n\s*\n+", "\n", t).strip()


ACT_DEAD_RE = re.compile(
    r"\{\s*(?:Закон|Кодекс|Постанова|Наказ|Указ|Розпорядження|Декрет|Положення|Порядок|Рішення|Інструкція|Правила)"
    r"\s+(?:втратив|втратила|втратило)\s+чинність[^}]*\}")


def txt_name(npa_id: str) -> str:
    return npa_id.replace("/", "_") + ".txt"


def html_name(npa_id: str) -> str:
    return npa_id.replace("/", "_") + ".html"


def _age_hours(path: str) -> float:
    return (time.time() - os.path.getmtime(path)) / 3600


def save_page(npa_id: str, page: str) -> str:
    """Зберегти сирий HTML (для радара) і текст; повернути шлях до .txt."""
    text = html_to_text(page)
    out = txt_name(npa_id)
    with open(out, "w", encoding="utf-8") as f:
        f.write(text)
    with open(html_name(npa_id), "w", encoding="utf-8") as f:
        f.write(page)
    return out


def fetch_page(npa_id: str):
    """Без sys.exit: HTML-сторінка або None (рядок [ПОМИЛКА] уже надруковано). Для radar/status."""
    try:
        code, raw = _fetch_raw(npa_id)
    except FetchError as e:
        print(str(e))
        return None
    page = raw.decode("utf-8", errors="ignore")
    if code != 200 or "<html" not in page[:2000].lower():
        print(f"[ПОМИЛКА] {npa_id}: HTTP {code}, це не HTML")
        return None
    save_page(npa_id, page)
    return page


def do_fetch(npa_id: str) -> str:
    code, raw = fetch_html(npa_id)
    page = raw.decode("utf-8", errors="ignore")
    if code != 200 or "<html" not in page[:2000].lower():
        print(f"[ПОМИЛКА] HTTP {code}, це не HTML – переходити до конекторів (Tavily → Firecrawl scrape)")
        sys.exit(3)
    out = save_page(npa_id, page)
    with open(out, encoding="utf-8") as f:
        report(f.read(), out)
    return out


ED_RE = re.compile(r"(Редакція|Визнання неконституційними окремих положень|Визнання конституційними окремих положень"
                   r"|Прийняття)\s*від\s*(\d{2}\.\d{2}\.\d{4})(?:\s*[,;]?\s*підстава\s*[-–—]?\s*([\w/.-]+))?")


def edition_info(text: str):
    """(вид, дата, підстава) останньої події акта з хвоста /print (там zakon пише рядок редакції)."""
    for idx, zone in enumerate((text[-3500:], text[:2500])):
        ms = list(ED_RE.finditer(re.sub(r"\s+", " ", zone)))
        if ms:
            m = ms[-1] if idx == 0 else ms[0]
            return m.group(1), m.group(2), m.group(3) or ""
    return None, None, ""


def edition_line(text: str) -> str:
    kind, date, basis = edition_info(text)
    if not kind:
        return "рядок редакції не знайдено – звірити вручну"
    kind = {"Визнання неконституційними окремих положень": "КСУ: визнання неконституційними окремих положень",
            "Визнання конституційними окремих положень": "КСУ: визнання конституційними окремих положень"}.get(kind, kind)
    return f"{kind} від {date}" + (f", підстава – {basis}" if basis else "")


def act_status(text: str):
    flat = re.sub(r"\s+", " ", text[-5000:])
    m = re.search(r"Законодавство України станом на\s*\d{2}\.\d{2}\.\d{4}\s*(.+?)"
                  r"(?=\s+(?:Публікації|Документи та файли|Постійна адреса)|$)", flat)
    return m.group(1).strip()[:60] if m else None


BAD_STATUS = ("втратив", "втратила", "не набрав", "не набрала", "зупин", "скасов", "нечинн")


def status_mark(st) -> str:
    if not st:
        return "статус не зчитано: звірити на сторінці акта"
    low = st.lower()
    if "попередн" in low:
        return f"[!?] zakon віддав ПОПЕРЕДНЮ редакцію ({st}): цитувати за цим ID не можна, звіряти іншим шляхом"
    if any(b in low for b in BAD_STATUS):
        return f"[!!] СТАТУС: {st}"
    return st


def report(text: str, out: str, cached_hours=None) -> None:
    arts = ART_RE.findall(text)
    title = text.split("\n", 1)[0][:120]
    cache = f" (кеш, завантажено {cached_hours:.1f} год тому)" if cached_hours is not None else ""
    print(f"[OK] {out}{cache}: {len(text):,} символів, статей: {len(arts)} | {title}")
    print(f"[РЕДАКЦІЯ] {edition_line(text)}")
    print(f"[СТАТУС] {status_mark(act_status(text))}")
    kind, date, _ = edition_info(text)
    if kind and "неконституційними" in kind:
        print(f"[УВАГА] Остання подія акта – рішення КСУ від {date} про неконституційність окремих положень: "
              f"перед цитуванням статті прочитати її примітки (детектор check)")
    if not arts:
        print("[ПРИМІТКА] структури «Стаття N.» немає – акт з пунктами; шукати через grep")
    head = text[:4000]
    m1 = re.search(r"(?m)^(Стаття 1\.|Розділ I\b|1\. )", text)
    if m1 and m1.start() < 20000:
        head = text[:m1.start()]
    dead = ACT_DEAD_RE.search(head)
    if dead:
        print(f"[СТОП] АКТ ВТРАТИВ ЧИННІСТЬ: {dead.group(0)[:300]}")
        print("        Цитувати заборонено – знайти акт, що його замінив (див. примітку), і працювати з ним.")


def load(src: str) -> str:
    """src – або шлях до .txt, або ID акта (тоді файл <ID>.txt; старший за CACHE_HOURS
    або з ключем --fresh – завантажити заново). Кожне читання друкує редакцію і статус."""
    if os.path.isfile(src):
        with open(src, encoding="utf-8") as f:
            text = f.read()
        report(text, src, cached_hours=_age_hours(src))
        return text
    path = txt_name(src)
    if os.path.isfile(path) and not FRESH and _age_hours(path) < CACHE_HOURS:
        with open(path, encoding="utf-8") as f:
            text = f.read()
        report(text, path, cached_hours=_age_hours(path))
        return text
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


def split_point(text: str, pt_no: str, nth: int = 1):
    """Пункт «N.» або «N-M.» на початку рядка – до наступного пункту того самого рівня.
    Примітки {...} після тексту пункту входять у витяг. nth – яке входження номера взяти
    (у постанові кілька додатків з власною нумерацією)."""
    ms = list(re.finditer(r'^\s*%s\.\s' % re.escape(pt_no), text, flags=re.M))
    if len(ms) < nth:
        return None
    m = ms[nth - 1]
    if len(ms) > 1:
        print(f"[УВАГА] пункт {pt_no} зустрічається {len(ms)} рази (додатки з власною нумерацією): "
              f"показано входження {nth}; інші – ключ --nth K")
    rest = text[m.end():]
    m2 = re.search(r'^\s*\d+(-\d+)?\.\s', rest, flags=re.M)
    end = m.end() + (m2.start() if m2 else len(rest))
    return text[m.start():end].strip()


# ---------------------------------------------------------------- check
def _parse_ua_date(s: str):
    m = re.match(r"(\d{2})\.(\d{2})\.(\d{4})", s)
    if m:
        return datetime(int(m.group(3)), int(m.group(2)), int(m.group(1)))
    m = re.match(r"(\d{1,2})\s+(\w+)\s+(\d{4})", s)
    if m and m.group(2) in MONTHS:
        return datetime(int(m.group(3)), MONTHS[m.group(2)], int(m.group(1)))
    return None


DEFER_RE = re.compile(r"(набира\w*\s+чинності|вводиться\s+в\s+дію|вводяться\s+в\s+дію)\s+з\s+"
                      r"(\d{2}\.\d{2}\.\d{4}|\d{1,2}\s+[а-яіїє]+\s+\d{4})")


def check(seg: str, label: str) -> bool:
    flat = seg.replace("\n", " ")
    notes = re.findall(r'\{[^}]+\}', flat)
    law = label.startswith("Стаття")
    key = ("ст. " if law else "п. ") + label.split(" ", 1)[1].strip() if " " in label else None
    crit_hits, warn_hits, other, unknown = [], [], [], []
    today = datetime.now()
    for note in notes:
        head = re.sub(r"\s*-\s*", "-", note.split("згідно")[0])
        tgt = _ann_target(head, law)
        if key and tgt and tgt != key and (not law or tgt.startswith("ст.")):
            other.append(note.strip()[:160])
            continue
        d = DEFER_RE.search(note)
        if d:
            when = _parse_ua_date(d.group(2))
            if when and when > today:
                crit_hits.append((f"ЩЕ НЕ НАБРАЛО ЧИННОСТІ (з {d.group(2)})", note.strip()[:240]))
            else:
                warn_hits.append((f"відкладене набрання чинності (з {d.group(2)}, дата настала)", note.strip()[:160]))
            continue
        if re.search(r"не набра\w*\s+чинності", note):
            crit_hits.append(("НЕ НАБРАЛО ЧИННОСТІ", note.strip()[:240]))
            continue
        if re.match(r"\{\s*Абзац[^{}]{0,160}виключено", note):
            warn_hits.append(("виключено абзац: звірити, що цитований абзац чинний", note.strip()[:160]))
            continue
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
                    hit = True
                    break
        if not hit:
            unknown.append(note.strip()[:160])
    print("=" * 74)
    print("НОРМА:", label, "| приміток у фігурних дужках:", len(notes))
    if crit_hits:
        print("ВЕРДИКТ: [СТОП] – критичних маркерів:", len(crit_hits))
        for name, note in crit_hits:
            print("  !!", name)
            print("     ", note)
        print("  ЦИТУВАТИ ЗАБОРОНЕНО до ручного розбору кожної примітки вище.")
    elif warn_hits or unknown:
        print("ВЕРДИКТ: [УВАГА] – редакційних маркерів:", len(warn_hits),
              f"| некласифікованих приміток: {len(unknown)}" if unknown else "")
        for name, note in warn_hits[:6]:
            print("  ~", name, "|", note)
        for note in unknown[:4]:
            print("  ? прочитати вручну |", note)
        print("  Звірити дату останньої зміни; текст норми читати повністю.")
    else:
        print("ВЕРДИКТ: [ЧИСТО] – приміток щодо цієї норми немає.")
        print("  Окремо перевірити спецрежими поза текстом статті (перехідні положення, воєнний стан).")
    if other:
        print(f"  (ще {len(other)} приміток стосуються інших пунктів/статей і на вердикт не впливають)")
    return bool(crit_hits)


# ---------------------------------------------------------------- radar
def paragraphs(page: str):
    """Абзаци /print за тегами <p>; примітки zakon {…} – окремими абзацами."""
    page = re.sub(r"<script.*?</script>|<style.*?</style>", "", page, flags=re.S | re.I)
    page = re.sub(r"<sup[^>]*>\s*([\d,\s-]+?)\s*</sup>", r"-\1", page, flags=re.I)
    out = []
    for chunk in re.split(r"<p[\s>]", page)[1:]:
        t = re.sub(r"<br\s*/?>", " ", chunk.split("</p>")[0])
        t = html.unescape(re.sub(r"<[^>]+>", "", "<" + t))
        t = re.sub(r"\s+", " ", t).strip()
        if t:
            out.append(t)
    return out


REF_RE = re.compile(r"№\s*([0-9A-Za-zА-ЯІЇЄҐа-яіїєґ'/-]+)\s*від\s*(\d{2}\.\d{2}\.\d{4})")


def _is_law(act_id: str) -> bool:
    return not act_id.endswith("-п") and act_id[:1] not in "zv"


def _ann_target(head: str, law: bool):
    """Місце зміни з тексту примітки до слова «згідно»: п. N / ст. N / додаток N."""
    h = re.sub(r"\s*-\s*", "-", head)
    art = re.search(r"[Сс]татт\w*\s+(\d+(?:-\d+)?)", h)
    if law and art:
        return f"ст. {art.group(1)}"
    m = re.search(r"[Пп]ідпункт\w*\s+\d+(?:-\d+)?\s+пункт\w*\s+(\d+(?:-\d+)?)", h)
    if m:
        return f"п. {m.group(1)}"
    m = re.search(r"(?<![Пп]ід)[Пп]ункт\w*\s+(\d+(?:-\d+)?)", h)
    if m:
        r = re.search(r"[Рр]озділ\w*\s+([IVXLC]+)", h)
        return f"розд. {r.group(1)} п. {m.group(1)}" if r else f"п. {m.group(1)}"
    if art:
        return f"ст. {art.group(1)}"
    m = re.search(r"[Дд]одат\w*\s+(\d+)", h)
    if m:
        return f"додаток {m.group(1)}"
    m = re.search(r"[Рр]озділ\w*\s+([IVXLC]+)", h)
    return f"розд. {m.group(1)}" if m else None


def amendment_refs(paras, act_id: str):
    """{'N@ДД.ММ.РРРР': [(місце, вид)]} з усіх приміток zakon {…} акта."""
    law = _is_law(act_id)
    point_re = re.compile(r"^(\d{1,3}(?:-\d{1,2})?)\.\s")
    art_re = re.compile(r"^Стаття\s+(\d+(?:-\d+)?)\.")
    cur, out = None, {}
    for p in paras:
        if not p.startswith("{"):
            m = art_re.match(p) or (None if law else point_re.match(p))
            if m:
                cur = ("ст. " if p.startswith("Стаття") else "п. ") + m.group(1)
            continue
        refs = REF_RE.findall(p)
        if not refs:
            continue
        where = _ann_target(p.split("згідно")[0], law) or cur or "шапка"
        kind = next((k for k in ("в редакції", "доповнено", "виключено", "зупинено", "втратив", "неконституційн", "змін")
                     if k in p), "інше")
        kind = {"змін": "зміни", "неконституційн": "КСУ: неконституційність"}.get(kind, kind)
        for num, date in refs:
            out.setdefault(f"{num}@{date}", []).append((where, kind))
    return out


def _ed_date(s):
    m = re.search(r"(\d{2})\.(\d{2})\.(\d{4})", s or "")
    return (int(m.group(3)), int(m.group(2)), int(m.group(1))) if m else None


def _dkey(ref: str):
    return _ed_date(ref.split("@")[1]) or (0, 0, 0)


def new_refs(act: dict, refs: dict, since=None):
    """Акти змін, яких немає в еталоні акта (або прийняті після дати since)."""
    if since:
        s = _ed_date(since)
        return sorted((r for r in refs if _dkey(r) > s), key=_dkey)
    known = set((act.get("refs") or "").split())
    if not known:
        s = _ed_date(act.get("edition")) or (0, 0, 0)
        return sorted((r for r in refs if _dkey(r) > s), key=_dkey)
    return sorted((r for r in refs if r not in known), key=_dkey)


def _place_key(w: str):
    return [int(x) for x in re.findall(r"\d+", w)] or [0]


def summarize_places(items) -> str:
    agg = {}
    for w, k in items:
        if w != "шапка":
            agg.setdefault(w, []).append(k)
    if not agg:
        return "лише в шапці акта (місце не зазначено)"
    parts = []
    for w in sorted(agg, key=_place_key):
        ks = agg[w]
        main_kind = max(set(ks), key=ks.count)
        parts.append(f"{w} ({main_kind}{f' ×{len(ks)}' if len(ks) > 1 else ''})")
    return ", ".join(parts)


def _nums(spec: str):
    out = set()
    for tok in re.split(r"\s*(?:,|\bі\b|\bта\b)\s*", spec):
        tok = tok.strip()
        m = re.fullmatch(r"(\d+)\s*[–—]\s*(\d+)", tok)
        if m and 0 < int(m.group(2)) - int(m.group(1)) < 100:
            out |= {str(x) for x in range(int(m.group(1)), int(m.group(2)) + 1)}
        elif re.fullmatch(r"\d+(?:-\d+)?", tok):
            out.add(tok)
    return out


def _line_targets(line: str):
    """Пункти, статті й пункти розділів закону, на які посилається рядок тексту скіла."""
    l = re.sub(r"пп\.\s*\d+(?:-\d+)?\s+(?=п\.\s*\d)", "", line)        # «пп. 4 п. 65» → п. 65
    l = re.sub(r"пп\.\s*[\d–-]+\s+ч\.\s*\d+", "", l)                   # «пп. 1–3 ч. 1 ст. 2»
    l = re.sub(r"\d+\.\d+(?:\.\d+)*", " ", l)                          # 4.1, 197.1.5 – не пункти
    sect = set()
    for m in re.finditer(r"(?<![\w.])п\.\s*(\d+(?:-\d+)?)\s+розд\w*\.?\s+([IVXLC]+)\b", l):
        sect.add((m.group(2), m.group(1)))
    l = re.sub(r"(?<![\w.])п\.\s*\d+(?:-\d+)?\s+розд\w*\.?\s+[IVXLC]+\b", " ", l)
    pts, arts = set(), set()
    for m in re.finditer(r"(?<![\w.])пп?\.\s*(\d+(?:-\d+)?(?:\s*(?:,|–|\bі\b|\bта\b)\s*\d+(?:-\d+)?)*)", l):
        pts |= _nums(m.group(1))
    for m in re.finditer(r"(?<![Пп]ід)пункт\w*\s+(\d+(?:-\d+)?)", l):
        pts.add(m.group(1))
    for m in re.finditer(r"(?:point|article)\s+\S+\s+\"?(?:Стаття\s+)?(\d+(?:-\d+)?)", line):
        (arts if "article" in m.group(0) else pts).add(m.group(1))
    for m in re.finditer(r"(?<![\w.])ст\.\s*(\d+(?:-\d+)?)|[Сс]татт\w*\s+(\d+(?:-\d+)?)", l):
        arts.add(m.group(1) or m.group(2))
    return pts, arts, sect


def _skill_files(skill_dir: str):
    files = [os.path.join(skill_dir, "SKILL.md")]
    mdir = os.path.join(skill_dir, "modules")
    if os.path.isdir(mdir):
        files += [os.path.join(mdir, f) for f in sorted(os.listdir(mdir)) if f.endswith(".md")]
    return [f for f in files if os.path.isfile(f)]


def _act_of(text: str, acts):
    best, n = None, 0
    for a in acts:
        c = sum(text.count(al) for al in a.get("aliases", []))
        if c > n:
            best, n = a["id"], c
    return best


def skill_refs(watch: dict, act_id: str, place: str):
    """Де текст скіла посилається на змінене місце: [(файл, рядок, розділ)]."""
    m = re.match(r"(?:розд\. ([IVXLC]+) )?(п|ст|додаток)\.?\s+(\d+(?:-\d+)?)$", place)
    if not m:
        return []
    sect_no, kind, num = m.group(1), m.group(2), m.group(3)
    acts = watch["acts"]
    aliases = next((a.get("aliases", []) for a in acts if a["id"] == act_id), [])
    default = watch.get("default_act")
    hits = []
    for path in _skill_files(watch["_dir"]):
        with open(path, encoding="utf-8") as f:
            lines = f.read().split("\n")
        sections, cur, buf = {}, "", []
        for line in lines:
            if line.startswith("#"):
                sections[cur] = _act_of("\n".join(buf), acts)
                cur, buf = line.strip("# ").strip()[:60], []
            else:
                buf.append(line)
        sections[cur] = _act_of("\n".join(buf), acts)
        cur = ""
        for i, line in enumerate(lines, 1):
            if line.startswith("#"):
                cur = line.strip("# ").strip()[:60]
                continue
            if kind == "додаток":
                found = re.search(rf"додат\w*\s+{num}\b", line)
            else:
                pts, arts, sect = _line_targets(line)
                found = (sect_no, num) in sect if sect_no else num in (pts if kind == "п" else arts)
            if not found:
                continue
            owner = act_id if any(al in line for al in aliases) else (_act_of(line, acts) or sections.get(cur) or default)
            if owner == act_id:
                hits.append((os.path.relpath(path, watch["_dir"]).replace(os.sep, "/"), i, cur))
    seen, out = set(), []
    for h in hits:
        if (h[0], h[2]) not in seen:
            seen.add((h[0], h[2]))
            out.append(h)
    return out


def print_changes(watch: dict, act: dict, refs: dict, fresh_refs, details=True):
    for r in fresh_refs:
        num, date = r.split("@")
        print(f"  [!] № {num} від {date}: {summarize_places(refs[r])}")
        if not details:
            continue
        places = sorted({w for w, _ in refs[r] if w != "шапка"}, key=_place_key)
        touched = {}
        for w in places:
            for f, ln, sec in skill_refs(watch, act["id"], w):
                touched.setdefault((f, sec), []).append((w, ln))
        if touched:
            print("      скіл посилається на змінені місця (перечитати й за потреби оновити):")
            for (f, sec), ws in sorted(touched.items()):
                print(f"        {f}:{ws[0][1]} [{sec or 'початок файла'}] → "
                      f"{', '.join(sorted({w for w, _ in ws}, key=_place_key))}")
        else:
            print("      у тексті скіла прямих посилань на ці місця не знайдено")


def load_watch(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        w = json.load(f)
    w["_dir"] = os.path.dirname(os.path.abspath(path))
    return w


def _page_for_radar(npa_id: str):
    """Сирий HTML: свіжий кеш (RADAR_HOURS) або нове завантаження."""
    hp = html_name(npa_id)
    if os.path.isfile(hp) and not FRESH and _age_hours(hp) < RADAR_HOURS:
        with open(hp, encoding="utf-8") as f:
            return f.read()
    return fetch_page(npa_id)


def _pages(ids):
    """Паралельно, 3 потоки (більше zakon не любить): {ID: html або None}."""
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=3) as ex:
        return dict(zip(ids, ex.map(_page_for_radar, ids)))


def _expiring(watch: dict):
    today = datetime.now()
    out = []
    for e in watch.get("expiring", []):
        d = _parse_ua_date(e.get("until", ""))
        if not d:
            continue
        if d < today:
            out.append(f"[!] ПРОСТРОЧЕНО: {e.get('what')} (до {e['until']}) – {e.get('where', '')}")
        elif d - today < timedelta(days=30):
            out.append(f"[i] спливає {e['until']}: {e.get('what')} – {e.get('where', '')}")
    return out


def cmd_radar(watch_path: str):
    w = load_watch(watch_path)
    acts = w["acts"]
    pages = _pages([a["id"] for a in acts])
    failed, newer, bad, changed, ksu = [], [], [], [], []
    print(f"РАДАР скіла {w.get('skill', '?')} | еталон {w.get('snapshot_date', '?')} | актів: {len(acts)}")
    for a in acts:
        page = pages.get(a["id"])
        if not page:
            failed.append(a["id"])
            continue
        text = html_to_text(page)
        line = edition_line(text)
        live, snap = _ed_date(line), _ed_date(a.get("edition"))
        if live and snap and live > snap:
            mark = f"[!] НОВІША за еталон ({a.get('edition')})"
            newer.append(a["id"])
        elif live and snap and live == snap:
            mark = "= еталон"
        else:
            mark = f"звірити вручну (еталон: {a.get('edition') or 'немає'})"
        st = status_mark(act_status(text))
        if st.startswith("[!") and a.get("known_issue"):
            st += f" (відомо: {a['known_issue']})"
        elif st.startswith("[!"):
            bad.append(a["id"])
        if "неконституційними" in line and live and snap and live > snap:
            ksu.append(a["id"])
        print(f"{a['id']:13s} {a.get('name', '')[:40]:40s} | {line} | {mark} | {st}")
        refs = amendment_refs(paragraphs(page), a["id"])
        fr = new_refs(a, refs)
        if fr:
            changed.append(a["id"])
            print_changes(w, a, refs, fr, details=False)
    print()
    try:
        age = (datetime.now() - datetime.strptime(w.get("snapshot_date", ""), "%d.%m.%Y")).days
        if age > int(w.get("stale_days", 60)):
            print(f"[!] Еталону {age} днів: навіть за збігу редакцій сказати Стасу, що скіл пора звірити й оновити.")
    except ValueError:
        print("[!] дата еталона не зчитана – оновити watch.json командою snapshot --write")
    for line in _expiring(w):
        print(line)
    if ksu:
        print(f"[!] Нові рішення КСУ щодо актів: {', '.join(ksu)} – детектор check перед цитуванням кожної статті.")
    if bad:
        print(f"[!!] Статус або текст ненадійні: {', '.join(bad)}. Норми цих актів не цитувати, доки не з'ясовано, "
              f"що їх замінило або де взяти чинний текст; сказати Стасу.")
    if newer or changed:
        print(f"[!] Зміни після еталона: {', '.join(sorted(set(newer + changed)))}. Працювати ТІЛЬКИ за живим текстом; "
              f"деталі й зачеплені місця скіла – changes {os.path.basename(watch_path)} <ID>; сказати Стасу, що скіл пора оновити.")
    elif not failed and not bad:
        print("Змін після еталона немає.")
    if failed:
        print(f"[ПОМИЛКА] не отримано: {', '.join(failed)}; дозволені конектори (Tavily → Firecrawl → Chrome).")


def cmd_changes(watch_path: str, act_id=None, since=None):
    w = load_watch(watch_path)
    acts = [a for a in w["acts"] if not act_id or a["id"] == act_id]
    if act_id and not acts:
        acts = [{"id": act_id, "name": act_id, "aliases": [], "edition": since or w.get("snapshot_date"), "refs": ""}]
    pages = _pages([a["id"] for a in acts])
    found = False
    for a in acts:
        page = pages.get(a["id"])
        if not page:
            continue
        text = html_to_text(page)
        refs = amendment_refs(paragraphs(page), a["id"])
        fr = new_refs(a, refs, since)
        if not fr and not act_id:
            continue
        found = found or bool(fr)
        basis = f"після {since}" if since else f"проти еталона {w.get('snapshot_date')}"
        print(f"{a['id']} | {edition_line(text)} | {status_mark(act_status(text))} | акти змін {basis}: {len(fr)}")
        print_changes(w, a, refs, fr, details=True)
    if not act_id and not found:
        print("Нових актів змін у примітках zakon немає (за всіма актами watch.json).")


def cmd_snapshot(watch_path: str, write: bool):
    w = load_watch(watch_path)
    pages = _pages([a["id"] for a in w["acts"]])
    missing = []
    for a in w["acts"]:
        page = pages.get(a["id"])
        if not page:
            missing.append(a["id"])
            continue
        text = html_to_text(page)
        kind, date, basis = edition_info(text)
        a["edition"] = date or ""
        a["edition_line"] = edition_line(text)
        a["refs"] = " ".join(sorted(amendment_refs(paragraphs(page), a["id"]), key=_dkey))
    if missing:
        print(f"[ПОМИЛКА] не отримано: {', '.join(missing)} – еталон для них не оновлено")
    w["snapshot_date"] = datetime.now().strftime("%d.%m.%Y")
    out = {k: v for k, v in w.items() if k != "_dir"}
    data = json.dumps(out, ensure_ascii=False, indent=1)
    if write:
        with open(watch_path, "w", encoding="utf-8", newline="\n") as f:
            f.write(data + "\n")
        print(f"[OK] еталон записано: {watch_path} ({len(w['acts'])} актів, дата {w['snapshot_date']})")
    else:
        print(data)


def cmd_status(ids):
    pages = _pages(ids)
    for i in ids:
        page = pages.get(i)
        if not page:
            print(f"{i:13s} | НЕ ОТРИМАНО")
            continue
        text = html_to_text(page)
        title = re.sub(r"\s+", " ", text[:160]).split("(Текст для друку)")[0][:70]
        print(f"{i:13s} | {title} | {edition_line(text)} | {status_mark(act_status(text))}")


# ---------------------------------------------------------------- main
def main(argv):
    argv = [a for a in argv if a != "--fresh"]
    nth = 1
    if "--nth" in argv:
        k = argv.index("--nth")
        nth = int(argv[k + 1])
        del argv[k:k + 2]
    if len(argv) >= 2 and argv[1] == "status":
        cmd_status(argv[2:])
        return
    if len(argv) >= 3 and argv[1] == "radar":
        cmd_radar(argv[2])
        return
    if len(argv) >= 3 and argv[1] == "changes":
        rest = argv[3:]
        since = next((a for a in rest if re.fullmatch(r"\d{2}\.\d{2}\.\d{4}", a)), None)
        act = next((a for a in rest if a != since), None)
        cmd_changes(argv[2], act, since)
        return
    if len(argv) >= 3 and argv[1] == "snapshot":
        cmd_snapshot(argv[2], "--write" in argv)
        return
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
        seg = split_point(text, pt, nth)
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
