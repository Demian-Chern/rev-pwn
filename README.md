# ctfkit

[![CI](https://github.com/Demian-Chern/rev-pwn/actions/workflows/ci.yml/badge.svg)](https://github.com/Demian-Chern/rev-pwn/actions/workflows/ci.yml)

Утилита-помощник для CTF под **Linux ELF x86-64** (rev + pwn): быстрый триаж
бинаря, генерация скелета эксплойта на pwntools, ROP/GOT-хелперы. Чистый пакет
без внешних зависимостей для базового режима + сборка в один портируемый
`ctfkit.pyz`, который можно `scp`-ом кинуть на любую тачку с Python 3.

```
   __  ____ _____ _    _ _
  / _||  _ \_   _| |/ /(_) |_
 | |  | | | || | | ' / | | __|   rev + pwn, Linux ELF x86-64
 | |_ | |_| || | | . \ | | |_
  \__||____/ |_| |_|\_\|_|\__|
```

## Команды

| Команда | Что делает |
|---|---|
| `triage <bin>` | полный разбор бинаря + эвристический вектор атаки |
| `pwn <bin>` | скелет эксплойта (BOF / ret2win / ret2libc / fmtstr); `--auto-offset`, `--libc`, `--libc-leak` |
| `offset <bin>` | авто-поиск оффсета переполнения (свой cyclic + gdb) |
| `onegadget <libc>` | магические `execve("/bin/sh")` гаджеты + их constraints |
| `libcid --leak sym=addr` | опознание libc по утечке (libc.rip / офлайн), `--download` |
| `heap <bin>` | скелет под heap-челлендж: парсит меню, даёт обёртки + шпаргалку |
| `rop <bin>` | ROP-гаджеты и `/bin/sh` |
| `libc <bin> <libc>` | GOT/PLT, оффсеты, one_gadget'ы |
| `web` | локальный веб-интерфейс в браузере |
| *(без аргументов)* | интерактивное меню (TUI) |

## Что делает

- **triage** — за один запуск: тип файла, `checksec` (RELRO/Canary/NX/PIE),
  опасные импорты (`gets`, `system`, `printf`, `malloc`/`free`…), поиск
  win/backdoor-функций по именам, интересные строки (`/bin/sh`, `flag`, `%n`…),
  GOT/PLT, превью дизассемблера `main`/`vuln`, и **эвристическая подсказка**
  вектора атаки (BOF / format string / heap / ret2libc / ret2win).
- **pwn** — генерит готовый скелет эксплойта под конкретный бинарь: уже
  проставлены митигации, найденные символы, `pop rdi`/`ret`, `system@plt`,
  win-функции, и выбрана подходящая заготовка тела. Переключатель local/GDB/REMOTE.
  С флагом `--auto-offset` сразу прогоняет бинарь и подставляет найденный `OFFSET`.
- **offset** — авто-поиск оффсета переполнения: кидает в бинарь циклический
  паттерн (De Bruijn), ловит креш под `gdb` и по `$pc` считает расстояние до
  сохранённого RIP. Не зависит от ASLR/PIE, работает без pwntools. **Запускает
  бинарь локально** — только для своих/CTF-челленджей.
- **rop** — полезные гаджеты (`pop rdi; ret`, `leave; ret`, `syscall`…) и `/bin/sh`.
- **onegadget** — магические адреса `execve("/bin/sh")` из libc через `one_gadget`,
  с их constraints. Встроено и в `libc`, и в `pwn --libc` (впишет в скелет).
- **heap** — скелет под heap-челлендж: парсит меню (alloc/free/edit/show + номера
  и промпты), генерит обёртки `alloc/free/edit/show` и шпаргалку по
  tcache/UAF/double-free.
- **web** — локальный веб-интерфейс в браузере (на stdlib, без зависимостей):
  панель с кнопками на все команды и цветным выводом. Слушает только `127.0.0.1`,
  API защищён токеном.
- **libcid** — определение libc по утечке: `--leak puts=0x..340` → подбирает
  версию libc (онлайн через libc.rip или офлайн по папке `--libs`), считает базу
  из лика и резолвит `system`/`str_bin_sh`/прочее. С `--download` качает опознанную
  libc (только с libc.rip, с проверкой ELF). А `pwn --libc-leak ...` делает всё
  сразу: опознаёт → скачивает → вписывает libc и one_gadget'ы в скелет.
- **libc** — GOT/PLT + заметки по ret2libc; с переданным `libc.so.6` вытащит
  оффсеты `system`/`puts`/`/bin/sh` и one_gadget'ы.
- **без аргументов** — интерактивное меню (TUI).

## Структура проекта

```
ctfkit/
  __init__.py     версия
  __main__.py     python -m ctfkit
  ui.py           цвета, вывод, баннер
  shell.py        обёртки над readelf/objdump/nm
  elf.py          загрузка ELF, символы, таблицы эвристик, pwntools-детект
  checksec.py     митигации (+ тихий вариант для кодогенерации)
  triage.py       анализ + команда triage
  rop.py          ROP-гаджеты, GOT/PLT + команда rop
  pwngen.py       шаблон и генератор эксплойта + команда pwn
  offset.py       авто-поиск BOF-оффсета (свой cyclic + gdb)
  onegadget.py    обёртка над one_gadget + парсер constraints
  libcid.py       определение libc по leak (libc.rip + офлайн)
  heap.py         парсер меню + генератор heap-скелета
  web.py          локальный веб-интерфейс (stdlib http.server)
  libc.py         ret2libc-хелпер + команда libc
  tui.py          интерактивное меню
  cli.py          argparse + диспетчер
pyproject.toml    установка, точка входа `ctfkit`
build.py          сборка одного файла ctfkit.pyz (zipapp)
```

## Установка / запуск

Три способа — выбирай под ситуацию.

**1. Поставить как пакет (локальная разработка):**
```bash
pip install -e ".[full]"     # [full] = тянет pwntools
ctfkit triage ./chall
```

**2. Без установки, прямо из папки:**
```bash
python3 -m ctfkit triage ./chall
```

**3. Один файл на удалённую тачку (главная фишка):**
```bash
python3 build.py                 # собирает ctfkit.pyz
scp ctfkit.pyz user@box:~/
python3 ctfkit.pyz triage ./chall
```
`ctfkit.pyz` уже лежит в репо собранным — можно сразу копировать. После правок
кода пересобери через `python3 build.py`.

### Зависимости

Базовый режим работает **без зависимостей** (fallback на `readelf`/`objdump`/`nm`).
Для полной точности:
```bash
pip install pwntools          # точный checksec, символы, ROP
sudo apt install binutils     # readelf/objdump/nm для fallback
sudo apt install gdb          # нужен для `offset` (авто-поиск оффсета)
gem install one_gadget        # нужен для `onegadget` / `pwn --libc`
pip install ROPgadget ropper  # опционально, rop без pwntools
```

## Примеры

```bash
python3 -m ctfkit triage ./chall
```
```bash
python3 -m ctfkit pwn ./chall -o exploit.py --host ctf.example.com --port 1337
```
```bash
python3 -m ctfkit pwn ./chall --auto-offset        # прогнать и вписать OFFSET
```
```bash
python3 -m ctfkit offset ./chall                   # только найти оффсет
```
```bash
python3 -m ctfkit offset ./chall --update exploit.py   # и вписать его в скелет
```
```bash
python3 -m ctfkit onegadget ./libc.so.6                # магические execve-гаджеты
```
```bash
python3 -m ctfkit libcid --leak puts=0x7f3b2c0a4340    # опознать libc по утечке
```
```bash
python3 -m ctfkit libcid --leak puts=0x..340 --libs ./libs   # офлайн, по своей папке
```
```bash
python3 -m ctfkit libcid --leak puts=0x..340 --download      # скачать опознанную libc
```
```bash
python3 -m ctfkit pwn ./chall --libc-leak puts=0x..340       # опознать+скачать+вписать
```
```bash
python3 -m ctfkit pwn ./chall --libc ./libc.so.6       # вписать libc + one_gadget'ы
```
```bash
python3 -m ctfkit heap ./chall -o heap.py              # скелет под heap-челлендж
```
```bash
python3 -m ctfkit web                                   # веб-интерфейс в браузере
```
```bash
python3 -m ctfkit rop ./chall
```
```bash
python3 -m ctfkit libc ./chall ./libc.so.6
```

### Запуск сгенерированного эксплойта

```bash
python3 exploit.py           # локальный процесс
python3 exploit.py GDB       # локально под gdb (нужен tmux)
python3 exploit.py REMOTE    # коннект к HOST:PORT
```

Дальше: находишь `OFFSET` через `cyclic`, доводишь выбранную заготовку — и го.

## Тесты

Юнит-тесты чистой логики (cyclic, парсер one_gadget, все ветки генератора,
MiniELF, CLI) не требуют pwntools/gdb/one_gadget — только `pytest`:

```bash
pip install -e ".[dev]"
python -m pytest
```

На каждый push GitHub Actions гоняет их на Python 3.8–3.13 и собирает `ctfkit.pyz`
(см. бейдж вверху и `.github/workflows/ci.yml`).

## Заметки

- Цвет отключается через `NO_COLOR=1` или при выводе не в терминал.
- Эвристики — подсказки, а не истина: сложные челленджи всё равно открывай в
  Ghidra/IDA. ctfkit экономит первые 10 минут рутины.
- Только для бинарей, которые тебе разрешено анализировать (CTF / свои).

## Хотелки на будущее

- доставка паттерна через `recvuntil`-промпт и сокет (для авто-оффсета по сети)
- готовые заготовки эксплойтов под конкретные техники (house-of-*, FSOP)
- авто-скачивание loader/ld вместе с libc (для `patchelf`-воркфлоу)
