#!/usr/bin/env python3
"""
Управление пользователями AmneziaWG 3.1 (контейнер, установленный приложением Amnezia)
с выдачей ключей в формате vpn://, как в приложении Amnezia.

Один раз:
  ./awg-users.py template            вставить ключ vpn:// любого пользователя, созданного в приложении
                                     (он используется как образец формата)

Дальше:
  ./awg-users.py add vasya "Петя Иванов"   создать пользователей и вывести их ключи vpn://
  ./awg-users.py add -f names.txt    то же для списка имён из файла (одно имя на строку)
  ./awg-users.py show "Петя Иванов"  показать ключ пользователя ещё раз
                                     (имена с пробелами в командной строке берите в кавычки)
  ./awg-users.py del vasya petya     удалить пользователей (и созданных в приложении тоже)
  ./awg-users.py list                список пользователей и время последнего подключения

Пользователи, созданные скриптом, видны и в приложении Amnezia.
"""
import argparse
import base64
import fcntl
import json
import os
import re
import subprocess
import sys
import zlib
from datetime import datetime

# ---- Настройки ----
CONTAINER = "amnezia-awg2"
AWG_DIR = "/opt/amnezia/awg"
IFACE = "awg0"
CLIENTS_DIR = "/root/awg-clients"   # здесь хранятся ключи пользователей и образец
# -------------------

CONF = f"{AWG_DIR}/{IFACE}.conf"
TABLE = f"{AWG_DIR}/clientsTable"
TEMPLATE = os.path.join(CLIENTS_DIR, "template.json")
LOCK = "/var/lock/awg-users.lock"
NAME_RE = re.compile(r"^[^\x00-\x1f\x7f/\\]{1,64}$")
KEY_RE = r"[A-Za-z0-9+/]{42,43}="


def die(msg):
    print(f"Ошибка: {msg}", file=sys.stderr)
    sys.exit(1)


def cx(*args, data=None):
    """Выполнить команду в контейнере."""
    kw = {"input": data} if data is not None else {"stdin": subprocess.DEVNULL}
    r = subprocess.run(["docker", "exec", "-i", CONTAINER, *args],
                       capture_output=True, text=True, encoding="utf-8", **kw)
    if r.returncode != 0:
        die(f"в контейнере не выполнилось «{' '.join(args[:3])}»: {r.stderr.strip()}")
    return r.stdout


def read_file(path):
    return cx("cat", path)


def write_file(path, content):
    if not content.strip():
        die(f"получилось пустое содержимое для {path}, запись отменена")
    cx("sh", "-c", f"cat > '{path}'", data=content)


def load_table():
    try:
        t = read_file(TABLE).strip()
    except SystemExit:
        return []
    return json.loads(t) if t else []


def save_table(table):
    write_file(TABLE, json.dumps(table, indent=4, ensure_ascii=False) + "\n")


def key_path(name):
    """Имя файла ключа: пробелы и спецсимволы заменяются на _."""
    return os.path.join(CLIENTS_DIR, re.sub(r"[^\w.-]+", "_", name) + ".key")


def client_name(c):
    return c.get("userData", {}).get("clientName", "")


# ---- Формат vpn:// (Qt qCompress + base64url) ----

def decode_key(s):
    s = s.strip()
    if s.startswith("vpn://"):
        s = s[6:]
    raw = base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    try:
        return zlib.decompress(raw[4:]).decode(), True
    except zlib.error:
        return raw.decode(), False


def encode_key(text, compressed=True):
    data = text.encode()
    if compressed:
        data = len(data).to_bytes(4, "big") + zlib.compress(data, 8)
    return "vpn://" + base64.urlsafe_b64encode(data).decode().rstrip("=")


def load_template():
    if not os.path.exists(TEMPLATE):
        die("нет образца ключа. Сначала выполните: ./awg-users.py template")
    with open(TEMPLATE) as f:
        return json.load(f)


def make_key(tpl, priv, pub, psk, ip):
    t = tpl["text"]
    for old, new in ((tpl["priv"], priv), (tpl["pub"], pub), (tpl["psk"], psk)):
        t = t.replace(old, new)
    t = re.sub(r"(?<![\d.])" + re.escape(tpl["ip"]) + r"(?!\d)", ip, t)
    json.loads(t)  # проверка, что JSON не сломан
    return encode_key(t, tpl["compressed"])


# ---- Команды ----

def cmd_template(_args):
    print("Вставьте ключ vpn:// пользователя, созданного в приложении Amnezia, и нажмите Enter:")
    key = sys.stdin.readline().strip()
    if not key:
        die("ключ не введён")
    try:
        text, compressed = decode_key(key)
        json.loads(text)
    except Exception as e:  # noqa: BLE001
        die(f"не удалось разобрать ключ: {e}")

    def find(pattern, what):
        m = re.search(pattern, text)
        if not m:
            die(f"в ключе не найден {what} — это точно ключ AmneziaWG?")
        return m.group(1)

    priv = find(r"PrivateKey = (" + KEY_RE + ")", "PrivateKey")
    psk = find(r"PresharedKey = (" + KEY_RE + ")", "PresharedKey")
    ip = find(r"Address = (\d+\.\d+\.\d+\.\d+)", "Address")
    pub = cx("awg", "pubkey", data=priv + "\n").strip()

    # Проверим, что образец относится к этому серверу
    srv_pub = read_file(f"{AWG_DIR}/wireguard_server_public_key.key").strip()
    conf = read_file(CONF)
    hpk = re.search(r"^HeaderProtectionKey\s*=\s*(\S+)", conf, re.M)
    if srv_pub not in text:
        print("Внимание: в ключе нет публичного ключа этого сервера. Образец от другого сервера?")
    if hpk and hpk.group(1) not in text:
        print("Внимание: параметры обфускации в ключе не совпадают с сервером. "
              "Создайте образец заново после переустановки протокола.")

    os.makedirs(CLIENTS_DIR, mode=0o700, exist_ok=True)
    with open(TEMPLATE, "w") as f:
        json.dump({"text": text, "compressed": compressed,
                   "priv": priv, "pub": pub, "psk": psk, "ip": ip}, f)
    os.chmod(TEMPLATE, 0o600)
    print(f"Образец сохранён. Пользователя, ключ которого вы вставили ({ip}), "
          "теперь можно удалить в приложении — образец продолжит работать.")


def next_ip(conf):
    addr = re.search(r"^Address\s*=\s*(\d+\.\d+\.\d+)\.\d+", conf, re.M)
    if not addr:
        die("не найден Address в конфиге сервера")
    base = addr.group(1)
    used = {int(x) for x in re.findall(r"^AllowedIPs\s*=\s*" + re.escape(base) + r"\.(\d+)", conf, re.M)}
    for i in range(1, 255):
        if i not in used:
            return f"{base}.{i}"
    die(f"свободные адреса в подсети {base}.0/24 закончились")


def add_user(name, tpl, table):
    priv = cx("awg", "genkey").strip()
    pub = cx("awg", "pubkey", data=priv + "\n").strip()
    psk = cx("awg", "genpsk").strip()
    ip = next_ip(read_file(CONF))
    key = make_key(tpl, priv, pub, psk, ip)  # до изменений на сервере: если что-то не так, ничего не трогаем

    # Применяем сразу, без перезапуска — остальные пользователи не отключатся
    cx("awg", "set", IFACE, "peer", pub, "preshared-key", "/dev/stdin",
       "allowed-ips", f"{ip}/32", data=psk + "\n")
    cx("sh", "-c", f"cat >> '{CONF}'",
       data=f"\n[Peer]\nPublicKey = {pub}\nPresharedKey = {psk}\nAllowedIPs = {ip}/32\n")
    table.append({"clientId": pub, "userData": {
        "clientName": name,
        "creationDate": datetime.now().strftime("%a %b %-d %H:%M:%S %Y")}})
    save_table(table)

    path = key_path(name)
    with open(path, "w", encoding="utf-8") as f:
        f.write(key + "\n")
    os.chmod(path, 0o600)
    return key


def cmd_add(args):
    names = list(args.names)
    if args.file:
        with open(args.file, "rb") as f:
            raw = f.read()
        try:
            text = raw.decode("utf-8-sig")   # UTF-8, в том числе с BOM из Блокнота
        except UnicodeDecodeError:
            text = raw.decode("cp1251")      # старый Блокнот сохраняет кириллицу в ANSI
        names += [ln.strip() for ln in text.splitlines() if ln.strip() and not ln.strip().startswith("#")]
    names = [" ".join(n.split()) for n in names]  # лишние пробелы внутри имени
    if not names:
        die("укажите имена или файл со списком (-f)")
    bad = [n for n in names if not NAME_RE.match(n)]
    if bad:
        die("недопустимые имена: " + ", ".join(bad) +
            " (до 64 символов, без символов / и \\)")

    tpl = load_template()
    table = load_table()
    existing = {client_name(c) for c in table}
    results, seen = [], set()
    for n in names:
        if n in existing or n in seen:
            print(f"Пропущен {n}: такой пользователь уже есть", file=sys.stderr)
            continue
        seen.add(n)
        results.append((n, add_user(n, tpl, table)))

    if not results:
        return
    os.makedirs(CLIENTS_DIR, mode=0o700, exist_ok=True)
    out = os.path.join(CLIENTS_DIR, datetime.now().strftime("keys-%Y%m%d-%H%M%S.txt"))
    with open(out, "w", encoding="utf-8") as f:
        for _, k in results:          # только ключи, в том же порядке, что и имена в списке
            f.write(f"{k}\n")
    os.chmod(out, 0o600)
    print()
    for n, k in results:
        print(f"{n}: {k}\n")
    print(f"Создано пользователей: {len(results)}. Ключи сохранены в {out}")


def cmd_show(args):
    path = key_path(args.name)
    if not os.path.exists(path):
        die(f"нет ключа {path} (ключи хранятся только для пользователей, созданных этим скриптом)")
    with open(path, encoding="utf-8") as f:
        print(f.read().strip())


def cmd_del(args):
    table = load_table()
    for name in args.names:
        found = [c for c in table if client_name(c) == name]
        if not found:
            print(f"Пропущен {name}: не найден", file=sys.stderr)
            continue
        pub = found[0]["clientId"]
        cx("awg", "set", IFACE, "peer", pub, "remove")

        blocks = re.split(r"(?m)^(?=\[)", read_file(CONF))
        keep = [b for b in blocks
                if not (b.startswith("[Peer]") and
                        re.search(r"^PublicKey\s*=\s*" + re.escape(pub) + r"\s*$", b, re.M))]
        write_file(CONF, "".join(keep))

        table = [c for c in table if c.get("clientId") != pub]
        save_table(table)
        try:
            os.remove(key_path(name))
        except FileNotFoundError:
            pass
        print(f"Пользователь {name} удалён")


def cmd_list(_args):
    peers = {}
    for line in cx("awg", "show", IFACE, "dump").splitlines()[1:]:
        p = line.split("\t")
        if len(p) >= 5:
            peers[p[0]] = (p[3].split("/")[0], int(p[4]) if p[4].isdigit() else 0)
    print(f"{'NAME':<24} {'IP':<14} LAST HANDSHAKE")
    for c in load_table():
        ip, hs = peers.get(c.get("clientId"), ("-", None))
        if hs is None:
            when = "нет на сервере"
        elif hs == 0:
            when = "не подключался"
        else:
            when = datetime.fromtimestamp(hs).strftime("%d.%m.%Y %H:%M")
        print(f"{client_name(c):<24} {ip:<14} {when}")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("template").set_defaults(fn=cmd_template)
    p = sub.add_parser("add")
    p.add_argument("names", nargs="*")
    p.add_argument("-f", "--file")
    p.set_defaults(fn=cmd_add)
    p = sub.add_parser("show")
    p.add_argument("name")
    p.set_defaults(fn=cmd_show)
    p = sub.add_parser("del")
    p.add_argument("names", nargs="+")
    p.set_defaults(fn=cmd_del)
    sub.add_parser("list").set_defaults(fn=cmd_list)
    args = ap.parse_args()

    if os.geteuid() != 0:
        die("запустите от root")
    names = subprocess.run(["docker", "ps", "--format", "{{.Names}}"],
                           capture_output=True, text=True).stdout.split()
    if CONTAINER not in names:
        die(f"контейнер {CONTAINER} не запущен")

    with open(LOCK, "w") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            die("скрипт уже выполняется в другом окне")
        args.fn(args)


if __name__ == "__main__":
    main()
