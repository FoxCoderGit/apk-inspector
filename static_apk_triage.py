#!/usr/bin/env python3
import argparse
import json
import os
import re
import struct
from pathlib import Path


ANDROID_NS = "http://schemas.android.com/apk/res/android"


def u16(data, off):
    return struct.unpack_from("<H", data, off)[0]


def u32(data, off):
    return struct.unpack_from("<I", data, off)[0]


def sleb(data, off):
    result = 0
    shift = 0
    pos = off
    while True:
        b = data[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        shift += 7
        if (b & 0x80) == 0:
            break
    if shift < 32 and (b & 0x40):
        result |= - (1 << shift)
    return result, pos


def uleb(data, off):
    result = 0
    shift = 0
    pos = off
    while True:
        b = data[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        shift += 7
        if (b & 0x80) == 0:
            break
    return result, pos


def dex_string(data, off):
    _, pos = uleb(data, off)
    out = bytearray()
    while pos < len(data) and data[pos] != 0:
        out.append(data[pos])
        pos += 1
    return out.decode("utf-8", "replace")


def parse_dex(path):
    data = Path(path).read_bytes()
    if not data.startswith(b"dex\n"):
        return None
    string_ids_size, string_ids_off = u32(data, 56), u32(data, 60)
    type_ids_size, type_ids_off = u32(data, 64), u32(data, 68)
    proto_ids_size, proto_ids_off = u32(data, 72), u32(data, 76)
    field_ids_size, field_ids_off = u32(data, 80), u32(data, 84)
    method_ids_size, method_ids_off = u32(data, 88), u32(data, 92)
    class_defs_size, class_defs_off = u32(data, 96), u32(data, 100)

    strings = []
    for i in range(string_ids_size):
        off = u32(data, string_ids_off + i * 4)
        strings.append(dex_string(data, off))

    def s(idx):
        return strings[idx] if 0 <= idx < len(strings) else f"<bad-string-{idx}>"

    types = []
    for i in range(type_ids_size):
        types.append(s(u32(data, type_ids_off + i * 4)))

    protos = []
    for i in range(proto_ids_size):
        shorty_idx, return_type_idx, params_off = struct.unpack_from("<III", data, proto_ids_off + i * 12)
        params = []
        if params_off:
            size = u32(data, params_off)
            for j in range(size):
                params.append(types[u16(data, params_off + 4 + j * 2)])
        protos.append({"shorty": s(shorty_idx), "return": types[return_type_idx], "params": params})

    fields = []
    for i in range(field_ids_size):
        class_idx, type_idx, name_idx = struct.unpack_from("<HHI", data, field_ids_off + i * 8)
        fields.append({"class": types[class_idx], "type": types[type_idx], "name": s(name_idx)})

    methods = []
    for i in range(method_ids_size):
        class_idx, proto_idx, name_idx = struct.unpack_from("<HHI", data, method_ids_off + i * 8)
        methods.append({"class": types[class_idx], "name": s(name_idx), "proto": protos[proto_idx]})

    classes = []
    for i in range(class_defs_size):
        off = class_defs_off + i * 32
        class_idx, access_flags, super_idx, interfaces_off, source_idx, annotations_off, class_data_off, static_values_off = struct.unpack_from("<IIIIIIII", data, off)
        classes.append({
            "class": types[class_idx],
            "super": types[super_idx] if super_idx != 0xFFFFFFFF and super_idx < len(types) else None,
            "source": s(source_idx) if source_idx != 0xFFFFFFFF else None,
            "class_data_off": class_data_off,
        })

    return {"path": str(path), "strings": strings, "types": types, "fields": fields, "methods": methods, "classes": classes}


class StringPool:
    def __init__(self, data, off):
        self.data = data
        self.off = off
        self.strings = []
        chunk_type = u16(data, off)
        if chunk_type not in (0x0001,):
            raise ValueError("not a string pool")
        header_size = u16(data, off + 2)
        string_count = u32(data, off + 8)
        flags = u32(data, off + 16)
        strings_start = u32(data, off + 20)
        utf8 = bool(flags & 0x100)
        offsets = [u32(data, off + header_size + i * 4) for i in range(string_count)]
        for rel in offsets:
            pos = off + strings_start + rel
            if utf8:
                _, pos = self._len8(pos)
                blen, pos = self._len8(pos)
                raw = data[pos:pos + blen]
                self.strings.append(raw.decode("utf-8", "replace"))
            else:
                clen, pos = self._len16(pos)
                raw = data[pos:pos + clen * 2]
                self.strings.append(raw.decode("utf-16le", "replace"))

    def _len8(self, pos):
        val = self.data[pos]
        pos += 1
        if val & 0x80:
            val = ((val & 0x7F) << 8) | self.data[pos]
            pos += 1
        return val, pos

    def _len16(self, pos):
        val = u16(self.data, pos)
        pos += 2
        if val & 0x8000:
            val = ((val & 0x7FFF) << 16) | u16(self.data, pos)
            pos += 2
        return val, pos

    def get(self, idx):
        if idx == 0xFFFFFFFF:
            return None
        if 0 <= idx < len(self.strings):
            return self.strings[idx]
        return f"<bad-string-{idx}>"


TYPE_STRING = 0x03
TYPE_INT_DEC = 0x10
TYPE_INT_HEX = 0x11
TYPE_INT_BOOLEAN = 0x12


def attr_value(strings, raw_value_idx, data_type, data_value):
    if data_type == TYPE_STRING:
        return strings.get(raw_value_idx)
    if data_type == TYPE_INT_BOOLEAN:
        return "true" if data_value else "false"
    if data_type == TYPE_INT_DEC:
        return str(data_value)
    if data_type == TYPE_INT_HEX:
        return hex(data_value)
    if raw_value_idx != 0xFFFFFFFF:
        return strings.get(raw_value_idx)
    return str(data_value)


def parse_axml(path):
    data = Path(path).read_bytes()
    if u16(data, 0) != 0x0003:
        raise ValueError("not binary XML")
    pos = u16(data, 2)
    strings = None
    manifest = {"elements": []}
    stack = []
    while pos + 8 <= len(data):
        chunk_type = u16(data, pos)
        header_size = u16(data, pos + 2)
        chunk_size = u32(data, pos + 4)
        if chunk_size <= 0:
            break
        if chunk_type == 0x0001:
            strings = StringPool(data, pos)
        elif chunk_type == 0x0102 and strings:
            line = u32(data, pos + 8)
            name_idx = u32(data, pos + 20)
            name = strings.get(name_idx)
            attr_start = u16(data, pos + 24)
            attr_size = u16(data, pos + 26)
            attr_count = u16(data, pos + 28)
            attrs = {}
            for i in range(attr_count):
                aoff = pos + attr_start + i * attr_size
                ns_idx = u32(data, aoff)
                aname_idx = u32(data, aoff + 4)
                raw_value_idx = u32(data, aoff + 8)
                data_type = data[aoff + 15]
                data_value = u32(data, aoff + 16)
                aname = strings.get(aname_idx)
                ns = strings.get(ns_idx)
                key = f"android:{aname}" if ns == ANDROID_NS else aname
                attrs[key] = attr_value(strings, raw_value_idx, data_type, data_value)
            elem = {"name": name, "attrs": attrs, "line": line, "parent": stack[-1] if stack else None}
            manifest["elements"].append(elem)
            stack.append(name)
        elif chunk_type == 0x0103 and strings:
            if stack:
                stack.pop()
        pos += chunk_size
    for elem in manifest["elements"]:
        if elem["name"] == "manifest":
            manifest["manifest_attrs"] = elem["attrs"]
            break
    return manifest


KEYWORDS = [
    "login", "auth", "token", "access_token", "refresh_token", "session", "cookie",
    "email", "google", "account", "uuid", "user_id", "device_id", "password",
    "proxy", "server", "api", "jwt", "bearer", "firebase", "license", "telegram",
    "discord", "hack", "cheat", "mod", "admin", "panel", "request", "response",
]

URL_RE = re.compile(rb"(?i)\b(?:https?://|wss?://)[^\s\"'<>\\\)\]]+")
DOMAIN_RE = re.compile(rb"(?i)\b(?:[a-z0-9-]+\.)+(?:com|net|org|io|gg|ru|br|dev|app|cloud|xyz|me|co|us|info|biz|top|site|online|store|live|games|game)\b")
IP_RE = re.compile(rb"\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b")
TG_RE = re.compile(rb"\b\d{6,12}:[A-Za-z0-9_-]{30,}\b")
DISCORD_RE = re.compile(rb"https?://(?:canary\.|ptb\.)?discord(?:app)?\.com/api/webhooks/[^\s\"'<>\\\)\]]+", re.I)


def ascii_strings(data, min_len=4):
    out = []
    cur = bytearray()
    for b in data:
        if 32 <= b <= 126:
            cur.append(b)
        else:
            if len(cur) >= min_len:
                out.append(cur.decode("latin1", "replace"))
            cur = bytearray()
    if len(cur) >= min_len:
        out.append(cur.decode("latin1", "replace"))
    return out


def scan_file(path, max_keyword_hits=200):
    data = Path(path).read_bytes()
    found = {
        "urls": sorted(set(x.decode("latin1", "replace") for x in URL_RE.findall(data))),
        "domains": sorted(set(x.decode("latin1", "replace") for x in DOMAIN_RE.findall(data))),
        "ips": sorted(set(x.decode("latin1", "replace") for x in IP_RE.findall(data))),
        "telegram_tokens": sorted(set(x.decode("latin1", "replace") for x in TG_RE.findall(data))),
        "discord_webhooks": sorted(set(x.decode("latin1", "replace") for x in DISCORD_RE.findall(data))),
        "keyword_hits": [],
    }
    low_keywords = [k.lower() for k in KEYWORDS]
    for s in ascii_strings(data):
        sl = s.lower()
        if any(k in sl for k in low_keywords):
            found["keyword_hits"].append(s)
            if len(found["keyword_hits"]) >= max_keyword_hits:
                break
    return found


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["manifest", "dex", "scan"])
    ap.add_argument("paths", nargs="+")
    ap.add_argument("--out")
    args = ap.parse_args()
    if args.mode == "manifest":
        result = parse_axml(args.paths[0])
    elif args.mode == "dex":
        result = [parse_dex(p) for p in args.paths]
    else:
        result = {p: scan_file(p) for p in args.paths}
    text = json.dumps(result, ensure_ascii=False, indent=2)
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
    else:
        print(text)


if __name__ == "__main__":
    main()
