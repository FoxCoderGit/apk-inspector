(() => {
    "use strict";

    const MAX_FILE_READ = 30 * 1024 * 1024;
    const MAX_TOTAL_READ = 220 * 1024 * 1024;
    const MAX_SCAN_OUTPUT = 2 * 1024 * 1024;
    const MAX_REPORT_ITEMS = 18;
    const ZIP_EOCD_SIGNATURE = 0x06054b50;
    const ZIP_CENTRAL_SIGNATURE = 0x02014b50;
    const ZIP_LOCAL_SIGNATURE = 0x04034b50;

    const keywordRules = {
        password: "medium",
        passwd: "high",
        token: "info",
        access_token: "high",
        refresh_token: "high",
        auth: "info",
        login: "info",
        uuid: "info",
        email: "info",
        proxy: "info",
        websocket: "info",
        key: "info",
        secret: "medium",
        api_key: "high",
        firebase: "info",
        analytics: "info",
        adjust: "info",
        appsflyer: "info",
        amplitude: "info",
        onesignal: "info",
        facebook: "info",
        google: "info",
        billing: "info",
        purchase: "info",
        root: "info",
        su: "info",
        frida: "high",
        xposed: "high",
        sslpinning: "medium",
        certificate: "info"
    };

    const suspiciousWords = Object.keys(keywordRules);

    const dangerousPermissions = new Set([
        "android.permission.READ_SMS",
        "android.permission.SEND_SMS",
        "android.permission.RECEIVE_SMS",
        "android.permission.READ_CALL_LOG",
        "android.permission.WRITE_CALL_LOG",
        "android.permission.PROCESS_OUTGOING_CALLS",
        "android.permission.SYSTEM_ALERT_WINDOW",
        "android.permission.REQUEST_INSTALL_PACKAGES",
        "android.permission.WRITE_SETTINGS",
        "android.permission.MANAGE_EXTERNAL_STORAGE",
        "android.permission.BIND_ACCESSIBILITY_SERVICE"
    ]);

    const sensitivePermissions = new Set([
        "android.permission.READ_CONTACTS",
        "android.permission.WRITE_CONTACTS",
        "android.permission.RECORD_AUDIO",
        "android.permission.CAMERA",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.ACCESS_COARSE_LOCATION",
        "android.permission.READ_PHONE_STATE"
    ]);

    const mediaExtensions = new Set([
        ".png", ".jpg", ".jpeg", ".webp", ".gif", ".bmp", ".mp4", ".m4v", ".mov", ".avi", ".mkv",
        ".mp3", ".ogg", ".wav", ".flac", ".aac", ".ttf", ".otf", ".woff", ".woff2"
    ]);

    const dom = {
        input: document.getElementById("apk-file"),
        dropzone: document.getElementById("dropzone"),
        fileSummary: document.getElementById("file-summary"),
        progressBar: document.getElementById("progress-bar"),
        progressText: document.getElementById("progress-text"),
        emptyState: document.getElementById("empty-state"),
        resultRoot: document.getElementById("result-root"),
        copy: document.getElementById("copy-report"),
        download: document.getElementById("download-report"),
        clear: document.getElementById("clear-report")
    };

    let lastReport = "";

    const formatBytes = (bytes) => {
        if (!Number.isFinite(bytes) || bytes < 0) {
            return "0 Б";
        }

        const units = ["Б", "КБ", "МБ", "ГБ"];
        let value = bytes;
        let unit = 0;
        while (value >= 1024 && unit < units.length - 1) {
            value /= 1024;
            unit += 1;
        }
        return `${value >= 10 || unit === 0 ? value.toFixed(0) : value.toFixed(1)} ${units[unit]}`;
    };

    const escapeHtml = (value) => String(value)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;");

    const setProgress = (percent, text, isError = false) => {
        dom.progressBar.style.width = `${Math.max(0, Math.min(100, percent))}%`;
        dom.progressText.textContent = text;
        dom.progressText.classList.toggle("error", isError);
    };

    const uniquePush = (list, value, limit = MAX_REPORT_ITEMS) => {
        if (!value || list.includes(value) || list.length >= limit) {
            return;
        }
        list.push(value);
    };

    const normalizeName = (name) => String(name || "").replace(/\\/g, "/");
    const lowerName = (entry) => normalizeName(entry.name).toLowerCase();

    const getExtension = (name) => {
        const clean = lowerName({ name }).split("?")[0];
        const dot = clean.lastIndexOf(".");
        return dot >= 0 ? clean.slice(dot) : "";
    };

    const readSlice = (file, start, end) => file.slice(start, end).arrayBuffer();

    const decodeFileName = (bytes) => {
        try {
            return new TextDecoder("utf-8").decode(bytes);
        } catch {
            return Array.from(bytes, (byte) => String.fromCharCode(byte)).join("");
        }
    };

    const findEndOfCentralDirectory = async (file) => {
        const tailSize = Math.min(file.size, 66000);
        const tailOffset = file.size - tailSize;
        const buffer = await readSlice(file, tailOffset, file.size);
        const view = new DataView(buffer);

        for (let offset = tailSize - 22; offset >= 0; offset -= 1) {
            if (view.getUint32(offset, true) === ZIP_EOCD_SIGNATURE) {
                return {
                    centralDirectorySize: view.getUint32(offset + 12, true),
                    centralDirectoryOffset: view.getUint32(offset + 16, true),
                    totalEntries: view.getUint16(offset + 10, true),
                    commentLength: view.getUint16(offset + 20, true)
                };
            }
        }

        throw new Error("Не найдено ZIP-оглавление. Проверьте, что файл является APK/XAPK/APKM/ZIP.");
    };

    const parseZipEntries = async (file) => {
        const eocd = await findEndOfCentralDirectory(file);
        if (eocd.centralDirectoryOffset === 0xffffffff || eocd.centralDirectorySize === 0xffffffff) {
            throw new Error("ZIP64 пока не поддерживается в лёгком MVP.");
        }

        const end = eocd.centralDirectoryOffset + eocd.centralDirectorySize;
        if (end > file.size) {
            throw new Error("ZIP-оглавление повреждено или выходит за пределы файла.");
        }

        const buffer = await readSlice(file, eocd.centralDirectoryOffset, end);
        const view = new DataView(buffer);
        const entries = [];
        let offset = 0;

        while (offset + 46 <= buffer.byteLength) {
            if (view.getUint32(offset, true) !== ZIP_CENTRAL_SIGNATURE) {
                break;
            }

            const flags = view.getUint16(offset + 8, true);
            const method = view.getUint16(offset + 10, true);
            const compressedSize = view.getUint32(offset + 20, true);
            const uncompressedSize = view.getUint32(offset + 24, true);
            const nameLength = view.getUint16(offset + 28, true);
            const extraLength = view.getUint16(offset + 30, true);
            const commentLength = view.getUint16(offset + 32, true);
            const localHeaderOffset = view.getUint32(offset + 42, true);
            const nameStart = offset + 46;
            const nameEnd = nameStart + nameLength;

            if (nameEnd > buffer.byteLength) {
                break;
            }

            const name = normalizeName(decodeFileName(new Uint8Array(buffer, nameStart, nameLength)));
            entries.push({
                name,
                flags,
                method,
                compressedSize,
                uncompressedSize,
                localHeaderOffset,
                isDirectory: name.endsWith("/")
            });

            offset = nameEnd + extraLength + commentLength;
        }

        return entries;
    };

    const inflateRaw = async (blob) => {
        if (typeof DecompressionStream !== "function") {
            throw new Error("Браузер не поддерживает DecompressionStream для чтения сжатых ZIP-файлов.");
        }

        const stream = blob.stream().pipeThrough(new DecompressionStream("deflate-raw"));
        return new Response(stream).arrayBuffer();
    };

    const readEntryData = async (file, entry, state) => {
        if (entry.isDirectory) {
            return null;
        }
        if (entry.uncompressedSize > MAX_FILE_READ) {
            state.skipped.push(`${entry.name} — ${formatBytes(entry.uncompressedSize)}, больше лимита на файл`);
            return null;
        }
        if (state.bytesRead + entry.uncompressedSize > MAX_TOTAL_READ) {
            state.skipped.push(`${entry.name} — пропущен из-за суммарного лимита чтения`);
            return null;
        }

        const headerBuffer = await readSlice(file, entry.localHeaderOffset, entry.localHeaderOffset + 30);
        const header = new DataView(headerBuffer);
        if (header.getUint32(0, true) !== ZIP_LOCAL_SIGNATURE) {
            state.skipped.push(`${entry.name} — не удалось прочитать local header`);
            return null;
        }

        const nameLength = header.getUint16(26, true);
        const extraLength = header.getUint16(28, true);
        const dataStart = entry.localHeaderOffset + 30 + nameLength + extraLength;
        const dataEnd = dataStart + entry.compressedSize;
        if (dataEnd > file.size) {
            state.skipped.push(`${entry.name} — данные выходят за пределы архива`);
            return null;
        }

        let buffer;
        if (entry.method === 0) {
            buffer = await readSlice(file, dataStart, dataEnd);
        } else if (entry.method === 8) {
            buffer = await inflateRaw(file.slice(dataStart, dataEnd));
        } else {
            state.skipped.push(`${entry.name} — метод сжатия ${entry.method} не поддерживается`);
            return null;
        }

        state.bytesRead += buffer.byteLength;
        return buffer;
    };

    const extractAsciiStrings = (buffer) => {
        const bytes = new Uint8Array(buffer);
        const chunks = [];
        let current = "";
        let total = 0;

        for (const byte of bytes) {
            if (byte >= 32 && byte <= 126) {
                current += String.fromCharCode(byte);
                if (current.length > 4096) {
                    chunks.push(current);
                    total += current.length;
                    current = "";
                }
            } else {
                if (current.length >= 4) {
                    chunks.push(current);
                    total += current.length;
                    if (total > MAX_SCAN_OUTPUT) {
                        break;
                    }
                }
                current = "";
            }
        }

        if (current.length >= 4 && total <= MAX_SCAN_OUTPUT) {
            chunks.push(current);
        }

        return chunks.join("\n").slice(0, MAX_SCAN_OUTPUT);
    };

    const decodeTextLike = (buffer) => {
        try {
            return new TextDecoder("utf-8", { fatal: false }).decode(buffer).slice(0, MAX_SCAN_OUTPUT);
        } catch {
            return extractAsciiStrings(buffer);
        }
    };

    const countMatches = (text, regex) => {
        const matches = text.match(regex);
        return matches ? matches.length : 0;
    };

    const scanText = (entryName, text, result) => {
        const urlRegex = /\b(?:https?:\/\/|wss?:\/\/)[^\s"'<>\\\])}]+/gi;
        const domainRegex = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|ru|io|app|dev|me|co|ai|gg|top|xyz|info|biz|ua|by|kz|in|cn|jp|de|uk|us)\b/gi;
        const ipRegex = /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g;
        const emailRegex = /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi;

        for (const match of text.match(urlRegex) || []) {
            uniquePush(result.urls, `${match} (${entryName})`, 30);
        }
        for (const match of text.match(domainRegex) || []) {
            uniquePush(result.domains, `${match.toLowerCase()} (${entryName})`, 40);
        }
        for (const match of text.match(ipRegex) || []) {
            uniquePush(result.ips, `${match} (${entryName})`, 20);
        }
        for (const match of text.match(emailRegex) || []) {
            uniquePush(result.emails, `${match} (${entryName})`, 20);
        }

        const lower = text.toLowerCase();
        for (const word of suspiciousWords) {
            const safe = word.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
            const count = countMatches(lower, new RegExp(`\\b${safe}\\b`, "g"));
            if (!count) {
                continue;
            }
            if (!result.keywords[word]) {
                result.keywords[word] = { count: 0, files: [] };
            }
            result.keywords[word].count += count;
            uniquePush(result.keywords[word].files, entryName, 8);
        }
    };

    const parseStringPool = (buffer, offset) => {
        const view = new DataView(buffer);
        const headerSize = view.getUint16(offset + 2, true);
        const size = view.getUint32(offset + 4, true);
        const stringCount = view.getUint32(offset + 8, true);
        const flags = view.getUint32(offset + 16, true);
        const stringsStart = view.getUint32(offset + 20, true);
        const isUtf8 = (flags & 0x100) !== 0;
        const offsetsStart = offset + headerSize;
        const strings = [];

        const readUtf8Length = (bytes, pos) => {
            const first = bytes[pos];
            if ((first & 0x80) !== 0) {
                return { value: ((first & 0x7f) << 8) | bytes[pos + 1], bytes: 2 };
            }
            return { value: first, bytes: 1 };
        };

        const readUtf16Length = (viewRef, pos) => {
            const first = viewRef.getUint16(pos, true);
            if ((first & 0x8000) !== 0) {
                return { value: ((first & 0x7fff) << 16) | viewRef.getUint16(pos + 2, true), bytes: 4 };
            }
            return { value: first, bytes: 2 };
        };

        for (let i = 0; i < stringCount; i += 1) {
            const stringOffset = view.getUint32(offsetsStart + i * 4, true);
            let pos = offset + stringsStart + stringOffset;

            if (pos < offset || pos >= offset + size) {
                strings.push("");
                continue;
            }

            if (isUtf8) {
                const bytes = new Uint8Array(buffer);
                const utf16Length = readUtf8Length(bytes, pos);
                pos += utf16Length.bytes;
                const byteLength = readUtf8Length(bytes, pos);
                pos += byteLength.bytes;
                strings.push(new TextDecoder("utf-8").decode(bytes.slice(pos, pos + byteLength.value)));
            } else {
                const length = readUtf16Length(view, pos);
                pos += length.bytes;
                const end = Math.min(pos + length.value * 2, offset + size);
                strings.push(new TextDecoder("utf-16le").decode(new Uint8Array(buffer, pos, Math.max(0, end - pos))));
            }
        }

        return { strings, size };
    };

    const formatTypedValue = (type, data, strings) => {
        if (type === 0x03) {
            return strings[data] || "";
        }
        if (type >= 0x1c && type <= 0x1f) {
            return `#${(data >>> 0).toString(16).padStart(8, "0")}`;
        }
        if (type === 0x10 || type === 0x11) {
            return String(data);
        }
        if (type === 0x12) {
            return data !== 0 ? "true" : "false";
        }
        if (type === 0x01) {
            return `@0x${data.toString(16)}`;
        }
        if (type === 0x04) {
            return String(new DataView(new Uint32Array([data]).buffer).getFloat32(0, true));
        }
        return data ? `0x${data.toString(16)}` : "";
    };

    const completeManifestFromStrings = (manifest, strings) => {
        if (!Array.isArray(strings) || !strings.length) {
            return manifest;
        }

        const packageCandidate = strings.find((value) => (
            /^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+){1,}$/.test(value)
            && !value.startsWith("android.")
            && !value.startsWith("java.")
            && !value.startsWith("kotlin.")
            && !value.startsWith("http.")
            && !value.startsWith("https.")
        ));

        if (!manifest.packageName && packageCandidate) {
            manifest.packageName = packageCandidate;
        }

        for (const value of strings) {
            if (/^[A-Z0-9_.]+\.permission\.[A-Z0-9_.]+$/i.test(value) || /^android\.permission\.[A-Z0-9_.]+$/i.test(value)) {
                uniquePush(manifest.permissions, value, 200);
            }
        }

        return manifest;
    };

    const parseAndroidManifest = (buffer) => {
        const view = new DataView(buffer);
        if (view.getUint16(0, true) !== 0x0003) {
            const plain = decodeTextLike(buffer);
            if (plain.includes("<manifest")) {
                return parsePlainManifest(plain);
            }
            return { decoded: false, message: "AndroidManifest.xml найден, но в MVP пока не декодирован полностью." };
        }

        let offset = view.getUint16(2, true);
        let strings = [];
        const manifest = {
            decoded: true,
            packageName: "",
            versionName: "",
            versionCode: "",
            minSdk: "",
            targetSdk: "",
            permissions: [],
            components: []
        };
        const stack = [];
        let currentComponent = null;

        while (offset + 8 <= buffer.byteLength) {
            const type = view.getUint16(offset, true);
            const headerSize = view.getUint16(offset + 2, true);
            const size = view.getUint32(offset + 4, true);
            if (size <= 0 || offset + size > buffer.byteLength) {
                break;
            }

            if (type === 0x0001) {
                strings = parseStringPool(buffer, offset).strings;
            } else if (type === 0x0102) {
                const nameIndex = view.getUint32(offset + 20, true);
                const tagName = strings[nameIndex] || "";
                const attributeStart = view.getUint16(offset + 24, true);
                const attributeSize = view.getUint16(offset + 26, true);
                const attributeCount = view.getUint16(offset + 28, true);
                let attributesOffset = offset + 16 + attributeStart;
                if (attributesOffset + attributeCount * attributeSize > offset + size && offset + attributeStart + attributeCount * attributeSize <= offset + size) {
                    attributesOffset = offset + attributeStart;
                }
                const attrs = {};

                for (let i = 0; i < attributeCount; i += 1) {
                    const attrOffset = attributesOffset + i * attributeSize;
                    const attrNameIndex = view.getUint32(attrOffset + 4, true);
                    const rawValue = view.getUint32(attrOffset + 8, true);
                    const valueType = view.getUint8(attrOffset + 15);
                    const valueData = view.getUint32(attrOffset + 16, true);
                    const attrName = strings[attrNameIndex] || `attr_${attrNameIndex}`;
                    const value = rawValue !== 0xffffffff
                        ? (strings[rawValue] || "")
                        : formatTypedValue(valueType, valueData, strings);
                    attrs[attrName] = value;
                }

                stack.push(tagName);
                if (tagName === "manifest") {
                    manifest.packageName = attrs.package || manifest.packageName;
                    manifest.versionName = attrs.versionName || manifest.versionName;
                    manifest.versionCode = attrs.versionCode || manifest.versionCode;
                } else if (tagName === "uses-sdk") {
                    manifest.minSdk = attrs.minSdkVersion || manifest.minSdk;
                    manifest.targetSdk = attrs.targetSdkVersion || manifest.targetSdk;
                } else if (tagName === "uses-permission" || tagName === "uses-permission-sdk-23") {
                    uniquePush(manifest.permissions, attrs.name || attrs.permission || "", 200);
                } else if (["activity", "activity-alias", "service", "receiver", "provider"].includes(tagName)) {
                    currentComponent = {
                        type: tagName,
                        name: attrs.name || "",
                        exported: attrs.exported || "",
                        permission: attrs.permission || "",
                        intentFilters: 0
                    };
                    manifest.components.push(currentComponent);
                } else if (tagName === "intent-filter" && currentComponent) {
                    currentComponent.intentFilters += 1;
                }
            } else if (type === 0x0103) {
                const nameIndex = view.getUint32(offset + 20, true);
                const tagName = strings[nameIndex] || stack[stack.length - 1] || "";
                if (currentComponent && ["activity", "activity-alias", "service", "receiver", "provider"].includes(tagName)) {
                    currentComponent = null;
                }
                stack.pop();
            }

            offset += size || headerSize;
        }

        return completeManifestFromStrings(manifest, strings);
    };

    const parsePlainManifest = (text) => {
        const pick = (regex) => (text.match(regex) || [])[1] || "";
        const permissions = Array.from(text.matchAll(/<uses-permission[^>]+(?:android:)?name=["']([^"']+)["']/g), (match) => match[1]);
        return {
            decoded: true,
            packageName: pick(/<manifest[^>]+package=["']([^"']+)["']/),
            versionName: pick(/(?:android:)?versionName=["']([^"']+)["']/),
            versionCode: pick(/(?:android:)?versionCode=["']([^"']+)["']/),
            minSdk: pick(/(?:android:)?minSdkVersion=["']([^"']+)["']/),
            targetSdk: pick(/(?:android:)?targetSdkVersion=["']([^"']+)["']/),
            permissions: [...new Set(permissions)],
            components: []
        };
    };

    const detectStructure = (entries) => {
        const structure = {
            totalFiles: entries.filter((entry) => !entry.isDirectory).length,
            totalDirectories: entries.filter((entry) => entry.isDirectory).length,
            apks: [],
            obb: [],
            classesDex: [],
            libs: [],
            assets: 0,
            res: 0,
            metaInf: 0,
            largest: [],
            suspiciousExtensions: [],
            technologies: []
        };

        const tech = new Set();
        const sorted = entries.filter((entry) => !entry.isDirectory)
            .slice()
            .sort((a, b) => b.uncompressedSize - a.uncompressedSize)
            .slice(0, 12);

        structure.largest = sorted.map((entry) => `${entry.name} — ${formatBytes(entry.uncompressedSize)}`);

        for (const entry of entries) {
            const name = normalizeName(entry.name);
            const lower = name.toLowerCase();
            const ext = getExtension(name);

            if (entry.isDirectory) {
                continue;
            }
            if (lower.endsWith(".apk")) {
                structure.apks.push(`${name} — ${formatBytes(entry.uncompressedSize)}`);
            }
            if (lower.endsWith(".obb")) {
                structure.obb.push(`${name} — ${formatBytes(entry.uncompressedSize)}`);
            }
            if (/^classes\d*\.dex$/i.test(name)) {
                structure.classesDex.push(`${name} — ${formatBytes(entry.uncompressedSize)}`);
            }
            if (/^lib\/[^/]+\/[^/]+\.so$/i.test(name)) {
                structure.libs.push(`${name} — ${formatBytes(entry.uncompressedSize)}`);
            }
            if (lower.startsWith("assets/")) {
                structure.assets += 1;
            }
            if (lower.startsWith("res/")) {
                structure.res += 1;
            }
            if (lower.startsWith("meta-inf/")) {
                structure.metaInf += 1;
            }

            if ([".exe", ".bat", ".cmd", ".ps1", ".sh", ".jar"].includes(ext)) {
                structure.suspiciousExtensions.push(`${name} — ${formatBytes(entry.uncompressedSize)}`);
            }
            if (ext === ".dex" && !/^classes\d*\.dex$/i.test(name)) {
                structure.suspiciousExtensions.push(`${name} — .dex вне обычного корня APK`);
            }

            if (lower.includes("libil2cpp.so") || lower.includes("global-metadata.dat")) {
                tech.add("Unity IL2CPP");
            }
            if (lower.includes("assembly-csharp.dll")) {
                tech.add("Unity Mono");
            }
            if (lower.includes("libue4.so") || lower.includes("libunreal.so")) {
                tech.add("Unreal Engine");
            }
            if (lower.includes("libflutter.so") || lower.startsWith("assets/flutter_assets/")) {
                tech.add("Flutter");
            }
            if (lower.endsWith("index.android.bundle")) {
                tech.add("React Native");
            }
            if (lower.endsWith("www/cordova.js") || lower === "assets/www/cordova.js") {
                tech.add("Cordova/WebView");
            }
        }

        structure.technologies = Array.from(tech);
        return structure;
    };

    const shouldScanEntry = (entry, structure, state) => {
        const lower = lowerName(entry);
        const ext = getExtension(entry.name);

        if (entry.isDirectory) {
            return false;
        }
        if (lower.endsWith(".obb") || mediaExtensions.has(ext)) {
            state.skipped.push(`${entry.name} — крупный/медиа тип не читается в MVP`);
            return false;
        }
        if (entry.uncompressedSize > MAX_FILE_READ) {
            state.skipped.push(`${entry.name} — ${formatBytes(entry.uncompressedSize)}, больше лимита на файл`);
            return false;
        }
        if (/^classes\d*\.dex$/i.test(entry.name) || /^lib\/[^/]+\/[^/]+\.so$/i.test(entry.name)) {
            return true;
        }
        if (lower === "androidmanifest.xml") {
            return true;
        }
        if (lower.startsWith("assets/") && /\.(txt|json|xml|html|js|bundle|properties|conf|config|ini|yml|yaml|env)$/i.test(lower)) {
            return true;
        }
        if (lower.startsWith("res/") && /\.(xml|json|txt)$/i.test(lower)) {
            return true;
        }
        if ([".dex", ".so", ".jar", ".xml", ".json", ".txt", ".js", ".bundle", ".properties"].includes(ext)) {
            return true;
        }

        return false;
    };

    const analyzeEntries = async (file, entries) => {
        const state = { bytesRead: 0, skipped: [] };
        const structure = detectStructure(entries);
        const result = {
            file,
            entries,
            structure,
            manifest: null,
            urls: [],
            domains: [],
            ips: [],
            emails: [],
            keywords: {},
            skipped: state.skipped,
            bytesRead: 0,
            errors: []
        };

        const candidates = entries.filter((entry) => shouldScanEntry(entry, structure, state));
        let processed = 0;

        for (const entry of candidates) {
            processed += 1;
            setProgress(28 + (processed / Math.max(1, candidates.length)) * 54, `Чтение ${processed}/${candidates.length}: ${entry.name}`);

            try {
                const buffer = await readEntryData(file, entry, state);
                if (!buffer) {
                    continue;
                }

                if (lowerName(entry) === "androidmanifest.xml") {
                    try {
                        result.manifest = parseAndroidManifest(buffer);
                    } catch (error) {
                        result.manifest = {
                            decoded: false,
                            message: "AndroidManifest.xml найден, но в MVP пока не декодирован полностью.",
                            error: error.message
                        };
                    }
                }

                const text = /\.(dex|so|jar)$/i.test(entry.name) ? extractAsciiStrings(buffer) : decodeTextLike(buffer);
                if (text) {
                    scanText(entry.name, text, result);
                }
            } catch (error) {
                result.errors.push(`${entry.name}: ${error.message}`);
            }
        }

        if (!result.manifest && entries.some((entry) => lowerName(entry) === "androidmanifest.xml")) {
            result.manifest = { decoded: false, message: "AndroidManifest.xml найден, но не был прочитан из-за лимитов или ошибки распаковки." };
        }

        result.bytesRead = state.bytesRead;
        return result;
    };

    const scoreRisk = (result) => {
        let score = 0;
        const reasons = [];
        const manifest = result.manifest;

        if (result.structure.suspiciousExtensions.length) {
            const points = Math.min(28, result.structure.suspiciousExtensions.length * 10);
            score += points;
            reasons.push(`подозрительные расширения: ${result.structure.suspiciousExtensions.length}`);
        }

        const keywordSignals = Object.entries(result.keywords).reduce((summary, [word, item]) => {
            const severity = keywordRules[word] || "info";
            if (severity === "high") {
                summary.high += 1;
                summary.points += Math.min(10, 6 + item.files.length);
            } else if (severity === "medium") {
                summary.medium += 1;
                summary.points += Math.min(4, Math.ceil(item.files.length / 3));
            } else {
                summary.info += 1;
            }
            return summary;
        }, { high: 0, medium: 0, info: 0, points: 0 });

        if (keywordSignals.points) {
            const points = Math.min(24, keywordSignals.points);
            score += points;
            reasons.push(`сильные маркеры в строках: ${keywordSignals.high}, средние: ${keywordSignals.medium}`);
        }

        if (result.ips.length || result.emails.length) {
            const points = Math.min(8, result.ips.length * 2 + result.emails.length);
            score += points;
            reasons.push(`IP/email в строках: ${result.ips.length + result.emails.length}`);
        }

        if (manifest?.decoded) {
            const dangerous = manifest.permissions.filter((permission) => dangerousPermissions.has(permission));
            if (dangerous.length) {
                const points = Math.min(32, dangerous.length * 8);
                score += points;
                reasons.push(`опасные разрешения Android: ${dangerous.length}`);
            }

            const sensitive = manifest.permissions.filter((permission) => sensitivePermissions.has(permission));
            if (sensitive.length) {
                const points = Math.min(12, sensitive.length * 3);
                score += points;
                reasons.push(`чувствительные разрешения Android: ${sensitive.length}`);
            }

            const exported = manifest.components.filter((component) => component.exported === "true");
            const implicit = manifest.components.filter((component) => !component.exported && component.intentFilters > 0);
            if (exported.length || implicit.length) {
                const exportedPoints = exported.reduce((sum, component) => {
                    if (component.type === "activity" && component.intentFilters > 0) {
                        return sum + 1;
                    }
                    return sum + 4;
                }, 0);
                const points = Math.min(14, exportedPoints + implicit.length);
                score += points;
                reasons.push(`exported/intent-filter компоненты: ${exported.length + implicit.length}`);
            }
        }

        if (result.errors.length) {
            score += Math.min(6, result.errors.length * 2);
            reasons.push(`ошибки чтения части файлов: ${result.errors.length}`);
        }

        const level = score >= 70 ? "high" : score >= 28 ? "medium" : "low";
        const label = level === "high" ? "Высокий" : level === "medium" ? "Средний" : "Низкий";
        return { score, level, label, reasons };
    };

    const renderList = (items, emptyText, className = "") => {
        if (!items || !items.length) {
            return `<p>${escapeHtml(emptyText)}</p>`;
        }
        return `<div class="list ${className}">${items.slice(0, MAX_REPORT_ITEMS).map((item) => `
            <div class="list-item"><strong class="mono">${escapeHtml(item)}</strong></div>
        `).join("")}</div>`;
    };

    const renderPills = (items, emptyText, type = "") => {
        if (!items || !items.length) {
            return `<p>${escapeHtml(emptyText)}</p>`;
        }
        const pillClass = type ? ` pill-${type}` : "";
        return `<div class="pill-row">${items.slice(0, 60).map((item) => `<span class="pill${pillClass}">${escapeHtml(item)}</span>`).join("")}</div>`;
    };

    const renderResults = (result) => {
        const risk = scoreRisk(result);
        const manifest = result.manifest;
        const dangerous = manifest?.decoded ? manifest.permissions.filter((permission) => dangerousPermissions.has(permission)) : [];
        const sensitive = manifest?.decoded ? manifest.permissions.filter((permission) => sensitivePermissions.has(permission)) : [];
        const exported = manifest?.decoded ? manifest.components
            .filter((component) => component.exported === "true" || (!component.exported && component.intentFilters > 0))
            .map((component) => `${component.type}: ${component.name || "без имени"}${component.exported ? `, exported=${component.exported}` : ", exported не указан"}${component.intentFilters ? `, intent-filter=${component.intentFilters}` : ""}`)
            : [];

        const severityRank = { high: 0, medium: 1, info: 2 };
        const severityLabels = { high: "сильный", medium: "средний", info: "инфо" };
        const keywordItems = Object.entries(result.keywords)
            .sort((a, b) => {
                const rankDiff = (severityRank[keywordRules[a[0]] || "info"] ?? 9) - (severityRank[keywordRules[b[0]] || "info"] ?? 9);
                return rankDiff || b[1].count - a[1].count;
            })
            .map(([word, item]) => `${severityLabels[keywordRules[word] || "info"]}: ${word}: ${item.count}; файлы: ${item.files.join(", ")}`);

        dom.resultRoot.innerHTML = `
            <article class="risk-card risk-${risk.level}">
                <div class="risk-mark">${escapeHtml(risk.label)}</div>
                <div>
                    <h3>Оценка риска: ${escapeHtml(risk.label.toLowerCase())}</h3>
                    <p>Счёт ${risk.score}. ${risk.reasons.length ? escapeHtml(risk.reasons.join("; ")) : "Критичных признаков в прочитанных данных не найдено."}</p>
                </div>
            </article>

            <article class="result-card">
                <h3>Файл</h3>
                <div class="metric-grid">
                    <div class="metric"><span>Имя</span><strong>${escapeHtml(result.file.name)}</strong></div>
                    <div class="metric"><span>Размер</span><strong>${formatBytes(result.file.size)}</strong></div>
                    <div class="metric"><span>Тип браузера</span><strong>${escapeHtml(result.file.type || "не указан")}</strong></div>
                    <div class="metric"><span>Прочитано для анализа</span><strong>${formatBytes(result.bytesRead)}</strong></div>
                </div>
            </article>

            <article class="result-card">
                <h3>Структура</h3>
                <div class="metric-grid">
                    <div class="metric"><span>Файлов</span><strong>${result.structure.totalFiles}</strong></div>
                    <div class="metric"><span>APK внутри</span><strong>${result.structure.apks.length}</strong></div>
                    <div class="metric"><span>classes.dex</span><strong>${result.structure.classesDex.length}</strong></div>
                    <div class="metric"><span>lib/*.so</span><strong>${result.structure.libs.length}</strong></div>
                    <div class="metric"><span>assets</span><strong>${result.structure.assets}</strong></div>
                    <div class="metric"><span>res</span><strong>${result.structure.res}</strong></div>
                    <div class="metric"><span>META-INF</span><strong>${result.structure.metaInf}</strong></div>
                    <div class="metric"><span>OBB</span><strong>${result.structure.obb.length}</strong></div>
                </div>
            </article>

            <article class="result-card">
                <h3>Manifest и разрешения</h3>
                ${manifest?.decoded ? `
                    <div class="metric-grid">
                        <div class="metric"><span>Package</span><strong>${escapeHtml(manifest.packageName || "не найден")}</strong></div>
                        <div class="metric"><span>Version</span><strong>${escapeHtml([manifest.versionName, manifest.versionCode].filter(Boolean).join(" / ") || "не найдена")}</strong></div>
                        <div class="metric"><span>minSdk</span><strong>${escapeHtml(manifest.minSdk || "не найден")}</strong></div>
                        <div class="metric"><span>targetSdk</span><strong>${escapeHtml(manifest.targetSdk || "не найден")}</strong></div>
                    </div>
                    <h3>Permissions</h3>
                    ${renderPills(manifest.permissions, "Разрешения не найдены.", dangerous.length ? "danger" : (sensitive.length ? "warn" : ""))}
                    <h3>Exported components</h3>
                    ${renderList(exported, "Exported components или компоненты с intent-filter не найдены.")}
                ` : `<p>${escapeHtml(manifest?.message || "AndroidManifest.xml не найден.")}</p>`}
            </article>

            <article class="result-card">
                <h3>Домены и URL</h3>
                ${renderList([...result.urls, ...result.domains, ...result.ips, ...result.emails], "Домены, URL, IP и email в прочитанных файлах не найдены.")}
            </article>

            <article class="result-card">
                <h3>Ключевые слова и подозрительные признаки</h3>
                ${renderList([...result.structure.suspiciousExtensions, ...keywordItems], "Подозрительные расширения и ключевые слова в прочитанных файлах не найдены.")}
            </article>

            <article class="result-card">
                <h3>Движок и технологии</h3>
                ${renderPills(result.structure.technologies, "По структуре движок или фреймворк не определён.")}
            </article>

            <article class="result-card">
                <h3>Крупные файлы</h3>
                ${renderList(result.structure.largest, "Список файлов пуст.")}
            </article>

            <article class="result-card">
                <h3>Пропущенные большие файлы</h3>
                ${renderList([...result.structure.obb, ...result.skipped, ...result.errors], "Ничего не пропущено по лимитам.")}
            </article>
        `;

        lastReport = buildReport(result, risk, dangerous, sensitive, exported, keywordItems);
        dom.emptyState.hidden = true;
        dom.resultRoot.hidden = false;
        dom.copy.disabled = false;
        dom.download.disabled = false;
    };

    const buildReport = (result, risk, dangerous, sensitive, exported, keywordItems) => {
        const manifest = result.manifest;
        const lines = [
            "APK Risk Checker — Filero",
            "Это не антивирус, а статический анализ признаков риска.",
            "Файл не загружался на сервер.",
            "",
            `Оценка риска: ${risk.label} (${risk.score})`,
            `Причины: ${risk.reasons.join("; ") || "критичных признаков в прочитанных данных не найдено"}`,
            "",
            `Файл: ${result.file.name}`,
            `Размер: ${formatBytes(result.file.size)}`,
            `Тип: ${result.file.type || "не указан"}`,
            "",
            "Структура:",
            `- файлов: ${result.structure.totalFiles}`,
            `- APK внутри: ${result.structure.apks.length}`,
            `- OBB: ${result.structure.obb.length}`,
            `- classes.dex: ${result.structure.classesDex.length}`,
            `- lib/*.so: ${result.structure.libs.length}`,
            `- assets: ${result.structure.assets}`,
            `- res: ${result.structure.res}`,
            `- META-INF: ${result.structure.metaInf}`,
            "",
            "Manifest:"
        ];

        if (manifest?.decoded) {
            lines.push(`- package: ${manifest.packageName || "не найден"}`);
            lines.push(`- versionName/versionCode: ${[manifest.versionName, manifest.versionCode].filter(Boolean).join(" / ") || "не найдены"}`);
            lines.push(`- minSdk/targetSdk: ${[manifest.minSdk, manifest.targetSdk].filter(Boolean).join(" / ") || "не найдены"}`);
            lines.push(`- permissions: ${manifest.permissions.join(", ") || "не найдены"}`);
            lines.push(`- dangerous permissions: ${dangerous.join(", ") || "не найдены"}`);
            lines.push(`- sensitive permissions: ${sensitive.join(", ") || "не найдены"}`);
            lines.push(`- exported components: ${exported.join("; ") || "не найдены"}`);
        } else {
            lines.push(`- ${manifest?.message || "AndroidManifest.xml не найден"}`);
        }

        lines.push("");
        lines.push("Домены/URL/IP/email:");
        lines.push(...([...result.urls, ...result.domains, ...result.ips, ...result.emails].slice(0, 80).map((item) => `- ${item}`)));
        lines.push("");
        lines.push("Подозрительные признаки:");
        lines.push(...([...result.structure.suspiciousExtensions, ...keywordItems].slice(0, 80).map((item) => `- ${item}`)));
        lines.push("");
        lines.push(`Технологии: ${result.structure.technologies.join(", ") || "не определены"}`);
        lines.push("");
        lines.push("Крупные файлы:");
        lines.push(...result.structure.largest.map((item) => `- ${item}`));
        lines.push("");
        lines.push("Пропущено/ошибки:");
        lines.push(...([...result.structure.obb, ...result.skipped, ...result.errors].slice(0, 80).map((item) => `- ${item}`)));

        return lines.join("\n");
    };

    const handleFile = async (file) => {
        if (!file) {
            return;
        }

        lastReport = "";
        dom.copy.disabled = true;
        dom.download.disabled = true;
        dom.emptyState.hidden = false;
        dom.resultRoot.hidden = true;
        dom.resultRoot.innerHTML = "";
        dom.fileSummary.hidden = false;
        dom.fileSummary.innerHTML = `
            <strong>${escapeHtml(file.name)}</strong>
            <span>Размер: ${formatBytes(file.size)}</span>
            <span>Тип: ${escapeHtml(file.type || "не указан")}</span>
        `;

        try {
            setProgress(8, "Читаю ZIP-оглавление...");
            const entries = await parseZipEntries(file);
            setProgress(24, `Найдено файлов: ${entries.filter((entry) => !entry.isDirectory).length}`);
            const result = await analyzeEntries(file, entries);
            setProgress(100, "Готово. Отчёт сформирован.");
            renderResults(result);
        } catch (error) {
            setProgress(100, error.message || "Не удалось проверить файл.", true);
        } finally {
            dom.input.value = "";
        }
    };

    const clearAll = () => {
        lastReport = "";
        dom.input.value = "";
        dom.fileSummary.hidden = true;
        dom.fileSummary.innerHTML = "";
        dom.emptyState.hidden = false;
        dom.resultRoot.hidden = true;
        dom.resultRoot.innerHTML = "";
        dom.copy.disabled = true;
        dom.download.disabled = true;
        setProgress(0, "Ожидание файла");
    };

    dom.input.addEventListener("change", (event) => {
        handleFile(event.target.files?.[0]);
    });

    dom.dropzone.addEventListener("dragover", (event) => {
        event.preventDefault();
        dom.dropzone.classList.add("dragging");
    });

    dom.dropzone.addEventListener("dragleave", () => {
        dom.dropzone.classList.remove("dragging");
    });

    dom.dropzone.addEventListener("drop", (event) => {
        event.preventDefault();
        dom.dropzone.classList.remove("dragging");
        handleFile(event.dataTransfer?.files?.[0]);
    });

    dom.copy.addEventListener("click", async () => {
        if (!lastReport) {
            return;
        }
        await navigator.clipboard.writeText(lastReport);
        setProgress(100, "Отчёт скопирован.");
    });

    dom.download.addEventListener("click", () => {
        if (!lastReport) {
            return;
        }
        const blob = new Blob([lastReport], { type: "text/plain;charset=utf-8" });
        const link = document.createElement("a");
        link.href = URL.createObjectURL(blob);
        link.download = "apk-risk-report.txt";
        link.click();
        URL.revokeObjectURL(link.href);
        setProgress(100, "Отчёт подготовлен для скачивания.");
    });

    dom.clear.addEventListener("click", clearAll);
})();
