// Распаковка загруженного пользователем ZIP-архива ПРЯМО В ПАМЯТИ.
// На диск ничего не пишем, ничего не сохраняем — как и с архивами GitHub.
// После ответа от кода не остаётся ни одного файла.

import { unzipSync, type UnzipFileInfo } from "fflate";
import { ScanUserError } from "./github";
import type { ScannedFile } from "./engine";

// Лимиты — те же по духу, что у GitHub-режима.
export const MAX_ZIP_BYTES = 30 * 1024 * 1024; // 30 МБ сам архив
const MAX_UNPACKED_BYTES = 120 * 1024 * 1024; // защита от «зип-бомб»
const MAX_FILE_BYTES = 512 * 1024; // файлы больше 512 КБ пропускаем
const MAX_FILES = 4000;

// Быстрая проверка «файл текстовый?»: в первых байтах нет нулевого байта.
function isTextContent(buf: Uint8Array): boolean {
  const probe = buf.subarray(0, 1024);
  return !probe.includes(0);
}

// Мусорные пути, которых не должно быть в отчёте.
function isJunkPath(path: string): boolean {
  const parts = path.split("/");
  return (
    parts.includes("__MACOSX") ||
    parts.some((p) => p === ".DS_Store") ||
    path.startsWith("/") ||
    path.includes("..") // защита от path traversal (мы не пишем на диск, но на всякий)
  );
}

// Проверяем сигнатуру ZIP (PK\x03\x04 или пустой архив PK\x05\x06).
export function looksLikeZip(buf: Uint8Array): boolean {
  return buf.length >= 4 && buf[0] === 0x50 && buf[1] === 0x4b;
}

// Buffer/Uint8Array архива → список текстовых файлов (в памяти).
export function filesFromZip(buf: Uint8Array): ScannedFile[] {
  if (!looksLikeZip(buf)) throw new ScanUserError("bad_zip");

  // Считаем суммарный распакованный размер ДО распаковки (по заголовкам),
  // огромные файлы вообще не распаковываем — так «зип-бомба» не сработает.
  let keptTotal = 0;
  let bomb = false;
  let unzipped: Record<string, Uint8Array>;
  try {
    unzipped = unzipSync(buf, {
      filter: (f: UnzipFileInfo) => {
        if (f.name.endsWith("/")) return false; // папки пропускаем
        if (f.originalSize > MAX_FILE_BYTES) return false; // большие не распаковываем
        keptTotal += f.originalSize;
        if (keptTotal > MAX_UNPACKED_BYTES) {
          bomb = true;
          return false;
        }
        return true;
      },
    });
  } catch {
    throw new ScanUserError("bad_zip");
  }
  if (bomb) throw new ScanUserError("too_big");

  const entries = Object.entries(unzipped);
  if (entries.length === 0) throw new ScanUserError("empty_zip");

  // Экспорты из Lovable/Bolt часто лежат в одной корневой папке (my-app/...).
  // Если у ВСЕХ файлов один общий верхний сегмент — убираем его, чтобы пути были чистыми.
  const tops = new Set(entries.map(([p]) => p.split("/")[0]));
  const stripRoot =
    tops.size === 1 && entries.every(([p]) => p.includes("/"));

  const files: ScannedFile[] = [];
  for (const [rawPath, data] of entries) {
    if (files.length >= MAX_FILES) break;
    if (isJunkPath(rawPath)) continue;
    const path = stripRoot ? rawPath.split("/").slice(1).join("/") : rawPath;
    if (!path || path.endsWith("/")) continue;
    if (!isTextContent(data)) continue; // бинарные пропускаем
    files.push({ path, content: Buffer.from(data).toString("utf8") });
  }

  if (files.length === 0) throw new ScanUserError("no_text_files");
  return files;
}
