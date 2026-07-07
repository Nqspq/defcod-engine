// Скачивание публичного GitHub-репозитория для сканирования.
// Архив распаковывается ПРЯМО В ПАМЯТИ — на диск ничего не пишем,
// поэтому после ответа от кода не остаётся ни одного файла.

import { gunzipSync } from "zlib";
import type { ScannedFile } from "./engine";

// Лимиты: маленькие проекты — наша аудитория, большие вежливо отклоняем.
const MAX_ARCHIVE_BYTES = 30 * 1024 * 1024; // ~30 МБ сжатого архива
const MAX_UNPACKED_BYTES = 120 * 1024 * 1024; // защита от «архивных бомб»
const MAX_FILE_BYTES = 512 * 1024; // файлы больше 512 КБ пропускаем
const MAX_FILES = 4000;
const FETCH_TIMEOUT_MS = 25_000;

export type ScanErrorCode =
  | "bad_url"
  | "not_found"
  | "too_big"
  | "download_failed"
  | "empty_repo"
  // Коды режима загрузки ZIP:
  | "bad_zip"
  | "empty_zip"
  | "no_text_files";

export class ScanUserError extends Error {
  code: ScanErrorCode;
  constructor(code: ScanErrorCode) {
    super(code);
    this.code = code;
  }
}

// Принимаем ссылки вида https://github.com/owner/repo (с хвостами или без).
export function parseGitHubUrl(input: string): { owner: string; repo: string } {
  let url: URL;
  try {
    url = new URL(input.trim());
  } catch {
    throw new ScanUserError("bad_url");
  }
  if (!/^(www\.)?github\.com$/.test(url.hostname)) throw new ScanUserError("bad_url");
  const parts = url.pathname.split("/").filter(Boolean);
  if (parts.length < 2) throw new ScanUserError("bad_url");
  const owner = parts[0];
  const repo = parts[1].replace(/\.git$/, "");
  // Строгая проверка имён — они пойдут в URL запроса к GitHub.
  if (!/^[A-Za-z0-9_.-]+$/.test(owner) || !/^[A-Za-z0-9_.-]+$/.test(repo)) {
    throw new ScanUserError("bad_url");
  }
  return { owner, repo };
}

// Скачиваем tar.gz основной ветки, считая байты, чтобы не превысить лимит.
async function downloadArchive(owner: string, repo: string): Promise<Buffer> {
  const url = `https://codeload.github.com/${owner}/${repo}/tar.gz/HEAD`;
  let res: Response;
  try {
    res = await fetch(url, {
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
      headers: { "User-Agent": "defcod-scanner" },
    });
  } catch {
    throw new ScanUserError("download_failed");
  }
  if (res.status === 404) throw new ScanUserError("not_found");
  if (!res.ok || !res.body) throw new ScanUserError("download_failed");

  const chunks: Uint8Array[] = [];
  let total = 0;
  const reader = res.body.getReader();
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > MAX_ARCHIVE_BYTES) {
      await reader.cancel();
      throw new ScanUserError("too_big");
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks);
}

// Быстрая проверка «файл текстовый?»: в первых байтах нет нулевого байта.
function isTextContent(buf: Buffer): boolean {
  const probe = buf.subarray(0, 1024);
  return !probe.includes(0);
}

// Разбор tar-архива в памяти. Формат простой: заголовок 512 байт + данные.
// Поддерживаем pax-заголовки (типы 'x'/'g') — GitHub использует их для длинных путей.
function untar(tarBuf: Buffer): ScannedFile[] {
  const files: ScannedFile[] = [];
  let offset = 0;
  let paxPath: string | null = null;

  const readString = (start: number, len: number) => {
    const slice = tarBuf.subarray(start, start + len);
    const end = slice.indexOf(0);
    return slice.subarray(0, end === -1 ? len : end).toString("utf8");
  };

  while (offset + 512 <= tarBuf.length) {
    const name = readString(offset, 100);
    if (!name) break; // два нулевых блока — конец архива

    const sizeOctal = readString(offset + 124, 12).trim();
    const size = parseInt(sizeOctal || "0", 8) || 0;
    const typeflag = String.fromCharCode(tarBuf[offset + 156]);
    const prefix = readString(offset + 345, 155);
    const dataStart = offset + 512;
    const dataEnd = dataStart + size;

    if (typeflag === "x" || typeflag === "g") {
      // pax-заголовок: строки вида "<len> key=value\n" — берём path, если есть.
      const data = tarBuf.subarray(dataStart, dataEnd).toString("utf8");
      const m = data.match(/\d+ path=([^\n]+)\n/);
      if (typeflag === "x" && m) paxPath = m[1];
    } else if (typeflag === "0" || typeflag === "\0") {
      const rawPath = paxPath ?? (prefix ? `${prefix}/${name}` : name);
      paxPath = null;
      // Убираем первый сегмент пути ("repo-sha/...") — он одинаковый у всех файлов.
      const path = rawPath.split("/").slice(1).join("/");
      if (path && size > 0 && size <= MAX_FILE_BYTES && files.length < MAX_FILES) {
        const content = tarBuf.subarray(dataStart, dataEnd);
        if (isTextContent(content)) {
          files.push({ path, content: content.toString("utf8") });
        }
      }
    } else {
      paxPath = null;
    }

    // Данные выровнены по 512 байт.
    offset = dataStart + Math.ceil(size / 512) * 512;
  }
  return files;
}

// Главная функция: ссылка → список текстовых файлов репозитория (в памяти).
export async function fetchRepoFiles(
  repoUrl: string,
): Promise<{ repo: string; files: ScannedFile[] }> {
  const { owner, repo } = parseGitHubUrl(repoUrl);
  const archive = await downloadArchive(owner, repo);

  let tarBuf: Buffer;
  try {
    tarBuf = gunzipSync(archive, { maxOutputLength: MAX_UNPACKED_BYTES });
  } catch (e) {
    const isTooBig =
      e instanceof RangeError ||
      (e as NodeJS.ErrnoException)?.code === "ERR_BUFFER_TOO_LARGE";
    throw new ScanUserError(isTooBig ? "too_big" : "download_failed");
  }

  const files = untar(tarBuf);
  if (files.length === 0) throw new ScanUserError("empty_repo");
  return { repo: `${owner}/${repo}`, files };
}
