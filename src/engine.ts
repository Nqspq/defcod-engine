// Движок сканера: принимает список текстовых файлов (путь + содержимое)
// и возвращает список находок. Ничего не пишет на диск и не логирует.

import {
  Finding,
  HARDCODED_SECRET_RE,
  JWT_RE,
  KEY_RULES,
  PRIVATE_KEY_RE,
  envLineHasRealValue,
  isRealEnvFile,
  isServiceRoleJwt,
  looksLikeClientCode,
  looksLikePlaceholder,
  maskSecret,
} from "./rules";

export type ScannedFile = { path: string; content: string };

// Ограничения, чтобы отчёт оставался читаемым, а функция — быстрой.
const MAX_FINDINGS_TOTAL = 300;
// Сколько строк одного типа в одном файле собираем (потом всё это — одна карточка).
const MAX_LINES_PER_FILE_PER_TYPE = 20;

export type ScanOutput = { findings: Finding[]; filesScanned: number };

// Схлопываем находки одного типа в одном файле в одну карточку со списком строк.
function groupFindings(raw: Finding[]): Finding[] {
  const map = new Map<string, Finding>();
  for (const f of raw) {
    const key = `${f.type}:${f.file}`;
    const g = map.get(key);
    if (!g) {
      map.set(key, { ...f, lines: [f.line] });
    } else {
      if (!g.lines!.includes(f.line)) g.lines!.push(f.line);
      g.inClientCode = g.inClientCode || f.inClientCode;
    }
  }
  const groups = [...map.values()];
  for (const g of groups) {
    g.lines!.sort((a, b) => a - b);
    g.line = g.lines![0];
  }
  return groups;
}

// Папки и файлы, где секретов не бывает или ложных срабатываний слишком много.
const SKIP_PATH_RE =
  /(^|\/)(node_modules|\.git|dist|build|\.next|out|vendor|coverage|__pycache__|\.venv)\//;
const SKIP_FILE_RE = /(\.min\.(js|css)|\.map|\.lock|-lock\.(json|yaml)|\.svg)$|(^|\/)(package-lock\.json|yarn\.lock|pnpm-lock\.yaml)$/;

function lineNumberAt(content: string, index: number): number {
  let line = 1;
  for (let i = 0; i < index && i < content.length; i++) {
    if (content[i] === "\n") line++;
  }
  return line;
}

export function scanFiles(files: ScannedFile[]): ScanOutput {
  const findings: Finding[] = [];
  // Один и тот же секрет в одном файле не дублируем.
  const seen = new Set<string>();
  // Считаем только файлы, которые сканер реально проверил (после пропусков).
  let filesScanned = 0;

  const push = (f: Finding, secret: string) => {
    if (findings.length >= MAX_FINDINGS_TOTAL) return;
    const dedupeKey = `${f.type}:${f.file}:${secret}`;
    if (seen.has(dedupeKey)) return;
    const perFileCount = findings.filter(
      (x) => x.type === f.type && x.file === f.file,
    ).length;
    if (perFileCount >= MAX_LINES_PER_FILE_PER_TYPE) return;
    seen.add(dedupeKey);
    findings.push(f);
  };

  // Отладка (только при SCAN_DEBUG): что пришло, что отброшено и почему.
  const debug = !!process.env.SCAN_DEBUG;
  const dropped: string[] = [];

  for (const file of files) {
    if (SKIP_PATH_RE.test(file.path)) {
      if (debug) dropped.push(`${file.path}  (путь в списке пропуска)`);
      continue;
    }
    if (SKIP_FILE_RE.test(file.path)) {
      if (debug) dropped.push(`${file.path}  (тип файла в списке пропуска)`);
      continue;
    }
    filesScanned++;

    // 1. Закоммиченный .env с реальными значениями — критично.
    if (isRealEnvFile(file.path)) {
      const realKeys: string[] = [];
      for (const line of file.content.split("\n")) {
        const hit = envLineHasRealValue(line);
        if (hit) realKeys.push(hit.key);
      }
      if (realKeys.length > 0) {
        push(
          {
            type: "env_file",
            severity: "critical",
            file: file.path,
            line: 1,
            masked: realKeys.slice(0, 8).join(", "),
          },
          file.path,
        );
      }
    }

    // 2. Ключи конкретных провайдеров.
    for (const rule of KEY_RULES) {
      for (const m of file.content.matchAll(rule.re)) {
        const secret = m[0];
        if (looksLikePlaceholder(secret)) continue;
        push(
          {
            type: rule.type,
            severity: rule.severity,
            file: file.path,
            line: lineNumberAt(file.content, m.index),
            masked: maskSecret(secret),
          },
          secret,
        );
      }
    }

    // 3. Supabase service_role JWT. В клиентском коде — отдельно помечаем.
    for (const m of file.content.matchAll(JWT_RE)) {
      const token = m[0];
      if (!isServiceRoleJwt(token)) continue;
      push(
        {
          type: "supabase_service_role",
          severity: "critical",
          file: file.path,
          line: lineNumberAt(file.content, m.index),
          masked: maskSecret(token),
          inClientCode: looksLikeClientCode(file.path),
        },
        token,
      );
    }

    // 4. Приватные ключи (PEM).
    for (const m of file.content.matchAll(PRIVATE_KEY_RE)) {
      push(
        {
          type: "private_key",
          severity: "critical",
          file: file.path,
          line: lineNumberAt(file.content, m.index),
          masked: m[0].replace(/-----/g, "").trim(),
        },
        `${file.path}:${m.index}`,
      );
    }

    // 5. Захардкоженные пароли/секреты — уровень "важно".
    for (const m of file.content.matchAll(HARDCODED_SECRET_RE)) {
      const value = m[2];
      if (looksLikePlaceholder(value)) continue;
      // Значение уже поймано правилом выше (например, это sk-... ключ)? Не дублируем.
      if (seen.has(`openai_key:${file.path}:${value}`)) continue;
      if ([...seen].some((k) => k.endsWith(`:${file.path}:${value}`))) continue;
      push(
        {
          type: "hardcoded_secret",
          severity: "warning",
          file: file.path,
          line: lineNumberAt(file.content, m.index),
          masked: `${m[1]} = ${maskSecret(value)}`,
        },
        value,
      );
    }
  }

  // Схлопываем дубли (один тип в одном файле — одна карточка со списком строк).
  const grouped = groupFindings(findings);

  if (debug) {
    console.error(
      `[scan] файлов получено: ${files.length} | проверено (прошли фильтры): ${filesScanned} | ` +
        `отброшено: ${dropped.length} | сработало правил (до группировки): ${findings.length} | ` +
        `карточек (после группировки): ${grouped.length}`,
    );
    if (dropped.length) console.error("[scan] отброшенные файлы:\n  " + dropped.join("\n  "));
  }

  // Критичное — наверх.
  const order: Record<string, number> = { critical: 0, warning: 1, info: 2 };
  grouped.sort((a, b) => order[a.severity] - order[b.severity]);
  return { findings: grouped, filesScanned };
}
