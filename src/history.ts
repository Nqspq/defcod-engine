// Скан истории git через GitHub REST API.
//
// Зачем: частый случай утечки — ключ закоммитили, потом «удалили», но он
// остался в старых версиях кода и виден любому, кто откроет историю
// репозитория на GitHub.
//
// Как: список коммитов (1 запрос) + дифф каждого коммита (по запросу на
// коммит). Сканируются только ДОБАВЛЕННЫЕ строки диффов — правилами для
// критичных утечек (ключи провайдеров, service_role JWT, приватные ключи).
// Менее строгие правила (hardcoded_secret и т.п.) в истории не применяются:
// на диффах они дают слишком много шума.
//
// ВАЖНО про лимиты: без токена GitHub REST даёт 60 запросов/час на IP —
// для серверов за общим IP это делает анонимный скан истории невозможным.
// С токеном пользователя лимит 5000/час. Поэтому предполагается вызов
// с токеном; сам токен используется только как заголовок запроса,
// нигде не сохраняется и не логируется.

import {
  Finding,
  JWT_RE,
  KEY_RULES,
  PRIVATE_KEY_RE,
  hasPrivateKeyBody,
  isServiceRoleJwt,
  looksLikePlaceholder,
  maskSecret,
} from "./rules";
import type { ScannedFile } from "./engine";
import { ScanUserError, parseGitHubUrl } from "./github";

const API = "https://api.github.com";
const FETCH_TIMEOUT_MS = 15_000;

export type FetchHistoryOptions = {
  // Токен пользователя GitHub (обязателен на практике — см. лимиты выше).
  token?: string;
  // Сколько последних коммитов смотреть (максимум 100 — одна страница API).
  maxCommits?: number;
  // Бюджет времени на всю историю; вышли — честно останавливаемся.
  timeBudgetMs?: number;
  // Сколько диффов запрашивать параллельно.
  concurrency?: number;
};

// Дифф одного коммита: только добавленные строки, по файлам.
export type CommitDiff = {
  sha: string;
  date: string; // ISO-дата коммита
  files: { path: string; addedText: string }[];
};

export type HistoryFetchResult = {
  commits: CommitDiff[];
  commitsChecked: number;
  // true — проверили не всё (кончился бюджет времени или коммитов больше лимита).
  partial: boolean;
};

// Из текста patch достаём только добавленные строки ("+", кроме заголовка "+++").
export function extractAddedLines(patch: string): string {
  return patch
    .split("\n")
    .filter((l) => l.startsWith("+") && !l.startsWith("+++"))
    .map((l) => l.slice(1))
    .join("\n");
}

async function apiGet(path: string, token?: string): Promise<Response> {
  const headers: Record<string, string> = {
    "User-Agent": "defcod-scanner",
    Accept: "application/vnd.github+json",
  };
  if (token) headers.Authorization = `Bearer ${token}`;
  try {
    return await fetch(`${API}${path}`, {
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
      headers,
    });
  } catch {
    throw new ScanUserError("download_failed");
  }
}

// Скачиваем историю: список коммитов + диффы (добавленные строки).
export async function fetchRepoHistory(
  repoUrl: string,
  options: FetchHistoryOptions = {},
): Promise<HistoryFetchResult> {
  const { owner, repo } = parseGitHubUrl(repoUrl);
  const maxCommits = Math.min(options.maxCommits ?? 50, 100);
  const timeBudgetMs = options.timeBudgetMs ?? 20_000;
  const concurrency = options.concurrency ?? 6;
  const startedAt = Date.now();

  const listRes = await apiGet(
    `/repos/${owner}/${repo}/commits?per_page=${maxCommits}`,
    options.token,
  );
  if (listRes.status === 401) throw new ScanUserError("auth_failed");
  if (listRes.status === 404) throw new ScanUserError("not_found");
  if (!listRes.ok) throw new ScanUserError("download_failed");

  type ListedCommit = { sha: string; parents: unknown[]; commit?: { committer?: { date?: string } } };
  const listed = (await listRes.json()) as ListedCommit[];
  if (!Array.isArray(listed)) throw new ScanUserError("download_failed");

  // Merge-коммиты (2+ родителя) пропускаем: их дифф дублирует диффы веток,
  // и одна утечка превратилась бы в две карточки.
  const targets = listed.filter((c) => (c.parents?.length ?? 0) <= 1);

  const commits: CommitDiff[] = [];
  let stoppedEarly = false;
  let cursor = 0;

  // Простой пул: воркеры разбирают коммиты, пока есть время и коммиты.
  const worker = async () => {
    for (;;) {
      if (Date.now() - startedAt > timeBudgetMs) {
        stoppedEarly = true;
        return;
      }
      const c = targets[cursor++];
      if (!c) return;
      const res = await apiGet(`/repos/${owner}/${repo}/commits/${c.sha}`, options.token);
      // Один неудачный дифф не роняет всю историю — просто пропускаем коммит.
      if (!res.ok) continue;
      const detail = (await res.json()) as {
        commit?: { committer?: { date?: string } };
        files?: { filename?: string; patch?: string }[];
      };
      const files = (detail.files ?? [])
        .filter((f) => f.filename && f.patch)
        .map((f) => ({ path: f.filename!, addedText: extractAddedLines(f.patch!) }))
        .filter((f) => f.addedText.length > 0);
      if (files.length > 0) {
        commits.push({
          sha: c.sha.slice(0, 7),
          date: detail.commit?.committer?.date ?? c.commit?.committer?.date ?? "",
          files,
        });
      }
    }
  };
  await Promise.all(Array.from({ length: concurrency }, worker));

  const commitsChecked = Math.min(cursor, targets.length);
  return {
    commits,
    commitsChecked,
    partial: stoppedEarly || listed.length === maxCommits,
  };
}

// Провайдер по типу находки — для совета «зайди к провайдеру и создай новый ключ».
export const HISTORY_PROVIDER_LABEL: Partial<Record<Finding["type"], string>> = {
  openai_key: "OpenAI",
  anthropic_key: "Anthropic",
  stripe_live_key: "Stripe",
  aws_key: "AWS",
  google_key: "Google",
  supabase_service_role: "Supabase",
};

export type HistoryScanResult = {
  findings: Finding[];
  commitsChecked: number;
  partial: boolean;
};

// Скан диффов: только критичные типы (ключи провайдеров, service_role, PEM).
// Дедупликация:
//  - секрет виден в ТЕКУЩЕМ коде → историческую находку не показываем
//    (о нём уже есть обычная карточка);
//  - один секрет в нескольких коммитах → одна карточка.
export function scanRepoHistory(
  history: HistoryFetchResult,
  currentFiles: ScannedFile[],
): HistoryScanResult {
  const findings: Finding[] = [];
  const seenSecrets = new Set<string>();
  const currentPaths = new Set(currentFiles.map((f) => f.path));
  const inCurrentCode = (secret: string) =>
    currentFiles.some((f) => f.content.includes(secret));

  const push = (
    type: Finding["type"],
    secret: string,
    masked: string,
    commit: CommitDiff,
    path: string,
  ) => {
    if (seenSecrets.has(secret)) return;
    seenSecrets.add(secret);
    if (inCurrentCode(secret)) return;
    findings.push({
      type,
      severity: "critical",
      file: path,
      line: 0, // номер строки в старой версии кода не имеет смысла для читателя
      masked,
      inHistory: true,
      historyVariant: currentPaths.has(path) ? "value_removed" : "file_deleted",
      commitSha: commit.sha,
      commitDate: commit.date,
    });
  };

  for (const commit of history.commits) {
    for (const file of commit.files) {
      const text = file.addedText;

      for (const rule of KEY_RULES) {
        for (const m of text.matchAll(rule.re)) {
          if (rule.severity !== "critical") continue;
          if (looksLikePlaceholder(m[0])) continue;
          push(rule.type, m[0], maskSecret(m[0]), commit, file.path);
        }
      }

      for (const m of text.matchAll(JWT_RE)) {
        if (!isServiceRoleJwt(m[0])) continue;
        push("supabase_service_role", m[0], maskSecret(m[0]), commit, file.path);
      }

      for (const m of text.matchAll(PRIVATE_KEY_RE)) {
        if (!hasPrivateKeyBody(text, m.index + m[0].length)) continue;
        // У PEM нет короткого «секрета» для поиска в текущем коде — берём тело.
        const body = text.slice(m.index, m.index + 200);
        push("private_key", body, m[0].replace(/-----/g, "").trim(), commit, file.path);
      }
    }
  }

  return {
    findings,
    commitsChecked: history.commitsChecked,
    partial: history.partial,
  };
}
