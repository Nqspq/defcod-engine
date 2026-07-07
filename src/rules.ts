// Правила поиска секретов для сканера v0.
// Никаких внешних сканеров — только регулярные выражения на чистом JS.
// ВАЖНО: найденные секреты никогда не возвращаются целиком — только маска.

export type Severity = "critical" | "warning" | "info";

// Идентификаторы типов находок. По ним подбираются заготовленные объяснения.
export type FindingType =
  | "openai_key"
  | "anthropic_key"
  | "stripe_live_key"
  | "aws_key"
  | "google_key"
  | "supabase_service_role"
  | "private_key"
  | "hardcoded_secret"
  | "env_file";

export type Finding = {
  type: FindingType;
  severity: Severity;
  file: string;
  line: number;
  // После группировки: все строки, где встретился этот тип находки в этом файле.
  lines?: number[];
  // Замаскированный секрет или короткое безопасное описание (например, имена переменных из .env).
  masked: string;
  // Для service_role: нашли ли его в клиентском коде (это хуже всего).
  inClientCode?: boolean;
};

// Маскируем секрет: первые символы + **** . Целиком не показываем никогда.
export function maskSecret(secret: string): string {
  const head = secret.slice(0, Math.min(7, Math.max(4, Math.floor(secret.length / 6))));
  return `${head}****`;
}

// Значения-заглушки не считаем утечкой: "your_api_key", "sk-xxxx", "<KEY>" и т.п.
const PLACEHOLDER_RE =
  /your|example|sample|placeholder|change[-_ ]?me|dummy|fake|test[-_]?key|xxx|\.\.\.|<[^>]*>|\$\{|%s|todo/i;

export function looksLikePlaceholder(value: string): boolean {
  return PLACEHOLDER_RE.test(value);
}

// --- Правила по конкретным провайдерам ---
// У каждого правила: тип, уровень важности и regex с группой-секретом.

type KeyRule = {
  type: FindingType;
  severity: Severity;
  re: RegExp;
};

export const KEY_RULES: KeyRule[] = [
  // OpenAI: sk-..., включая новые sk-proj-... (но не sk-ant-... — это Anthropic, и не sk_live — это Stripe)
  {
    type: "openai_key",
    severity: "critical",
    re: /\bsk-(?:proj-|svcacct-)?(?!ant-)[A-Za-z0-9_-]{20,}\b/g,
  },
  // Anthropic: sk-ant-...
  {
    type: "anthropic_key",
    severity: "critical",
    re: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g,
  },
  // Stripe: живые секретные ключи sk_live_... и rk_live_...
  {
    type: "stripe_live_key",
    severity: "critical",
    re: /\b[sr]k_live_[A-Za-z0-9]{16,}\b/g,
  },
  // AWS Access Key ID: AKIA + 16 заглавных букв/цифр
  {
    type: "aws_key",
    severity: "critical",
    re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g,
  },
  // Google API key: AIza + 35 символов
  {
    type: "google_key",
    severity: "critical",
    re: /\bAIza[0-9A-Za-z_-]{35}\b/g,
  },
];

// Приватные ключи (PEM): достаточно факта наличия заголовка.
export const PRIVATE_KEY_RE =
  /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----/g;

// JWT: три base64url-части через точки. Дальше отдельно проверяем payload на "role":"service_role".
export const JWT_RE = /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g;

// Проверяем, что JWT — это именно Supabase service_role ключ.
export function isServiceRoleJwt(token: string): boolean {
  try {
    const payload = token.split(".")[1];
    const decoded = Buffer.from(payload, "base64url").toString("utf8");
    const data = JSON.parse(decoded);
    return data?.role === "service_role";
  } catch {
    return false;
  }
}

// Захардкоженные пароли/секреты: password = "...", api_key: '...' и т.п.
// Уровень "warning" — бывают ложные срабатывания, поэтому не "critical".
// Имя переменной может иметь префикс/суффикс: adminPassword, DB_SECRET_KEY и т.п.
export const HARDCODED_SECRET_RE =
  /\b(\w*(?:password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?token|auth[_-]?token)\w*)\s*[:=]\s*["'`]([^"'`\s]{8,})["'`]/gi;

// Файлы .env с реальным содержимым. .env.example и подобные — это нормально.
export function isRealEnvFile(path: string): boolean {
  const base = path.split("/").pop() ?? "";
  if (!/^\.env(\..+)?$/.test(base)) return false;
  return !/(example|sample|template|dist|defaults?)$/i.test(base);
}

// Строка из .env выглядит как настоящее значение (не пустая, не заглушка)?
export function envLineHasRealValue(line: string): { key: string } | null {
  const m = line.match(/^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+?)\s*$/);
  if (!m) return null;
  const value = m[2].replace(/^["']|["']$/g, "");
  if (value.length < 8 || looksLikePlaceholder(value)) return null;
  return { key: m[1] };
}

// Похоже ли, что файл — часть клиентского кода (попадает в браузер)?
// Для service_role это самый опасный случай: ключ увидит любой посетитель сайта.
export function looksLikeClientCode(path: string): boolean {
  if (/(^|\/)(api|server|scripts?|functions|supabase|backend|lambda)\//.test(path)) return false;
  if (/\.env/.test(path)) return false;
  return /\.(jsx?|tsx?|vue|svelte|html)$/.test(path);
}
