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
  | "env_file"
  // .env в репозитории, но внутри только публичные по замыслу значения:
  // сами значения не секретны, поэтому уровень «совет», а не «критично».
  | "env_file_public";

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
// Список открытый — пополняй, когда встретишь новый вид заглушки.
const PLACEHOLDER_RE =
  /your|example|sample|placeholder|change[-_ ]?me|replace[-_ ]?me|dummy|fake|mock|demo|lorem|foo|bar|baz|test[-_]?key|xxx|\.\.\.|<[^>]*>|\$\{|%s|todo|redacted|removed|omitted|hidden|not[-_ ]?real|n\/a|^(none|null|undefined|empty)$|\*{3,}|•/i;

export function looksLikePlaceholder(value: string): boolean {
  return PLACEHOLDER_RE.test(value);
}

// Энтропия Шеннона (бит на символ). Случайный ключ ~4-6, словарное слово ~2-3.
export function shannonEntropy(value: string): number {
  if (value.length === 0) return 0;
  const counts = new Map<string, number>();
  for (const ch of value) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let h = 0;
  for (const n of counts.values()) {
    const p = n / value.length;
    h -= p * Math.log2(p);
  }
  return h;
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

// Похоже ли значение на ключ какого-нибудь провайдера (для оценки .env).
function looksLikeProviderKey(value: string): boolean {
  return KEY_RULES.some((rule) => {
    const re = new RegExp(rule.re.source, rule.re.flags.replace("g", ""));
    return re.test(value);
  });
}

// --- Приватные ключи (PEM) ---
// Заголовок PEM. Сам по себе НЕ находка: тот же заголовок постоянно встречается
// в коде, который собирает ключ из переменной окружения. Обязательно нужно тело
// ключа — см. hasPrivateKeyBody ниже.
export const PRIVATE_KEY_RE =
  /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----/g;

// Та же проверка без флага g — для одиночных .test() (у /g-регулярок .test() запоминает
// позицию и на втором вызове врёт).
const PRIVATE_KEY_HEADER_RE = new RegExp(PRIVATE_KEY_RE.source);

// Минимальная длина тела ключа в символах base64 (без пробелов и переводов строк).
// Самый короткий настоящий приватный ключ (EC 256 бит) — около 120 символов.
const MIN_PRIVATE_KEY_BODY = 100;

// Признаки того, что ключ подставляется в рантайме, а не лежит в файле.
const KEY_FROM_RUNTIME_RE =
  /\$\{|process\.env|Deno\.env|import\.meta\.env|os\.environ|os\.Getenv|getenv|ENV\[|env\(|<[^>]*>|%s|\{\{/i;

// Убираем служебные строки PEM-брони («Version: GnuPG v1», «Proc-Type: 4,ENCRYPTED»).
function stripArmorHeaders(segment: string): string {
  return segment.replace(/^[ \t]*[A-Za-z][A-Za-z0-9-]*:[^\n]*\n/gm, "");
}

// Насколько далеко после заголовка ищем признак подстановки из переменной.
// Окно узкое нарочно: при сборке ключа подстановка идёт сразу за заголовком.
// Широкое окно ловило бы посторонний код ниже в файле и глушило настоящие находки.
const RUNTIME_LOOKAHEAD = 200;

// Есть ли после заголовка PEM настоящее тело ключа?
// Одинокий заголовок (или заголовок + подстановка из переменной) находкой не считается.
export function hasPrivateKeyBody(content: string, headerEndIndex: number): boolean {
  // Смотрим от конца заголовка до закрывающей строки (или 8000 символов — с запасом).
  const rest = content.slice(headerEndIndex, headerEndIndex + 8000);
  const endMatch = rest.search(/-----END[^\n]*-----/);
  const segment = endMatch === -1 ? rest : rest.slice(0, endMatch);

  // Ключ подставляется в рантайме сразу за заголовком — это не утечка.
  if (KEY_FROM_RUNTIME_RE.test(segment.slice(0, RUNTIME_LOOKAHEAD))) return false;

  // Нормализуем: убираем брони-заголовки, пробелы, кавычки, запятые,
  // экранированные переводы строк ("\n" внутри строкового литерала) и склейку строк.
  const normalized = stripArmorHeaders(segment)
    .replace(/\\[nrt]/g, "")
    .replace(/[\s"'`,;]/g, "");

  // Тело ключа должно начинаться сразу и быть достаточно длинным.
  const body = normalized.match(/^[A-Za-z0-9+/=]+/)?.[0] ?? "";
  return body.length >= MIN_PRIVATE_KEY_BODY;
}

// JWT: три base64url-части через точки. Дальше отдельно проверяем payload на "role":"service_role".
export const JWT_RE = /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g;

// Разбираем payload JWT. null — если это не JWT.
function jwtPayload(token: string): Record<string, unknown> | null {
  try {
    const payload = token.split(".")[1];
    const decoded = Buffer.from(payload, "base64url").toString("utf8");
    const data = JSON.parse(decoded);
    return typeof data === "object" && data !== null ? data : null;
  } catch {
    return null;
  }
}

// Проверяем, что JWT — это именно Supabase service_role ключ.
export function isServiceRoleJwt(token: string): boolean {
  return jwtPayload(token)?.role === "service_role";
}

// Публичный (anon) ключ Supabase — его видно в браузере по замыслу, это не утечка.
export function isAnonJwt(token: string): boolean {
  return jwtPayload(token)?.role === "anon";
}

// --- Захардкоженные пароли и секреты ---

// Захардкоженные пароли/секреты: password = "...", api_key: '...' и т.п.
// Уровень "warning" — бывают ложные срабатывания, поэтому не "critical".
// Имя переменной может иметь префикс/суффикс: adminPassword, DB_SECRET_KEY и т.п.
export const HARDCODED_SECRET_RE =
  /\b(\w*(?:password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?token|auth[_-]?token)\w*)\s*[:=]\s*["'`]([^"'`\s]{8,})["'`]/gi;

// Минимальная длина значения, которое вообще может быть секретом.
const MIN_SECRET_VALUE_LEN = 8;

// Имя переменной описывает НАЗВАНИЕ поля/заголовка, а не само значение.
// Например: apiKeyHeader = "X-API-Key", passwordPlaceholder = "••••".
const NAME_IS_NOT_A_VALUE_RE =
  /(header|headername|placeholder|label|field|prompt|hint|caption|title|regex|pattern|example|sample|column|param)s?$/i;

// Имя переменной прямо говорит, что это тестовое значение.
// Ловим и TEST_SECRET, и camelCase testPassword (но не testimonialSecret).
const NAME_IS_TEST_RE =
  /^(test|demo|example|sample|mock|fixture|dummy)(?:[_-]|(?=[A-Z]))/;

// Известные публичные тестовые ключи из документации сервисов — не утечка.
// Список открытый — пополняй по мере находок.
export const KNOWN_PUBLIC_TEST_VALUES: RegExp[] = [
  // Cloudflare Turnstile: тестовые site- и secret-ключи (1x000…AA, 2x000…AB, 3x000…FF)
  /^[123]x0{15,}[A-Za-z]{2}$/,
  // Тестовые ключи с общепринятой пометкой _test_ в середине:
  // sk_test_… (Stripe), pk_test_…, zk_test_… и прочие сервисы с той же схемой.
  /^[A-Za-z]{1,5}_test_[A-Za-z0-9_-]+$/,
  // Google reCAPTCHA: тестовая пара из официальной документации
  /^6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI$/,
  /^6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe$/,
  // Supabase: publishable-ключ (публичен по замыслу, в отличие от secret-ключа)
  /^sb_publishable_/,
];

// Значение похоже на название HTTP-заголовка, а не на секрет: X-API-Key, Content-Type.
const HTTP_HEADER_VALUE_RE =
  /^(?:x-[a-z0-9]+(?:-[a-z0-9]+)*|authorization|content-type|accept|user-agent|bearer)$/i;

export function isKnownPublicTestValue(value: string): boolean {
  return KNOWN_PUBLIC_TEST_VALUES.some((re) => re.test(value));
}

// Главный фильтр шума для hardcoded_secret: похоже ли это на настоящий секрет?
// name — имя переменной, value — её значение.
export function isLikelySecretValue(name: string, value: string): boolean {
  if (value.length < MIN_SECRET_VALUE_LEN) return false;
  if (looksLikePlaceholder(value)) return false;
  if (isKnownPublicTestValue(value)) return false;

  // Имя переменной описывает поле/заголовок, а не значение.
  if (NAME_IS_NOT_A_VALUE_RE.test(name)) return false;
  if (NAME_IS_TEST_RE.test(name)) return false;

  // Значение — название HTTP-заголовка.
  if (HTTP_HEADER_VALUE_RE.test(value)) return false;

  // Значение — само имя переменной окружения (ANTHROPIC_API_KEY), а не её значение.
  if (/^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$/.test(value)) return false;

  // Значение — ссылка на переменную окружения или шаблон.
  if (KEY_FROM_RUNTIME_RE.test(value)) return false;

  // Явно тестовое значение: test-..., test_...
  if (/^(?:test|demo|sample|mock)[-_]/i.test(value)) return false;

  // Ключ известного провайдера — точно секрет, дальше не фильтруем.
  if (looksLikeProviderKey(value)) return true;

  // Одно словарное слово без цифр и символов — скорее подпись или текст, чем секрет.
  // (Настоящие слабые пароли вида "password123" содержат цифры и здесь не отсекаются.)
  if (/^[a-z]+$/.test(value) && value.length < 20) return false;

  // Достаточная энтропия: отсекаем повторы вида "aaaaaaaa" и "00000000".
  if (shannonEntropy(value) < 2.0) return false;

  return true;
}

// --- Файлы .env ---

// Файл-образец: .env.example, config.sample.ts, settings.template.json и т.п.
// Значения внутри такого файла по определению заглушки, поэтому правило
// hardcoded_secret по нему не работает. Ключи конкретных провайдеров (sk-…, AKIA…)
// проверяются даже здесь: настоящий ключ в образце — всё равно утечка.
export function isExampleFile(path: string): boolean {
  const base = (path.split("/").pop() ?? "").toLowerCase();
  return /(^|[.\-_])(examples?|samples?|templates?|dist|defaults?|fixtures?)(\.|$)/.test(base);
}

// Файлы .env с реальным содержимым. .env.example и подобные — это нормально.
export function isRealEnvFile(path: string): boolean {
  const base = path.split("/").pop() ?? "";
  if (!/^\.env(\..+)?$/.test(base)) return false;
  return !/(example|sample|template|dist|defaults?)$/i.test(base);
}

// Строка из .env выглядит как настоящее значение (не пустая, не заглушка)?
export function envLineHasRealValue(line: string): { key: string } | null {
  const parsed = parseEnvLine(line);
  return parsed ? { key: parsed.key } : null;
}

function parseEnvLine(line: string): { key: string; value: string } | null {
  const m = line.match(/^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+?)\s*$/);
  if (!m) return null;
  const value = m[2].replace(/^["']|["']$/g, "");
  if (value.length < 8 || looksLikePlaceholder(value)) return null;
  return { key: m[1], value };
}

// Префиксы фреймворков, означающие «эта переменная уходит в браузер».
// ВАЖНО: префикс НЕ делает значение безопасным (VITE_OPENAI_API_KEY — реальная утечка,
// причём худшего вида). Префикс только отбрасывается перед сверкой со списком ниже.
export const PUBLIC_ENV_PREFIXES = [
  "VITE_",
  "NEXT_PUBLIC_",
  "REACT_APP_",
  "PUBLIC_",
  "EXPO_PUBLIC_",
  "NUXT_PUBLIC_",
  "GATSBY_",
  "ASTRO_PUBLIC_",
];

// Переменные, публичные ПО ЗАМЫСЛУ: их значения и так видит любой посетитель сайта.
// .env с одними такими переменными — плохая привычка, но не утечка.
// Список открытый — пополняй по мере находок.
export const PUBLIC_ENV_NAMES = [
  // Supabase
  "SUPABASE_URL",
  "SUPABASE_ANON_KEY",
  "SUPABASE_PUBLISHABLE_KEY",
  "SUPABASE_PROJECT_ID",
  "SUPABASE_PROJECT_REF",
  // Firebase (ключ ограничивается доменом, публичен по замыслу)
  "FIREBASE_API_KEY",
  "FIREBASE_AUTH_DOMAIN",
  "FIREBASE_PROJECT_ID",
  "FIREBASE_APP_ID",
  "FIREBASE_STORAGE_BUCKET",
  "FIREBASE_MESSAGING_SENDER_ID",
  // Платежи и авторизация — публичные половины пар ключей
  "STRIPE_PUBLISHABLE_KEY",
  "CLERK_PUBLISHABLE_KEY",
  "PAYPAL_CLIENT_ID",
  // Аналитика и мониторинг
  "SENTRY_DSN",
  "POSTHOG_KEY",
  "POSTHOG_HOST",
  "GA_MEASUREMENT_ID",
  "GTM_ID",
  "AMPLITUDE_API_KEY",
  // Капчи — site-ключи публичны (secret-ключи НЕ входят в список)
  "TURNSTILE_SITE_KEY",
  "RECAPTCHA_SITE_KEY",
  "HCAPTCHA_SITE_KEY",
  // Карты — специально публичные токены
  "MAPBOX_PUBLIC_TOKEN",
  // Адреса и окружение
  "APP_URL",
  "SITE_URL",
  "BASE_URL",
  "API_URL",
  "API_BASE_URL",
  "PUBLIC_URL",
  "VERCEL_URL",
  "APP_NAME",
  "APP_ENV",
  "APP_VERSION",
  "NODE_ENV",
  "PORT",
  "HOST",
  "TZ",
  "LOG_LEVEL",
];

// Признаки чувствительного имени переменной. Проверяются ПОСЛЕ списка публичных,
// поэтому SUPABASE_ANON_KEY не попадает сюда из-за подстроки "KEY".
// Список открытый — пополняй по мере находок.
export const SENSITIVE_ENV_MARKERS = [
  "SERVICE_ROLE",
  "SECRET",
  "PRIVATE",
  "PASSWORD",
  "PASSWD",
  "PWD",
  "API_KEY",
  "APIKEY",
  "ACCESS_KEY",
  "ACCESS_TOKEN",
  "AUTH_TOKEN",
  "REFRESH_TOKEN",
  "CLIENT_SECRET",
  "WEBHOOK_SECRET",
  "SIGNING_KEY",
  "JWT_SECRET",
  "SESSION_SECRET",
  "ENCRYPTION_KEY",
  "CREDENTIAL",
  "DATABASE_URL",
  "DB_URL",
  "CONNECTION_STRING",
  "DSN_PASSWORD",
  "TOKEN",
];

// Значения, публичные по форме (не зависят от имени переменной).
const PUBLIC_VALUE_RE = /^(?:sb_publishable_|pk_live_|pk_test_|https?:\/\/|\d+$)/;

function stripPublicPrefix(key: string): string {
  const upper = key.toUpperCase();
  for (const prefix of PUBLIC_ENV_PREFIXES) {
    if (upper.startsWith(prefix)) return upper.slice(prefix.length);
  }
  return upper;
}

// Публичная ли эта переменная .env — по имени и по значению.
export function isPublicEnvVar(key: string, value: string): boolean {
  const bare = stripPublicPrefix(key);

  // Значение — настоящий ключ провайдера или мастер-ключ базы: всегда чувствительно,
  // как бы переменная ни называлась.
  if (looksLikeProviderKey(value)) return false;
  if (isServiceRoleJwt(value)) return false;
  if (PRIVATE_KEY_HEADER_RE.test(value)) return false;

  // Явно публичный anon-ключ Supabase.
  if (isAnonJwt(value)) return true;

  // Имя в списке публичных.
  if (PUBLIC_ENV_NAMES.includes(bare)) return true;

  // Имя содержит чувствительный маркер.
  if (SENSITIVE_ENV_MARKERS.some((marker) => bare.includes(marker))) return false;

  // Значение публично по форме (адрес, номер, publishable-ключ).
  if (PUBLIC_VALUE_RE.test(value)) return true;

  // Имя неизвестно: смотрим на само значение. Длинная строка с высокой энтропией
  // похожа на секрет, всё остальное считаем безобидным.
  const looksRandom = value.length >= 20 && shannonEntropy(value) >= 3.2;
  return !looksRandom;
}

export type EnvClassification = {
  // Имена переменных с чувствительными значениями.
  sensitiveKeys: string[];
  // Имена публичных по замыслу переменных.
  publicKeys: string[];
};

// Разбираем .env: что внутри — настоящие секреты или только публичные значения?
export function classifyEnvFile(content: string): EnvClassification {
  const sensitiveKeys: string[] = [];
  const publicKeys: string[] = [];
  for (const line of content.split("\n")) {
    const parsed = parseEnvLine(line);
    if (!parsed) continue;
    if (isPublicEnvVar(parsed.key, parsed.value)) publicKeys.push(parsed.key);
    else sensitiveKeys.push(parsed.key);
  }
  return { sensitiveKeys, publicKeys };
}

// Похоже ли, что файл — часть клиентского кода (попадает в браузер)?
// Для service_role это самый опасный случай: ключ увидит любой посетитель сайта.
export function looksLikeClientCode(path: string): boolean {
  if (/(^|\/)(api|server|scripts?|functions|supabase|backend|lambda)\//.test(path)) return false;
  if (/\.env/.test(path)) return false;
  return /\.(jsx?|tsx?|vue|svelte|html)$/.test(path);
}
