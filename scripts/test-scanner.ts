// Локальный тест сканера: прогоняем движок по «дырявому» проекту-примеру
// и проверяем, что все заложенные «дыры» найдены, а чистые файлы — нет.
// Запуск: npm run test:scanner
//
// ВАЖНО: проект-пример собирается прямо здесь, в памяти, на лету.
// Все «секреты» — фейковые и склеиваются из кусочков в рантайме, чтобы
// ни gitleaks, ни наш собственный сканер не находили их в исходнике
// этого файла. Отдельная папка с фикстурами не нужна: свежий клон
// репозитория проходит тест без подготовки.

import { zipSync, strToU8 } from "fflate";
import { scanFiles, type ScannedFile } from "../src/engine";
import { cannedExplanations } from "../src/explain";
import { parseGitHubUrl, ScanUserError } from "../src/github";
import { filesFromZip } from "../src/zip";

// --- Тест-векторы (фейковые ключи), собираются из кусочков в рантайме ---

const j = (...parts: string[]) => parts.join("");
const b64u = (s: string) => Buffer.from(s).toString("base64url");

// Тело ключа OpenAI отдельно: ниже проверяем, что его нет в отчёте целиком.
const openaiBody = j("Ab9Qz7Lm3", "Np5Rt8Vw2", "Xy4Cd6Ef1", "Gh0JkPq9", "Sr7Tu");

const V = {
  openai: j("sk", "-", openaiBody),
  stripeEnv: j("sk", "_live_", "Qw8Er5Ty2", "Ui9Op3As6", "Df1Gh4Jk7Lz"),
  stripeConfig: j("sk", "_live_", "Zx4Cv7Bn1", "Mq8Wd5Ke2", "Rh9Tj6Yu3Ls"),
  google: j("AI", "za", "Qw3Er6Ty9Ui2", "Op5As8Df1Gh4", "Jk7LzXc0Vb2"),
  googleZip: j("AI", "za", "SyB12345678", "90abcdefghij", "klmnopqrstuv"),
  awsMulti1: j("AK", "IA", "Z8Q4W2N9", "R7T5Y1P3"),
  awsMulti2: j("AK", "IA", "B6M2K8J4", "H9G7F5D1"),
  awsServer: j("AK", "IA", "Q7RT2WD5", "KE8RH3TJ"),
  dbUrl: j("postgres://admin:", "sUp3rS3", "cretDbP4ss", "@db.internal.host:5432/prod"),
  adminPw: j("hunter2", "hunter2"),
  pemHeader: j("-----BEGIN ", "PRIV", "ATE KEY-----"),
  pemFooter: j("-----END ", "PRIV", "ATE KEY-----"),
  // Тело фейкового ключа: ~1600 символов base64, как у настоящего RSA-2048.
  // Одного заголовка теперь недостаточно — движок требует тело (см. баг 1).
  pemBody: Array.from({ length: 26 }, (_, i) =>
    j(
      "MIIEvQIBADANBgkq",
      "hkiG9w0BAQEFAASC",
      "BKcwggSjAgEAAoIB",
      "AQDb9xKmN4pQrS",
      String(i % 10),
      String((i + 3) % 10),
    ),
  ).join("\n"),
  // Supabase service_role JWT собираем честно: заголовок + payload + подпись.
  supabaseJwt: [
    b64u(JSON.stringify({ alg: "HS256", typ: "JWT" })),
    b64u(
      JSON.stringify({
        iss: "supabase",
        ref: "abcdefghijklmnop",
        role: j("service", "_role"),
        iat: 1751500000,
        exp: 2067076000,
      }),
    ),
    b64u("foobarbazquxfoobarbazqux"),
  ].join("."),
};

// --- Проект-пример (в памяти, вместо папки test-fixtures) ---

const files: ScannedFile[] = [
  {
    path: "README.md",
    content: [
      "# Vulnerable test app",
      "",
      "Нарочно «дырявый» проект для проверки сканера DEFCOD. Все ключи фейковые.",
      "Чистый файл: сканер не должен ничего найти в этом README.",
      "",
      "Правильный пример (не должен ловиться): OPENAI_API_KEY=sk-your-api-key-here",
    ].join("\n"),
  },
  {
    path: ".env",
    content: [
      j("OPENAI_", "API_KEY=", V.openai),
      j("DATABASE_URL=", V.dbUrl),
      j("STRIPE_", "SECRET=", V.stripeEnv),
    ].join("\n"),
  },
  {
    path: "src/config.js",
    content: [
      "// Плохая практика нарочно: секреты прямо в коде (для теста сканера).",
      "export const config = {",
      j('  stripeKey: "', V.stripeConfig, '",'),
      j('  googleMapsKey: "', V.google, '",'),
      j("  admin", "Pass", 'word: "', V.adminPw, '",'),
      "};",
    ].join("\n"),
  },
  {
    path: "src/App.jsx",
    content: [
      "// Худший случай нарочно: service_role ключ Supabase в клиентском коде.",
      'import { createClient } from "@supabase/supabase-js";',
      "",
      "const supabase = createClient(",
      '  "https://abcdefghijklmnop.supabase.co",',
      j('  "', V.supabaseJwt, '",'),
      ");",
      "",
      "export default function App() {",
      "  return <div>hello</div>;",
      "}",
    ].join("\n"),
  },
  {
    path: "server/aws.js",
    content: [
      "// AWS-ключ в коде (для теста сканера).",
      j("const AWS_ACCESS_", 'KEY_ID = "', V.awsServer, '";'),
      "module.exports = { AWS_ACCESS_KEY_ID };",
    ].join("\n"),
  },
  {
    path: "keys/deploy.pem",
    content: [V.pemHeader, V.pemBody, V.pemFooter].join("\n"),
  },
  {
    path: "multi-keys.js",
    content: [
      "// Тест группировки: ДВА РАЗНЫХ ключа ОДНОГО типа в ОДНОМ файле.",
      j('const first = "', V.awsMulti1, '";'),
      'const config = { region: "us-east-1" };',
      j('const second = "', V.awsMulti2, '";'),
      "export { first, second, config };",
    ].join("\n"),
  },
];

const { findings, filesScanned } = scanFiles(files);
const explained = cannedExplanations(findings);

console.log(`Файлов просканировано: ${filesScanned}`);
console.log(`Находок (карточек после группировки): ${findings.length}\n`);
for (const f of explained) {
  console.log(`[${f.severity.toUpperCase()}] ${f.texts.ru.title}`);
  console.log(`  Файл: ${f.file}  строки: ${(f.lines ?? [f.line]).join(", ")}  →  ${f.masked}`);
}

// --- Проверки ---
let failed = 0;
function expect(cond: boolean, what: string) {
  if (cond) console.log(`  ✅ ${what}`);
  else {
    console.log(`  ❌ ПРОВАЛ: ${what}`);
    failed++;
  }
}

console.log("\nПроверки:");
const types = findings.map((f) => `${f.type}@${f.file}`);
expect(types.includes("env_file@.env"), ".env с реальными значениями пойман");
expect(types.includes("openai_key@.env"), "ключ OpenAI в .env пойман");
expect(types.some((t) => t.startsWith("stripe_live_key@")), "живой ключ Stripe пойман");
expect(types.includes("google_key@src/config.js"), "ключ Google пойман");
expect(types.includes("aws_key@server/aws.js"), "ключ AWS пойман");
expect(types.includes("supabase_service_role@src/App.jsx"), "service_role JWT пойман");
expect(
  findings.some((f) => f.type === "supabase_service_role" && f.inClientCode === true),
  "service_role помечен как «в клиентском коде»",
);
expect(types.includes("private_key@keys/deploy.pem"), "приватный ключ пойман");
expect(types.some((t) => t.startsWith("hardcoded_secret@")), "захардкоженный пароль пойман");
expect(!types.some((t) => t.endsWith("@README.md")), "чистый README не даёт ложных находок");
expect(
  !findings.some((f) => f.masked.includes(openaiBody)),
  "секреты в отчёте замаскированы (полного ключа нет)",
);
expect(
  explained.every(
    (f) =>
      f.texts.en.title &&
      f.texts.en.explanation &&
      f.texts.en.fix.length > 0 &&
      f.texts.ru.title &&
      f.texts.ru.explanation &&
      f.texts.ru.fix.length > 0,
  ),
  "у каждой находки есть заголовок, объяснение и шаги починки на ОБОИХ языках",
);
// Тексты EN и RU действительно разные (двуязычие реально работает).
expect(
  explained.every((f) => f.texts.en.title !== f.texts.ru.title),
  "тексты находки отличаются между EN и RU",
);

// --- Группировка ---
// Два разных ключа одного типа в одном файле → ОДНА карточка со списком из 2 строк.
const awsInMulti = findings.filter(
  (f) => f.type === "aws_key" && f.file === "multi-keys.js",
);
expect(awsInMulti.length === 1, "один тип в одном файле — одна карточка (группировка)");
expect(
  (awsInMulti[0]?.lines?.length ?? 0) === 2,
  "в карточке список из 2 строк (обе строки собраны)",
);
// Один тип в РАЗНЫХ файлах → РАЗНЫЕ карточки (aws_key есть и в server/aws.js).
expect(
  findings.filter((f) => f.type === "aws_key").length === 2,
  "один тип в разных файлах — разные карточки",
);
// РАЗНЫЕ типы в одном файле → отдельные карточки (src/config.js: stripe/google/hardcoded).
const cfgTypes = findings.filter((f) => f.file === "src/config.js").map((f) => f.type);
expect(
  new Set(cfgTypes).size === cfgTypes.length && cfgTypes.length >= 3,
  "разные типы в одном файле — отдельные карточки",
);

// Разбор ссылок на GitHub
expect(parseGitHubUrl("https://github.com/vercel/next.js").repo === "next.js", "обычная ссылка разбирается");
expect(parseGitHubUrl("https://github.com/a/b.git/tree/main").repo === "b", "ссылка с .git и веткой разбирается");
try {
  parseGitHubUrl("https://evil.com/a/b");
  expect(false, "чужой домен отклонён");
} catch {
  expect(true, "чужой домен отклонён");
}

// --- Режим загрузки ZIP ---
console.log("\nZIP-режим:");

// 1) Архив с вложенной корневой папкой (как экспорт из Lovable/Bolt).
const zipNested = zipSync({
  "my-app/README.md": strToU8("# clean readme, ничего опасного"),
  "my-app/server/aws.js": strToU8(j('const k = "', V.awsMulti1, '";')),
  "my-app/src/config.js": strToU8(j('const key = "', V.googleZip, '";')),
});
const zf = filesFromZip(zipNested);
const zPaths = zf.map((f) => f.path);
expect(
  zPaths.includes("server/aws.js") && zPaths.includes("src/config.js"),
  "вложенная корневая папка учтена (общий корень 'my-app/' убран)",
);
const { findings: zFindings } = scanFiles(zf);
const zTypes = zFindings.map((f) => `${f.type}@${f.file}`);
expect(zTypes.includes("aws_key@server/aws.js"), "утечка в ZIP поймана (AWS)");
expect(zTypes.includes("google_key@src/config.js"), "утечка в ZIP поймана (Google)");

// 2) Архив без общей корневой папки — пути не трогаем.
const zipFlat = zipSync({
  "app.js": strToU8(j('const k = "', V.awsMulti2, '";')),
  "notes.txt": strToU8("просто заметки"),
});
const flatPaths = filesFromZip(zipFlat).map((f) => f.path);
expect(
  flatPaths.includes("app.js") && flatPaths.includes("notes.txt"),
  "без общего корня пути остаются как есть",
);

// 3) Не-ZIP (нет сигнатуры PK) → ошибка bad_zip.
try {
  filesFromZip(strToU8("это точно не zip-архив, а обычный текст"));
  expect(false, "не-ZIP отклонён (bad_zip)");
} catch (e) {
  expect(e instanceof ScanUserError && e.code === "bad_zip", "не-ZIP отклонён (bad_zip)");
}

// 4) Архив только с бинарным файлом → no_text_files.
try {
  const bin = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x00, 0x01, 0x02, 0x00]);
  filesFromZip(zipSync({ "logo.png": bin }));
  expect(false, "архив без текстовых файлов отклонён (no_text_files)");
} catch (e) {
  expect(
    e instanceof ScanUserError && e.code === "no_text_files",
    "архив без текстовых файлов отклонён (no_text_files)",
  );
}

// --- Режим вставки кода ---
// Роут /api/scan-text сканирует один псевдо-файл "pasted-code" тем же движком.
console.log("\nРежим вставки кода:");

const pastedSnippet = [
  "const config = {",
  j('  openaiKey: "', V.openai, '",'),
  '  region: "eu-central-1",',
  "};",
].join("\n");
const { findings: pFindings } = scanFiles([
  { path: "pasted-code", content: pastedSnippet },
]);
const pTypes = pFindings.map((f) => f.type);
expect(pTypes.includes("openai_key"), "фейковый ключ во вставленном тексте пойман");
expect(
  pFindings.every((f) => !f.masked.includes(openaiBody)),
  "ключ из вставленного текста замаскирован в отчёте",
);

// Чистый вставленный фрагмент не даёт ложных находок.
const { findings: cleanPasted } = scanFiles([
  { path: "pasted-code", content: "function add(a, b) {\n  return a + b;\n}" },
]);
expect(cleanPasted.length === 0, "чистый вставленный фрагмент не даёт находок");

// ============================================================================
// Борьба с ложными срабатываниями (v0.1.1)
// Три источника шума, найденные прогоном по 54 публичным вайбкод-репозиториям.
// На каждый баг — пара тестов: шум НЕ должен находиться, настоящая утечка
// того же типа — должна. Иначе, убирая шум, легко потерять детект.
// ============================================================================

// Короткий помощник: типы находок в одном псевдо-файле.
const scanOne = (path: string, content: string) =>
  scanFiles([{ path, content }]).findings;
const typesOf = (path: string, content: string) =>
  scanOne(path, content).map((f) => f.type);

// --- Баг 1: приватный ключ (PEM) — нужен не только заголовок, но и тело ---
console.log("\nБаг 1 — приватные ключи (PEM):");

// ЛОЖНОЕ: код собирает ключ из переменной окружения. Заголовок и подвал есть,
// тела ключа нет. Именно так выглядели все 17 ложных находок в реальном прогоне.
const pemFromEnv = [
  "const privateKey = [",
  j('  "', V.pemHeader, '",'),
  "  process.env.GOOGLE_PRIVATE_KEY,",
  j('  "', V.pemFooter, '",'),
  '].join("\\n");',
].join("\n");
expect(
  !typesOf("supabase/functions/sign/index.ts", pemFromEnv).includes("private_key"),
  "ключ из переменной окружения НЕ считается утечкой (было 17 ложных)",
);

// ЛОЖНОЕ: одинокий заголовок как строковая константа.
const pemHeaderOnly = j('const PEM_HEADER = "', V.pemHeader, '";');
expect(
  !typesOf("src/lib/crypto.ts", pemHeaderOnly).includes("private_key"),
  "одинокий заголовок PEM НЕ считается утечкой",
);

// ЛОЖНОЕ: заголовок и подвал вплотную, между ними ничего.
expect(
  !typesOf("src/empty.ts", [V.pemHeader, V.pemFooter].join("\n")).includes("private_key"),
  "заголовок + подвал без тела НЕ считается утечкой",
);

// ЛОЖНОЕ: шаблон с подстановкой {{PRIVATE_KEY}} в конфиге.
const pemTemplate = [V.pemHeader, "{{PRIVATE_KEY}}", V.pemFooter].join("\n");
expect(
  !typesOf("deploy/config.yaml", pemTemplate).includes("private_key"),
  "шаблон-заглушка вместо тела ключа НЕ считается утечкой",
);

// НАСТОЯЩЕЕ: полноценный файл ключа — по-прежнему находится.
expect(
  typesOf("keys/id_rsa", [V.pemHeader, V.pemBody, V.pemFooter].join("\n")).includes(
    "private_key",
  ),
  "настоящий файл приватного ключа по-прежнему находится",
);

// НАСТОЯЩЕЕ: ключ вписан прямо в JS-строку с экранированными переводами строк.
const pemInlineJs = j(
  'const key = "',
  V.pemHeader,
  "\\n",
  V.pemBody.split("\n").join("\\n"),
  "\\n",
  V.pemFooter,
  '";',
);
expect(
  typesOf("src/server/sign.js", pemInlineJs).includes("private_key"),
  "ключ, вписанный в JS-строку через \\n, находится",
);

// НАСТОЯЩЕЕ: посторонний шаблонный код ДАЛЬШЕ в файле не должен глушить находку.
// (Проверка окна: признак подстановки ищем только сразу за заголовком.)
const pemThenTemplate = [
  V.pemHeader,
  V.pemBody,
  V.pemFooter,
  "",
  "// ниже — совсем другой код, к ключу не относится",
  "const url = `${base}/api/v1`;",
  "const cfg = process.env.SOME_OTHER_VALUE;",
].join("\n");
expect(
  typesOf("keys/service-account.pem", pemThenTemplate).includes("private_key"),
  "шаблонный код ниже в файле не глушит настоящий ключ",
);

// НАСТОЯЩЕЕ: ключ без закрывающей строки (файл обрезан) — тело всё равно есть.
expect(
  typesOf("keys/truncated.pem", [V.pemHeader, V.pemBody].join("\n")).includes("private_key"),
  "ключ без закрывающей строки находится (тело на месте)",
);

// --- Баг 2: уровень .env зависит от содержимого ---
console.log("\nБаг 2 — уровень закоммиченного .env:");

// anon-ключ Supabase: публичен по замыслу, собираем честный JWT с role=anon.
const anonJwt = [
  b64u(JSON.stringify({ alg: "HS256", typ: "JWT" })),
  b64u(
    JSON.stringify({
      iss: "supabase",
      ref: "abcdefghijklmnop",
      role: "anon",
      iat: 1751500000,
      exp: 2067076000,
    }),
  ),
  b64u("anonanonanonanonanonanon"),
].join(".");

// ТОЛЬКО ПУБЛИЧНОЕ: ровно тот набор, что был в 12 из 15 репозиториев.
const envPublicOnly = [
  "VITE_SUPABASE_URL=https://abcdefghijklmnop.supabase.co",
  j("VITE_SUPABASE_ANON_KEY=", anonJwt),
  "VITE_SUPABASE_PROJECT_ID=abcdefghijklmnop",
  j("SUPABASE_PUBLISHABLE_KEY=", "sb_publishable_", "Ab9Qz7Lm3Np5Rt8Vw2Xy4"),
].join("\n");
const publicEnvFindings = scanOne(".env", envPublicOnly);
expect(
  publicEnvFindings.length === 1 && publicEnvFindings[0].type === "env_file_public",
  ".env только с публичными значениями → тип env_file_public (было critical)",
);
expect(
  publicEnvFindings[0]?.severity === "info",
  ".env только с публичными значениями → уровень «совет»",
);
expect(
  !publicEnvFindings.some((f) => f.type === "env_file"),
  ".env только с публичными значениями больше НЕ помечается как критичный",
);

// НАСТОЯЩЕЕ: service_role в .env — критично, как и раньше.
const envServiceRole = [
  "VITE_SUPABASE_URL=https://abcdefghijklmnop.supabase.co",
  j("SUPABASE_SERVICE_ROLE_KEY=", V.supabaseJwt),
].join("\n");
const srFindings = scanOne(".env", envServiceRole);
expect(
  srFindings.some((f) => f.type === "env_file" && f.severity === "critical"),
  ".env с service_role по-прежнему критичен",
);

// НАСТОЯЩЕЕ: публичный префикс НЕ делает значение безопасным.
// VITE_OPENAI_API_KEY — реальная утечка, причём худшего вида (уезжает в браузер).
const envViteSecret = [
  "VITE_SUPABASE_URL=https://abcdefghijklmnop.supabase.co",
  j("VITE_OPENAI_", "API_KEY=", V.openai),
].join("\n");
const viteFindings = scanOne(".env", envViteSecret);
expect(
  viteFindings.some((f) => f.type === "env_file" && f.severity === "critical"),
  "префикс VITE_ НЕ делает настоящий ключ безопасным — остаётся критично",
);

// НАСТОЯЩЕЕ: пароль базы данных в .env — критично.
const envDbPassword = [
  "APP_NAME=my-app",
  j("DATABASE_URL=", V.dbUrl),
].join("\n");
expect(
  scanOne(".env", envDbPassword).some(
    (f) => f.type === "env_file" && f.severity === "critical",
  ),
  ".env с паролем базы данных критичен",
);

// .env.example по-прежнему игнорируется целиком.
expect(
  scanOne(".env.example", envPublicOnly).length === 0,
  ".env.example не даёт находок",
);

// У нового типа есть заготовленные тексты на обоих языках.
const publicEnvExplained = cannedExplanations(publicEnvFindings);
expect(
  publicEnvExplained.every(
    (f) =>
      f.texts.en.title &&
      f.texts.en.explanation &&
      f.texts.en.fix.length > 0 &&
      f.texts.ru.title &&
      f.texts.ru.explanation &&
      f.texts.ru.fix.length > 0 &&
      f.texts.en.title !== f.texts.ru.title,
  ),
  "у env_file_public есть объяснение и шаги починки на обоих языках",
);

// --- Баг 3: hardcoded_secret перестал шуметь ---
console.log("\nБаг 3 — шум в hardcoded_secret:");

// ЛОЖНОЕ: имя переменной описывает НАЗВАНИЕ заголовка, а не значение.
expect(
  !typesOf("src/api.ts", j("const api", 'KeyHeader = "X-API-Key";')).includes(
    "hardcoded_secret",
  ),
  'apiKeyHeader = "X-API-Key" НЕ находка (название заголовка)',
);
expect(
  !typesOf("src/api.ts", j("const auth", 'TokenHeader = "Authorization";')).includes(
    "hardcoded_secret",
  ),
  'authTokenHeader = "Authorization" НЕ находка',
);

// ЛОЖНОЕ: очевидные заглушки.
const placeholders = [
  j("const password", 'Placeholder = "••••••••";'),
  j("const api", 'Key = "your-api-key-here";'),
  j("const ", 'secret = "changeme123";'),
  j("const ", 'apiKey = "<YOUR_KEY_HERE>";'),
  j("const ", 'password = "xxxxxxxx";'),
  j("const ", 'secret = "${process.env.SECRET}";'),
];
for (const line of placeholders) {
  expect(
    !typesOf("src/config.ts", line).includes("hardcoded_secret"),
    `заглушка НЕ находка: ${line.slice(0, 42)}…`,
  );
}

// ЛОЖНОЕ: публичные тестовые ключи из документации сервисов.
expect(
  !typesOf(
    "src/captcha.ts",
    j("const turnstile", 'Secret = "1x', '0000000000000000000000000000000AA";'),
  ).includes("hardcoded_secret"),
  "тестовый ключ Cloudflare Turnstile НЕ находка",
);
expect(
  !typesOf("src/pay.ts", j("const stripe", 'ApiKey = "sk', '_test_4eC39HqLyjWDarjtT1zdp7dc";')).includes(
    "hardcoded_secret",
  ),
  "тестовый ключ Stripe НЕ находка",
);

// ЛОЖНОЕ: значение — это ИМЯ переменной окружения, а не сам секрет.
expect(
  !typesOf("docs/setup.md", j("Нужные ", 'secrets = "ANTHROPIC_API_KEY";')).includes(
    "hardcoded_secret",
  ),
  "значение-имя переменной (ANTHROPIC_API_KEY) НЕ находка",
);

// ЛОЖНОЕ: имя переменной помечено как тестовое.
expect(
  !typesOf("src/test-utils.ts", j("const TEST_", 'SECRET = "abcdefghij";')).includes(
    "hardcoded_secret",
  ),
  "TEST_SECRET НЕ находка",
);

// ЛОЖНОЕ: одно словарное слово без цифр и символов.
expect(
  !typesOf("docs/readme.md", j("Хранение ", 'secret = "securely";')).includes(
    "hardcoded_secret",
  ),
  "словарное слово вместо значения НЕ находка",
);

// ЛОЖНОЕ: повторяющийся символ — нулевая энтропия.
expect(
  !typesOf("src/config.ts", j("const ", 'password = "00000000";')).includes(
    "hardcoded_secret",
  ),
  "значение из одного повторяющегося символа НЕ находка",
);

// ЛОЖНОЕ: camelCase-имя, помеченное как тестовое (нашлось в реальном прогоне).
expect(
  !typesOf("src/auth.test.ts", j("const test", 'Password = "testpass123";')).includes(
    "hardcoded_secret",
  ),
  "testPassword (camelCase) НЕ находка",
);

// ЛОЖНОЕ: значения внутри файла-образца — заглушки по определению.
expect(
  !typesOf(".env.example", j("ZENITH_", 'API_KEY="zk', '_test_Ab9Qz7Lm3Np5"')).includes(
    "hardcoded_secret",
  ),
  "значение в .env.example НЕ находка",
);
expect(
  !typesOf("config.sample.ts", j("export const ", 'apiKey = "Ab9Qz7Lm3Np5Rt8";')).includes(
    "hardcoded_secret",
  ),
  "значение в config.sample.ts НЕ находка",
);

// ЛОЖНОЕ: тестовый ключ с общепринятой пометкой _test_.
expect(
  !typesOf("src/pay.ts", j("const ", 'apiKey = "zk', '_test_Ab9Qz7Lm3Np5Rt8";')).includes(
    "hardcoded_secret",
  ),
  "ключ с пометкой _test_ НЕ находка",
);

// НАСТОЯЩЕЕ: но настоящий ключ провайдера в файле-образце ловится и там —
// правило hardcoded_secret отключено, правила провайдеров работают.
expect(
  typesOf(".env.example", j("OPENAI_", "API_KEY=", V.openai)).includes("openai_key"),
  "настоящий ключ OpenAI в .env.example всё равно находится",
);

// НАСТОЯЩЕЕ: имя testimonialSecret не считается тестовым (проверка границы правила).
expect(
  typesOf("src/x.ts", j("const testimonial", 'Secret = "Xk7$mQ92pLz!4vBn";')).includes(
    "hardcoded_secret",
  ),
  "testimonialSecret НЕ путается с тестовым именем — находка на месте",
);

// НАСТОЯЩЕЕ: сильный пароль со всеми классами символов.
expect(
  typesOf("src/db.ts", j("const db", 'Password = "Xk7$mQ92pLz!4vBn";')).includes(
    "hardcoded_secret",
  ),
  "сильный пароль в коде — находка",
);

// НАСТОЯЩЕЕ: случайный hex-токен.
expect(
  typesOf("src/auth.ts", j("const ", 'apiKey = "a8f3d9c2b7e14056', 'f9a3d8c1b6e2049f";')).includes(
    "hardcoded_secret",
  ),
  "случайный hex-токен в коде — находка",
);

// НАСТОЯЩЕЕ: слабый, но реальный пароль с цифрами — осознанно НЕ отсеиваем.
expect(
  typesOf("src/login.tsx", j("const admin", 'Password = "password123";')).includes(
    "hardcoded_secret",
  ),
  "слабый пароль password123 — всё ещё находка (это реальная дыра)",
);

// НАСТОЯЩЕЕ: пароль базы в документации — находка (так и было в реальном прогоне).
expect(
  typesOf("docs/deploy.md", j("POSTGRES_", 'PASS', 'WORD = "Wm4Kt8Zc2Qh6Nb1";')).includes(
    "hardcoded_secret",
  ),
  "пароль базы в документации — находка",
);

// НАСТОЯЩЕЕ: ключ провайдера в переменной с «шумным» именем всё равно ловится
// своим правилом (не теряем детект из-за фильтра имён).
expect(
  typesOf("src/api.ts", j("const api", 'KeyHeader = "', V.openai, '";')).includes(
    "openai_key",
  ),
  "настоящий ключ OpenAI ловится даже в переменной с именем ...Header",
);

// ============================================================================
// Сквозная проверка на двух архивах-приложениях (аналог test-app-with-leaks.zip
// и clean-app.zip, только собираются в памяти — отдельные файлы не нужны).
// «Дырявое» приложение должно давать находки, аккуратное — оставаться чистым.
// ============================================================================
console.log("\nДва архива-приложения (сквозная проверка):");

// 1) Приложение с утечками: полный набор типов.
const leakyZip = zipSync({
  "app/README.md": strToU8("# my app\nСобрано через Lovable."),
  "app/.env": strToU8(
    [
      "VITE_SUPABASE_URL=https://abcdefghijklmnop.supabase.co",
      j("SUPABASE_SERVICE_ROLE_KEY=", V.supabaseJwt),
      j("OPENAI_", "API_KEY=", V.openai),
    ].join("\n"),
  ),
  "app/src/config.ts": strToU8(j('export const stripeKey = "', V.stripeConfig, '";')),
  "app/keys/deploy.pem": strToU8([V.pemHeader, V.pemBody, V.pemFooter].join("\n")),
});
const leakyFindings = scanFiles(filesFromZip(leakyZip)).findings;
const leakyTypes = new Set(leakyFindings.map((f) => f.type));
expect(leakyFindings.length > 0, "«дырявый» архив даёт находки");
expect(
  leakyFindings.some((f) => f.severity === "critical"),
  "«дырявый» архив даёт критические находки",
);
for (const t of ["env_file", "openai_key", "supabase_service_role", "stripe_live_key", "private_key"]) {
  expect(leakyTypes.has(t as never), `«дырявый» архив: найден ${t}`);
}

// 2) Аккуратное приложение: секреты только в переменных окружения.
// Специально содержит все три бывших источника шума — и должно остаться чистым.
const cleanZip = zipSync({
  "app/README.md": strToU8("# my app\nНастрой переменные окружения в .env.local."),
  "app/package.json": strToU8('{ "name": "my-app", "private": true }'),
  "app/.env.example": strToU8(
    ["VITE_SUPABASE_URL=your-project-url", "VITE_SUPABASE_ANON_KEY=your-anon-key"].join("\n"),
  ),
  "app/src/lib/supabase.ts": strToU8(
    [
      'import { createClient } from "@supabase/supabase-js";',
      "export const supabase = createClient(",
      "  import.meta.env.VITE_SUPABASE_URL,",
      "  import.meta.env.VITE_SUPABASE_ANON_KEY,",
      ");",
    ].join("\n"),
  ),
  // Бывший шум №1: ключ собирается из переменной окружения.
  "app/supabase/functions/sign/index.ts": strToU8(
    [
      "const privateKey = [",
      j('  "', V.pemHeader, '",'),
      "  Deno.env.get(\"GOOGLE_PRIVATE_KEY\"),",
      j('  "', V.pemFooter, '",'),
      '].join("\\n");',
    ].join("\n"),
  ),
  // Бывший шум №2: название HTTP-заголовка и заглушка.
  "app/src/api.ts": strToU8(
    [
      j("const api", 'KeyHeader = "X-API-Key";'),
      j("const api", 'Key = "your-api-key-here";'),
      "export { apiKeyHeader, apiKey };",
    ].join("\n"),
  ),
  // Бывший шум №3: публичный тестовый ключ капчи.
  "app/src/captcha.ts": strToU8(
    j("export const turnstile", 'SiteKey = "1x', '00000000000000000000AA";'),
  ),
});
const cleanFindings = scanFiles(filesFromZip(cleanZip)).findings;
expect(
  cleanFindings.length === 0,
  `аккуратный архив остаётся чистым (найдено ${cleanFindings.length}: ${cleanFindings
    .map((f) => `${f.type}@${f.file}`)
    .join(", ")})`,
);

if (failed > 0) {
  console.log(`\n${failed} проверок провалено`);
  process.exit(1);
}
console.log("\nВсе проверки пройдены ✅");
