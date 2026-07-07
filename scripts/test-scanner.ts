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
    content: [
      V.pemHeader,
      j("MIIEvQIBADANBgkq", "hkiG9w0BAQEFAASC"),
      "(содержимое сокращено — для теста достаточно заголовка)",
      V.pemFooter,
    ].join("\n"),
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

if (failed > 0) {
  console.log(`\n${failed} проверок провалено`);
  process.exit(1);
}
console.log("\nВсе проверки пройдены ✅");
