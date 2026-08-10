// Публичный API движка defcod-engine.
// Всё, что нужно приложению поверх движка, экспортируется отсюда.

export { scanFiles, type ScannedFile, type ScanOutput } from "./engine";
export {
  KEY_RULES,
  maskSecret,
  looksLikePlaceholder,
  type Finding,
  type FindingType,
  type Severity,
} from "./rules";
// Списки-фильтры шума и их проверки. Вынесены в публичный API, чтобы их было
// легко пополнять и тестировать снаружи движка.
export {
  PUBLIC_ENV_NAMES,
  PUBLIC_ENV_PREFIXES,
  PUBLIC_ENV_SUFFIXES,
  SENSITIVE_ENV_MARKERS,
  isBrowserPublicName,
  assignmentNameAt,
  KNOWN_PUBLIC_TEST_VALUES,
  classifyEnvFile,
  isPublicEnvVar,
  isLikelySecretValue,
  isKnownPublicTestValue,
  isExampleFile,
  hasPrivateKeyBody,
  shannonEntropy,
  type EnvClassification,
} from "./rules";
export {
  fetchRepoFiles,
  parseGitHubUrl,
  ScanUserError,
  type ScanErrorCode,
  type FetchRepoOptions,
} from "./github";
export { filesFromZip, looksLikeZip, MAX_ZIP_BYTES } from "./zip";
export {
  fetchRepoHistory,
  scanRepoHistory,
  extractAddedLines,
  HISTORY_PROVIDER_LABEL,
  type FetchHistoryOptions,
  type HistoryFetchResult,
  type HistoryScanResult,
  type CommitDiff,
} from "./history";
export {
  cannedExplanations,
  type ExplainedFinding,
  type FindingTexts,
  type Lang,
} from "./explain";
