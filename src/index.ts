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
export {
  fetchRepoFiles,
  parseGitHubUrl,
  ScanUserError,
  type ScanErrorCode,
} from "./github";
export { filesFromZip, looksLikeZip, MAX_ZIP_BYTES } from "./zip";
export {
  cannedExplanations,
  type ExplainedFinding,
  type FindingTexts,
  type Lang,
} from "./explain";
