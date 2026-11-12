import type { Attachment } from "./eml.js";

export interface AttachmentFlag {
  id: string;
  points: number;
  title: string;
  detail: string;
}

const EXEC = new Set(["exe", "scr", "bat", "cmd", "com", "pif", "vbs", "vbe", "js", "jse", "wsf", "wsh", "ps1", "msi", "jar", "lnk", "hta", "cpl", "reg", "dll", "iso", "img", "vhd", "one"]);
const MACRO = new Set(["docm", "xlsm", "pptm", "dotm", "xlam"]);
const ARCHIVE = new Set(["zip", "rar", "7z", "gz", "tar", "ace", "cab"]);
const DOCS = new Set(["pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "jpg", "jpeg", "png", "gif", "rtf", "csv"]);

export function extensions(filename: string): string[] {
  const name = filename.replace(/[‮​-‏]/g, "");
  const parts = name.split(".");
  return parts.slice(1).map((p) => p.trim().toLowerCase());
}

export function analyzeAttachment(a: Attachment): AttachmentFlag[] {
  const flags: AttachmentFlag[] = [];
  const f = (id: string, points: number, title: string, detail: string) => flags.push({ id, points, title, detail });
  const exts = extensions(a.filename);
  const last = exts[exts.length - 1] ?? "";
  if (/[‮]/.test(a.filename)) f("att.rtlo", 35, "Right-to-left override in file name", "The name is visually reversed to disguise the real extension.");
  if (EXEC.has(last)) f("att.exec", 40, `Executable attachment (.${last})`, `${a.filename} can run code when opened.`);
  if (MACRO.has(last)) f("att.macro", 25, `Macro-enabled Office file (.${last})`, "Macros are a common first stage for malware.");
  if (ARCHIVE.has(last)) f("att.archive", 8, `Archive attachment (.${last})`, "Archives are used to bypass attachment scanners.");
  if (last === "html" || last === "htm" || last === "svg") f("att.html", 25, `HTML attachment (.${last})`, "Local HTML files are used for credential-harvesting pages.");
  if (exts.length >= 2 && DOCS.has(exts[exts.length - 2]!) && (EXEC.has(last) || ARCHIVE.has(last))) {
    f("att.double", 30, "Double extension", `${a.filename} pretends to be a .${exts[exts.length - 2]} file.`);
  }
  const head = a.head;
  const isMZ = head.length >= 2 && head[0] === 0x4d && head[1] === 0x5a;
  const isPK = head.length >= 2 && head[0] === 0x50 && head[1] === 0x4b;
  if (isMZ && !EXEC.has(last)) f("att.magic", 40, "Windows executable disguised by name", `${a.filename} starts with an MZ header but its extension is .${last || "none"}.`);
  if (isPK && last === "pdf") f("att.magic", 20, "ZIP content named as PDF", "The file signature does not match its extension.");
  if (a.size === 0) f("att.empty", 3, "Empty attachment", `${a.filename} has no content.`);
  return flags;
}
