/**
 * Tool output is treated as model output: it must flow through the exact same
 * markdown pipeline as assistant responses (markdown-it + highlight.js +
 * KaTeX + code copy button + typewriter pacing) — mirroring how Kun routes
 * every model-produced text through its Streamdown assistant renderer.
 *
 * This module normalizes raw tool payloads and converts them into markdown
 * source that AssistantMarkdown can render.
 */

export function decodeUnicodeEscapes(content: string) {
  return String(content || "").replace(/\\u([0-9a-fA-F]{4})/g, (_, hex) =>
    String.fromCharCode(Number.parseInt(hex, 16)),
  );
}

export function normalizeEmbeddedObservationContent(content: string) {
  return decodeUnicodeEscapes(content)
    .split("\n")
    .map((line) => {
      const separatorIndex = line.indexOf("=");
      if (separatorIndex <= 0) {
        return line;
      }
      const key = line.slice(0, separatorIndex);
      const rawValue = line.slice(separatorIndex + 1).trim();
      if (!["output", "context"].includes(key)) {
        return `${key}=${rawValue}`;
      }
      try {
        const parsed = JSON.parse(rawValue) as unknown;
        return `${key}=${JSON.stringify(normalizeToolDisplayValue(parsed), null, 2)}`;
      } catch {
        return `${key}=${rawValue}`;
      }
    })
    .join("\n");
}

export function normalizeToolDisplayValue(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map((item) => normalizeToolDisplayValue(item));
  }
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>).map(([key, item]) => [
        key,
        normalizeToolDisplayValue(item),
      ]),
    );
  }
  if (typeof value === "string") {
    const decoded = decodeUnicodeEscapes(value);
    if (decoded.includes("tool_key=") && (decoded.includes("\noutput=") || decoded.includes("\ncontext="))) {
      return normalizeEmbeddedObservationContent(decoded);
    }
    return decoded;
  }
  return value;
}

export function formatToolOutputContent(content: string) {
  try {
    const parsed = JSON.parse(content) as unknown;
    return JSON.stringify(normalizeToolDisplayValue(parsed), null, 2);
  } catch {
    return normalizeEmbeddedObservationContent(content);
  }
}

/** Pick a fence longer than any backtick run inside the content so embedded
 * ``` sequences can never break out of the code block. */
function fenceFor(content: string): string {
  const longestRun = content.match(/`+/g)?.reduce((max, run) => Math.max(max, run.length), 0) ?? 0;
  return "`".repeat(Math.max(3, longestRun + 1));
}

/** key=value observation lines (tool_key=… / output=…) read as logs, not prose. */
function looksLikeObservation(content: string): boolean {
  return /^[A-Za-z_][\w.-]*=/m.test(content);
}

/**
 * Convert a raw tool payload into markdown source for AssistantMarkdown:
 * - JSON payloads become a fenced ```json block (hljs highlight + copy button)
 * - key=value observation logs become a fenced ```text block
 * - anything else (natural language / markdown) renders as markdown directly
 */
export function toolOutputToMarkdown(content: string): string {
  const raw = String(content || "").trim();
  if (!raw) {
    return "";
  }
  try {
    const parsed = JSON.parse(raw) as unknown;
    const pretty = JSON.stringify(normalizeToolDisplayValue(parsed), null, 2);
    const fence = fenceFor(pretty);
    return `${fence}json\n${pretty}\n${fence}`;
  } catch {
    // Not JSON — fall through to text handling.
  }
  const normalized = normalizeEmbeddedObservationContent(raw);
  if (looksLikeObservation(normalized)) {
    const fence = fenceFor(normalized);
    return `${fence}text\n${normalized}\n${fence}`;
  }
  return normalized;
}
