import MarkdownIt from "markdown-it";
import hljs from "highlight.js/lib/common";
import texmath from "markdown-it-texmath";
import katex from "katex";

/**
 * Shared markdown renderer for assistant output. Mirrors the capabilities of
 * Kun's Streamdown pipeline (GFM + syntax-highlighted code + KaTeX math) but
 * built on the Vue-friendly markdown-it stack.
 */
const md: MarkdownIt = new MarkdownIt({
  html: false, // never trust raw HTML from the model
  linkify: true,
  breaks: true, // chat models rely on single newlines as soft breaks
  highlight: (code: string, language: string): string => {
    const lang = (language || "").toLowerCase();
    let inner = "";
    if (lang && hljs.getLanguage(lang)) {
      try {
        inner = hljs.highlight(code, { language: lang, ignoreIllegals: true }).value;
      } catch {
        inner = escapeHtml(code);
      }
    } else {
      try {
        inner = hljs.highlightAuto(code).value;
      } catch {
        inner = escapeHtml(code);
      }
    }
    const label = lang || "text";
    // The copy button is wired up via event delegation in AssistantMarkdown.vue.
    return (
      `<div class="assistant-code-block" data-code-lang="${escapeHtml(label)}">` +
      `<div class="assistant-code-head">` +
      `<span class="assistant-code-lang">${escapeHtml(label)}</span>` +
      `<button type="button" class="assistant-code-copy" data-code-copy aria-label="Copy code">复制</button>` +
      `</div>` +
      `<pre class="hljs"><code class="hljs language-${escapeHtml(label)}">${inner}</code></pre>` +
      `</div>`
    );
  },
});

md.use(texmath, {
  engine: katex,
  delimiters: "dollars", // $inline$ and $$block$$
  katexOptions: { throwOnError: false, errorColor: "#ef4444" },
});

// Render /api/v1/sessions/.../artifacts/.../content links as clickable download buttons.
const defaultLinkRender =
  md.renderer.rules.link_open ||
  ((tokens, idx, options, _env, self) => self.renderToken(tokens, idx, options));
md.renderer.rules.link_open = (tokens, idx, options, env, self) => {
  const token = tokens[idx];
  const href = token.attrGet("href") || "";
  if (/^https?:\/\//i.test(href)) {
    token.attrSet("target", "_blank");
    token.attrSet("rel", "noreferrer noopener");
  }
  // Artifact download links: add download attribute so the browser downloads
  // the file instead of navigating to it, and add a visual indicator class.
  if (/^\/api\/v1\/sessions\/[^/]+\/artifacts\//i.test(href)) {
    token.attrSet("download", "");
    token.attrSet("class", "artifact-download-link");
  }
  return defaultLinkRender(tokens, idx, options, env, self);
};

/**
 * Custom markdown-it plugin: auto-link bare artifact download URLs.
 *
 * markdown-it's built-in `linkify` only handles full URLs (http://, https://).
 * Artifact download URLs are relative paths like
 *   /api/v1/sessions/{id}/artifacts/{id}/content
 * which linkify ignores. This plugin detects such bare paths in text tokens
 * and wraps them in markdown link tokens so they render as clickable links
 * (and get the `artifact-download-link` class from the link_open rule above).
 */
function artifactAutoLink(md: MarkdownIt): void {
  const ARTIFACT_RE = /(^|[\s(：:])(\/api\/v1\/sessions\/[a-f0-9-]+\/artifacts\/[a-f0-9-]+\/content)(?=[\s).,;:!\?？。”》、]|$)/gi;

  md.core.ruler.push("artifact_auto_link", (state) => {
    // Obtain the Token constructor from an existing token (markdown-it does
    // not expose it as a static property on the instance or core namespace).
    const TokenCtor = state.tokens[0]?.constructor as any;

    for (const token of state.tokens) {
      if (token.type !== "inline") continue;
      const children = token.children;
      if (!children) continue;

      const newChildren: MarkdownIt.Token[] = [];
      for (const child of children) {
        if (child.type !== "text") {
          newChildren.push(child);
          continue;
        }
        const text = child.content;
        if (!ARTIFACT_RE.test(text)) {
          newChildren.push(child);
          continue;
        }
        ARTIFACT_RE.lastIndex = 0;
        let lastIndex = 0;
        let match: RegExpExecArray | null;
        while ((match = ARTIFACT_RE.exec(text)) !== null) {
          const prefix = match[1]; // whitespace or punctuation before the URL
          const url = match[2];
          const matchStart = match.index;
          const urlStart = matchStart + prefix.length;

          // Text before the match (if any)
          if (urlStart > lastIndex) {
            const before = text.slice(lastIndex, urlStart);
            const beforeToken = new TokenCtor("text", "", 0);
            beforeToken.content = before;
            newChildren.push(beforeToken);
          }

          // Create link_open token
          const linkOpen = new TokenCtor("link_open", "a", 1);
          linkOpen.attrSet("href", url);
          linkOpen.attrSet("download", "");
          linkOpen.attrSet("class", "artifact-download-link");
          newChildren.push(linkOpen);

          // Create text token with the URL as visible label
          const linkText = new TokenCtor("text", "", 0);
          linkText.content = url;
          newChildren.push(linkText);

          // Create link_close token
          const linkClose = new TokenCtor("link_close", "a", -1);
          newChildren.push(linkClose);

          lastIndex = matchStart + match[0].length;
        }
        // Remaining text after the last match
        if (lastIndex < text.length) {
          const after = text.slice(lastIndex);
          const afterToken = new TokenCtor("text", "", 0);
          afterToken.content = after;
          newChildren.push(afterToken);
        }
      }
      token.children = newChildren;
    }
  });
}

md.use(artifactAutoLink);

/** Strip the internal framework marker before rendering. */
export function displayAssistantContent(content: string): string {
  const marker = content.indexOf("[Framework]");
  return marker >= 0 ? content.slice(0, marker).trim() : content.trim();
}

export function renderAssistantMarkdown(content: string): string {
  const source = displayAssistantContent(content);
  if (!source) {
    return "";
  }
  return md.render(source);
}

function escapeHtml(content: string): string {
  return content
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}
