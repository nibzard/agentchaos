// Inert evidence rendering (spec 17.3, T036): one shared module
// every view uses to render evidence payloads. Hostile payload text
// becomes inert text — no active HTML, no tool execution, no
// automatic external retrieval from a log. URLs and data URIs render
// as visible text, never as href or src. Object references render as
// digests; the referenced bytes are read from the evidence store by
// an operator action, never fetched by this page.
//
// Rules the renderer keeps:
//   1. Every character of payload text reaches the output escaped;
//      nothing is silently dropped.
//   2. The only tags in the output are the ones this module writes.
//   3. No attribute of any emitted tag carries payload text.

import { escapeHtml } from "./overview";

/** The most payload bytes shown inline. Longer payloads are cut at a
 * character boundary and marked truncated; the full bytes live in
 * the evidence store. */
export const inlineLimit = 2000;

/** Control characters (C0, DEL, C1 minus the newline family) render
 * as their visible escape form, so a terminal-control or RTL-override
 * trick cannot smuggle meaning through a text node. */
function neutralizeControls(text: string): string {
  return [...text].map((character) => {
    const code = character.codePointAt(0)!;
    if (character === "\n") return "\n";
    if (character === "\t") return "\t";
    if (code < 0x20 || code === 0x7f ||
      (code >= 0x80 && code <= 0x9f)) {
      return `\\u{${code.toString(16).padStart(2, "0")}}`;
    }
    // Bidi overrides and join controls disguise text; name them.
    if (code === 0x202e || code === 0x202d || code === 0x200e ||
      code === 0x200f || code === 0x2066 || code === 0x2067 ||
      code === 0x2068 || code === 0x2069 || code === 0x200b ||
      code === 0x200c || code === 0x200d || code === 0xfeff) {
      return `\\u{${code.toString(16)}}`;
    }
    return character;
  }).join("");
}

export interface InlinePayload {
  readonly text: string;
  readonly redacted: boolean;
  readonly truncated: boolean;
}

/** Render an inline payload as inert text. */
export function renderInline(payload: InlinePayload): string {
  const neutralized = neutralizeControls(payload.text);
  const cut = neutralized.length > inlineLimit;
  const visible = cut
    ? neutralized.slice(0, inlineLimit) : neutralized;
  const notes = [
    payload.redacted ? "redacted at the source" : null,
    payload.truncated ? "truncated at the source" : null,
    cut ? `showing the first ${inlineLimit} characters; read the ` +
      `full payload from the evidence store` : null,
  ].filter((note): note is string => note !== null);
  return `<span class="payload inline">` +
    `${escapeHtml(visible)}</span>` +
    (notes.length === 0 ? ""
      : ` <span class="payload notes">${notes.join("; ")}</span>`);
}

/** Render an object reference: a digest to read elsewhere, never a
 * fetch made here. A missing digest is stated, not papered over. */
export function renderObjectRef(digest: string | null): string {
  const body = digest === null ? "digest missing"
    : escapeHtml(digest);
  return `<span class="payload object-ref"><code>${body}</code> — ` +
    `read the raw content from the evidence store; this page does ` +
    `not fetch it</span>`;
}

/** Render a metadata-only marker. */
export function renderMetadataOnly(): string {
  return `<span class="payload metadata-only">metadata only; no ` +
    `payload bytes were recorded</span>`;
}

/** True when a rendered payload string is inert: no tag attributes
 * carry payload text, and no link or image element exists. Exported
 * for the hostile-input suite and for page-level checks. */
export function isInertHtml(html: string): boolean {
  // No anchor, image, iframe, embed, object, video, audio, source,
  // track, or form control may appear anywhere in payload output.
  // Escaped payload text (&lt;img…) is inert and must pass.
  const reActiveTag = new RegExp("<(a|img|iframe|embed|object|video|" +
    "audio|source|track|form|button|input|link|meta|base|svg|math|" +
    "style|script)\\b", "i");
  if (reActiveTag.test(html)) {
    return false;
  }
  // No event-handler attribute may appear on any real tag.
  if (/<[a-z][^>]*\son[a-z]+\s*=/i.test(html)) {
    return false;
  }
  // No URL-bearing attribute may appear on any real tag.
  const reUrlAttr = new RegExp("<[a-z][^>]*\\s(href|src|srcset|" +
    "action|formaction|data|xlink:href)\\s*=", "i");
  if (reUrlAttr.test(html)) {
    return false;
  }
  return true;
}
