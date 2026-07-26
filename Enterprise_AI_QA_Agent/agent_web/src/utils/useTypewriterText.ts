import { onBeforeUnmount, ref, watch, type Ref } from "vue";

/**
 * Paces streaming text so it reveals sequentially, decoupled from SSE chunk
 * sizes — ported from Kun's useTypewriterText. Without this, one bursty chunk
 * spans several markdown blocks and every affected line appears at once.
 */

// Reveal ~1/8 of the outstanding backlog per frame…
const CATCHUP_DIVISOR = 8;
// …but never more than this, so a huge backlog drains as fast typing instead
// of a near-instant wall of text.
const MAX_STEP_PER_FRAME = 32;

const COMBINING_MARK_REGEX = /\p{Mark}/u;
const VARIATION_SELECTOR_REGEX = /\p{Variation_Selector}/u;
const IntlWithSegmenter = Intl as unknown as {
  Segmenter?: new (
    locales?: string | string[],
    options?: { granularity?: "grapheme" | "word" | "sentence" },
  ) => { segment(input: string): Iterable<{ index: number; segment: string }> };
};
const graphemeSegmenter =
  typeof IntlWithSegmenter.Segmenter === "function"
    ? new IntlWithSegmenter.Segmenter(undefined, { granularity: "grapheme" })
    : null;

export function nextVisibleLength(current: number, target: number): number {
  if (current === target) return current;
  // Live text shrank (interrupt / reset) — snap, never animate backwards.
  if (current > target) return target;
  const backlog = target - current;
  return current + Math.min(MAX_STEP_PER_FRAME, Math.max(1, Math.ceil(backlog / CATCHUP_DIVISOR)));
}

function fallbackBoundary(text: string, length: number): number {
  let boundary = length;
  const previousCode = text.charCodeAt(boundary - 1);
  if (previousCode >= 0xd800 && previousCode <= 0xdbff && boundary < text.length) {
    boundary += 1;
  }

  while (boundary < text.length) {
    const codePoint = text.codePointAt(boundary);
    if (codePoint == null) break;
    const char = String.fromCodePoint(codePoint);
    if (COMBINING_MARK_REGEX.test(char) || VARIATION_SELECTOR_REGEX.test(char)) {
      boundary += char.length;
      continue;
    }
    if (codePoint === 0x200d) {
      boundary += 1;
      const joinedCodePoint = text.codePointAt(boundary);
      if (joinedCodePoint == null) break;
      boundary += String.fromCodePoint(joinedCodePoint).length;
      continue;
    }
    break;
  }

  return boundary;
}

function nextTextBoundary(text: string, visibleLength: number): number {
  const length = Math.max(0, Math.min(visibleLength, text.length));
  if (length === 0 || length === text.length) return length;

  if (graphemeSegmenter) {
    for (const segment of graphemeSegmenter.segment(text)) {
      const boundary = segment.index + segment.segment.length;
      if (boundary >= length) return boundary;
    }
  }

  return fallbackBoundary(text, length);
}

export function visibleTextForTypewriter(text: string, visibleLength: number): string {
  return text.slice(0, nextTextBoundary(text, visibleLength));
}

/**
 * Returns a reactive string that reveals `text` progressively while
 * `streaming` is true, and shows it fully once streaming settles.
 */
export function useTypewriterText(
  text: Ref<string>,
  streaming: Ref<boolean>,
): Ref<string> {
  const paced = ref(text.value);
  // Start at the current length so re-entering a thread mid-turn does not
  // replay everything already on screen.
  let visibleLength = text.value.length;
  let target = text.value.length;
  let raf = 0;

  const stop = () => {
    if (raf) {
      cancelAnimationFrame(raf);
      raf = 0;
    }
  };

  const tick = () => {
    const next = nextVisibleLength(visibleLength, target);
    if (next !== visibleLength) {
      visibleLength = next;
      paced.value = visibleTextForTypewriter(text.value, visibleLength);
    }
    raf = requestAnimationFrame(tick);
  };

  const sync = () => {
    target = text.value.length;
    if (!streaming.value) {
      stop();
      visibleLength = target;
      paced.value = text.value;
      return;
    }
    if (!raf) {
      raf = requestAnimationFrame(tick);
    }
  };

  watch([text, streaming], sync, { immediate: true });
  onBeforeUnmount(stop);

  return paced;
}
