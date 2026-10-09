// Untrusted-text helpers shared by the intel layer (validate at the door) and the output layer (escape on the way out).
// Everything that came from OSV, CISA, EPSS or a lockfile is hostile until it passes through here.

// control characters (C0, DEL, C1, line and paragraph separators) and invisible or bidirectional formatting characters
const CONTROL = /[\u0000-\u001f\u007f-\u009f\u2028\u2029]/g;
const INVISIBLE = /[\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff]/g;

/** shorten, then replace control characters with spaces and drop invisible/bidi formatting characters */
export function clean(s, max = 300) {
  return String(s ?? '').slice(0, max).replace(CONTROL, ' ').replace(INVISIBLE, '');
}

/**
 * Text that is rendered as Markdown (issue tables, notes, the job summary): neutralize HTML, Markdown control
 * characters, @mentions, autolinks (scheme://, www.), math ($) and GH-123 issue references.
 */
export function md(s, max = 300) {
  return clean(s, max)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/[\\`*_{}[\]()#+!|~$]/g, (c) => '\\' + c)
    .replace(/@/g, '@\u200b')
    .replace(/([a-z][a-z0-9+.-]*):\/\//gi, '$1\u200b://')
    .replace(/www\./gi, 'www\u200b.')
    .replace(/(GH)-(?=\d)/gi, '$1\u200b-');
}

/** plain text for fenced draft blocks: no backticks (fence breakout), no control characters, one line */
export const plain = (s, max = 300) => clean(s, max).replace(/`/g, "'");

/**
 * Text inside a Markdown code span (used in table cells). Backticks cannot appear in a code span, so they become
 * apostrophes; "|" is escaped for the table. Nothing else is escaped, because code spans show backslashes literally.
 */
export function codeSpan(s, max = 120) {
  const t = clean(s, max).replace(/`/g, "'").replace(/\|/g, '\\|').trim();
  return '`' + (t || 'n/a') + '`';
}

/**
 * A fenced code block as an array of lines. The fence is longer than any backtick run in the content, so the content
 * cannot close it, whatever it contains (CommonMark: a closing fence needs at least as many backticks as the opener).
 */
export function fenced(lines, info = 'text') {
  const text = lines.join('\n');
  let longest = 0;
  for (const m of text.matchAll(/`+/g)) longest = Math.max(longest, m[0].length);
  const fence = '`'.repeat(Math.max(3, longest + 1));
  return [fence + info, text, fence];
}

// --- validators: return the clean value, or null when the input is not what that field must look like ---

export const SEVERITIES = ['LOW', 'MODERATE', 'MEDIUM', 'HIGH', 'CRITICAL'];
export const severity = (s) => {
  const u = typeof s === 'string' ? s.trim().toUpperCase() : '';
  return SEVERITIES.includes(u) ? u : null;
};

/** YYYY-MM-DD only (CISA KEV dateAdded and dueDate) */
export const isoDate = (s) => (typeof s === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(s) && Number.isFinite(Date.parse(s)) ? s : null);

/** a version string as semver, Maven, PyPI (epochs, post releases), Debian-style or a commit hash: no spaces, quotes, backticks or markup */
export const version = (s) => (typeof s === 'string' && /^[A-Za-z0-9][A-Za-z0-9.+_~:!-]{0,63}$/.test(s) ? s : null);

/** an https link that is safe to print inside <...> and to click: no whitespace, brackets, quotes, backticks or backslashes */
export const httpsUrl = (u, max = 300) => (typeof u === 'string' && u.length <= max && /^https:\/\/[A-Za-z0-9._~:/?#@!$&'*+,;=%-]+$/.test(u) ? u : null);

/** encodeURIComponent plus the characters it leaves alone that matter in Markdown links */
export const encodeId = (s) => encodeURIComponent(String(s)).replace(/[!'()*]/g, (c) => '%' + c.charCodeAt(0).toString(16).toUpperCase());

/** a short plain string from untrusted JSON: strings only, cleaned, capped; anything else becomes '' */
export const str = (s, max = 200) => (typeof s === 'string' ? clean(s, max).trim() : '');
