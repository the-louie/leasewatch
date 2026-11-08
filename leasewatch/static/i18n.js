/* leasewatch UI strings, loaded before app.js (both defer, so they run in this order).
 * Keys are "section.key". A value is plain text (app.js escapes it where it builds HTML) and may hold {n} or {name}
 * parameters. A value that depends on a count is { one: "…", other: "…" }, picked with Intl.PluralRules on {n}.
 * "en" is the fallback for a key a language lacks; a key missing everywhere shows as the key itself.
 * "sv" is filled in later. */
window.LW_STRINGS = {
  en: {
    "app.copied": "Copied",
    "app.click_to_copy": "Click to copy",
    "app.copy_hint": "selected: press Ctrl+C to copy",
    "count.devices": { one: "{n} device", other: "{n} devices" },
    "err.read_only": "Read-only: changes are off on this server",
  },
  sv: {},
};
