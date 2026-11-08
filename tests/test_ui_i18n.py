"""The string tables in i18n.js: the marked strings in index.html match English, every key is used, the Swedish table has
the same keys and parameters as the English one, and app.js escapes the texts it puts into HTML."""
import json
import re
import subprocess
import unittest
from html.parser import HTMLParser
from pathlib import Path

STATIC = Path(__file__).resolve().parent.parent / "leasewatch" / "static"
VOID = {"input", "br", "img", "meta", "link", "hr"}
PARAM = re.compile(r"\{(\w+)\}")
# words that read the same in Swedish: names, units, and the tag syntax (owner: is parsed by app.js, so it stays).
# A Swedish value equal to its English one is allowed when it has no lowercase letter outside {params}, or when every
# word in it is one of these
NEUTRAL_WORDS = {"IPv6", "Wi-Fi", "dBm", "min", "h", "d", "Status", "Port", "Online", "Offline", "online", "offline",
                 "client-id", "iot", "owner", "alex", "leases"}
# the t() calls whose key is computed: t's own definition and kindText (both "key"), and applyI18n (the marks)
COMPUTED_KEY_ARGS = {"key", "el.dataset.i18n", "pair.slice(i + 1"}


class Marks(HTMLParser):
    """Collects (key, collapsed text) for data-i18n and (key, attribute value) for data-i18n-attr pairs."""

    def __init__(self) -> None:
        super().__init__()
        self.texts: list[tuple[str, str]] = []
        self.attrs: list[tuple[str, str, str]] = []
        self.stack: list[list] = []  # [tag, key, text parts]

    def handle_starttag(self, tag, attrs) -> None:
        a = dict(attrs)
        for pair in (a.get("data-i18n-attr") or "").split(","):
            if pair:
                name, key = pair.split(":")
                self.attrs.append((tag, name, key, a.get(name)))
        if tag not in VOID:
            self.stack.append([tag, a.get("data-i18n"), []])

    def handle_endtag(self, tag) -> None:
        if tag in VOID or not self.stack:
            return
        el = self.stack.pop()
        if el[1]:
            self.texts.append((el[1], " ".join("".join(el[2]).split())))

    def handle_data(self, data) -> None:
        for el in self.stack:
            if el[1]:
                el[2].append(data)


def english() -> dict:
    js = f"const window = {{}}; eval(require('fs').readFileSync({json.dumps(str(STATIC / 'i18n.js'))}, 'utf8'));" \
         "process.stdout.write(JSON.stringify(window.LW_STRINGS));"
    r = subprocess.run(["node", "-e", js], capture_output=True, text=True, timeout=30, check=True)
    return json.loads(r.stdout)


def app_keys() -> list[str]:
    """The keys app.js passes to t() as a literal."""
    return re.findall(r"\bt\(\"([^\"]+)\"", (STATIC / "app.js").read_text(encoding="utf-8"))


def kind_keys() -> list[str]:
    """The kind.* keys kindText() builds: one per kind the events filter offers."""
    src = (STATIC / "app.js").read_text(encoding="utf-8")
    block = re.search(r"const EV_KINDS = (.*?);\n", src, re.S).group(1)
    return ["kind." + k for k in re.findall(r"\"([a-z_]+)\"", block)]


def computed_key_args() -> set[str]:
    """The argument text of every t() call whose key is not a string literal."""
    return set(re.findall(r"\bt\((?![\")])([^,)]*)", (STATIC / "app.js").read_text(encoding="utf-8")))


def forms(v) -> dict:
    """A value as {form: text}: a plain string is the one form ""; a plural value is its forms."""
    return v if isinstance(v, dict) else {"": v}


def neutral(text: str) -> bool:
    """A text that may read the same in both languages (see NEUTRAL_WORDS)."""
    bare = PARAM.sub("", text)
    return not re.search(r"[a-zåäö]", bare) or all(w in NEUTRAL_WORDS for w in re.findall(r"[A-Za-zåäöÅÄÖ][\w-]*", bare))


def unescaped_t(src: str) -> list[str]:
    """The lines that put a ${t(...)} into HTML without esc(): a line with innerHTML or insertAdjacentHTML, and the
    following lines of a template literal such a line opens and does not close (up to a line ending in a backtick and
    ';' or ')'). Line based: an HTML string built in a variable first and assigned later is not followed."""
    bad, inside = [], False
    for n, line in enumerate(src.splitlines(), 1):
        sink = "innerHTML" in line or "insertAdjacentHTML" in line
        if (sink or inside) and "${t(" in line:
            bad.append(f"{n}: {line.strip()}")
        if sink and not inside and line.count("`") % 2:
            inside = True
        elif inside and re.search(r"`[;)]+$", line.rstrip()):
            inside = False
    return bad


class I18nDriftTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.marks = Marks()
        cls.marks.feed((STATIC / "index.html").read_text(encoding="utf-8"))
        cls.strings = english()
        cls.en, cls.sv = cls.strings["en"], cls.strings["sv"]

    def need_sv(self) -> None:
        """Skip a Swedish cross-check only while the table is wholly empty: a half-filled one is checked (and fails)."""
        if len(self.sv) == 0:
            self.assertEqual(self.sv, {})
            self.skipTest("sv table not filled yet")

    def test_there_are_marks(self) -> None:
        self.assertGreater(len(self.marks.texts), 50)
        self.assertGreater(len(self.marks.attrs), 20)

    def test_text_marks_match_english(self) -> None:
        for key, text in self.marks.texts:
            self.assertIn(key, self.en, key)
            self.assertEqual(text, self.en[key], key)

    def test_attribute_marks_match_english(self) -> None:
        for tag, name, key, value in self.marks.attrs:
            self.assertIn(key, self.en, key)
            self.assertIsNotNone(value, f"<{tag}> has no {name} for {key}")
            self.assertEqual(" ".join(value.split()), self.en[key], f"{key} ({name})")

    # every key in every section is used: by a mark in index.html, a t("…") literal in app.js, or a key app.js builds
    # (kind.* in kindText, one per EV_KINDS kind); the next test keeps that list of built keys complete
    def test_no_dead_keys(self) -> None:
        used = {k for k, _ in self.marks.texts} | {k for _, _, k, _ in self.marks.attrs} | set(app_keys()) | set(kind_keys())
        dead = [k for k in self.en if k not in used]
        self.assertEqual(dead, [])

    def test_no_other_computed_keys(self) -> None:
        self.assertEqual(computed_key_args(), COMPUTED_KEY_ARGS, "a new computed t() key: add its keys to test_no_dead_keys")

    def test_app_keys_exist_in_english(self) -> None:
        keys = app_keys()
        self.assertGreater(len(keys), 50)
        self.assertEqual([k for k in keys if k not in self.en], [])

    def test_every_filter_kind_has_a_label(self) -> None:
        keys = kind_keys()
        self.assertEqual(len(keys), 23)
        self.assertEqual([k for k in keys if k not in self.en], [])

    def test_tables_are_the_only_languages(self) -> None:
        self.assertEqual(set(self.strings), {"en", "sv"})
        self.assertGreater(len(self.en), 200)

    def test_swedish_keys_exist_in_english(self) -> None:
        self.assertEqual(sorted(set(self.sv) - set(self.en)), [])

    def test_no_empty_values(self) -> None:
        for name, table in (("en", self.en), ("sv", self.sv)):
            empty = [k for k, v in table.items() if not v or any(not isinstance(s, str) or not s.strip() for s in forms(v).values())]
            self.assertEqual(empty, [], f"empty values in {name}")

    def test_english_plurals_have_one_and_other(self) -> None:
        bad = [k for k, v in self.en.items() if isinstance(v, dict) and not {"one", "other"} <= set(v)]
        self.assertEqual(bad, [])
        self.assertIn("count.devices", [k for k, v in self.en.items() if isinstance(v, dict)])

    def test_swedish_has_every_english_key(self) -> None:
        self.need_sv()
        self.assertEqual(sorted(set(self.en) - set(self.sv)), [], "keys missing from sv")

    # the same {param} names in both languages, form by form for a plural value
    def test_swedish_params_match_english(self) -> None:
        self.need_sv()
        bad = []
        for k, ev in self.en.items():
            if k not in self.sv:
                continue
            sv = self.sv[k]
            if isinstance(ev, dict) != isinstance(sv, dict):
                bad.append(f"{k}: plural in one language only")
                continue
            if isinstance(sv, dict) and not {"one", "other"} <= set(sv):
                bad.append(f"{k}: sv plural lacks one/other")
                continue
            for form, text in forms(ev).items():
                if form in forms(sv) and set(PARAM.findall(forms(sv)[form])) != set(PARAM.findall(text)):
                    bad.append(f"{k}{'.' + form if form else ''}: {forms(sv)[form]!r} vs {text!r}")
        self.assertEqual(bad, [])

    # an untranslated value (the English one copied) is flagged, unless the text is language neutral (see NEUTRAL_WORDS)
    def test_swedish_values_are_translated(self) -> None:
        self.need_sv()
        same = [k for k, v in self.sv.items() if k in self.en and v == self.en[k] and not all(neutral(s) for s in forms(v).values())]
        self.assertEqual(same, [], "sv values identical to en")

    def test_neutral_rule(self) -> None:
        self.assertTrue(all(map(neutral, ["MAC", "IPv6", "Wi-Fi", "SSID", "NEW", "{n} min", "< 1 min", "{d} d {h} h", "{name}: OK",
                                          "iot, owner:alex"])))
        self.assertFalse(any(map(neutral, ["Copied", "{n} devices", "Last AP", "Wi-Fi networks"])))

    # a ${t(…)} put into HTML must go through esc(): the table's texts are plain text
    def test_html_sinks_escape_texts(self) -> None:
        src = (STATIC / "app.js").read_text(encoding="utf-8")
        self.assertEqual(unescaped_t(src), [])
        # the checker sees a one-line sink and the lines of the drawer's multi-line template literal
        self.assertTrue(unescaped_t(src.replace('${esc(t("row.new"))}', '${t("row.new")}')))
        self.assertTrue(unescaped_t(src.replace('${esc(t("drawer.history"))}', '${t("drawer.history")}')))
        self.assertEqual(unescaped_t('x.title = `${t("a")}`;\ny.innerHTML = `\n${esc(t("b"))}`;\nz.title = `${t("c")}`;'), [])


if __name__ == "__main__":
    unittest.main()
