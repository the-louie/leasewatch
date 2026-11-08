"""The marked strings in index.html and the English table in i18n.js say the same thing, and no key is dead."""
import json
import subprocess
import unittest
from html.parser import HTMLParser
from pathlib import Path

STATIC = Path(__file__).resolve().parent.parent / "leasewatch" / "static"
AREAS = ("nav.", "card.", "tool.", "opt.", "th.", "empty.", "sel.", "foot.", "row.", "aria.", "ph.")
VOID = {"input", "br", "img", "meta", "link", "hr"}


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


class I18nDriftTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.marks = Marks()
        cls.marks.feed((STATIC / "index.html").read_text(encoding="utf-8"))
        cls.strings = english()
        cls.en = cls.strings["en"]

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

    def test_no_dead_keys(self) -> None:
        used = {k for k, _ in self.marks.texts} | {k for _, _, k, _ in self.marks.attrs}
        dead = [k for k in self.en if k.startswith(AREAS) and k not in used]
        self.assertEqual(dead, [])

    def test_swedish_is_still_empty(self) -> None:
        self.assertEqual(self.strings["sv"], {})


if __name__ == "__main__":
    unittest.main()
