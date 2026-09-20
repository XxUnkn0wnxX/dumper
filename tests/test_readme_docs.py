"""Check tracked documentation links, structure, navigation, and CLI tables."""

import ast
from html.parser import HTMLParser
from pathlib import Path
import re
import unittest
from urllib.parse import unquote, urlsplit


ROOT = Path(__file__).resolve().parents[1]
DOC_RELATIVE_PATHS = tuple(
    sorted(path.relative_to(ROOT) for path in (ROOT / "docs").glob("*.md"))
)
README_RELATIVE_PATHS = (
    Path("README.md"),
    Path("Helpers/README.md"),
    Path("tools/README.md"),
    Path("archives/wks-keys/README.md"),
    *DOC_RELATIVE_PATHS,
)
DOCUMENT_RELATIVE_PATHS = README_RELATIVE_PATHS + (Path("tests.md"),)
README_PATHS = tuple(ROOT / relative_path for relative_path in README_RELATIVE_PATHS)
DOCUMENT_PATHS = tuple(ROOT / relative_path for relative_path in DOCUMENT_RELATIVE_PATHS)
MARKDOWN_LINK = re.compile(r"\[[^\]]*\]\((<[^>]+>|[^)\s]+)\)")
MARKDOWN_HEADING = re.compile(r"^#{1,6}\s+(.+?)\s*#*\s*$", re.MULTILINE)
CLI_FLAG = re.compile(r"(?<![\w-])--?[a-z][a-z-]*")


class DetailsValidator(HTMLParser):
    """Track Markdown's HTML details blocks and their required summaries."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self._details = []
        self.errors = []

    def handle_starttag(self, tag, attrs):
        del attrs
        if tag == "details":
            self._details.append(False)
        elif tag == "summary":
            if not self._details:
                self.errors.append("summary is outside a details block")
            elif self._details[-1]:
                self.errors.append("details block has more than one summary")
            else:
                self._details[-1] = True

    def handle_endtag(self, tag):
        if tag != "details":
            return
        if not self._details:
            self.errors.append("closing details tag has no matching block")
            return
        if not self._details.pop():
            self.errors.append("details block is missing a summary")

    def finish(self):
        if self._details:
            self.errors.append("details block is not closed")


def markdown_anchors(text):
    """Return the GitHub-style anchors used by the repository's headings."""
    anchors = set()
    for heading in MARKDOWN_HEADING.findall(text):
        slug = re.sub(r"[^\w\s-]", "", heading.lower())
        slug = re.sub(r"\s+", "-", slug.strip())
        anchors.add(re.sub(r"-+", "-", slug))
    return anchors


def cli_flags(script):
    """Extract argparse option strings without importing the CLI module."""
    tree = ast.parse(script.read_text(encoding="utf-8"), filename=str(script))
    flags = {"-h", "--help"}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if not isinstance(node.func, ast.Attribute) or node.func.attr != "add_argument":
            continue
        option_nodes = list(node.args)
        for keyword in node.keywords:
            if keyword.arg == "option_strings":
                option_nodes.append(keyword.value)
        for option_node in option_nodes:
            if isinstance(option_node, ast.Constant) and isinstance(option_node.value, str):
                if option_node.value.startswith("-"):
                    flags.add(option_node.value)
            elif isinstance(option_node, (ast.List, ast.Tuple)):
                for item in option_node.elts:
                    if isinstance(item, ast.Constant) and isinstance(item.value, str):
                        if item.value.startswith("-"):
                            flags.add(item.value)
    return flags


class ReadmeDocumentationTests(unittest.TestCase):
    """Keep documentation links and examples aligned with shipped sources."""

    def test_readmes_have_valid_links_and_markdown_structure(self):
        for path in DOCUMENT_PATHS:
            relative_path = path.relative_to(ROOT)
            with self.subTest(readme=relative_path.as_posix()):
                self.assertTrue(path.is_file(), f"missing tracked README: {relative_path}")
                text = path.read_text(encoding="utf-8")
                self.assertNotIn(
                    str(Path.home()),
                    text,
                    f"{relative_path} contains a personal home path",
                )
                trailing_lines = [
                    str(line_number)
                    for line_number, line in enumerate(text.splitlines(), 1)
                    if line.rstrip() != line
                ]
                self.assertFalse(
                    trailing_lines,
                    f"{relative_path} has trailing whitespace on lines {', '.join(trailing_lines)}",
                )
                fence_count = len(re.findall(r"^\s*```", text, re.MULTILINE))
                self.assertEqual(
                    fence_count % 2,
                    0,
                    f"{relative_path} has {fence_count} Markdown fence markers",
                )

                details = DetailsValidator()
                details.feed(text)
                details.close()
                details.finish()
                self.assertEqual(
                    details.errors,
                    [],
                    f"{relative_path} has invalid details markup: {details.errors}",
                )

                destination_anchors = {
                    other_path: markdown_anchors(other_path.read_text(encoding="utf-8"))
                    for other_path in DOCUMENT_PATHS
                    if other_path.is_file()
                }
                for match in MARKDOWN_LINK.finditer(text):
                    target = match.group(1).strip("<>")
                    parsed = urlsplit(target)
                    if parsed.scheme or parsed.netloc:
                        self.assertNotRegex(
                            target,
                            r"github\.com/XxUnkn0wnxX/dumper/(?:blob|tree)/",
                            f"{relative_path} hard-codes a repository URL",
                        )
                        continue

                    self.assertFalse(
                        target.startswith("/"),
                        f"{relative_path} uses an absolute local link: {target}",
                    )
                    destination = path.parent / unquote(parsed.path) if parsed.path else path
                    self.assertTrue(
                        destination.is_file(),
                        f"{relative_path} links to missing local target {target}",
                    )
                    if parsed.fragment and destination.suffix.lower() == ".md":
                        anchors = destination_anchors.get(destination)
                        if anchors is None:
                            anchors = markdown_anchors(destination.read_text(encoding="utf-8"))
                        self.assertIn(
                            unquote(parsed.fragment),
                            anchors,
                            f"{relative_path} links to missing heading anchor {target}",
                        )

    def test_main_readme_links_every_dedicated_guide(self):
        main = (ROOT / "README.md").read_text(encoding="utf-8")
        for relative_path in DOC_RELATIVE_PATHS:
            self.assertIn(
                f"]({relative_path.as_posix()})",
                main,
                f"README.md has no direct guide link to {relative_path}",
            )
        self.assertIn(
            "](archives/wks-keys/README.md)",
            main,
            "README.md has no direct link to the archive inventory",
        )
        self.assertIn(
            "https://forum.videohelp.com/threads/408031-Dumping-Your-own-L3-CDM-with-Android-Studio",
            main,
            "README.md lost the primary VideoHelp reference",
        )

    def test_cli_flags_are_documented_with_examples(self):
        cli_tables = (
            (Path("init.py"), Path("docs/setup.md"), "Automatic environment setup"),
            (Path("full_auto.py"), Path("docs/full-auto.md"), "Controller arguments"),
            (Path("dump_keys.py"), Path("docs/dumper.md"), "Layout detection and options"),
            (Path("tools/setup_frida.py"), Path("docs/frida-setup.md"), "Frida server setup"),
            (Path("tools/regenerate_protobuf.py"), Path("docs/protobuf.md"), "Protobuf regeneration"),
        )
        for script_relative_path, doc_relative_path, section in cli_tables:
            with self.subTest(script=script_relative_path.as_posix()):
                script = ROOT / script_relative_path
                document = ROOT / doc_relative_path
                flags = cli_flags(script)
                text = document.read_text(encoding="utf-8")
                marker = f"## {section}\n"
                self.assertIn(marker, text, f"{doc_relative_path} has no {section!r} section")
                section_text = text.split(marker, 1)[1].split("\n## ", 1)[0]

                documented = set()
                rows_with_flags = 0
                for line in section_text.splitlines():
                    if not line.startswith("|"):
                        continue
                    cells = [cell.strip() for cell in line.split("|")]
                    if len(cells) != 6:
                        continue
                    row_flags = set(CLI_FLAG.findall(cells[1]))
                    if not row_flags:
                        continue
                    rows_with_flags += 1
                    documented.update(row_flags)
                    if row_flags == {"--non-interactive"}:
                        # Internal child flags should direct users to the
                        # controller rather than suggest a manual invocation.
                        self.assertIn("reserved", cells[2].lower())
                        self.assertIn("full_auto.py", cells[2])
                        self.assertIn("python full_auto.py", cells[4])
                        self.assertNotIn(script.name, cells[4])
                        continue
                    self.assertIn(
                        script.name,
                        cells[4],
                        f"{script_relative_path} option row has no {script.name} example: {cells[1]}",
                    )

                self.assertGreater(rows_with_flags, 0, f"no argument table rows found in {doc_relative_path}")
                self.assertEqual(
                    documented,
                    flags,
                    f"{script_relative_path} CLI/docs mismatch: "
                    f"missing={sorted(flags - documented)}, extra={sorted(documented - flags)}",
                )


if __name__ == "__main__":
    unittest.main()
