"""Let the verifier cite files that exist only in the reviewed commit."""

from pathlib import Path


def apply(root):
    path = root / "agents/verifier.py"
    text = path.read_text()
    for old, new in (
        (
            "    cited_file: str | None,\n    withdrawn_section: str,\n) -> str:",
            "    cited_file: str | None,\n    withdrawn_section: str,\n    citation: str | None = None,\n) -> str:",
        ),
        ('        cited_file or f"`{finding.path}`', '        cited_file or citation or f"`{finding.path}`'),
        (
            "        cited: str | None = None\n        if repo_root is not None and finding.path:",
            "        cited: str | None = None\n        citation: str | None = None\n"
            "        if repo_root is not None and finding.path:",
        ),
        (
            "                cited = None\n        dispatch.append(",
            "                cited = None\n"
            "                from mergecraft.localci_citation import describe\n\n"
            "                citation = describe(repo_root, finding.path, changed_paths)\n"
            "        dispatch.append(",
        ),
        (
            "cited_file=cited, withdrawn_section=section)",
            "cited_file=cited, withdrawn_section=section, citation=citation)",
        ),
    ):
        if text.count(old) != 1:
            raise RuntimeError(f"Pinned verifier anchor changed: {old[:60]}")
        text = text.replace(old, new, 1)
    compile(text, str(path), "exec")
    path.write_text(text)


if __name__ == "__main__":
    apply(Path("/opt/mergecraft/src/mergecraft"))
