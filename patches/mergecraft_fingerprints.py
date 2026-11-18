"""Apply a narrow compatibility fix to the pinned mergeCraft finding model."""

from pathlib import Path

VALIDATOR = """    @field_validator("fingerprint")
    @classmethod
    def _canonical_fingerprint(cls, value: str) -> str:
        # Older agent tools accept descriptive finding IDs. Canonicalize at model
        # ingestion, before persistence, deduplication, or export sees the value.
        if re.fullmatch(r"[0-9a-f]{6,}", value):
            return value
        if (
            not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,2047}", value)
            or ".." in re.split(r"[/:]", value)
        ):
            raise ValueError("fingerprint must be hex or a safe descriptive identifier")
        return hashlib.sha256(("mergecraft:fingerprint:v1:" + value).encode()).hexdigest()

"""


def apply(root: Path):
    path = root / "analyzers/finding.py"
    source = path.read_text()
    anchor = '    @field_validator("category")\n'
    if source.count(anchor) != 1 or "_canonical_fingerprint" in source:
        raise RuntimeError("Pinned mergeCraft source changed; review the fingerprint patch")
    source = source.replace("import json\n", "import hashlib\nimport json\n", 1)
    path.write_text(source.replace(anchor, VALIDATOR + anchor, 1))


if __name__ == "__main__":
    apply(Path("/opt/mergecraft/src/mergecraft"))
