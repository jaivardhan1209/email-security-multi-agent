"""Corpus loader (§12).

The dataset is plain JSON on disk so it can be extended without touching code,
and so a future version can be swapped for a customer-provided sample set.
"""

from __future__ import annotations

import json
from pathlib import Path

from email_security.models.schemas import Action, LabeledEmail, ThreatClass

DEFAULT_CORPUS_DIR = Path("data/emails")


def load_corpus(directory: Path | str = DEFAULT_CORPUS_DIR, categories: list[str] | None = None) -> list[LabeledEmail]:
    """Load every labelled email, sorted by message id for reproducible runs."""
    path = Path(directory)
    if not path.exists():
        raise FileNotFoundError(f"corpus directory not found: {path.resolve()}")

    files = sorted(path.glob("*.json"))
    if categories:
        wanted = {c.lower() for c in categories}
        files = [f for f in files if f.stem.lower() in wanted]
    if not files:
        raise FileNotFoundError(f"no corpus files matched in {path.resolve()}")

    items: list[LabeledEmail] = []
    for file in files:
        raw = json.loads(file.read_text(encoding="utf-8"))
        for entry in raw:
            items.append(LabeledEmail.model_validate(entry))
    items.sort(key=lambda i: i.email.message_id)
    return items


def corpus_summary(items: list[LabeledEmail]) -> dict[str, int]:
    """Ground-truth label distribution — note it differs from the file names,
    because several files carry deliberate control cases labelled CLEAN."""
    summary: dict[str, int] = {}
    for item in items:
        summary[str(item.label)] = summary.get(str(item.label), 0) + 1
    return dict(sorted(summary.items()))


__all__ = ["DEFAULT_CORPUS_DIR", "Action", "LabeledEmail", "ThreatClass", "corpus_summary", "load_corpus"]
