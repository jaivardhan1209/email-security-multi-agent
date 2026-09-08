"""Static attachment analysis (§7, §20).

SAFETY CONTRACT: nothing in this module executes, opens with a handler,
detonates, unpacks to disk, or fetches anything. It inspects filenames, MIME
types, declared sizes, magic bytes and printable strings only. Real dynamic
detonation is Defender's Safe Attachments sandbox — explicitly out of scope.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

from email_security.models.schemas import Attachment
from email_security.tools.threat_intel import ThreatIntelSource, get_threat_intel

# Extensions that are executable content or script hosts on Windows.
EXECUTABLE_EXTENSIONS = {
    "exe", "scr", "com", "pif", "bat", "cmd", "msi", "msp", "cpl", "jar", "app",
    "vbs", "vbe", "js", "jse", "wsf", "wsh", "ps1", "psm1", "hta", "reg", "lnk",
    "chm", "dll", "sys", "gadget", "inf", "scf", "application", "msc", "vb",
}
# Office formats that can carry macros / dynamic content.
MACRO_EXTENSIONS = {"docm", "xlsm", "pptm", "dotm", "xltm", "xlam", "potm", "ppam", "xlsb", "doc", "xls", "ppt", "rtf"}
ARCHIVE_EXTENSIONS = {"zip", "rar", "7z", "gz", "tar", "bz2", "cab", "iso", "img", "vhd", "vhdx", "ace", "arj", "z"}
# Disk-image containers are treated separately from ordinary archives: mounting
# one strips the Mark-of-the-Web from its contents, so they are chosen by
# attackers specifically to defeat the SmartScreen/Protected-View warnings that
# a .zip would preserve. Almost nobody mails a disk image legitimately.
MOTW_BYPASS_EXTENSIONS = {"iso", "img", "vhd", "vhdx"}
DOCUMENT_EXTENSIONS = {"pdf", "docx", "xlsx", "pptx", "txt", "csv", "odt", "ods", "rtf"}
IMAGE_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "bmp", "webp", "svg", "tiff"}

# Magic-byte prefixes — used to detect a declared type that does not match content.
MAGIC_SIGNATURES: list[tuple[bytes, str]] = [
    (b"MZ", "windows-executable"),
    (b"\x7fELF", "elf-executable"),
    (b"%PDF", "pdf"),
    (b"PK\x03\x04", "zip-container"),
    (b"\xd0\xcf\x11\xe0", "ole2-compound-document"),
    (b"Rar!\x1a\x07", "rar-archive"),
    (b"7z\xbc\xaf\x27\x1c", "7zip-archive"),
    (b"\x1f\x8b", "gzip"),
    (b"{\\rtf", "rtf"),
]

# Printable strings that indicate active content inside an Office/PDF file.
MACRO_STRING_PATTERNS = [
    (rb"vbaProject\.bin", "vba_project_stream"),
    (rb"Auto_?Open", "auto_open_macro"),
    (rb"Document_?Open", "document_open_macro"),
    (rb"Workbook_?Open", "workbook_open_macro"),
    (rb"Shell\s*\(", "shell_invocation"),
    (rb"WScript\.Shell", "wscript_shell"),
    (rb"powershell", "powershell_invocation"),
    (rb"CreateObject", "com_object_creation"),
    (rb"URLDownloadToFile", "remote_download_api"),
    (rb"/JavaScript", "pdf_embedded_javascript"),
    (rb"/OpenAction", "pdf_open_action"),
    (rb"/Launch", "pdf_launch_action"),
    (rb"/EmbeddedFile", "pdf_embedded_file"),
    (rb"DDEAUTO", "dde_auto_execution"),
    (rb"mshta", "mshta_invocation"),
]

# Declared content-type -> plausible extensions, for mismatch detection.
MIME_EXPECTATIONS: dict[str, set[str]] = {
    "application/pdf": {"pdf"},
    "image/png": {"png"},
    "image/jpeg": {"jpg", "jpeg"},
    "text/plain": {"txt", "log", "csv"},
    "text/csv": {"csv", "txt"},
    "application/zip": {"zip"},
    "application/msword": {"doc", "rtf", "docm"},
    "application/vnd.ms-excel": {"xls", "csv", "xlsm", "xlsb"},
    "application/vnd.ms-excel.sheet.macroenabled.12": {"xlsm"},
    "application/vnd.ms-word.document.macroenabled.12": {"docm"},
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": {"docx"},
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": {"xlsx"},
    "application/vnd.openxmlformats-officedocument.presentationml.presentation": {"pptx"},
}

_RTL_OVERRIDE = "‮"


def calculate_file_hash(data: bytes | None, filename: str = "", size_bytes: int = 0, algorithm: str = "sha256") -> str:
    """SHA256 of the payload, or a stable synthetic digest when bytes are absent.

    The POC's corpus ships metadata only; a real pipeline always has bytes and
    the synthetic branch never fires.
    """
    digest = hashlib.new(algorithm)
    digest.update(data if data is not None else f"{filename}:{size_bytes}".encode())
    return digest.hexdigest()


def get_extension(filename: str) -> str:
    name = (filename or "").strip().lower()
    return name.rsplit(".", 1)[-1] if "." in name else ""


def detect_double_extension(filename: str) -> str | None:
    """`invoice.pdf.exe` — a benign-looking type followed by a dangerous one."""
    parts = (filename or "").lower().split(".")
    if len(parts) < 3:
        return None
    final = parts[-1]
    penultimate = parts[-2]
    benign = DOCUMENT_EXTENSIONS | IMAGE_EXTENSIONS | {"zip"}
    if penultimate in benign and final in (EXECUTABLE_EXTENSIONS | ARCHIVE_EXTENSIONS):
        return f".{penultimate}.{final}"
    return None


def _sniff_magic(content: bytes | None) -> str | None:
    if not content:
        return None
    for prefix, label in MAGIC_SIGNATURES:
        if content.startswith(prefix):
            return label
    return None


def _scan_strings(content: bytes | None) -> list[str]:
    if not content:
        return []
    hits: list[str] = []
    for pattern, label in MACRO_STRING_PATTERNS:
        if re.search(pattern, content, re.IGNORECASE):
            hits.append(label)
    return hits


def analyze_attachment_metadata(attachment: Attachment, intel: ThreatIntelSource | None = None) -> dict[str, Any]:
    """Full static profile of one attachment, with a 0.0-1.0 risk score.

    The score is the *tool's* opinion. The Malware Agent owns the final verdict
    and may raise it further based on context (e.g. sender authentication).
    """
    intel = intel or get_threat_intel()
    filename = attachment.filename or "(unnamed)"
    ext = get_extension(filename)
    sha256 = attachment.ensure_hash() if attachment.sha256 is None else attachment.sha256
    if not sha256:
        sha256 = calculate_file_hash(attachment.content, filename, attachment.size_bytes)

    indicators: list[str] = []
    risk = 0.0

    def add(name: str, weight: float) -> None:
        nonlocal risk
        indicators.append(name)
        risk = min(1.0, risk + weight)

    ti = intel.lookup_hash(sha256)
    if ti.reputation == "MALICIOUS":
        add("known_malicious_hash", 0.95)

    if ext in EXECUTABLE_EXTENSIONS:
        add(f"executable_extension:{ext}", 0.65)
    if ext in MACRO_EXTENSIONS:
        add(f"macro_capable_format:{ext}", 0.30)
    if ext in MOTW_BYPASS_EXTENSIONS:
        add(f"motw_bypass_container:{ext}", 0.60)
    elif ext in ARCHIVE_EXTENSIONS:
        add(f"archive_container:{ext}", 0.25)
    if not ext:
        add("no_extension", 0.20)

    double = detect_double_extension(filename)
    if double:
        add(f"double_extension:{double}", 0.60)
    if _RTL_OVERRIDE in filename:
        add("rtl_override_filename", 0.65)  # fdp.exe rendered as exe.pdf
    if len(filename) > 90:
        add("excessively_long_filename", 0.10)
    if re.search(r"(invoice|payment|remittance|receipt|urgent|statement|scan|dhl|fedex|resume|cv|purchase[_ -]?order|swift)", filename, re.IGNORECASE):
        indicators.append("lure_themed_filename")  # context only, no score on its own

    declared = (attachment.content_type or "").split(";")[0].strip().lower()
    expected = MIME_EXPECTATIONS.get(declared)
    if expected and ext and ext not in expected:
        add(f"mime_extension_mismatch:{declared}!={ext}", 0.45)

    magic = _sniff_magic(attachment.content)
    if magic:
        indicators.append(f"magic:{magic}")
        if magic in {"windows-executable", "elf-executable"} and ext not in EXECUTABLE_EXTENSIONS:
            # A PE/ELF header inside a file claiming to be a document is about
            # as conclusive as static analysis gets — there is no benign reason.
            add("content_is_executable_but_extension_is_not", 0.90)
        if magic == "ole2-compound-document" and ext in {"pdf", "txt", "csv"}:
            add("content_type_contradicts_extension", 0.55)

    macro_hits = _scan_strings(attachment.content)
    for hit in macro_hits:
        weight = 0.45 if hit in {"auto_open_macro", "document_open_macro", "workbook_open_macro", "dde_auto_execution"} else 0.30
        add(f"active_content:{hit}", weight)

    # Metadata-only corpus: the fixture may assert indicators discovered by an
    # upstream static scanner. Treated exactly like locally derived findings.
    declared_indicators = []
    if attachment.model_extra:
        declared_indicators = list(attachment.model_extra.get("static_indicators", []))
    for hit in declared_indicators:
        add(f"static_scan:{hit}", 0.35)

    if attachment.size_bytes and attachment.size_bytes < 1500 and ext in DOCUMENT_EXTENSIONS:
        add("implausibly_small_document", 0.20)

    verdict = "MALICIOUS" if risk >= 0.85 else "SUSPICIOUS" if risk >= 0.45 else "LOW_RISK" if risk >= 0.2 else "BENIGN"
    return {
        "filename": filename,
        "extension": ext,
        "declared_content_type": declared,
        "size_bytes": attachment.size_bytes,
        "sha256": sha256,
        "hash_reputation": ti.reputation,
        "hash_notes": ti.notes,
        "magic": magic,
        "active_content": macro_hits,
        "double_extension": double,
        "indicators": indicators,
        "risk_score": round(risk, 3),
        "verdict": verdict,
    }


def analyze_attachments(attachments: list[Attachment], intel: ThreatIntelSource | None = None) -> dict[str, Any]:
    """Batch analysis with a rolled-up worst-case view."""
    reports = [analyze_attachment_metadata(a, intel=intel) for a in attachments]
    worst = max((r["risk_score"] for r in reports), default=0.0)
    return {
        "count": len(reports),
        "max_risk_score": worst,
        "malicious": [r["filename"] for r in reports if r["verdict"] == "MALICIOUS"],
        "suspicious": [r["filename"] for r in reports if r["verdict"] == "SUSPICIOUS"],
        "reports": reports,
    }
