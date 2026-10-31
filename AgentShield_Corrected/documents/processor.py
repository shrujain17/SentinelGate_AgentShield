"""Safe, bounded extraction of supported AgentShield document formats."""
from __future__ import annotations

import csv
import io
import os
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from docx import Document
from pypdf import PdfReader

def _configured_upload_limit_mb() -> int:
    raw_value = os.getenv("AGENTSHIELD_MAX_UPLOAD_MB", "12")
    try:
        return max(1, min(50, int(raw_value)))
    except (TypeError, ValueError):
        # Invalid environment configuration must not prevent the gateway booting.
        return 12


MAX_UPLOAD_MB = _configured_upload_limit_mb()
MAX_UPLOAD_BYTES = MAX_UPLOAD_MB * 1024 * 1024
MAX_EXTRACTED_CHARS = 1_500_000
MAX_PDF_PAGES = 400
MAX_DOCX_ENTRIES = 2_000
MAX_DOCX_UNCOMPRESSED_BYTES = 80 * 1024 * 1024
SUPPORTED_EXTENSIONS = {".pdf", ".docx", ".txt", ".csv"}


class DocumentIngestionError(ValueError):
    def __init__(self, message: str, code: str = "INVALID_DOCUMENT", status_code: int = 422):
        super().__init__(message)
        self.code = code
        self.status_code = status_code


@dataclass
class ExtractedDocument:
    text: str
    extension: str
    mime_type: str
    extraction_status: str = "EXTRACTED"
    warnings: Optional[list[str]] = None


def _decode_text(data: bytes) -> str:
    if b"\x00" in data:
        raise DocumentIngestionError("The selected text file contains binary data.")
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        try:
            text = data.decode("cp1252")
        except UnicodeDecodeError as exc:
            raise DocumentIngestionError("Text encoding is unsupported; save the file as UTF-8.") from exc
    if not text.strip():
        raise DocumentIngestionError("The document is empty or contains no readable text.")
    if len(text) > MAX_EXTRACTED_CHARS:
        raise DocumentIngestionError(
            f"Extracted text exceeds the {MAX_EXTRACTED_CHARS:,}-character safety limit.",
            code="EXTRACTED_TEXT_TOO_LARGE",
            status_code=413,
        )
    return text


def _extract_docx(data: bytes) -> str:
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            names = archive.namelist()
            if len(names) > MAX_DOCX_ENTRIES:
                raise DocumentIngestionError("DOCX contains too many package entries.")
            if "[Content_Types].xml" not in names or "word/document.xml" not in names:
                raise DocumentIngestionError("The file is not a valid DOCX document.")
            if any(".." in Path(name).parts for name in names):
                raise DocumentIngestionError("DOCX package contains an unsafe path entry.")
            if sum(info.file_size for info in archive.infolist()) > MAX_DOCX_UNCOMPRESSED_BYTES:
                raise DocumentIngestionError("DOCX expands beyond the permitted package size.", code="DOCX_TOO_LARGE", status_code=413)
            if any(name.lower().endswith("vbaproject.bin") for name in names):
                raise DocumentIngestionError("Macro-enabled Office content is not supported.")
        doc = Document(io.BytesIO(data))
    except DocumentIngestionError:
        raise
    except (zipfile.BadZipFile, KeyError, ValueError, OSError) as exc:
        raise DocumentIngestionError("DOCX is malformed or cannot be opened safely.") from exc

    sections: list[str] = []
    for paragraph in doc.paragraphs:
        if paragraph.text.strip():
            sections.append(paragraph.text)
    for table in doc.tables:
        for row in table.rows:
            cells = [cell.text.replace("\n", " ").strip() for cell in row.cells]
            if any(cells):
                sections.append(" | ".join(cells))
    for section in doc.sections:
        for part in (section.header, section.footer):
            for paragraph in part.paragraphs:
                if paragraph.text.strip():
                    sections.append(paragraph.text)
    text = "\n".join(sections).strip()
    if not text:
        raise DocumentIngestionError("The DOCX contains no extractable text.")
    if len(text) > MAX_EXTRACTED_CHARS:
        raise DocumentIngestionError("Extracted DOCX text exceeds the safety limit.", code="EXTRACTED_TEXT_TOO_LARGE", status_code=413)
    return text


def _extract_pdf(data: bytes) -> tuple[str, list[str]]:
    try:
        reader = PdfReader(io.BytesIO(data), strict=False)
    except Exception as exc:
        raise DocumentIngestionError("PDF is malformed or could not be parsed.") from exc
    if reader.is_encrypted:
        raise DocumentIngestionError("Encrypted PDFs are not supported. Upload an unlocked PDF.", code="ENCRYPTED_PDF")
    if len(reader.pages) > MAX_PDF_PAGES:
        raise DocumentIngestionError(f"PDF exceeds the {MAX_PDF_PAGES}-page safety limit.", code="PDF_TOO_MANY_PAGES", status_code=413)

    page_text: list[str] = []
    empty_pages: list[int] = []
    total_chars = 0
    for index, page in enumerate(reader.pages, start=1):
        try:
            extracted = (page.extract_text() or "").strip()
        except Exception:
            extracted = ""
        if not extracted:
            empty_pages.append(index)
        page_text.append(f"[Page {index}]\n{extracted}" if extracted else f"[Page {index}]\n[No selectable text]")
        total_chars += len(extracted)
        if total_chars > MAX_EXTRACTED_CHARS:
            raise DocumentIngestionError("Extracted PDF text exceeds the safety limit.", code="EXTRACTED_TEXT_TOO_LARGE", status_code=413)

    text = "\n\n".join(page_text).strip()
    if total_chars == 0:
        raise DocumentIngestionError(
            "No selectable text was found. This appears to be a scanned/image-only PDF; OCR is required before security approval.",
            code="OCR_REQUIRED",
        )
    if empty_pages:
        page_list = ", ".join(map(str, empty_pages[:30])) + (" …" if len(empty_pages) > 30 else "")
        raise DocumentIngestionError(
            f"OCR is required before this PDF can be scanned safely. Pages without selectable text: {page_list}.",
            code="OCR_REQUIRED",
        )
    return text, []


def _extract_csv(data: bytes) -> str:
    decoded = _decode_text(data)
    try:
        sample = decoded[:8192]
        try:
            dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|")
        except csv.Error:
            dialect = csv.excel
        reader = csv.reader(io.StringIO(decoded), dialect)
        rows: list[str] = []
        for row_index, row in enumerate(reader, start=1):
            if row_index > 50_000:
                raise DocumentIngestionError("CSV exceeds the 50,000-row safety limit.", code="CSV_TOO_MANY_ROWS", status_code=413)
            rows.append(" | ".join(cell.replace("\r", " ").replace("\n", " ") for cell in row))
        text = "\n".join(rows).strip()
    except DocumentIngestionError:
        raise
    except (csv.Error, UnicodeError) as exc:
        raise DocumentIngestionError("CSV structure is malformed or unreadable.") from exc
    if not text:
        raise DocumentIngestionError("The CSV contains no readable rows.")
    return text


def extract_document(filename: str, data: bytes, declared_mime: Optional[str] = None) -> ExtractedDocument:
    """Validate extension, declared MIME (when specific), signature and extract text."""
    suffix = Path(filename or "").suffix.lower()
    if suffix not in SUPPORTED_EXTENSIONS:
        raise DocumentIngestionError("Unsupported format. Upload PDF, DOCX, TXT or CSV only.", code="UNSUPPORTED_TYPE", status_code=415)
    if not data:
        raise DocumentIngestionError("The uploaded file is empty.", code="EMPTY_FILE")
    if len(data) > MAX_UPLOAD_BYTES:
        raise DocumentIngestionError(f"File exceeds the {MAX_UPLOAD_BYTES // (1024 * 1024)} MB upload limit.", code="FILE_TOO_LARGE", status_code=413)

    # The client MIME header is untrusted, but a contradictory specific type is a
    # useful validation signal. Generic octet-stream is permitted; signatures and
    # format parsers remain authoritative.
    submitted_mime = (declared_mime or "").split(";", 1)[0].strip().lower()
    if submitted_mime and submitted_mime != "application/octet-stream":
        allowed_mimes = {
            ".pdf": {"application/pdf"},
            ".docx": {"application/vnd.openxmlformats-officedocument.wordprocessingml.document", "application/zip"},
            ".txt": {"text/plain", "text/*"},
            ".csv": {"text/csv", "application/csv", "application/vnd.ms-excel", "text/plain", "text/*"},
        }[suffix]
        accepted = submitted_mime in allowed_mimes or ("text/*" in allowed_mimes and submitted_mime.startswith("text/"))
        if not accepted:
            raise DocumentIngestionError(
                "Uploaded MIME type conflicts with the selected file extension.",
                code="MIME_MISMATCH",
                status_code=415,
            )

    warnings: list[str] = []
    if suffix == ".pdf":
        if not data.startswith(b"%PDF-"):
            raise DocumentIngestionError("File extension says PDF but the file signature is invalid.", code="SIGNATURE_MISMATCH")
        text, warnings = _extract_pdf(data)
        mime = "application/pdf"
    elif suffix == ".docx":
        if not data.startswith(b"PK\x03\x04") or not zipfile.is_zipfile(io.BytesIO(data)):
            raise DocumentIngestionError("File extension says DOCX but the ZIP/Office signature is invalid.", code="SIGNATURE_MISMATCH")
        text = _extract_docx(data)
        mime = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    elif suffix == ".txt":
        text = _decode_text(data)
        mime = "text/plain"
    else:
        text = _extract_csv(data)
        mime = "text/csv"

    if len(text) > MAX_EXTRACTED_CHARS:
        raise DocumentIngestionError("Extracted text exceeds the safety limit.", code="EXTRACTED_TEXT_TOO_LARGE", status_code=413)
    return ExtractedDocument(text=text, extension=suffix[1:].upper(), mime_type=mime, warnings=warnings)


def chunk_text(text: str, chunk_size: int = 9_000, overlap: int = 700) -> list[tuple[int, str]]:
    """Return overlapping character chunks covering the entire extracted document."""
    if chunk_size <= overlap or overlap < 0:
        raise ValueError("chunk_size must be greater than overlap >= 0")
    chunks: list[tuple[int, str]] = []
    start = 0
    text_length = len(text)
    while start < text_length:
        end = min(text_length, start + chunk_size)
        if end < text_length:
            # Prefer a nearby paragraph/sentence boundary without leaving a gap.
            boundary = max(text.rfind("\n", start + chunk_size // 2, end), text.rfind(". ", start + chunk_size // 2, end))
            if boundary > start:
                end = boundary + 1
        chunks.append((start, text[start:end]))
        if end >= text_length:
            break
        start = max(start + 1, end - overlap)
    return chunks
