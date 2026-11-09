"""Conservative metadata and structural anomaly checks; not a steganography verdict."""
from pathlib import Path
import hashlib
import mimetypes

def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    """Calculate SHA-256 incrementally to avoid loading large evidence files into memory."""
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()

def _find_signature(data: bytes, marker: bytes, start: int = 0) -> int:
    """Find a structural end marker; return -1 if absent."""
    return data.find(marker, start)

def inspect_file(path: Path) -> dict:
    """Report size, SHA-256, MIME guess, and a few appended-data indicators."""
    stat = path.stat()
    result = {
        "path": str(path),
        "name": path.name,
        "size_bytes": stat.st_size,
        "sha256": sha256_file(path),
        "mime_guess": mimetypes.guess_type(path.name)[0],
        "indicators": [],
        "triage_note": "Indicators are heuristic only; confirm with specialist tools and context.",
    }
    # Read only a bounded prefix/suffix for format signatures.
    with path.open("rb") as stream:
        head = stream.read(16)
        tail_size = min(stat.st_size, 1024 * 1024)
        stream.seek(max(0, stat.st_size - tail_size))
        tail = stream.read(tail_size)

    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        end_marker = b"IEND\xaeB`\x82"
        pos = tail.rfind(end_marker)
        if pos >= 0:
            end_pos = max(0, stat.st_size - tail_size) + pos + len(end_marker)
            if end_pos < stat.st_size:
                result["indicators"].append({
                    "type": "possible_appended_data_after_png_end",
                    "offset": end_pos,
                    "extra_bytes": stat.st_size - end_pos,
                })
        else:
            result["indicators"].append({"type": "png_end_marker_not_found_in_last_1mb"})
    elif head.startswith(b"\xff\xd8"):
        pos = tail.rfind(b"\xff\xd9")
        if pos >= 0:
            end_pos = max(0, stat.st_size - tail_size) + pos + 2
            if end_pos < stat.st_size:
                result["indicators"].append({
                    "type": "possible_appended_data_after_jpeg_eoi",
                    "offset": end_pos,
                    "extra_bytes": stat.st_size - end_pos,
                })
        else:
            result["indicators"].append({"type": "jpeg_eoi_not_found_in_last_1mb"})
    elif head.startswith(b"%PDF-"):
        pos = tail.rfind(b"%%EOF")
        if pos >= 0:
            end_pos = max(0, stat.st_size - tail_size) + pos + len(b"%%EOF")
            if end_pos < stat.st_size and tail[pos + len(b"%%EOF"):].strip():
                result["indicators"].append({
                    "type": "possible_data_after_pdf_eof",
                    "offset": end_pos,
                    "extra_bytes": stat.st_size - end_pos,
                })
        else:
            result["indicators"].append({"type": "pdf_eof_marker_not_found_in_last_1mb"})
    return result

def scan_directory(target: str) -> dict:
    """Inspect files recursively, skipping symlinks and recording per-file errors."""
    root = Path(target)
    if not root.exists():
        return {"error": f"Target does not exist: {root}", "files": [], "errors": []}
    paths = [root] if root.is_file() else [p for p in root.rglob("*") if p.is_file() and not p.is_symlink()]
    rows, errors = [], []
    for path in paths:
        try:
            rows.append(inspect_file(path))
        except (OSError, PermissionError) as exc:
            errors.append({"path": str(path), "error": f"{type(exc).__name__}: {exc}"})
    return {"target": str(root), "files_inspected": len(rows), "files": rows, "errors": errors}
