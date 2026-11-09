"""Optional YARA scanning for authorized defensive triage."""
from pathlib import Path

def scan_with_yara(target: str, rules_path: str) -> dict:
    """Scan one file or a directory recursively; return matching rule metadata."""
    try:
        import yara
    except ImportError:
        return {"error": "yara-python is not installed; run: pip install yara-python", "matches": []}
    root = Path(target)
    rules_file = Path(rules_path)
    if not root.exists():
        return {"error": f"Target does not exist: {root}", "matches": []}
    if not rules_file.is_file():
        return {"error": f"Rules file does not exist: {rules_file}", "matches": []}
    try:
        rules = yara.compile(filepath=str(rules_file))
    except Exception as exc:
        return {"error": f"Could not compile YARA rules: {type(exc).__name__}: {exc}", "matches": []}

    paths = [root] if root.is_file() else [p for p in root.rglob("*") if p.is_file()]
    matches, errors = [], []
    for path in paths:
        try:
            for match in rules.match(str(path), timeout=15):
                matches.append({
                    "path": str(path),
                    "rule": match.rule,
                    "namespace": match.namespace,
                    "tags": list(match.tags),
                    "meta": dict(match.meta),
                    "strings": [
                        {"identifier": s.identifier, "instances": len(s.instances)}
                        for s in match.strings
                    ],
                })
        except Exception as exc:
            errors.append({"path": str(path), "error": f"{type(exc).__name__}: {exc}"})
    return {"target": str(root), "rules": str(rules_file), "scanned_files": len(paths),
            "matches": matches, "errors": errors}
