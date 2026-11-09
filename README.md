# SentinelTriage

Modular, read-only triage helper for authorized defensive investigations.

## Main Components

- `app.py`: Streamlit dashboard with Dashboard, Workspace Investigasi, File Scanner, YARA Scanner, Live Triage, and Report Center.
- `sentineltriage/collector.py`: host metadata, process and network collection, and supported system artifacts.
- `sentineltriage/file_triage.py`: SHA-256, MIME identification, and basic appended-data indicators.
- `sentineltriage/yara_scan.py`: YARA rule-based scanning.
- `sentineltriage/process_analysis.py`: initial rule-based process metadata assessment.
- `sentineltriage/network_analysis.py`: initial network socket assessment and duplicate grouping.
- `sentineltriage/timeline.py`: event timeline construction.
- `sentineltriage/html_report.py`: HTML report generation.
- `sentineltriage/reporting.py`: JSON, optional encrypted JSON, and PDF reports.
- `sentineltriage/cli.py`: command-line interface.
- `backend/app/`: optional FastAPI backend for authentication, case management, scans, and findings.

## Requirements
Python 3.10+ recommended. Create a virtual environment and install dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate          # macOS/Linux
# .venv\Scripts\activate         # Windows PowerShell
python -m pip install --upgrade pip
pip install -r requirements.txt
```

`yara-python` may require platform-specific build/runtime support. If it cannot install, omit it and run without `--yara-rules`; the tool reports the missing optional module.

## Examples
Scan a copied evidence folder and create reports:

```bash
python -m sentineltriage.cli --case-id CASE-001 --operator "Analyst Team" --scan ./evidence --output ./out
```

Scan with a YARA rule file:

```bash
python -m sentineltriage.cli --case-id CASE-002 --operator "Analyst Team" --scan ./evidence --yara-rules ./rules/example_apt_triage.yar --output ./out
```

Collect live artifacts from the current host (run only with authorization):

```bash
python -m sentineltriage.cli --case-id CASE-003 --operator "Analyst Team" --collect-live --output ./out
```

Do both and encrypt the reports:

```bash
python -m sentineltriage.cli --case-id CASE-004 --operator "Analyst Team" --collect-live --scan ./evidence --yara-rules ./rules/example_apt_triage.yar --encrypt --output ./out
```

Encrypted JSON format is `STENC1` + 16-byte salt + Fernet token. The PDF is password-protected. The plain `report.json` is also written for convenient inspection; protect or remove it according to your evidence-handling policy. If you need only encrypted output, adjust the CLI before deployment.

## Build a single executable

Install PyInstaller in the same environment:

```bash
pip install pyinstaller
pyinstaller --clean --onefile --name SentinelTriage -m sentineltriage.cli
```

If your PyInstaller version does not accept `-m` in this invocation, use the entry script:
```bash
pyinstaller --clean --onefile --name SentinelTriage sentineltriage/cli.py
```
For the entry-script form, package imports may need a small top-level `sentineltriage_cli.py` wrapper:
```python
from sentineltriage.cli import main
if __name__ == "__main__":
    main()
```
Then build with:
```bash
pyinstaller --clean --onefile --name SentinelTriage sentineltriage_cli.py
```

Build separately on each target OS and architecture (Windows `.exe`, Linux binary, macOS executable). Test on a clean VM. YARA native libraries may need explicit PyInstaller collection flags; check `pyinstaller --collect-all yara` if the compiled scanner is missing at runtime. Do not assume a binary built on macOS will run on Windows/Linux.

## Forensic limitations
- This is a triage utility, not a forensic imaging suite or a substitute for validated acquisition tools.
- Live collection can affect system state and cannot capture all volatile evidence.
- The sample YARA rule is a harmless demonstration marker, not a detection rule for real malware.
- Appended-data checks are heuristic and do not prove steganography.
- SHA-256 supports integrity verification but does not by itself prove authenticity or complete chain of custody.
- Preserve original media, document acquisition details and custody transfers, use trusted time sources, and verify tool versions and outputs.

## Development Notes

SentinelTriage was developed incrementally from an earlier prototype.
The existing codebase served as the development foundation and was
extended with process assessment, network assessment, timeline reporting,
a Streamlit dashboard, and FastAPI backend capabilities.

This development history is disclosed for transparency. The project
is intended for authorized defensive digital forensics and malware
triage. Automated findings require analyst verification.

The Streamlit dashboard and FastAPI backend run as separate services.
The backend uses MySQL configured for the development environment.
Never publish database passwords, API keys, or secret credentials.

