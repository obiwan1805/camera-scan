# Camera Scanner

Massive IP Camera Scanner with 3-Layer Pipe & Filter Architecture.

## Architecture

```
CIDR Input → Layer 1 (Port Scanner) → Queue1 → Layer 2 (Fingerprinter) → Queue2 → Layer 3 (CVE Searcher)
```

## Setup
Install masscan
```bash
sudo apt update
sudo apt install masscan
```
```bash
pip install -r requirements.txt
```

## Usage

```bash
python main.py
```

## Configuration

Edit `config/default.yaml` to customize scanner settings.

## File Structure

- `src/core/` - Interfaces and base classes
- `src/layers/` - Layer implementations
- `src/storage/` - Storage backends
- `src/pipeline/` - Orchestration
- `src/utils/` - Shared utilities
