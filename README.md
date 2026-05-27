# DNS Propagation Checker

Desktop GUI for checking DNS answers across public resolvers and authoritative nameservers.

## Requirements

- Python 3.10+
- Network access for DNS queries
- Dependencies from `requirements.txt`

## Install

```bash
python setup.py --venv
```

Or manually:

```bash
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

On Linux or macOS, activate the virtual environment with `source .venv/bin/activate`.

## Run

```bash
python dns_propagation_checker.py
```

## Files

- `dns_propagation_checker.py`: main app
- `requirements.txt`: runtime dependencies
- `setup.py`: local dependency installer

The app writes local runtime settings to `config.json`, which is ignored by Git.
