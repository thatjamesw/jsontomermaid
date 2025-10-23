# Azure JSON → Mermaid

A tiny Flask web app that converts Azure-style JSON into Mermaid diagrams, rendered in the browser and downloadable as SVG.
Front end uses Mermaid 11 with the ELK layout for readable network/topology graphs.

## Features

- Paste JSON or import a .json file and render to Mermaid instantly. 
- One-click Copy code (Mermaid) and Download SVG. 
- Optional Debug panel showing environment, timing and errors. 
- Clean, dark UI with simple cards and buttons.

## Project Structure

```
.
├─ app.py
├─ json_to_mermaid.py
├─ requirements.txt
└─ www/
   ├─ index.html
   └─ style.css
```

Note: The Flask app serves static/template files from the www/ folder. Ensure index.html and style.css live under www/.

## Prerequisites

- Python 3.10+ (tested with modern Python)
- Pip
- (Optional) A virtual python environment

## Quick Start Guide

### Clone & move files into place
```
git clone git@github.com:<you>/<repo>.git
cd <repo>
# Ensure web assets are under ./www
mkdir -p www
mv index.html style.css www/  # skip if already under www
```
### Create & activate a virtualenv (recommended)
```
python -m venv .venv
source ./.venv/bin/activate  # macOS/Linux
# .\.venv\Scripts\activate   # Windows PowerShell
```
### Install dependencies
```
pip install -r requirements.txt
```
### Run the app
```
python app.py
# → * Running on http://127.0.0.1:5002 (Press CTRL+C to quit)
```
### Open the UI
- Visit http://localhost:5002
- Click Import JSON file or paste JSON
- Click Render to see the diagram
- Copy code or Download SVG for documentation/export

  ## JSON expectations (high-level)

The converter expects Azure-style resource objects and relationships; it maps known resource types (e.g., VNets, subnets, NICs, VMs, IPs, gateways, firewalls, load balancers) to diagram nodes and draws links based on references/relationships. Unknown types are handled generically.

Tip: If you’re unsure whether a field is supported, render with Debug enabled to see any parser errors surfaced by the backend.
