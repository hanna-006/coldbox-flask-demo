# ColdBox Scanner — Demo Flask App

This is a safe demo of a ColdBox scanning tool wrapped in a Flask web app.  
It is intentionally restricted to scan only a safe target (`http://testphp.vulnweb.com`).

## Local run
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python app.py
