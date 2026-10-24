# Customer Management System — Streamlit

A responsive customer management web application built with Python, Streamlit, SQLite and Pandas.

## Features
- Admin login (demo account included)
- Dashboard metrics and customer status chart
- Add customer records
- Search and filter customers
- Edit and delete records with confirmation
- Export displayed customer data to CSV
- SQLite database initialized automatically

## Run locally
```bash
python -m venv .venv
```

Windows:
```powershell
.venv\Scripts\activate
```

macOS/Linux:
```bash
source .venv/bin/activate
```

Install dependencies and run:
```bash
python -m pip install -r requirements.txt
streamlit run app.py
```

Open the local URL shown in the terminal, usually `http://localhost:8501`.

## Demo login
- Username: `admin`
- Password: `Admin@123`

Change the demo credentials before using real customer data.

## Deploy on Streamlit Community Cloud
1. Create a GitHub repository and upload `app.py`, `requirements.txt`, and `README.md`.
2. Visit https://share.streamlit.io and sign in with GitHub.
3. Select **Create app**, then choose the repository, branch (`main`), and main file path (`app.py`).
4. Click **Deploy** and wait for the build to finish.

Official instructions: https://docs.streamlit.io/deploy/streamlit-community-cloud/deploy-your-app

## Important data persistence note
This starter app uses a local SQLite file. On hosted ephemeral environments, local files may not be durable across rebuilds or restarts. Use a managed database such as PostgreSQL or another persistent data service for long-term production records. Do not store real customer data in this demo without adding production security, CSRF/session hardening as applicable, backups, and appropriate access controls.
