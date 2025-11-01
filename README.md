# Email Threat Detection & Response SOC Web App

## Project Description
This is an automated phishing email detection system built with Python and Django. It simulates a Security Operations Center (SOC) for monitoring and responding to email threats. The app analyzes `.eml` files for phishing indicators, classifies them as Legitimate, Suspicious, or Malicious, quarantines malicious emails, stores scan history in a database, and generates PDF reports.

Key Features:
- Upload and analyze `.eml` files.
- Header analysis (SPF, DKIM, domain impersonation).
- Content analysis (keywords, URLs).
- Threat intelligence (VirusTotal API for URL scanning).
- Classification scoring (0-10 scale).
- Quarantine simulation for malicious emails.
- Scan history with table view.
- PDF report generation for scans.
- Responsive web UI.

This project demonstrates cybersecurity concepts like email forensics, incident response, and automation in a web app.

## Technologies Used
- **Python 3.12+**: Core scripting and logic.
- **Django 5.2+**: Web framework for UI, models, views.
- **Libraries**:
  - `dnspython`: SPF checks.
  - `dkimpy`: DKIM verification.
  - `requests`: VirusTotal API calls.
  - `beautifulsoup4` & `lxml`: HTML parsing for URLs.
  - `watchdog`: File monitoring (not used in web version).
  - `weasyprint`: PDF generation (requires GTK3).
  - `difflib`: Domain similarity.
- **Database**: SQLite (default Django).
- **Frontend**: HTML/CSS with basic styling.
- **Other**: Regex for header extraction, UUID for file naming.

## Installation

1. **Clone the Repository**:

2. **Create Virtual Environment**:

3. **Install Dependencies**:

4. **Install GTK3 for WeasyPrint (Windows)**:
- Download: https://github.com/tschoonj/GTK-for-Windows-Runtime-Environment-Installer/releases/download/2022-01-04/gtk3-runtime-3.24.31-2022-01-04-ts-win64.exe
- Install to `C:\Program Files\GTK3-Runtime Win64`.
- Add to PATH: `C:\Program Files\GTK3-Runtime Win64\bin`.

5. **Configure VirusTotal API**:
- In `detector/utils.py`, replace `'YOUR_VIRUSTOTAL_API_KEY'` with your free key from virustotal.com.

6. **Create Folders**:

7. **Run Migrations**:

8. **Create Admin User (Optional)**:


#### Usage

1. **Start the Server**:

2. **Open Browser**:
- Go to http://127.0.0.1:8000/
- Upload a `.eml` file (export from Gmail: "Show original" → Download).
- View result: Classification, score, issues.
- Download PDF report.
- Check history page for all scans.

3. **Test Emails**:
- Legitimate: Safe order confirmation.
- Suspicious: Fake verification with keywords.
- Malicious: Urgent scam with bad URLs – gets quarantined.

4. **Admin Panel**:
- http://127.0.0.1:8000/admin/ – Manage scans.

## How It Works (High-Level)

- **Upload**: User uploads `.eml` via form.
- **Analysis**: Parses headers/body, checks SPF/DKIM/domain, scans content/URLs.
- **Classification**: Scores and classifies; quarantines if malicious.
- **Storage**: Saves scan to DB.
- **PDF**: Generates report from HTML template using WeasyPrint.
- **History**: Lists all scans with PDF links.

## Author
This project was developed by [Your Name/User] as a resume portfolio piece. It demonstrates skills in Python, Django, and cybersecurity. Feel free to fork or contribute!

## License
MIT License – Free to use and modify.