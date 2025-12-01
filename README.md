# Employment Management

This Flask app provides a simple Employment Management System (EMS) with login/signup and a modern CRUD UI for employees. It uses Bootstrap, Animate.css, and a lightweight SQLite store (`employees.db`).

Quick start

1. Change into the `auth_app` folder:

```bash
cd auth_app
```

2. (Recommended) create and activate a virtualenv:

```bash
python -m venv .venv
source .venv/bin/activate
```

3. Install dependencies:

```bash
pip install -r requirements.txt
```

4. Run the app:

```bash
python app.py
```

5. Open http://127.0.0.1:5000 in your browser.

Notes
- The app uses a local `employees.db` SQLite database created automatically.
- Change the `FLASK_SECRET` environment variable to a secure value in production.
- The UI includes subtle animations, hover effects, and a responsive table for employees.
- To integrate your existing `expense_tracker.py`, you can add a link or import a function into `dashboard` or the employee detail views.

Next steps you might want:
- Add pagination and search for large employee lists.
- Add file upload for employee photos.
- Add role-based access control (admins vs regular users).
# Qodo-Training
