"""Employment Management System integrating the existing expense_tracker.py

This file provides:
- User signup/login
- Employee CRUD
- Integration endpoint /tracker that embeds the existing expense_tracker app templates and logic

Notes:
- The integration imports the module `expense_tracker` from the parent folder and
  adapts its template strings to use our `/tracker` endpoints so the tracker UI
  works inside the same Flask process.
"""
from flask import Flask, render_template, render_template_string, request, redirect, url_for, session, flash, send_file
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os
from datetime import datetime
import sys

# allow importing the sibling expense_tracker.py
sys.path.append(os.path.dirname(os.path.dirname(__file__)))
import expense_tracker as et


app = Flask(__name__, template_folder='templates', static_folder='static')
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET', 'dev-secret-change-me')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///employees.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)


class Employee(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(80), nullable=False)
    last_name = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    position = db.Column(db.String(120), nullable=True)
    department = db.Column(db.String(120), nullable=True)
    salary = db.Column(db.Float, nullable=True)
    hired_date = db.Column(db.String(30), nullable=True)


# ----- Auth routes -----
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('employees'))
    return redirect(url_for('login'))


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form.get('email', '').lower().strip()
        password = request.form.get('password', '')
        if not email or not password:
            flash('Please fill in all fields', 'danger')
            return redirect(url_for('signup'))
        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'warning')
            return redirect(url_for('signup'))

        user = User(email=email, password_hash=generate_password_hash(password, method='pbkdf2:sha256'))
        db.session.add(user)
        db.session.commit()
        flash('Account created. Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('signup.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').lower().strip()
        password = request.form.get('password', '')
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            session['user_email'] = user.email
            flash('Logged in successfully', 'success')
            return redirect(url_for('employees'))
        flash('Invalid credentials', 'danger')
        return redirect(url_for('login'))
    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out', 'info')
    return redirect(url_for('login'))


# ----- Employee CRUD -----
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash('Please log in first', 'warning')
        return redirect(url_for('login'))
    # Basic counts
    emp_count = Employee.query.count()

    # Counts by department
    dept_q = db.session.query(Employee.department, db.func.count(Employee.id)).group_by(Employee.department).all()
    dept_labels = [d if d else 'Unspecified' for d, _ in dept_q]
    dept_values = [int(c) for _, c in dept_q]

    # Counts by position (top N)
    pos_q = db.session.query(Employee.position, db.func.count(Employee.id)).group_by(Employee.position).order_by(db.func.count(Employee.id).desc()).all()
    pos_labels = [p if p else 'Unspecified' for p, _ in pos_q]
    pos_values = [int(c) for _, c in pos_q]

    # Salary buckets
    buckets = [
        (0, 30000, '0-30k'),
        (30000, 60000, '30k-60k'),
        (60000, 90000, '60k-90k'),
        (90000, 120000, '90k-120k'),
        (120000, None, '120k+')
    ]
    salary_labels = []
    salary_values = []
    for low, high, label in buckets:
        if high is None:
            cnt = Employee.query.filter(Employee.salary != None, Employee.salary >= low).count()
        else:
            cnt = Employee.query.filter(Employee.salary != None, Employee.salary >= low, Employee.salary < high).count()
        salary_labels.append(label)
        salary_values.append(int(cnt))

    # Hires per month for the last 12 months
    from datetime import date, timedelta
    today = date.today()
    months = []
    hires_values = []
    # Helper to convert total months to year/month
    for i in range(11, -1, -1):
        total_months = today.year * 12 + today.month - 1 - i
        y = total_months // 12
        m = total_months % 12 + 1
        month_start = date(y, m, 1)
        # compute next month start
        next_total = total_months + 1
        ny = next_total // 12
        nm = next_total % 12 + 1
        next_start = date(ny, nm, 1)
        end_date = next_start - timedelta(days=1)
        months.append(month_start.strftime('%Y-%m'))
        cnt = Employee.query.filter(Employee.hired_date != None, Employee.hired_date >= month_start.isoformat(), Employee.hired_date <= end_date.isoformat()).count()
        hires_values.append(int(cnt))

    return render_template(
        'dashboard.html',
        email=session.get('user_email'),
        emp_count=emp_count,
        dept_labels=dept_labels,
        dept_values=dept_values,
        pos_labels=pos_labels,
        pos_values=pos_values,
        salary_labels=salary_labels,
        salary_values=salary_values,
        months=months,
        hires_values=hires_values,
    )


@app.route('/employees')
def employees():
    if 'user_id' not in session:
        flash('Please log in first', 'warning')
        return redirect(url_for('login'))
    items = Employee.query.order_by(Employee.id.desc()).all()
    return render_template('employees.html', employees=items)


@app.route('/employees/new', methods=['GET', 'POST'])
def new_employee():
    if 'user_id' not in session:
        flash('Please log in first', 'warning')
        return redirect(url_for('login'))
    if request.method == 'POST':
        data = request.form
        emp = Employee(
            first_name=data.get('first_name', '').strip(),
            last_name=data.get('last_name', '').strip(),
            email=data.get('email', '').strip(),
            position=data.get('position', '').strip(),
            department=data.get('department', '').strip(),
            salary=float(data.get('salary') or 0) if data.get('salary') else None,
            hired_date=data.get('hired_date') or datetime.utcnow().date().isoformat(),
        )
        db.session.add(emp)
        db.session.commit()
        flash('Employee added', 'success')
        return redirect(url_for('employees'))
    return render_template('employee_form.html', employee=None)


@app.route('/employees/<int:emp_id>/edit', methods=['GET', 'POST'])
def edit_employee(emp_id):
    if 'user_id' not in session:
        flash('Please log in first', 'warning')
        return redirect(url_for('login'))
    emp = Employee.query.get_or_404(emp_id)
    if request.method == 'POST':
        data = request.form
        emp.first_name = data.get('first_name', emp.first_name)
        emp.last_name = data.get('last_name', emp.last_name)
        emp.email = data.get('email', emp.email)
        emp.position = data.get('position', emp.position)
        emp.department = data.get('department', emp.department)
        emp.salary = float(data.get('salary') or emp.salary) if data.get('salary') else emp.salary
        emp.hired_date = data.get('hired_date') or emp.hired_date
        db.session.commit()
        flash('Employee updated', 'success')
        return redirect(url_for('employees'))
    return render_template('employee_form.html', employee=emp)


@app.route('/employees/<int:emp_id>/delete', methods=['POST'])
def delete_employee(emp_id):
    if 'user_id' not in session:
        flash('Please log in first', 'warning')
        return redirect(url_for('login'))
    emp = Employee.query.get_or_404(emp_id)
    db.session.delete(emp)
    db.session.commit()
    flash('Employee removed', 'info')
    return redirect(url_for('employees'))


# ----- Expense Tracker integration -----
def _patch_template(src: str) -> str:
    # Map expense_tracker template url_for names to our tracker endpoints
    return (
        src
        .replace("url_for('index')", "url_for('tracker_index')")
        .replace("url_for('report')", "url_for('tracker_report')")
        .replace("url_for('export_csv')", "url_for('tracker_export')")
        .replace("url_for('add_expense')", "url_for('tracker_add')")
        .replace("url_for('delete'", "url_for('tracker_delete'")
        .replace("url_for('set_theme')", "url_for('tracker_set_theme')")
    )


@app.route('/tracker')
def tracker_index():
    if 'user_id' not in session:
        flash('Please log in first', 'warning')
        return redirect(url_for('login'))

    et.init_db()
    et.seed_if_empty()
    totals = et.totals_by_category()
    recents = et.fetch_recent(10)
    month_total = et.monthly_total(datetime.utcnow().date())

    tpl = _patch_template(et.INDEX_TEMPLATE)
    return render_template_string(
        tpl,
        totals=totals,
        recents=recents,
        month_total=month_total,
        today=datetime.utcnow().date().isoformat(),
        categories=et.DEFAULT_CATEGORIES,
        theme=et.get_theme_vars(),
        theme_name=et.get_theme_name(),
    )


@app.route('/tracker/add', methods=['POST'])
def tracker_add():
    if 'user_id' not in session:
        flash('Please log in first', 'warning')
        return redirect(url_for('login'))
    try:
        exp = et.validate_expense_input(
            request.form.get('date', ''),
            request.form.get('amount', ''),
            request.form.get('category', ''),
            request.form.get('description', ''),
        )
        et.insert_expense(exp)
        flash('Expense added', 'success')
    except ValueError as e:
        flash(str(e), 'error')
    return redirect(url_for('tracker_index'))


@app.route('/tracker/delete/<int:expense_id>', methods=['POST'])
def tracker_delete(expense_id: int):
    if 'user_id' not in session:
        flash('Please log in first', 'warning')
        return redirect(url_for('login'))
    et.delete_expense(expense_id)
    flash('Expense deleted', 'success')
    return redirect(url_for('tracker_index'))


@app.route('/tracker/report')
def tracker_report():
    if 'user_id' not in session:
        flash('Please log in first', 'warning')
        return redirect(url_for('login'))
    et.init_db()
    start = request.args.get('start', '') or None
    end = request.args.get('end', '') or None
    category = request.args.get('category', '') or None

    err = None
    rows = []
    total = 0.0
    try:
        res = et.fetch_report(start, end, category)
        rows = res['rows']
        total = res['total']
    except ValueError as e:
        err = str(e)

    tpl = _patch_template(et.REPORT_TEMPLATE)
    return render_template_string(
        tpl,
        rows=rows,
        total=total,
        error=err,
        start=start or '',
        end=end or '',
        category=category or '',
        categories=et.DEFAULT_CATEGORIES,
        theme=et.get_theme_vars(),
        theme_name=et.get_theme_name(),
    )


@app.route('/tracker/export.csv')
def tracker_export():
    if 'user_id' not in session:
        flash('Please log in first', 'warning')
        return redirect(url_for('login'))
    et.init_db()
    res = et.fetch_report(
        request.args.get('start', '') or None,
        request.args.get('end', '') or None,
        request.args.get('category', '') or None,
    )
    # build CSV in memory
    sio = et.StringIO()
    writer = et.csv.writer(sio)
    writer.writerow(['id', 'date', 'amount', 'category', 'description'])
    for r in res['rows']:
        writer.writerow([r['id'], r['date'], r['amount'], r['category'], r['description']])
    mem = sio.getvalue().encode('utf-8')
    sio.close()
    return send_file(et.io_bytes(mem), mimetype='text/csv', as_attachment=True, download_name='expenses.csv')


@app.route('/tracker/set-theme')
def tracker_set_theme():
    # lightweight theme setter that mirrors expense_tracker.set_theme
    name = request.args.get('name', 'blue')
    if name not in et.THEMES:
        name = 'blue'
    resp = redirect(request.referrer or url_for('tracker_index'))
    resp.set_cookie('theme', name, max_age=60 * 60 * 24 * 365)
    return resp


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=5000)
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os
from datetime import datetime

app = Flask(__name__, template_folder='templates', static_folder='static')
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET', 'dev-secret-change-me')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///employees.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)


class Employee(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(80), nullable=False)
    last_name = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    position = db.Column(db.String(120), nullable=True)
    department = db.Column(db.String(120), nullable=True)
    salary = db.Column(db.Float, nullable=True)
    hired_date = db.Column(db.String(30), nullable=True)


@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('employees'))
    return redirect(url_for('login'))


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form.get('email', '').lower().strip()
        password = request.form.get('password', '')
        if not email or not password:
            flash('Please fill in all fields', 'danger')
            return redirect(url_for('signup'))
        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'warning')
            return redirect(url_for('signup'))

        user = User(email=email, password_hash=generate_password_hash(password, method='pbkdf2:sha256'))
        db.session.add(user)
        db.session.commit()
        flash('Account created. Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('signup.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').lower().strip()
        password = request.form.get('password', '')
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            session['user_email'] = user.email
            flash('Logged in successfully', 'success')
            return redirect(url_for('employees'))
        flash('Invalid credentials', 'danger')
        return redirect(url_for('login'))
    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out', 'info')
    return redirect(url_for('login'))


@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash('Please log in first', 'warning')
        return redirect(url_for('login'))
    emp_count = Employee.query.count()
    return render_template('dashboard.html', email=session.get('user_email'), emp_count=emp_count)


@app.route('/employees')
def employees():
    if 'user_id' not in session:
        flash('Please log in first', 'warning')
        return redirect(url_for('login'))
    items = Employee.query.order_by(Employee.id.desc()).all()
    return render_template('employees.html', employees=items)


@app.route('/employees/new', methods=['GET', 'POST'])
def new_employee():
    if 'user_id' not in session:
        flash('Please log in first', 'warning')
        return redirect(url_for('login'))
    if request.method == 'POST':
        data = request.form
        emp = Employee(
            first_name=data.get('first_name', '').strip(),
            last_name=data.get('last_name', '').strip(),
            email=data.get('email', '').strip(),
            position=data.get('position', '').strip(),
            department=data.get('department', '').strip(),
            salary=float(data.get('salary') or 0) if data.get('salary') else None,
            hired_date=data.get('hired_date') or datetime.utcnow().date().isoformat(),
        )
        db.session.add(emp)
        db.session.commit()
        flash('Employee added', 'success')
        return redirect(url_for('employees'))
    return render_template('employee_form.html', employee=None)


@app.route('/employees/<int:emp_id>/edit', methods=['GET', 'POST'])
def edit_employee(emp_id):
    if 'user_id' not in session:
        flash('Please log in first', 'warning')
        return redirect(url_for('login'))
    emp = Employee.query.get_or_404(emp_id)
    if request.method == 'POST':
        data = request.form
        emp.first_name = data.get('first_name', emp.first_name)
        emp.last_name = data.get('last_name', emp.last_name)
        emp.email = data.get('email', emp.email)
        emp.position = data.get('position', emp.position)
        emp.department = data.get('department', emp.department)
        emp.salary = float(data.get('salary') or emp.salary) if data.get('salary') else emp.salary
        emp.hired_date = data.get('hired_date') or emp.hired_date
        db.session.commit()
        flash('Employee updated', 'success')
        return redirect(url_for('employees'))
    return render_template('employee_form.html', employee=emp)


@app.route('/employees/<int:emp_id>/delete', methods=['POST'])
def delete_employee(emp_id):
    if 'user_id' not in session:
        flash('Please log in first', 'warning')
        return redirect(url_for('login'))
    emp = Employee.query.get_or_404(emp_id)
    db.session.delete(emp)
    db.session.commit()
    flash('Employee removed', 'info')
    return redirect(url_for('employees'))


if __name__ == '__main__':
    # Ensure DB exists
    with app.app_context():
        db.create_all()

    app.run(debug=True, port=5000)
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os

app = Flask(__name__, template_folder='templates', static_folder='static')
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET', 'dev-secret-change-me')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///employees.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

# NOTE: The @app.before_first_request section was removed here.
# The database creation logic is now at the very bottom of this file.

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form.get('email', '').lower().strip()
        password = request.form.get('password', '')
        if not email or not password:
            flash('Please fill in all fields', 'danger')
            return redirect(url_for('signup'))
        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'warning')
            return redirect(url_for('signup'))

        # Use PBKDF2 (sha256) explicitly to avoid environments where hashlib.scrypt
        # is not available (some Python builds / OpenSSL variants).
        user = User(email=email, password_hash=generate_password_hash(password, method='pbkdf2:sha256'))
        db.session.add(user)
        db.session.commit()
        flash('Account created. Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('signup.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').lower().strip()
        password = request.form.get('password', '')
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            session['user_email'] = user.email
            flash('Logged in successfully', 'success')
            return redirect(url_for('dashboard'))
        flash('Invalid credentials', 'danger')
        return redirect(url_for('login'))
    return render_template('login.html')


@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash('Please log in first', 'warning')
        return redirect(url_for('login'))
    return render_template('dashboard.html', email=session.get('user_email'))


@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out', 'info')
    return redirect(url_for('login'))


if __name__ == '__main__':
    # This block creates the database tables before the app starts
    with app.app_context():
        db.create_all()
        
    app.run(debug=True, port=5000)