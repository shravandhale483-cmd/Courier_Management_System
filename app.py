import os
import sqlite3
import hashlib
import hmac
import secrets
import pandas as pd
import streamlit as st

st.set_page_config(
    page_title="CustomerHub | Customer Management",
    page_icon="👥",
    layout="wide",
    initial_sidebar_state="expanded",
)

DB_PATH = os.path.join(os.path.dirname(__file__), "customers.db")
STATUSES = ["Active", "Inactive", "Lead"]


def get_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def hash_password(password, salt=None):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 200_000).hex()
    return f"{salt}${digest}"


def verify_password(password, stored):
    try:
        salt, expected = stored.split("$", 1)
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 200_000).hex()
        return hmac.compare_digest(actual, expected)
    except (ValueError, AttributeError):
        return False


def init_db():
    with get_db() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS customers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                phone TEXT NOT NULL,
                company TEXT DEFAULT '',
                address TEXT DEFAULT '',
                status TEXT NOT NULL DEFAULT 'Active'
                    CHECK(status IN ('Active','Inactive','Lead')),
                notes TEXT DEFAULT '',
                created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
            )
        """)
        if db.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
            db.execute(
                "INSERT INTO users(username,password_hash) VALUES (?,?)",
                ("admin", hash_password("Admin@123")),
            )


def query_df(sql, params=()):
    with get_db() as db:
        return pd.read_sql_query(sql, db, params=params)


def add_customer(values):
    with get_db() as db:
        db.execute("""INSERT INTO customers
            (name,email,phone,company,address,status,notes)
            VALUES (?,?,?,?,?,?,?)""", values)


def update_customer(customer_id, values):
    with get_db() as db:
        db.execute("""UPDATE customers SET name=?,email=?,phone=?,company=?,
            address=?,status=?,notes=? WHERE id=?""", (*values, customer_id))


def login_screen():
    st.markdown("<div class='hero'><div class='eyebrow'>CUSTOMER RELATIONSHIP WORKSPACE</div><h1>CustomerHub</h1><p>One simple place to organize every customer relationship.</p></div>", unsafe_allow_html=True)
    left, center, right = st.columns([1, 1.15, 1])
    with center:
        with st.container(border=True):
            st.subheader("🔐 Admin sign in")
            with st.form("login_form"):
                username = st.text_input("Username", placeholder="Enter username")
                password = st.text_input("Password", type="password", placeholder="Enter password")
                submitted = st.form_submit_button("Sign in", type="primary", use_container_width=True)
            if submitted:
                user = query_df("SELECT * FROM users WHERE username = ?", (username.strip(),))
                if not user.empty and verify_password(password, user.iloc[0]["password_hash"]):
                    st.session_state["authenticated"] = True
                    st.session_state["username"] = username.strip()
                    st.rerun()
                else:
                    st.error("Invalid username or password.")
            st.caption("Demo credentials: `admin` / `Admin@123`")
            st.warning("Change the demo password and add production-grade security before using real customer data.")


def customer_form(default=None, key_prefix="add"):
    default = default or {}
    with st.form(f"{key_prefix}_customer_form"):
        c1, c2 = st.columns(2)
        with c1:
            name = st.text_input("Full name *", value=str(default.get("name", "")))
            email = st.text_input("Email address *", value=str(default.get("email", "")))
            phone = st.text_input("Phone number *", value=str(default.get("phone", "")))
            company = st.text_input("Company", value=str(default.get("company", "")))
        with c2:
            current_status = str(default.get("status", "Active"))
            status = st.selectbox("Status", STATUSES, index=STATUSES.index(current_status) if current_status in STATUSES else 0)
            address = st.text_input("Address", value=str(default.get("address", "")))
            notes = st.text_area("Notes", value=str(default.get("notes", "")), height=110)
        submitted = st.form_submit_button("Save customer", type="primary", use_container_width=True)
    if submitted:
        name, email, phone = name.strip(), email.strip().lower(), phone.strip()
        if not name or not email or not phone:
            st.error("Name, email, and phone are required.")
        elif "@" not in email or "." not in email.split("@")[-1]:
            st.error("Please enter a valid email address.")
        else:
            return (name, email, phone, company.strip(), address.strip(), status, notes.strip())
    return None


def dashboard():
    st.markdown("<div class='eyebrow'>OVERVIEW</div><h1>Customer dashboard</h1><p class='subhead'>A clear snapshot of your customer database.</p>", unsafe_allow_html=True)
    data = query_df("SELECT * FROM customers")
    total = len(data)
    active = int((data["status"] == "Active").sum()) if total else 0
    leads = int((data["status"] == "Lead").sum()) if total else 0
    inactive = int((data["status"] == "Inactive").sum()) if total else 0
    cols = st.columns(4)
    for col, label, value, icon in zip(cols, ["Total customers", "Active", "Potential leads", "Inactive"], [total, active, leads, inactive], ["👥", "✅", "🌱", "⏸️"]):
        with col:
            st.metric(f"{icon} {label}", value)
    st.write("")
    left, right = st.columns([1.35, 1])
    with left:
        with st.container(border=True):
            st.subheader("🕒 Recently added")
            recent = query_df("SELECT name,email,company,status,created_at FROM customers ORDER BY id DESC LIMIT 5")
            if recent.empty:
                st.info("No customer records yet. Open **Add customer** from the sidebar to create your first record.")
            else:
                st.dataframe(recent, use_container_width=True, hide_index=True)
    with right:
        with st.container(border=True):
            st.subheader("📊 Customer status")
            if total:
                counts = data["status"].value_counts().reindex(STATUSES, fill_value=0)
                st.bar_chart(counts)
            else:
                st.caption("Status chart appears after customers are added.")
            st.caption("Use the Customers page to search, filter, edit, delete, or export records.")


def customers_page():
    st.title("👥 Customers")
    st.caption("Search and manage your customer records.")
    c1, c2 = st.columns([3, 1])
    with c1:
        search = st.text_input("Search", placeholder="Search by name, email, phone or company", label_visibility="collapsed")
    with c2:
        status_filter = st.selectbox("Status", ["All statuses"] + STATUSES, label_visibility="collapsed")
    sql = "SELECT id,name,email,phone,company,status,created_at FROM customers WHERE 1=1"
    params = []
    if search.strip():
        term = f"%{search.strip()}%"
        sql += " AND (name LIKE ? OR email LIKE ? OR phone LIKE ? OR company LIKE ?)"
        params.extend([term, term, term, term])
    if status_filter != "All statuses":
        sql += " AND status=?"
        params.append(status_filter)
    sql += " ORDER BY id DESC"
    rows = query_df(sql, tuple(params))
    st.caption(f"{len(rows)} record(s) found")
    st.dataframe(rows, use_container_width=True, hide_index=True)
    if not rows.empty:
        csv_data = rows.to_csv(index=False).encode("utf-8")
        st.download_button("⬇️ Export displayed records to CSV", csv_data, "customers.csv", "text/csv")
    st.divider()
    st.subheader("Edit or delete a customer")
    all_customers = query_df("SELECT * FROM customers ORDER BY id DESC")
    if all_customers.empty:
        st.info("Add a customer first to enable editing and deletion.")
        return
    labels = {f"#{int(row['id'])} · {row['name']} ({row['email']})": int(row["id"]) for _, row in all_customers.iterrows()}
    selected_label = st.selectbox("Select customer", list(labels.keys()))
    customer_id = labels[selected_label]
    record = all_customers[all_customers["id"] == customer_id].iloc[0].to_dict()
    with st.expander("✏️ Edit selected customer"):
        values = customer_form(record, key_prefix=f"edit_{customer_id}")
        if values:
            try:
                update_customer(customer_id, values)
                st.success("Customer updated successfully.")
                st.rerun()
            except sqlite3.IntegrityError:
                st.error("That email address is already used by another customer.")
    with st.expander("🗑️ Delete selected customer"):
        st.warning(f"This will permanently delete {record['name']}'s record.")
        confirm = st.checkbox("I confirm that I want to delete this customer.", key=f"confirm_delete_{customer_id}")
        if st.button("Delete customer", type="primary", disabled=not confirm, key=f"delete_{customer_id}"):
            with get_db() as db:
                db.execute("DELETE FROM customers WHERE id=?", (customer_id,))
            st.success("Customer deleted.")
            st.rerun()


def add_page():
    st.title("➕ Add customer")
    st.caption("Create a new customer record.")
    values = customer_form(key_prefix="new")
    if values:
        try:
            add_customer(values)
            st.success("Customer added successfully.")
            st.rerun()
        except sqlite3.IntegrityError:
            st.error("A customer with this email already exists.")


def main():
    init_db()
    st.markdown("""
    <style>
     
    st.markdown("""
    <style>
      /* Main page: dark text on light background */
      .stApp,
      [data-testid="stAppViewContainer"],
      [data-testid="stMain"] {
          background: #f5f7fb !important;
          color: #182338 !important;
      }

      [data-testid="stMain"] h1,
      [data-testid="stMain"] h2,
      [data-testid="stMain"] h3,
      [data-testid="stMain"] p,
      [data-testid="stMain"] label,
      [data-testid="stMain"] span,
      [data-testid="stMain"] div {
          color: inherit;
      }

      [data-testid="stSidebar"] {
          background: #17233c !important;
      }

      [data-testid="stSidebar"] * {
          color: #f5f7ff;
      }

      .hero {
          text-align: center;
          padding: 3.2rem 0 1.5rem;
      }

      .hero h1 {
          color: #182338 !important;
          font-size: 3rem;
          font-weight: 800;
      }

      .hero p, .subhead {
          color: #718096 !important;
      }

      .eyebrow {
          color: #4965df !important;
          font-size: .75rem;
          font-weight: 800;
          letter-spacing: 1.8px;
      }

      [data-testid="stMetric"] {
          background: white;
          color: #182338 !important;
          padding: 1.1rem;
          border: 1px solid #e6ebf3;
          border-radius: 14px;
      }

      [data-testid="stMetric"] label,
      [data-testid="stMetric"] [data-testid="stMetricValue"] {
          color: #182338 !important;
      }

      [data-testid="stVerticalBlockBorderWrapper"] {
          background: white;
          border-radius: 14px;
      }

      .stButton button[kind="primary"],
      .stFormSubmitButton button[kind="primary"] {
          background: #3659d9;
          border-color: #3659d9;
          color: white !important;
      }
    </style>
    """, unsafe_allow_html=True)

    </style>
    """, unsafe_allow_html=True)

    if not st.session_state.get("authenticated", False):
        login_screen()
        return

    with st.sidebar:
        st.markdown("## 👥 CustomerHub")
        st.caption(f"Signed in as **{st.session_state.get('username', 'admin')}**")
        page = st.radio("NAVIGATION", ["Dashboard", "Customers", "Add customer"], label_visibility="visible")
        st.divider()
        if st.button("Log out", use_container_width=True):
            st.session_state.clear()
            st.rerun()
        st.caption("Python · Streamlit · SQLite")

    if page == "Dashboard":
        dashboard()
    elif page == "Customers":
        customers_page()
    else:
        add_page()


if __name__ == "__main__":
    main()
