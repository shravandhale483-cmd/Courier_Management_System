
import streamlit as st
import sqlite3
import pandas as pd
import hashlib
import secrets
import hmac
from datetime import datetime, date
import re

st.set_page_config(
    page_title="SwiftShip Courier System",
    page_icon="📦",
    layout="wide"
)

DB = "courier.db"

STATUSES = [
    "Booking Confirmed",
    "Pickup Scheduled",
    "Picked Up",
    "In Transit",
    "Arrived at Hub",
    "Out for Delivery",
    "Delivered",
    "Delivery Failed",
    "Returned to Sender"
]


# ---------------- DATABASE ----------------

def connect():
    con = sqlite3.connect(DB, timeout=30)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys = ON")
    return con


def hash_password(password):
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), salt.encode(), 200000
    ).hex()
    return salt + "$" + digest


def verify_password(password, stored):
    try:
        salt, digest = stored.split("$", 1)
        actual = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), salt.encode(), 200000
        ).hex()
        return hmac.compare_digest(actual, digest)
    except (ValueError, AttributeError):
        return False


def init_db():
    with connect() as con:
        con.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            phone TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'customer'
        );

        CREATE TABLE IF NOT EXISTS shipments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tracking_no TEXT UNIQUE NOT NULL,
            user_id INTEGER NOT NULL,
            sender_name TEXT NOT NULL,
            sender_phone TEXT NOT NULL,
            sender_address TEXT NOT NULL,
            sender_city TEXT NOT NULL,
            receiver_name TEXT NOT NULL,
            receiver_phone TEXT NOT NULL,
            receiver_address TEXT NOT NULL,
            receiver_city TEXT NOT NULL,
            parcel_type TEXT NOT NULL,
            weight REAL NOT NULL,
            amount REAL NOT NULL,
            payment_mode TEXT NOT NULL,
            status TEXT NOT NULL,
            expected_delivery TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS tracking_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            shipment_id INTEGER NOT NULL,
            status TEXT NOT NULL,
            location TEXT DEFAULT '',
            note TEXT DEFAULT '',
            event_time TEXT NOT NULL,
            FOREIGN KEY(shipment_id)
                REFERENCES shipments(id) ON DELETE CASCADE
        );
        """)

        # Demo admin account
        admin = con.execute(
            "SELECT id FROM users WHERE email = ?",
            ("admin@swiftship.demo",)
        ).fetchone()

        if not admin:
            con.execute("""
                INSERT INTO users
                (name, email, phone, password_hash, role)
                VALUES (?, ?, ?, ?, ?)
            """, (
                "Administrator",
                "admin@swiftship.demo",
                "9999999999",
                hash_password("Admin@123"),
                "admin"
            ))


def read_df(sql, params=()):
    with connect() as con:
        return pd.read_sql_query(sql, con, params=params)


def add_event(shipment_id, status, location, note):
    with connect() as con:
        con.execute("""
            INSERT INTO tracking_events
            (shipment_id, status, location, note, event_time)
            VALUES (?, ?, ?, ?, ?)
        """, (
            shipment_id, status, location, note,
            datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ))


# ---------------- UTILITIES ----------------

def make_tracking_number():
    return "SS" + datetime.now().strftime("%y%m%d") + secrets.token_hex(4).upper()


def estimate_price(weight, parcel, distance):
    base_prices = {
        "Document": 50,
        "Small Parcel": 80,
        "Medium Parcel": 130,
        "Large Parcel": 200
    }

    distance_prices = {
        "Same City": 0,
        "Within State": 50,
        "National": 100
    }

    return round(
        base_prices[parcel]
        + max(0, weight - 0.5) * 25
        + distance_prices[distance],
        2
    )


def record_event(shipment_id, status, location, note):
    # Keep current shipment status and its history consistent.
    with connect() as con:
        con.execute(
            "UPDATE shipments SET status = ? WHERE id = ?",
            (status, shipment_id)
        )
        con.execute("""
            INSERT INTO tracking_events
            (shipment_id, status, location, note, event_time)
            VALUES (?, ?, ?, ?, ?)
        """, (
            shipment_id, status, location.strip(), note.strip(),
            datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ))


# ---------------- LOGIN / REGISTER ----------------

def authentication_page():
    st.title("📦 SwiftShip")
    st.subheader("Courier Booking & Tracking System")
    st.write("Book parcels online and track their delivery progress.")

    login_tab, register_tab = st.tabs(
        ["Sign In", "Create Customer Account"]
    )

    with login_tab:
        with st.form("login_form"):
            email = st.text_input("Email")
            password = st.text_input("Password", type="password")
            login = st.form_submit_button(
                "Sign In", type="primary"
            )

        if login:
            users = read_df(
                "SELECT * FROM users WHERE lower(email)=lower(?)",
                (email.strip(),)
            )

            if (
                not users.empty
                and verify_password(
                    password, users.iloc[0]["password_hash"]
                )
            ):
                u = users.iloc[0]
                st.session_state["user"] = {
                    "id": int(u["id"]),
                    "name": u["name"],
                    "email": u["email"],
                    "role": u["role"]
                }
                st.rerun()
            else:
                st.error("Invalid email or password.")

    with register_tab:
        with st.form("register_form"):
            name = st.text_input("Full Name")
            new_email = st.text_input("Email Address")
            phone = st.text_input("Phone Number")
            p1 = st.text_input("Create Password", type="password")
            p2 = st.text_input("Confirm Password", type="password")
            register = st.form_submit_button(
                "Create Account", type="primary"
            )

        if register:
            if not all([
                name.strip(), new_email.strip(),
                phone.strip(), p1, p2
            ]):
                st.error("Please fill in all fields.")
            elif not re.fullmatch(
                r"[^@\s]+@[^@\s]+\.[^@\s]+",
                new_email.strip()
            ):
                st.error("Enter a valid email address.")
            elif len(p1) < 8:
                st.error("Password must have at least 8 characters.")
            elif p1 != p2:
                st.error("Passwords do not match.")
            else:
                try:
                    with connect() as con:
                        con.execute("""
                            INSERT INTO users
                            (name, email, phone, password_hash, role)
                            VALUES (?, ?, ?, ?, 'customer')
                        """, (
                            name.strip(),
                            new_email.strip().lower(),
                            phone.strip(),
                            hash_password(p1)
                        ))
                    st.success("Account created. Please sign in.")
                except sqlite3.IntegrityError:
                    st.error("This email is already registered.")

    st.caption(
        "Demo admin: admin@swiftship.demo | Password: Admin@123"
    )


# ---------------- CUSTOMER DASHBOARD ----------------


# ---------------- CUSTOMER DASHBOARD ----------------

def customer_dashboard(user):
    st.title(f"Welcome, {user['name']} 👋")
    st.caption("Your personal courier dashboard — everything you need in one place.")

    shipments = read_df(
        "SELECT * FROM shipments WHERE user_id=? ORDER BY id DESC",
        (user["id"],)
    )

    total = len(shipments)
    delivered = int(
        (shipments["status"] == "Delivered").sum()
    ) if total else 0
    returned = int(
        (shipments["status"] == "Returned to Sender").sum()
    ) if total else 0
    in_progress = total - delivered - returned

    # Dashboard metric cards
    st.markdown("### 📊 Shipment Overview")
    a, b, c, d = st.columns(4)

    a.metric("📦 Total Bookings", total)
    b.metric("🚚 In Progress", in_progress)
    c.metric("✅ Delivered", delivered)
    d.metric("↩️ Returned", returned)

    st.divider()

    # Quick action cards
    st.markdown("### ⚡ Quick Overview")

    col1, col2 = st.columns(2)

    with col1:
        st.markdown("#### 📦 Manage Your Couriers")
        st.write("Create a shipment booking and arrange delivery.")
        st.info("Use **Send a Courier** in the sidebar to book a parcel.")

    with col2:
        st.markdown("#### 🔎 Track Your Shipment")
        st.write("Check your parcel's latest tracking status.")
        st.info("Use **Track Courier** in the sidebar to track a parcel.")

    st.divider()

    # Shipment analytics
    chart_col, overview_col = st.columns([1.2, 1])

    with chart_col:
        st.markdown("### 📈 Shipment Analytics")

        if shipments.empty:
            st.info("Your chart will appear after your first booking.")
        else:
            status_counts = (
                shipments["status"]
                .fillna("Unknown")
                .value_counts()
                .rename_axis("Status")
                .reset_index(name="Shipments")
            )

            st.bar_chart(
                status_counts.set_index("Status"),
                height=300
            )

    with overview_col:
        st.markdown("### 🎯 Delivery Progress")

        if total == 0:
            st.write("You haven't booked any couriers yet.")
            st.progress(0.0)
        else:
            st.metric(
                "Delivery Success",
                f"{(delivered / total) * 100:.1f}%"
            )
            st.progress(delivered / total)
            st.caption(f"{delivered} out of {total} shipments delivered.")

            if in_progress > 0:
                st.warning(f"{in_progress} shipment(s) are still in progress.")
            elif delivered == total:
                st.success("All your shipments have been delivered!")

    st.divider()

    # Recent shipment table
    st.markdown("### 📋 My Recent Shipments")

    if shipments.empty:
        st.info(
            "No bookings yet. Select **Send a Courier** "
            "from the sidebar to get started."
        )
        return

    filter_col, search_col = st.columns([1, 2])

    with filter_col:
        statuses = ["All Statuses"] + sorted(
            shipments["status"].dropna().astype(str).unique().tolist()
        )
        selected_status = st.selectbox(
            "Filter by status",
            statuses,
            key="dashboard_status_filter"
        )

    with search_col:
        search_text = st.text_input(
            "Search shipments",
            placeholder="Tracking number, receiver or destination...",
            key="dashboard_search"
        )

    view = shipments[
        [
            "tracking_no",
            "receiver_name",
            "receiver_city",
            "status",
            "expected_delivery",
            "amount"
        ]
    ].copy()

    view.columns = [
        "Tracking Number",
        "Receiver",
        "Destination",
        "Status",
        "Expected Delivery",
        "Charge (INR)"
    ]

    if selected_status != "All Statuses":
        view = view[view["Status"].astype(str) == selected_status]

    if search_text.strip():
        term = search_text.strip().lower()
        mask = view.astype(str).apply(
            lambda col: col.str.lower().str.contains(term, regex=False)
        ).any(axis=1)
        view = view[mask]

    st.dataframe(
        view,
        use_container_width=True,
        hide_index=True
    )

    st.caption(f"Showing {len(view)} shipment(s).")


# ---------------- COURIER BOOKING ----------------

# ---------------- COURIER BOOKING ----------------

def booking_page(user):
    st.title("📮 Send a Courier")
    st.caption("Fields marked * are required.")

    with st.form("booking_form"):
        st.subheader("Sender Details")
        c1, c2 = st.columns(2)

        with c1:
            sender_name = st.text_input(
                "Sender Name *", value=user["name"]
            )
            sender_phone = st.text_input("Sender Phone *")
            sender_city = st.text_input("Pickup City *")
            sender_address = st.text_area("Pickup Address *")

        with c2:
            parcel = st.selectbox(
                "Parcel Type",
                ["Document", "Small Parcel",
                 "Medium Parcel", "Large Parcel"]
            )
            weight = st.number_input(
                "Weight (kg)", min_value=0.1,
                max_value=100.0, value=0.5, step=0.1
            )
            distance = st.selectbox(
                "Delivery Distance",
                ["Same City", "Within State", "National"]
            )
            payment = st.selectbox(
                "Payment Mode",
                ["Pay at Booking (Demo)",
                 "Cash on Delivery (Record Only)"]
            )

        st.subheader("Receiver Details")
        c1, c2 = st.columns(2)

        with c1:
            receiver_name = st.text_input("Receiver Name *")
            receiver_phone = st.text_input("Receiver Phone *")
            receiver_city = st.text_input("Destination City *")

        with c2:
            receiver_address = st.text_area("Delivery Address *")
            expected = st.date_input(
                "Expected Delivery Date",
                value=date.today(),
                min_value=date.today()
            )

        charge = estimate_price(weight, parcel, distance)
        st.info(
            f"Estimated courier charge: ₹{charge:.2f}. "
            "This is a demo estimate, not a real carrier quote."
        )

        submit = st.form_submit_button(
            "Confirm Booking", type="primary",
            use_container_width=True
        )

    if submit:
        required = [
            sender_name, sender_phone, sender_city, sender_address,
            receiver_name, receiver_phone, receiver_city,
            receiver_address
        ]

        if not all(x.strip() for x in required):
            st.error("Please complete all required fields.")
            return

        tracking = make_tracking_number()
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        try:
            with connect() as con:
                cur = con.execute("""
                    INSERT INTO shipments (
                        tracking_no, user_id,
                        sender_name, sender_phone,
                        sender_address, sender_city,
                        receiver_name, receiver_phone,
                        receiver_address, receiver_city,
                        parcel_type, weight, amount,
                        payment_mode, status,
                        expected_delivery, created_at
                    )
                    VALUES (
                        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                        ?, ?, ?, ?, ?, ?, ?
                    )
                """, (
                    tracking, user["id"],
                    sender_name.strip(), sender_phone.strip(),
                    sender_address.strip(), sender_city.strip(),
                    receiver_name.strip(), receiver_phone.strip(),
                    receiver_address.strip(), receiver_city.strip(),
                    parcel, float(weight), charge,
                    payment, "Booking Confirmed",
                    str(expected), now
                ))

                shipment_id = cur.lastrowid

            add_event(
                shipment_id,
                "Booking Confirmed",
                sender_city,
                "Booking created by customer."
            )

            st.success("Courier booked successfully!")
            st.subheader("Your Tracking Number")
            st.code(tracking)
            st.warning("Save this number for future reference.")

        except sqlite3.IntegrityError:
            st.error("Booking failed. Please try again.")


# ---------------- CUSTOMER TRACKING ----------------

def tracking_page(user):
    st.title("🔎 Track My Courier")

    with st.form("tracking_form"):
        tracking = st.text_input(
            "Enter Tracking Number",
            placeholder="Example: SS261024ABC12345"
        )
        submit = st.form_submit_button(
            "Track Shipment", type="primary"
        )

    if submit:
        shipment = read_df("""
            SELECT * FROM shipments
            WHERE upper(tracking_no)=upper(?) AND user_id=?
        """, (tracking.strip(), user["id"]))

        if shipment.empty:
            st.error("Tracking number not found in your account.")
            return

        s = shipment.iloc[0]

        st.subheader(f"Shipment: {s['tracking_no']}")
        st.success(f"Current Status: {s['status']}")

        c1, c2, c3 = st.columns(3)
        c1.metric("Origin", s["sender_city"])
        c2.metric("Destination", s["receiver_city"])
        c3.metric("Estimated Delivery", s["expected_delivery"])

        events = read_df("""
            SELECT status, location, note, event_time
            FROM tracking_events
            WHERE shipment_id=?
            ORDER BY id DESC
        """, (int(s["id"]),))

        st.subheader("Tracking Timeline")

        if events.empty:
            st.info("No tracking updates available.")
        else:
            for _, event in events.iterrows():
                st.markdown(
                    f"**📍 {event['status']}**  \n"
                    f"{event['event_time']}  \n"
                    f"Location: {event['location'] or 'Not updated'}  \n"
                    f"{event['note']}"
                )
                st.divider()


# ---------------- ADMIN DASHBOARD ----------------

def admin_dashboard():
    st.title("🛠️ Admin Operations")

    shipments = read_df("""
        SELECT s.*, u.email AS customer_email
        FROM shipments s
        JOIN users u ON u.id=s.user_id
        ORDER BY s.id DESC
    """)

    a, b, c = st.columns(3)
    a.metric("Total Bookings", len(shipments))
    b.metric(
        "In Transit",
        int(shipments["status"].isin([
            "Picked Up", "In Transit",
            "Arrived at Hub", "Out for Delivery"
        ]).sum()) if not shipments.empty else 0
    )
    c.metric(
        "Delivered",
        int((shipments["status"] == "Delivered").sum())
        if not shipments.empty else 0
    )

    st.subheader("All Courier Bookings")

    if shipments.empty:
        st.info("No courier bookings received yet.")
        return

    display = shipments.drop(
        columns=["id", "user_id"], errors="ignore"
    )
    st.dataframe(
        display, use_container_width=True, hide_index=True
    )

    st.download_button(
        "Download Bookings CSV",
        display.to_csv(index=False).encode("utf-8"),
        "courier_bookings.csv",
        "text/csv"
    )

    st.divider()
    st.subheader("Update Shipment Status")

    options = {
        f"{r.tracking_no} | {r.sender_city} → {r.receiver_city}": int(r.id)
        for r in shipments.itertuples()
    }

    selected = st.selectbox("Select Shipment", list(options.keys()))
    shipment_id = options[selected]

    with st.form("update_status_form"):
        new_status = st.selectbox("New Status", STATUSES)
        location = st.text_input(
            "Current Location / Hub",
            placeholder="Example: Nagpur Sorting Hub"
        )
        note = st.text_input(
            "Update Note",
            placeholder="Example: Parcel received at hub"
        )
        update = st.form_submit_button(
            "Save Tracking Update", type="primary"
        )

    if update:
        record_event(shipment_id, new_status, location, note)
        st.success("Tracking update saved.")
        st.rerun()

    st.divider()
    st.subheader("Registered Customers")

    customers = read_df("""
        SELECT id, name, email, phone, role
        FROM users ORDER BY id DESC
    """)

    st.dataframe(
        customers, use_container_width=True, hide_index=True
    )


# ---------------- MAIN APP ----------------

def main():
    init_db()
    
    st.markdown("""
<style>
/* ===== SwiftShip Modern UI ===== */
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');

:root {
    --bg: #0b1120;
    --panel: #111b2e;
    --panel-hover: #17243a;
    --border: #25334b;
    --primary: #3b82f6;
    --primary-light: #60a5fa;
    --text: #f1f5f9;
    --muted: #94a3b8;
    --green: #34d399;
    --orange: #fbbf24;
    --red: #fb7185;
}

html, body, [class*="css"] {
    font-family: 'Inter', sans-serif;
}

.stApp {
    background: var(--bg);
    color: var(--text);
}

/* Main content */
.block-container {
    max-width: 1500px;
    padding-top: 2rem;
    padding-bottom: 3rem;
}

/* Sidebar */
[data-testid="stSidebar"] {
    background: #0d1729;
    border-right: 1px solid var(--border);
}

[data-testid="stSidebar"] > div:first-child {
    padding-top: 1.5rem;
}

[data-testid="stSidebar"] * {
    color: var(--text);
}

[data-testid="stSidebar"] [data-testid="stMarkdownContainer"] h1 {
    color: var(--primary-light);
    font-size: 1.55rem;
    font-weight: 800;
}

/* Headings */
h1, h2, h3 {
    color: var(--text) !important;
    font-weight: 700 !important;
    letter-spacing: -0.5px;
}

h1 {
    font-size: 2rem !important;
}

h2 {
    font-size: 1.5rem !important;
}

p, label, .stMarkdown {
    color: #d5deea;
}

/* Metric cards */
[data-testid="stMetric"] {
    background: linear-gradient(145deg, #14213a, #101a2d);
    border: 1px solid var(--border);
    border-radius: 16px;
    padding: 20px 22px;
    box-shadow: 0 8px 24px rgba(0,0,0,.12);
    transition: transform .2s ease, border-color .2s ease;
}

[data-testid="stMetric"]:hover {
    transform: translateY(-3px);
    border-color: var(--primary);
}

[data-testid="stMetricLabel"] {
    color: var(--muted) !important;
    font-size: .88rem !important;
}

[data-testid="stMetricValue"] {
    color: #f8fafc !important;
    font-size: 1.9rem !important;
    font-weight: 800 !important;
}

[data-testid="stMetricDelta"] {
    font-size: .8rem;
}

/* Buttons */
.stButton > button,
.stFormSubmitButton > button {
    background: linear-gradient(135deg, #2563eb, #3b82f6);
    color: white !important;
    border: 1px solid #3b82f6;
    border-radius: 10px;
    padding: .65rem 1.15rem;
    font-weight: 600;
    transition: all .2s ease;
}

.stButton > button:hover,
.stFormSubmitButton > button:hover {
    background: #1d4ed8;
    border-color: #60a5fa;
    transform: translateY(-1px);
    box-shadow: 0 5px 16px rgba(59,130,246,.22);
}

.stButton > button:focus,
.stFormSubmitButton > button:focus {
    box-shadow: 0 0 0 3px rgba(59,130,246,.25);
}

/* Inputs and dropdowns */
.stTextInput input,
.stNumberInput input,
.stDateInput input,
.stTimeInput input,
.stTextArea textarea {
    background: #0d1729 !important;
    color: #f1f5f9 !important;
    border: 1px solid #33445f !important;
    border-radius: 10px !important;
}

.stTextInput input:focus,
.stNumberInput input:focus,
.stTextArea textarea:focus {
    border-color: var(--primary) !important;
    box-shadow: 0 0 0 2px rgba(59,130,246,.15) !important;
}

[data-baseweb="select"] > div {
    background: #0d1729 !important;
    border-color: #33445f !important;
    border-radius: 10px !important;
    color: #f1f5f9 !important;
}

[data-baseweb="popover"],
[data-baseweb="menu"] {
    background: #14213a !important;
    color: #f1f5f9 !important;
}

/* Forms and expanders */
[data-testid="stForm"],
[data-testid="stExpander"] {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 14px;
    padding: 10px;
}

[data-testid="stExpander"] summary {
    font-weight: 600;
}

/* Data tables */
[data-testid="stDataFrame"],
[data-testid="stTable"] {
    border: 1px solid var(--border);
    border-radius: 12px;
    overflow: hidden;
}

[data-testid="stDataFrame"] * {
    font-size: .9rem;
}

/* Tabs */
.stTabs [data-baseweb="tab-list"] {
    gap: 8px;
    border-bottom: 1px solid var(--border);
}

.stTabs [data-baseweb="tab"] {
    background: transparent;
    border-radius: 8px 8px 0 0;
    padding: 10px 16px;
    color: var(--muted);
}

.stTabs [aria-selected="true"] {
    color: var(--primary-light) !important;
    border-bottom: 2px solid var(--primary) !important;
}

/* Alerts */
[data-testid="stAlert"] {
    border-radius: 12px;
    border: 1px solid var(--border);
}

/* Progress bars */
.stProgress > div > div > div {
    background: var(--primary);
    border-radius: 20px;
}

/* Dividers and captions */
hr {
    border-color: var(--border) !important;
}

[data-testid="stCaptionContainer"] {
    color: var(--muted);
}

/* Scrollbar */
::-webkit-scrollbar {
    width: 8px;
    height: 8px;
}

::-webkit-scrollbar-track {
    background: #0b1120;
}

::-webkit-scrollbar-thumb {
    background: #33445f;
    border-radius: 10px;
}

::-webkit-scrollbar-thumb:hover {
    background: #4b6385;
}

/* Mobile responsiveness */
@media (max-width: 768px) {
    .block-container {
        padding: 1rem;
    }

    h1 {
        font-size: 1.6rem !important;
    }

    [data-testid="stMetric"] {
        padding: 14px;
    }

    [data-testid="stMetricValue"] {
        font-size: 1.4rem !important;
    }
}
</style>
""", unsafe_allow_html=True)


  
    user = st.session_state.get("user")

    if not user:
        authentication_page()
        return

    with st.sidebar:
        st.title("📦 SwiftShip")
        st.caption(f"Signed in: {user['name']}")

        if user["role"] == "admin":
            page = st.radio(
                "MENU",
                ["Admin Dashboard"]
            )
        else:
            page = st.radio(
                "MENU",
                [
                    "My Dashboard",
                    "Send a Courier",
                    "Track Courier"
                ]
            )

        if st.button("Sign Out", use_container_width=True):
            st.session_state.pop("user", None)
            st.rerun()

    if page == "Admin Dashboard":
        admin_dashboard()
    elif page == "My Dashboard":
        customer_dashboard(user)
    elif page == "Send a Courier":
        booking_page(user)
    elif page == "Track Courier":
        tracking_page(user)


if __name__ == "__main__":
    main()
