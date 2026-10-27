
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

        # Safe migration: add staff assignment without deleting existing bookings.
        shipment_columns = {
            row[1] for row in con.execute("PRAGMA table_info(shipments)").fetchall()
        }
        if "delivery_staff_id" not in shipment_columns:
            con.execute("ALTER TABLE shipments ADD COLUMN delivery_staff_id INTEGER")

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


# ---------------- DELIVERY STAFF DASHBOARD ----------------

def delivery_staff_dashboard(user):
    st.title("🚚 Delivery Staff Dashboard")
    st.caption("View only the shipments assigned to your account and update delivery progress.")

    shipments = read_df("""
        SELECT s.id, s.tracking_no, s.sender_name, s.sender_phone,
               s.sender_address, s.sender_city, s.receiver_name,
               s.receiver_phone, s.receiver_address, s.receiver_city,
               s.parcel_type, s.weight, s.status, s.expected_delivery,
               s.created_at
        FROM shipments s
        WHERE s.delivery_staff_id = ?
        ORDER BY s.id DESC
    """, (int(user["id"]),))

    total = len(shipments)
    delivered = int((shipments["status"] == "Delivered").sum()) if total else 0
    pending = total - delivered
    a, b, c = st.columns(3)
    a.metric("Assigned Shipments", total)
    b.metric("Pending Deliveries", pending)
    c.metric("Delivered", delivered)

    if shipments.empty:
        st.info("No shipments have been assigned to you yet. Please contact the admin.")
        return

    st.subheader("My Assigned Shipments")
    st.dataframe(
        shipments.drop(columns=["id"], errors="ignore"),
        use_container_width=True, hide_index=True
    )

    options = {
        f"{r.tracking_no} | {r.sender_city} → {r.receiver_city}": int(r.id)
        for r in shipments.itertuples()
    }
    st.subheader("Update Delivery Status")
    with st.form("staff_update_status_form"):
        selected = st.selectbox("Select assigned shipment", list(options.keys()))
        new_status = st.selectbox("New Status", STATUSES)
        location = st.text_input("Current Location / Hub", placeholder="Example: Nagpur Sorting Hub")
        note = st.text_input("Update Note", placeholder="Example: Parcel out for delivery")
        update = st.form_submit_button("Save Tracking Update", type="primary")

    if update:
        shipment_id = options[selected]
        # Server-side ownership check: staff can only update their assigned shipments.
        assigned = read_df(
            "SELECT id FROM shipments WHERE id = ? AND delivery_staff_id = ?",
            (shipment_id, int(user["id"]))
        )
        if assigned.empty:
            st.error("This shipment is not assigned to your account.")
        else:
            record_event(shipment_id, new_status, location, note)
            st.success("Tracking status updated successfully.")
            st.rerun()


# ---------------- ADMIN DASHBOARD ----------------

def admin_dashboard():
    st.title("🛠️ Admin Operations")

    # Admin can create delivery staff accounts; credentials are set by the admin.
    st.subheader("👷 Create Delivery Staff Account")
    with st.form("create_delivery_staff_form"):
        staff_name = st.text_input("Staff Full Name")
        staff_email = st.text_input("Staff Email")
        staff_phone = st.text_input("Staff Phone")
        staff_password = st.text_input("Temporary Password (minimum 8 characters)", type="password")
        create_staff = st.form_submit_button("Create Staff Account", type="primary")

    if create_staff:
        if not all([staff_name.strip(), staff_email.strip(), staff_phone.strip(), staff_password]):
            st.error("Please complete all staff fields.")
        elif not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", staff_email.strip()):
            st.error("Enter a valid staff email address.")
        elif len(staff_password) < 8:
            st.error("Staff password must have at least 8 characters.")
        else:
            try:
                with connect() as con:
                    con.execute("""
                        INSERT INTO users (name, email, phone, password_hash, role)
                        VALUES (?, ?, ?, ?, 'delivery')
                    """, (staff_name.strip(), staff_email.strip().lower(), staff_phone.strip(), hash_password(staff_password)))
                st.success("Delivery staff account created. Share the login details securely with the staff member.")
            except sqlite3.IntegrityError:
                st.error("An account with this email already exists.")

    st.divider()

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
    st.subheader("📦 Assign Courier to Delivery Staff")
    staff = read_df("SELECT id, name, email FROM users WHERE role = 'delivery' ORDER BY name")
    if staff.empty:
        st.info("Create a delivery staff account above before assigning shipments.")
    else:
        shipment_options = {
            f"{r.tracking_no} | {r.sender_city} → {r.receiver_city}": int(r.id)
            for r in shipments.itertuples()
        }
        staff_options = {
            f"{r.name} ({r.email})": int(r.id)
            for r in staff.itertuples()
        }
        with st.form("assign_shipment_form"):
            chosen_shipment = st.selectbox("Select courier", list(shipment_options.keys()))
            chosen_staff = st.selectbox("Assign to staff member", list(staff_options.keys()))
            assign = st.form_submit_button("Assign Courier", type="primary")
        if assign:
            with connect() as con:
                con.execute(
                    "UPDATE shipments SET delivery_staff_id = ? WHERE id = ?",
                    (staff_options[chosen_staff], shipment_options[chosen_shipment])
                )
            st.success("Courier assigned successfully.")
            st.rerun()

        assigned_view = read_df("""
            SELECT s.tracking_no, s.status, s.sender_city, s.receiver_city,
                   u.name AS delivery_staff, u.email AS staff_email
            FROM shipments s
            LEFT JOIN users u ON u.id = s.delivery_staff_id
            ORDER BY s.id DESC
        """)
        st.caption("Current staff assignments")
        st.dataframe(assigned_view, use_container_width=True, hide_index=True)

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
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');

:root {
    --bg: #080e1b;
    --surface: #101a2d;
    --surface-2: #14213a;
    --border: #263752;
    --blue: #3b82f6;
    --blue-light: #93c5fd;
    --text: #f1f5f9;
    --muted: #9aabc2;
}

/* ===== GLOBAL ===== */
html, body, [class*="css"] {
    font-family: 'Inter', sans-serif;
}

.stApp {
    background:
        radial-gradient(ellipse at 85% 0%, rgba(37,99,235,.12), transparent 35%),
        var(--bg);
    color: var(--text);
}

[data-testid="stAppViewContainer"] {
    background: transparent;
}

.block-container {
    max-width: 1480px;
    padding-top: 2.2rem;
    padding-bottom: 3rem;
}

/* ===== SWIFTSHIP PREMIUM ANIMATION UPGRADE ===== */

@keyframes swiftShipEntry {
    from {
        opacity: 0;
        transform: translateY(22px);
        filter: blur(5px);
    }
    to {
        opacity: 1;
        transform: translateY(0);
        filter: blur(0);
    }
}

@keyframes swiftShipGlow {
    0%, 100% {
        opacity: .45;
        transform: scale(1);
    }
    50% {
        opacity: .9;
        transform: scale(1.04);
    }
}

@keyframes swiftShipGradient {
    0%   { background-position: 0% 50%; }
    50%  { background-position: 100% 50%; }
    100% { background-position: 0% 50%; }
}

/* Ambient blue lighting */
.stApp {
    background:
        radial-gradient(
            ellipse at 15% 5%,
            rgba(37, 99, 235, .18),
            transparent 38%
        ),
        radial-gradient(
            ellipse at 90% 45%,
            rgba(14, 165, 233, .10),
            transparent 32%
        ),
        #080e1b !important;
    background-size: 160% 160%;
    animation: swiftShipGradient 16s ease infinite;
}

/* Smooth entrance for page content */
[data-testid="stMainBlockContainer"] {
    animation: swiftShipEntry .65s cubic-bezier(.2,.7,.2,1) both;
}

/* Premium glass-style metric cards */
[data-testid="stMetric"] {
    position: relative;
    overflow: hidden;
    background: linear-gradient(
        145deg,
        rgba(24, 43, 72, .96),
        rgba(12, 24, 43, .98)
    ) !important;
    border: 1px solid rgba(96, 165, 250, .24) !important;
    border-radius: 18px !important;
    box-shadow: 0 8px 30px rgba(0, 0, 0, .18);
    transition:
        transform .3s ease,
        border-color .3s ease,
        box-shadow .3s ease !important;
}

[data-testid="stMetric"]:hover {
    transform: translateY(-6px) scale(1.015);
    border-color: rgba(96, 165, 250, .8) !important;
    box-shadow:
        0 16px 38px rgba(37, 99, 235, .18),
        0 0 18px rgba(59, 130, 246, .12);
}

/* Animated premium buttons */
.stButton > button,
.stFormSubmitButton > button,
[data-testid="stDownloadButton"] > button {
    position: relative;
    overflow: hidden;
    background: linear-gradient(
        110deg,
        #1d4ed8,
        #3b82f6,
        #0ea5e9,
        #1d4ed8
    ) !important;
    background-size: 220% 100% !important;
    border: 1px solid rgba(147, 197, 253, .55) !important;
    border-radius: 12px !important;
    box-shadow: 0 5px 18px rgba(37, 99, 235, .14);
    transition: all .25s ease !important;
}

.stButton > button:hover,
.stFormSubmitButton > button:hover,
[data-testid="stDownloadButton"] > button:hover {
    background-position: 100% 50% !important;
    transform: translateY(-2px);
    box-shadow: 0 9px 26px rgba(37, 99, 235, .3);
}

/* Inputs glow when selected */
.stTextInput input:focus,
.stNumberInput input:focus,
.stTextArea textarea:focus,
.stDateInput input:focus {
    border-color: #60a5fa !important;
    box-shadow:
        0 0 0 2px rgba(59, 130, 246, .16),
        0 0 18px rgba(59, 130, 246, .12) !important;
}

/* Smooth tracking progress */
.stProgress > div > div > div {
    background: linear-gradient(
        90deg,
        #2563eb,
        #38bdf8,
        #93c5fd
    ) !important;
    background-size: 200% 100%;
    animation: swiftShipGradient 4s ease infinite;
    border-radius: 20px;
}

/* Elegant borders for booking forms */
[data-testid="stForm"] {
    border: 1px solid rgba(96, 165, 250, .22) !important;
    border-radius: 18px !important;
    box-shadow: 0 12px 36px rgba(0, 0, 0, .12);
    transition: border-color .25s ease, box-shadow .25s ease;
}

[data-testid="stForm"]:hover {
    border-color: rgba(96, 165, 250, .42) !important;
}

/* Accessible motion settings */
@media (prefers-reduced-motion: reduce) {
    *,
    *::before,
    *::after {
        animation: none !important;
        transition: none !important;
        scroll-behavior: auto !important;
    }
}

/* ===== TYPOGRAPHY ===== */
h1, h2, h3 {
    color: #f8fafc !important;
    font-weight: 750 !important;
    letter-spacing: -0.6px;
}

h1 {
    font-size: clamp(1.65rem, 3vw, 2.2rem) !important;
}

h2 {
    font-size: 1.45rem !important;
}

h3 {
    font-size: 1.12rem !important;
}

p, label, [data-testid="stMarkdownContainer"] {
    color: #d5deea;
}

[data-testid="stCaptionContainer"] {
    color: var(--muted) !important;
}

/* ===== SIDEBAR ===== */
[data-testid="stSidebar"] {
    background: linear-gradient(180deg, #101b30 0%, #0a1221 100%);
    border-right: 1px solid #23334d;
}

[data-testid="stSidebar"] > div:first-child {
    padding-top: 1.5rem;
}

[data-testid="stSidebar"] h1 {
    color: var(--blue-light) !important;
    font-size: 1.65rem !important;
    font-weight: 800 !important;
}

[data-testid="stSidebar"] [data-testid="stMarkdownContainer"] p {
    color: #a9b9d0;
}

/* Sidebar radio navigation */
[data-testid="stSidebar"] [role="radiogroup"] {
    gap: 7px;
}

[data-testid="stSidebar"] [role="radio"] {
    border-radius: 10px;
    padding: 10px 12px;
    transition: background .2s ease;
}

[data-testid="stSidebar"] [role="radio"]:hover {
    background: #1a2a43;
}

/* ===== METRIC CARDS ===== */
[data-testid="stMetric"] {
    background: linear-gradient(145deg, #15243d, #101a2d);
    border: 1px solid #2a3d5b;
    border-radius: 16px;
    padding: 20px;
    min-height: 112px;
    box-shadow: 0 8px 24px rgba(0,0,0,.14);
    transition: transform .2s ease, border-color .2s ease,
                box-shadow .2s ease;
}

[data-testid="stMetric"]:hover {
    transform: translateY(-3px);
    border-color: #4b8df8;
    box-shadow: 0 12px 28px rgba(37,99,235,.12);
}

[data-testid="stMetricLabel"] {
    color: #a8b8cf !important;
    font-size: .88rem !important;
    font-weight: 500;
}

[data-testid="stMetricValue"] {
    color: #f8fafc !important;
    font-size: clamp(1.35rem, 2vw, 1.9rem) !important;
    font-weight: 800 !important;
}

[data-testid="stMetricDelta"] {
    font-size: .8rem;
}

/* ===== BUTTONS ===== */
.stButton > button,
.stFormSubmitButton > button,
[data-testid="stDownloadButton"] > button {
    background: linear-gradient(135deg, #2563eb, #3b82f6);
    color: #fff !important;
    border: 1px solid #4b8df8;
    border-radius: 10px;
    min-height: 42px;
    font-weight: 650;
    transition: all .2s ease;
}

.stButton > button:hover,
.stFormSubmitButton > button:hover,
[data-testid="stDownloadButton"] > button:hover {
    background: linear-gradient(135deg, #1d4ed8, #2563eb);
    border-color: #93c5fd;
    transform: translateY(-1px);
    box-shadow: 0 7px 18px rgba(37,99,235,.22);
}

/* ===== INPUTS ===== */
.stTextInput input,
.stNumberInput input,
.stDateInput input,
.stTextArea textarea {
    background: #0b1425 !important;
    color: #f1f5f9 !important;
    border: 1px solid #344762 !important;
    border-radius: 10px !important;
    min-height: 42px;
}

.stTextInput input:focus,
.stNumberInput input:focus,
.stDateInput input:focus,
.stTextArea textarea:focus {
    border-color: #60a5fa !important;
    box-shadow: 0 0 0 2px rgba(59,130,246,.17) !important;
}

[data-baseweb="select"] > div {
    background: #0b1425 !important;
    border-color: #344762 !important;
    border-radius: 10px !important;
    color: #f1f5f9 !important;
}

[data-baseweb="popover"],
[data-baseweb="menu"] {
    background: #14213a !important;
}

/* ===== FORMS & CONTAINERS ===== */
[data-testid="stForm"] {
    background: linear-gradient(145deg, #101b2e, #0d1728);
    border: 1px solid #263752;
    border-radius: 16px;
    padding: 20px;
}

[data-testid="stExpander"] {
    background: #101a2d;
    border: 1px solid #263752;
    border-radius: 12px;
}

/* ===== TABLES ===== */
[data-testid="stDataFrame"],
[data-testid="stTable"] {
    border: 1px solid #293c59;
    border-radius: 12px;
    overflow: hidden;
}

[data-testid="stDataFrame"] {
    background: #101a2d;
}

/* ===== TABS ===== */
.stTabs [data-baseweb="tab-list"] {
    gap: 8px;
    border-bottom: 1px solid #263752;
}

.stTabs [data-baseweb="tab"] {
    border-radius: 9px 9px 0 0;
    padding: 10px 16px;
    color: #a5b4c8;
}

.stTabs [aria-selected="true"] {
    color: #93c5fd !important;
    border-bottom: 2px solid #3b82f6 !important;
}

/* ===== ALERTS & PROGRESS ===== */
[data-testid="stAlert"] {
    border-radius: 12px;
}

.stProgress > div > div > div {
    background: linear-gradient(90deg, #2563eb, #60a5fa);
    border-radius: 20px;
}

/* ===== DIVIDERS ===== */
hr {
    border-color: #263752 !important;
}

/* ===== FOCUS ACCESSIBILITY ===== */
button:focus-visible,
input:focus-visible {
    outline: 2px solid #93c5fd !important;
    outline-offset: 2px;
}

/* ===== RESPONSIVE ===== */
@media (max-width: 768px) {
    .block-container {
        padding: 1.2rem 1rem 2rem;
    }

    [data-testid="stMetric"] {
        padding: 14px;
        min-height: 90px;
    }

    [data-testid="stForm"] {
        padding: 14px;
    }

    h1 {
        font-size: 1.6rem !important;
    }
}

@media (prefers-reduced-motion: reduce) {
    *, *::before, *::after {
        transition: none !important;
        animation: none !important;
    }
}

/* ===== SWIFTSHIP CINEMATIC STARTUP ANIMATION ===== */

@keyframes introBackdrop {
    0% { opacity: 1; visibility: visible; }
    75% { opacity: 1; visibility: visible; }
    100% { opacity: 0; visibility: hidden; }
}

@keyframes logoReveal {
    0% {
        opacity: 0;
        transform: translateY(25px) scale(.65);
        filter: blur(14px);
    }
    60% {
        opacity: 1;
        transform: translateY(-3px) scale(1.04);
        filter: blur(0);
    }
    100% {
        opacity: 1;
        transform: translateY(0) scale(1);
    }
}

@keyframes parcelLaunch {
    0% { transform: translateX(-100px) rotate(-20deg); }
    45% { transform: translateX(0) rotate(0); }
    75% { transform: translateX(12px) rotate(8deg); }
    100% { transform: translateX(0) rotate(0); }
}

@keyframes routeDraw {
    from { transform: scaleX(0); opacity: .2; }
    to { transform: scaleX(1); opacity: 1; }
}

@keyframes glowPulse {
    0%, 100% {
        box-shadow: 0 0 20px rgba(59,130,246,.15);
    }
    50% {
        box-shadow: 0 0 65px rgba(59,130,246,.48);
    }
}

@keyframes dashboardReveal {
    from { opacity: 0; transform: translateY(18px); }
    to { opacity: 1; transform: translateY(0); }
}

/* Intro glow around the brand heading */
.stApp h1 {
    animation: dashboardReveal .75s ease-out both;
}

/* Animated blue lighting across the app */
.stApp {
    background:
        radial-gradient(ellipse at 50% 0%,
            rgba(37,99,235,.20), transparent 45%),
        radial-gradient(ellipse at 100% 70%,
            rgba(14,165,233,.09), transparent 35%),
        #080e1b !important;
}

/* Startup reveal for the main application */
[data-testid="stMainBlockContainer"] {
    animation: dashboardReveal .85s cubic-bezier(.2,.7,.2,1) both;
}

/* Brand glow */
[data-testid="stSidebar"] h1 {
    animation: glowPulse 3s ease-in-out infinite;
}

/* Premium interactive dashboard cards */
[data-testid="stMetric"] {
    animation: dashboardReveal .65s ease-out both;
    transition: transform .28s ease,
                box-shadow .28s ease,
                border-color .28s ease !important;
}

[data-testid="stMetric"]:hover {
    transform: translateY(-6px) scale(1.015);
    border-color: #60a5fa !important;
    box-shadow: 0 12px 35px rgba(37,99,235,.25);
}

/* Reduced motion accessibility */
@media (prefers-reduced-motion: reduce) {
    *, *::before, *::after {
        animation: none !important;
        transition: none !important;
    }
}

</style>
""", unsafe_allow_html=True)

    # ===== SWIFTSHIP CINEMATIC STARTUP INTRO =====
    if "swiftship_intro_seen" not in st.session_state:
        st.session_state["swiftship_intro_seen"] = True

        st.markdown("""
        <style>
        @keyframes ssIntroFade {
            0%, 78% {
                opacity: 1;
                visibility: visible;
            }
            100% {
                opacity: 0;
                visibility: hidden;
                pointer-events: none;
            }
        }

        @keyframes ssLogoReveal {
            0% {
                opacity: 0;
                transform: translateY(28px) scale(.75);
                filter: blur(12px);
            }
            60% {
                opacity: 1;
                transform: translateY(-5px) scale(1.05);
                filter: blur(0);
            }
            100% {
                opacity: 1;
                transform: translateY(0) scale(1);
            }
        }

        @keyframes ssParcelTravel {
            0%   { left: 0%; transform: translateY(0) rotate(-15deg); }
            25%  { transform: translateY(-15px) rotate(5deg); }
            50%  { transform: translateY(0) rotate(15deg); }
            75%  { transform: translateY(-12px) rotate(-5deg); }
            100% { left: calc(100% - 48px); transform: translateY(0) rotate(0); }
        }

        @keyframes ssRouteGlow {
            from { transform: scaleX(0); opacity: .2; }
            to   { transform: scaleX(1); opacity: 1; }
        }

        @keyframes ssRing {
            0%   { transform: scale(.65); opacity: .8; }
            100% { transform: scale(1.6); opacity: 0; }
        }

        @keyframes ssTextReveal {
            from { opacity: 0; transform: translateY(12px); }
            to   { opacity: 1; transform: translateY(0); }
        }

        .ss-intro-overlay {
            position: fixed;
            inset: 0;
            z-index: 999999;
            display: flex;
            align-items: center;
            justify-content: center;
            overflow: hidden;
            background:
                radial-gradient(ellipse at 50% 40%,
                    rgba(37,99,235,.24), transparent 42%),
                radial-gradient(ellipse at 15% 85%,
                    rgba(14,165,233,.13), transparent 35%),
                #050a14;
            animation: ssIntroFade 4.8s ease forwards;
            pointer-events: auto;
        }

        .ss-intro-content {
            width: min(680px, 88vw);
            text-align: center;
            color: #f8fafc;
        }

        .ss-intro-icon {
            position: relative;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            width: 104px;
            height: 104px;
            margin-bottom: 26px;
            border: 1px solid rgba(96,165,250,.7);
            border-radius: 30px;
            background: linear-gradient(145deg,#152d50,#0b1425);
            box-shadow: 0 0 60px rgba(37,99,235,.25);
            font-size: 54px;
            animation: ssLogoReveal .85s cubic-bezier(.2,.7,.2,1) both;
        }

        .ss-intro-icon::after {
            content: "";
            position: absolute;
            inset: -9px;
            border: 1px solid rgba(96,165,250,.5);
            border-radius: 36px;
            animation: ssRing 2s ease-out .3s infinite;
        }

        .ss-intro-title {
            margin: 0;
            font-size: clamp(38px, 7vw, 68px);
            font-weight: 850;
            letter-spacing: -2.5px;
            line-height: 1.1;
            color: #f8fafc;
            animation: ssLogoReveal .9s ease .12s both;
        }

        .ss-intro-title span {
            color: #60a5fa;
            text-shadow: 0 0 32px rgba(59,130,246,.55);
        }

        .ss-intro-subtitle {
            margin-top: 16px;
            color: #a9bed8;
            font-size: clamp(12px, 2vw, 16px);
            letter-spacing: 3px;
            text-transform: uppercase;
            animation: ssTextReveal .8s ease .45s both;
        }

        .ss-route {
            position: relative;
            width: min(430px, 80%);
            height: 55px;
            margin: 48px auto 24px;
            border-bottom: 2px dashed rgba(96,165,250,.35);
        }

        .ss-route-line {
            position: absolute;
            bottom: -2px;
            left: 0;
            width: 100%;
            height: 3px;
            transform-origin: left;
            background: linear-gradient(90deg,#2563eb,#38bdf8,#93c5fd);
            box-shadow: 0 0 14px rgba(56,189,248,.7);
            animation: ssRouteGlow 1.5s ease .5s both;
        }

        .ss-parcel {
            position: absolute;
            bottom: -12px;
            left: 0;
            font-size: 34px;
            filter: drop-shadow(0 0 12px rgba(96,165,250,.75));
            animation: ssParcelTravel 2s cubic-bezier(.4,0,.2,1) .8s both;
        }

        .ss-intro-footer {
            color: #8da5c3;
            font-size: 13px;
            letter-spacing: 1px;
            animation: ssTextReveal .8s ease .7s both;
        }

        .ss-intro-footer strong {
            color: #93c5fd;
        }

        @media (prefers-reduced-motion: reduce) {
            .ss-intro-overlay,
            .ss-intro-overlay * {
                animation-duration: .01ms !important;
                animation-iteration-count: 1 !important;
            }
        }

        @media (max-width: 480px) {
            .ss-intro-icon {
                width: 82px;
                height: 82px;
                border-radius: 24px;
                font-size: 42px;
            }
            .ss-intro-subtitle {
                letter-spacing: 1.5px;
            }
        }
        </style>

        <div class="ss-intro-overlay">
            <div class="ss-intro-content">
                <div class="ss-intro-icon">📦</div>
                <h1 class="ss-intro-title">
                    Swift<span>Ship</span>
                </h1>
                <div class="ss-intro-subtitle">
                    Every parcel. Every mile. On time.
                </div>
                <div class="ss-route">
                    <div class="ss-route-line"></div>
                    <div class="ss-parcel">📦</div>
                </div>
                <div class="ss-intro-footer">
                    <strong>PREPARING YOUR JOURNEY</strong>
                    <br><br>
                    Smart logistics · Seamless tracking
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)

  
# ==========================================
# SWIFTSHIP — PREMIUM CINEMATIC INTRO
# ==========================================
  if "swiftship_intro_seen" not in st.session_state:
    st.session_state["swiftship_intro_seen"] = True

    st.markdown("""
    <style>
    .ss-cinema {
        position: fixed;
        inset: 0;
        z-index: 999999;
        overflow: hidden;
        display: flex;
        align-items: center;
        justify-content: center;
        background:
          radial-gradient(ellipse at 50% 48%,
            rgba(18, 89, 180, .27), transparent 48%),
          linear-gradient(135deg, #030817 0%, #07152e 52%, #020610 100%);
        animation: ss-exit 5.4s ease 1 forwards;
        pointer-events: none;
    }

    .ss-cinema::before {
        content: "";
        position: absolute;
        inset: -50%;
        background: repeating-linear-gradient(
          115deg,
          transparent 0px,
          transparent 95px,
          rgba(64, 160, 255, .055) 96px,
          transparent 98px
        );
        animation: ss-sweep 8s linear infinite;
    }

    .ss-orb {
        position: absolute;
        width: 360px;
        height: 360px;
        border-radius: 50%;
        background: #087cff;
        filter: blur(130px);
        opacity: .17;
        animation: ss-orb-pulse 2.5s ease-in-out infinite alternate;
    }

    .ss-content {
        position: relative;
        width: min(850px, 94vw);
        text-align: center;
        color: #fff;
        animation: ss-arrive 1s cubic-bezier(.2,.8,.2,1) both;
    }

    .ss-brand {
        display: flex;
        align-items: center;
        justify-content: center;
        gap: 13px;
        margin-bottom: 8px;
    }

    .ss-logo {
        width: 53px;
        height: 53px;
        display: grid;
        place-items: center;
        border: 1px solid rgba(111,190,255,.6);
        border-radius: 17px;
        background: linear-gradient(145deg,#1488ff,#0750bc);
        box-shadow: 0 0 35px rgba(0,132,255,.42);
        font-size: 27px;
        animation: ss-logo-glow 2s ease-in-out infinite alternate;
    }

    .ss-wordmark {
        font-size: clamp(28px, 5vw, 43px);
        font-weight: 900;
        letter-spacing: 2px;
    }

    .ss-wordmark span { color: #51b8ff; }

    .ss-tagline {
        color: #a9bfdc;
        font-size: clamp(10px, 1.7vw, 13px);
        letter-spacing: 4px;
        text-transform: uppercase;
        margin: 12px 0 0;
        animation: ss-text-in .9s ease .3s both;
    }

    .ss-scene {
        position: relative;
        height: clamp(165px, 27vw, 225px);
        margin: 18px auto 0;
        overflow: hidden;
    }

    .ss-horizon {
        position: absolute;
        width: 80%;
        height: 100px;
        bottom: 30px;
        left: 10%;
        background: radial-gradient(ellipse,
            rgba(0,125,255,.23), transparent 70%);
    }

    .ss-road {
        position: absolute;
        left: -10%;
        right: -10%;
        bottom: 24px;
        height: 3px;
        background: linear-gradient(90deg,
          transparent, #087bff, #a1eaff, #087bff, transparent);
        box-shadow: 0 0 12px #078aff, 0 0 35px #087bff;
    }

    .ss-road::after {
        content: "";
        position: absolute;
        inset: 9px 0 auto;
        height: 1px;
        background: linear-gradient(90deg,
          transparent, rgba(39,131,255,.6), transparent);
    }

    .ss-dash {
        position: absolute;
        left: -35%;
        bottom: 7px;
        width: 170%;
        height: 2px;
        background: repeating-linear-gradient(
          90deg, transparent 0 34px,
          rgba(108,195,255,.8) 35px 65px,
          transparent 66px 100px
        );
        animation: ss-road-run .65s linear infinite;
    }

    .ss-truck {
        position: absolute;
        bottom: 31px;
        left: -230px;
        width: 220px;
        height: 120px;
        filter: drop-shadow(0 0 15px rgba(0,128,255,.4));
        animation: ss-drive 3.1s cubic-bezier(.25,.65,.35,1) .45s both;
    }

    .ss-truck svg { width: 100%; height: 100%; overflow: visible; }

    .ss-wheel {
        transform-box: fill-box;
        transform-origin: center;
        animation: ss-wheel-spin .42s linear infinite;
    }

    .ss-headlight {
        animation: ss-light 1s ease-in-out infinite alternate;
    }

    .ss-particle {
        position: absolute;
        width: 4px;
        height: 4px;
        border-radius: 50%;
        background: #83d9ff;
        box-shadow: 0 0 10px #078aff;
        animation: ss-particle-fly 1.7s linear infinite;
    }

    .ss-p1 { top: 26%; left: 18%; animation-delay: -.3s; }
    .ss-p2 { top: 48%; left: 78%; animation-delay: -.9s; }
    .ss-p3 { top: 20%; left: 65%; animation-delay: -1.2s; }
    .ss-p4 { top: 66%; left: 30%; animation-delay: -.6s; }

    .ss-status {
        display: flex;
        justify-content: center;
        align-items: center;
        gap: 9px;
        color: #a7c9ef;
        font-size: 12px;
        letter-spacing: 2px;
        text-transform: uppercase;
        animation: ss-text-in 1s ease .8s both;
    }

    .ss-dot {
        width: 7px;
        height: 7px;
        border-radius: 50%;
        background: #42f5b0;
        box-shadow: 0 0 12px #42f5b0;
        animation: ss-dot-pulse 1s ease-in-out infinite;
    }

    .ss-progress {
        width: min(260px, 65vw);
        height: 3px;
        margin: 18px auto 0;
        border-radius: 10px;
        overflow: hidden;
        background: rgba(135,180,230,.15);
    }

    .ss-progress span {
        display: block;
        height: 100%;
        width: 0;
        background: linear-gradient(90deg,#087bff,#69e2ff);
        box-shadow: 0 0 12px #159bff;
        animation: ss-load 4.4s ease .15s forwards;
    }

    @keyframes ss-exit {
        0%, 79% { opacity: 1; visibility: visible; }
        100% { opacity: 0; visibility: hidden; }
    }
    @keyframes ss-arrive {
        from { opacity: 0; transform: translateY(22px) scale(.97); }
        to { opacity: 1; transform: translateY(0) scale(1); }
    }
    @keyframes ss-text-in {
        from { opacity: 0; letter-spacing: 7px; }
        to { opacity: 1; letter-spacing: 2px; }
    }
    @keyframes ss-sweep {
        from { transform: translateX(-4%) translateY(-2%); }
        to { transform: translateX(4%) translateY(2%); }
    }
    @keyframes ss-orb-pulse {
        from { transform: scale(.85); opacity: .12; }
        to { transform: scale(1.15); opacity: .25; }
    }
    @keyframes ss-logo-glow {
        from { box-shadow: 0 0 18px rgba(0,132,255,.3); }
        to { box-shadow: 0 0 38px rgba(0,132,255,.75); }
    }
    @keyframes ss-drive {
        0% { left: -230px; transform: scale(.83); }
        65% { left: calc(50% - 110px); transform: scale(1.05); }
        82% { left: calc(50% - 110px); transform: scale(1.05); }
        100% { left: calc(100% + 20px); transform: scale(.96); }
    }
    @keyframes ss-wheel-spin { to { transform: rotate(360deg); } }
    @keyframes ss-road-run { to { transform: translateX(100px); } }
    @keyframes ss-light {
        from { opacity: .65; }
        to { opacity: 1; }
    }
    @keyframes ss-particle-fly {
        0% { transform: translate(0,0) scale(.5); opacity: 0; }
        30% { opacity: 1; }
        100% { transform: translate(-65px,35px) scale(1.3); opacity: 0; }
    }
    @keyframes ss-load { to { width: 100%; } }
    @keyframes ss-dot-pulse {
        50% { opacity: .35; transform: scale(.75); }
    }

    @media (max-width: 600px) {
        .ss-tagline { letter-spacing: 2px; }
        .ss-scene { margin-top: 24px; }
        .ss-truck { width: 185px; height: 105px; }
        @keyframes ss-drive {
            0% { left: -195px; transform: scale(.8); }
            65%,82% { left: calc(50% - 92px); transform: scale(1); }
            100% { left: calc(100% + 20px); transform: scale(.9); }
        }
    }

    @media (prefers-reduced-motion: reduce) {
        .ss-cinema, .ss-cinema *, .ss-cinema::before {
            animation-duration: .01ms !important;
            animation-iteration-count: 1 !important;
        }
    }
    </style>

    <div class="ss-cinema">
      <div class="ss-orb"></div>
      <div class="ss-content">
        <div class="ss-brand">
          <div class="ss-logo">⚡</div>
          <div class="ss-wordmark">SWIFT<span>SHIP</span></div>
        </div>

        <div class="ss-tagline">Delivering Beyond Expectations</div>

        <div class="ss-scene">
          <div class="ss-horizon"></div>
          <div class="ss-particle ss-p1"></div>
          <div class="ss-particle ss-p2"></div>
          <div class="ss-particle ss-p3"></div>
          <div class="ss-particle ss-p4"></div>

          <div class="ss-truck">
            <svg viewBox="0 0 240 130" xmlns="http://www.w3.org/2000/svg">
              <defs>
                <linearGradient id="ssBody" x1="0" y1="0" x2="1" y2="1">
                  <stop offset="0%" stop-color="#42b7ff"/>
                  <stop offset="100%" stop-color="#0750bb"/>
                </linearGradient>
                <linearGradient id="ssBox" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stop-color="#f4f8ff"/>
                  <stop offset="100%" stop-color="#b5d5f5"/>
                </linearGradient>
                <filter id="ssGlow">
                  <feGaussianBlur stdDeviation="5"/>
                </filter>
              </defs>

              <!-- Headlight beam -->
              <path d="M204 67 L239 48 L239 92 L204 82Z"
                    fill="#57dfff" opacity=".22" filter="url(#ssGlow)"/>

              <!-- Cargo body -->
              <rect x="13" y="20" width="137" height="77" rx="7"
                    fill="url(#ssBox)" stroke="#80cfff" stroke-width="1.5"/>
              <path d="M23 31 H139 V86 H23Z"
                    fill="#d8eaff" stroke="#a2c9f0" stroke-width="1"/>

              <!-- Parcel mark -->
              <path d="M66 40 L84 30 L102 40 L84 51Z"
                    fill="#1488ff"/>
              <path d="M66 40 V61 L84 72 V51Z" fill="#0870da"/>
              <path d="M84 51 L102 40 V61 L84 72Z" fill="#3faeff"/>
              <path d="M84 31 V51" stroke="#dff7ff" stroke-width="2"/>

              <!-- Cabin -->
              <path d="M150 47 H185 L211 68 V96 H150Z"
                    fill="url(#ssBody)" stroke="#71cbff" stroke-width="1.5"/>
              <path d="M161 53 H181 L199 69 H161Z"
                    fill="#b9eaff" stroke="#e4f7ff" stroke-width="1"/>
              <path d="M166 57 H179 L191 67 H166Z"
                    fill="#183f69"/>

              <!-- Bumper and chassis -->
              <path d="M9 96 H215 V105 H9Z" fill="#112f50"/>
              <path d="M194 92 H216 V99 H194Z" fill="#8bdcff"/>
              <rect x="207" y="77" width="7" height="12" rx="2"
                    fill="#fff0a5" class="ss-headlight"/>

              <!-- Wheels -->
              <g class="ss-wheel">
                <circle cx="48" cy="99" r="17" fill="#020712" stroke="#54708f" stroke-width="3"/>
                <circle cx="48" cy="99" r="8" fill="#6c91b5"/>
                <circle cx="48" cy="99" r="3" fill="#d5f1ff"/>
                <path d="M48 84 V91 M48 107 V114 M33 99 H40 M56 99 H63"
                      stroke="#d5f1ff" stroke-width="2"/>
              </g>
              <g class="ss-wheel">
                <circle cx="181" cy="99" r="17" fill="#020712" stroke="#54708f" stroke-width="3"/>
                <circle cx="181" cy="99" r="8" fill="#6c91b5"/>
                <circle cx="181" cy="99" r="3" fill="#d5f1ff"/>
                <path d="M181 84 V91 M181 107 V114 M166 99 H173 M189 99 H196"
                      stroke="#d5f1ff" stroke-width="2"/>
              </g>
            </svg>
          </div>

          <div class="ss-road"><div class="ss-dash"></div></div>
        </div>

        <div class="ss-status">
          <span class="ss-dot"></span>
          YOUR DELIVERY JOURNEY STARTS HERE
        </div>

        <div class="ss-progress"><span></span></div>
      </div>
    </div>
    """, unsafe_allow_html=True)


  
    user = st.session_state.get("user")

    if not user:
        authentication_page()
        return

    with st.sidebar:
        st.title("📦 SwiftShip")
        st.caption(f"Signed in: {user['name']}")

        if user["role"] == "admin":
            page = st.radio("MENU", ["Admin Dashboard"])
        elif user["role"] == "delivery":
            page = st.radio("MENU", ["Delivery Staff Dashboard"])
        else:
            page = st.radio(
                "MENU",
                ["My Dashboard", "Send a Courier", "Track Courier"]
            )

        if st.button("Sign Out", use_container_width=True):
            st.session_state.pop("user", None)
            st.rerun()

    if page == "Admin Dashboard":
        admin_dashboard()
    elif page == "Delivery Staff Dashboard":
        delivery_staff_dashboard(user)
    elif page == "My Dashboard":
        customer_dashboard(user)
    elif page == "Send a Courier":
        booking_page(user)
    elif page == "Track Courier":
        tracking_page(user)


if __name__ == "__main__":
    main()
