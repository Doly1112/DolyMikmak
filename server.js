const express = require("express");
const session = require("express-session");
const bcrypt = require("bcrypt");
const { Pool } = require("pg");
const pgSession = require("connect-pg-simple")(session);

const app = express();
app.use(express.urlencoded({ extended: true }));

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false,
});

app.set("trust proxy", 1);

app.use(
    session({
        store: new pgSession({
            pool,
            tableName: "session",
            createTableIfMissing: true,
        }),
        secret: process.env.SESSION_SECRET || "mySuperSecretKey",
        resave: false,
        saveUninitialized: false,
        cookie: {
            secure: process.env.NODE_ENV === "production",
            sameSite: "lax",
            httpOnly: true,
            maxAge: 1000 * 60 * 60 * 24 * 7,
        },
    })
);

// ---------- Toast helpers ----------
function setToast(req, type, message) {
    req.session.toast = { type, message };
}

function consumeToast(req) {
    const t = req.session.toast;
    req.session.toast = null;
    return t;
}

function toastHtml(toast) {
    if (!toast) return "";

    const type = toast.type === "success" ? "success" : "error";
    const msg = escapeHtml(String(toast.message || ""));

    return `
  <div id="toast" class="toast ${type}">
    <div class="toast-title">${type === "success" ? "Success" : "Error"}</div>
    <div class="toast-msg">${msg}</div>
  </div>
  <script>
    (function(){
      const t = document.getElementById("toast");
      if (!t) return;
      setTimeout(() => { t.classList.add("show"); }, 20);
      setTimeout(() => { t.classList.remove("show"); }, 3500);
      setTimeout(() => { t.remove(); }, 4200);
    })();
  </script>
  `;
}

function pageHtml(title, body, toast) {
    return `
  <!doctype html>
  <html>
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width,initial-scale=1" />
    <title>${escapeHtml(title)}</title>
    <style>
      body { font-family: Arial, sans-serif; padding: 20px; }
      input { padding: 10px; width: 280px; max-width: 100%; }
      button { padding: 10px 14px; cursor: pointer; }
      a { text-decoration: none; }

      .toast{
        position: fixed;
        top: 14px;
        left: 50%;
        transform: translate(-50%, -20px);
        min-width: 280px;
        max-width: 520px;
        width: calc(100% - 28px);
        background: #fff;
        border-radius: 10px;
        padding: 12px 14px;
        box-shadow: 0 10px 30px rgba(0,0,0,0.15);
        border: 1px solid rgba(0,0,0,0.08);
        opacity: 0;
        transition: opacity 220ms ease, transform 220ms ease;
        z-index: 9999;
      }
      .toast.show{
        opacity: 1;
        transform: translate(-50%, 0);
      }
      .toast.error{ border-left: 6px solid #e53935; }
      .toast.success{ border-left: 6px solid #43a047; }
      .toast-title{ font-weight: 700; margin-bottom: 4px; }
      .toast-msg{ color: #333; }
      .hint{ color: #555; font-size: 14px; }
      .row{ margin: 10px 0; }
      .nav a{ margin-right: 10px; }
      .card{ background:#fafafa; border:1px solid #eee; border-radius: 10px; padding: 14px; }
    </style>
  </head>
  <body>
    ${toastHtml(toast)}
    ${body}
  </body>
  </html>
  `;
}

function escapeHtml(s) {
    return s
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
}

// ---------- DB init ----------
async function initDb() {
    await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username TEXT NOT NULL,
      username_lc TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);

    await pool.query(`
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS email TEXT,
    ADD COLUMN IF NOT EXISTS birth_date DATE;
  `);

    await pool.query(`
    CREATE UNIQUE INDEX IF NOT EXISTS users_email_unique ON users(email);
  `);
}

initDb().catch((e) => console.error("DB init error:", e));

// ---------- Auth helpers ----------
function requireLogin(req, res, next) {
    if (req.session && req.session.user) return next();
    setToast(req, "error", "You must login first.");
    res.redirect("/login");
}

function isValidEmail(email) {
    const e = String(email || "").trim();
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e);
}

function isStrongPassword(pw) {
    const p = String(pw || "");
    if (p.length < 5 || p.length > 12) return { ok: false, msg: "Password must be 5 to 12 characters." };
    if (!/[^A-Za-z0-9]/.test(p)) return { ok: false, msg: "Password must include at least 1 special character." };
    return { ok: true };
}

// ---------- Routes ----------

app.get("/__ping", (req, res) => {
    res.send("PING_OK");
});

app.get("/", (req, res) => {
    const toast = consumeToast(req);
    const isLoggedIn = !!(req.session && req.session.user);

    res.send(
        pageHtml(
            "Home",
            `
      <h1>Home</h1>
      <div class="card">
        <p>Status: <b>${isLoggedIn ? "Logged in" : "Not logged in"}</b></p>
        <div class="nav">
          <a href="/me">My Account</a>
          <a href="/register">Register</a>
          <a href="/login">Login</a>
          <a href="/dashboard">Dashboard</a>
          <a href="/logout">Logout</a>
        </div>
      </div>
      `,
            toast
        )
    );
});

app.get("/register", (req, res) => {
    const toast = consumeToast(req);

    res.send(
        pageHtml(
            "Register",
            `
      <h1>Register</h1>
      <div class="card">
        <form method="POST" action="/register">
          <div class="row"><input name="username" placeholder="Username" required minlength="3" /></div>
          <div class="row"><input name="email" type="email" placeholder="Email" required /></div>
          <div class="row">
            <label class="hint">Birth date</label><br/>
            <input name="birthDate" type="date" required />
          </div>
          <div class="row"><input name="password" type="password" placeholder="Password" required minlength="5" maxlength="12" /></div>
          <div class="hint">Password rules: 5-12 chars, must include at least 1 special character.</div>
          <div class="row"><button type="submit">Create account</button></div>
        </form>
        <p><a href="/login">Already have an account?</a></p>
      </div>
      `,
            toast
        )
    );
});

app.post("/register", async (req, res) => {
    try {
        const username = (req.body.username || "").trim();
        const email = (req.body.email || "").trim();
        const birthDate = (req.body.birthDate || "").trim();
        const password = req.body.password || "";

        if (username.length < 3) {
            setToast(req, "error", "Username too short, minimum 3 characters.");
            return res.redirect("/register");
        }

        if (!isValidEmail(email)) {
            setToast(req, "error", "Email is not valid.");
            return res.redirect("/register");
        }

        if (!birthDate) {
            setToast(req, "error", "Birth date is required.");
            return res.redirect("/register");
        }

        const pw = isStrongPassword(password);
        if (!pw.ok) {
            setToast(req, "error", pw.msg);
            return res.redirect("/register");
        }

        const passwordHash = await bcrypt.hash(password, 10);
        const usernameLc = username.toLowerCase();

        await pool.query(
            `INSERT INTO users (username, username_lc, email, birth_date, password_hash)
       VALUES ($1, $2, $3, $4, $5)`,
            [username, usernameLc, email, birthDate, passwordHash]
        );

        setToast(req, "success", "Account created, you can login now.");
        return res.redirect("/login");
    } catch (err) {
        if (err && err.code === "23505") {
            setToast(req, "error", "Username or email already exists.");
            return res.redirect("/register");
        }
        console.error(err);
        setToast(req, "error", "Server error.");
        res.redirect("/register");
    }
});

app.get("/login", (req, res) => {
    const toast = consumeToast(req);

    res.send(
        pageHtml(
            "Login",
            `
      <h1>Login</h1>
      <div class="card">
        <form method="POST" action="/login">
          <div class="row"><input name="username" placeholder="Username" required /></div>
          <div class="row"><input name="password" type="password" placeholder="Password" required /></div>
          <div class="row"><button type="submit">Login</button></div>
        </form>
        <p><a href="/register">Create account</a></p>
      </div>
      `,
            toast
        )
    );
});

app.post("/login", async (req, res) => {
    try {
        const username = (req.body.username || "").trim();
        const password = req.body.password || "";

        const usernameLc = username.toLowerCase();

        const result = await pool.query(
            `SELECT id, username, password_hash FROM users WHERE username_lc=$1 LIMIT 1`,
            [usernameLc]
        );

        if (result.rowCount === 0) {
            setToast(req, "error", "Wrong username or password.");
            return res.redirect("/login");
        }

        const user = result.rows[0];
        const ok = await bcrypt.compare(password, user.password_hash);
        if (!ok) {
            setToast(req, "error", "Wrong username or password.");
            return res.redirect("/login");
        }

        req.session.user = { id: user.id, username: user.username };
        setToast(req, "success", "Logged in successfully.");
        res.redirect("/dashboard");
    } catch (err) {
        console.error(err);
        setToast(req, "error", "Server error.");
        res.redirect("/login");
    }
});

app.get("/dashboard", requireLogin, (req, res) => {
    const toast = consumeToast(req);

    res.send(
        pageHtml(
            "Dashboard",
            `
      <h1>Dashboard</h1>
      <div class="card">
        <p>Welcome, <b>${escapeHtml(req.session.user.username)}</b></p>
        <p><a href="/me">My Account</a></p>
        <p><a href="/logout">Logout</a></p>
      </div>
      `,
            toast
        )
    );
});

app.get("/me", requireLogin, async (req, res) => {
    const toast = consumeToast(req);

    const r = await pool.query(
        "SELECT username, email, birth_date, created_at FROM users WHERE id=$1 LIMIT 1",
        [req.session.user.id]
    );

    const u = r.rows[0];

    res.send(
        pageHtml(
            "My Account",
            `
      <h1>My Account</h1>
      <div class="card">
        <p>Username: <b>${escapeHtml(u.username)}</b></p>
        <p>Email: <b>${escapeHtml(u.email)}</b></p>
        <p>Birth date: <b>${escapeHtml(String(u.birth_date))}</b></p>
        <p>Created: <b>${escapeHtml(String(u.created_at))}</b></p>
        <p><a href="/dashboard">Back</a></p>
      </div>
      `,
            toast
        )
    );
});

app.get("/logout", (req, res) => {
    req.session.destroy(() => {
        res.redirect("/login");
    });
});

app.get("/admin/reset-users", (req, res) => {
    res.send("OK");
});

app.post("/admin/reset-users", async (req, res) => {
    const key = req.headers["x-admin-key"];
    if (key !== process.env.ADMIN_MIGRATION_KEY) {
        return res.status(403).send("Forbidden");
    }

    try {
        await pool.query(`
      ALTER TABLE users
      ADD COLUMN IF NOT EXISTS email TEXT,
      ADD COLUMN IF NOT EXISTS birth_date DATE;
    `);

        await pool.query(`
      DELETE FROM users
      WHERE email IS NULL OR birth_date IS NULL;
    `);

        await pool.query(`
      CREATE UNIQUE INDEX IF NOT EXISTS users_email_unique ON users(email);
    `);

        res.json({ ok: true, message: "Old users removed successfully" });
    } catch (e) {
        res.status(500).json({ ok: false, error: e.message });
    }
});


const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Running on http://localhost:${PORT}`);
});
// redeploy
