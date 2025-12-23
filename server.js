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
function setFormDraft(req, draft) {
    req.session.formDraft = draft;
}
function consumeFormDraft(req) {
    const d = req.session.formDraft || null;
    req.session.formDraft = null;
    return d;
}


function toastHtml(toast) {
    if (!toast) return "";

    const type = toast.type === "success" ? "success" : "error";
    const msg = escapeHtml(String(toast.message || ""));

    return `
  <div id="toast" class="toast ${type}" dir="rtl">
    <div class="toast-row">
      <div class="toast-icon">${type === "success" ? "✅" : "⚠️"}</div>
      <div class="toast-text">
        <div class="toast-title">${type === "success" ? "הצלחה" : "שגיאה"}</div>
        <div class="toast-msg">${msg}</div>
      </div>
      <button class="toast-close" aria-label="סגור" onclick="this.parentElement.parentElement.remove()">×</button>
    </div>
    <div class="toast-bar"></div>
  </div>
  <script>
    (function(){
      const t = document.getElementById("toast");
      if (!t) return;
      setTimeout(() => t.classList.add("show"), 20);
      setTimeout(() => t.classList.remove("show"), 4200);
      setTimeout(() => t.remove(), 4700);
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
  transform: translate(-50%, -18px);
  min-width: 300px;
  max-width: 560px;
  width: calc(100% - 28px);
  background: #ffffff;
  border-radius: 14px;
  padding: 12px 12px;
  box-shadow: 0 14px 40px rgba(0,0,0,0.18);
  border: 1px solid rgba(0,0,0,0.08);
  opacity: 0;
  transition: opacity 220ms ease, transform 220ms ease;
  z-index: 9999;
  overflow: hidden;
}
.toast.show{
  opacity: 1;
  transform: translate(-50%, 0);
}
.toast.error{ border-right: 6px solid #e53935; }
.toast.success{ border-right: 6px solid #43a047; }

.toast-row{
  display:flex;
  gap:10px;
  align-items:flex-start;
}
.toast-icon{
  width: 34px;
  height: 34px;
  display:flex;
  align-items:center;
  justify-content:center;
  background: rgba(0,0,0,0.04);
  border-radius: 10px;
  font-size: 18px;
}
.toast-text{ flex:1; }
.toast-title{ font-weight: 800; margin-bottom: 4px; }
.toast-msg{ color:#333; line-height: 1.35; }

.toast-close{
  border: 0;
  background: transparent;
  font-size: 20px;
  cursor: pointer;
  line-height: 1;
  opacity: 0.6;
}
.toast-close:hover{ opacity: 1; }

.toast-bar{
  height: 3px;
  margin-top: 10px;
  background: rgba(0,0,0,0.06);
  position: relative;
  border-radius: 999px;
  overflow: hidden;
}
.toast-bar::after{
  content:"";
  position:absolute;
  top:0;
  right:0;
  height:100%;
  width:100%;
  background: rgba(67,160,71,0.55);
  animation: toastbar 4.2s linear forwards;
}
.toast.error .toast-bar::after{
  background: rgba(229,57,53,0.55);
}
@keyframes toastbar{
  from { width:100%; }
  to { width:0%; }
}

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
      password_hash TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);

    // Make sure columns exist even if table was created before
    await pool.query(`
    ALTER TABLE users
      ADD COLUMN IF NOT EXISTS username_lc TEXT,
      ADD COLUMN IF NOT EXISTS email TEXT,
      ADD COLUMN IF NOT EXISTS birth_date DATE;
  `);

    // Backfill username_lc for existing rows
    await pool.query(`
    UPDATE users
    SET username_lc = LOWER(username)
    WHERE username_lc IS NULL;
  `);

    // Unique constraint/index for username_lc
    await pool.query(`
    CREATE UNIQUE INDEX IF NOT EXISTS users_username_lc_unique ON users(username_lc);
  `);

    // Unique constraint/index for email (allows multiple NULLs, but you already cleaned old users)
    await pool.query(`
    CREATE UNIQUE INDEX IF NOT EXISTS users_email_unique ON users(email);
  `);
}


initDb().catch((e) => console.error("DB init error:", e));

// ---------- Auth helpers ----------
function requireLogin(req, res, next) {
    if (req.session && req.session.user) return next();
    setToast(req, "error", "צריך להתחבר קודם.");

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
    const draft = consumeFormDraft(req) || {};

    const username = escapeHtml(draft.username || "");
    const email = escapeHtml(draft.email || "");
    const birthDate = escapeHtml(draft.birthDate || "");

    res.send(
        pageHtml(
            "הרשמה",
            `
      <h1 dir="rtl">הרשמה</h1>
      <div class="card" dir="rtl">
        <form method="POST" action="/register">
          <div class="row"><input name="username" placeholder="שם משתמש" required minlength="3" value="${username}" /></div>
          <div class="row"><input name="email" type="email" placeholder="אימייל" required value="${email}" /></div>
          <div class="row">
            <label class="hint">תאריך לידה</label><br/>
            <input name="birthDate" type="date" required value="${birthDate}" />
          </div>
          <div class="row"><input name="password" type="password" placeholder="סיסמה" required minlength="5" maxlength="12" /></div>
          <div class="hint">כללים: 5 עד 12 תווים, חובה תו מיוחד אחד לפחות.</div>
          <div class="row"><button type="submit">צור משתמש</button></div>
        </form>
        <p><a href="/login">כבר יש לך משתמש?</a></p>
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

        setFormDraft(req, { username, email, birthDate });

        if (username.length < 3) {
            setToast(req, "error", "שם המשתמש קצר מדי, מינימום 3 תווים.");
            return res.redirect("/register");
        }

        if (!isValidEmail(email)) {
            setToast(req, "error", "האימייל לא תקין.");
            return res.redirect("/register");
        }

        if (!birthDate) {
            setToast(req, "error", "חובה לבחור תאריך לידה.");
            return res.redirect("/register");
        }

        const pw = isStrongPassword(password);
        if (!pw.ok) {
            setToast(req, "error", pw.msg === "Password must be 5 to 12 characters."
                ? "הסיסמה חייבת להיות בין 5 ל 12 תווים."
                : "הסיסמה חייבת להכיל לפחות תו מיוחד אחד, לדוגמה ! @ # $");
            return res.redirect("/register");
        }

        const passwordHash = await bcrypt.hash(password, 10);
        const usernameLc = username.toLowerCase();

        await pool.query(
            `INSERT INTO users (username, username_lc, email, birth_date, password_hash)
             VALUES ($1, $2, $3, $4, $5)`,
            [username, usernameLc, email, birthDate, passwordHash]
        );

        req.session.formDraft = null;
        setToast(req, "success", "המשתמש נוצר בהצלחה, אפשר להתחבר.");
        return res.redirect("/login");
    } catch (err) {
        if (err && err.code === "23505") {
            setToast(req, "error", "שם משתמש או אימייל כבר קיימים.");
            return res.redirect("/register");
        }
        console.error(err);
        setToast(req, "error", "שגיאת שרת.");
        return res.redirect("/register");
    }
});


app.get("/login", (req, res) => {
    const toast = consumeToast(req);
    const draft = consumeFormDraft(req) || {};
    const username = escapeHtml(draft.username || "");

    res.send(
        pageHtml(
            "התחברות",
            `
      <h1 dir="rtl">התחברות</h1>
      <div class="card" dir="rtl">
        <form method="POST" action="/login">
          <div class="row"><input name="username" placeholder="שם משתמש" required value="${username}" /></div>
          <div class="row"><input name="password" type="password" placeholder="סיסמה" required /></div>
          <div class="row"><button type="submit">התחבר</button></div>
        </form>
        <p><a href="/register">צור משתמש</a></p>
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

        setFormDraft(req, { username });

        const usernameLc = username.toLowerCase();

        const result = await pool.query(
            `SELECT id, username, password_hash FROM users WHERE username_lc=$1 LIMIT 1`,
            [usernameLc]
        );

        if (result.rowCount === 0) {
            setToast(req, "error", "שם משתמש או סיסמה לא נכונים.");
            return res.redirect("/login");
        }

        const user = result.rows[0];
        const ok = await bcrypt.compare(password, user.password_hash);
        if (!ok) {
            setToast(req, "error", "שם משתמש או סיסמה לא נכונים.");
            return res.redirect("/login");
        }

        req.session.formDraft = null;
        req.session.user = { id: user.id, username: user.username };
        setToast(req, "success", "התחברת בהצלחה.");
        return res.redirect("/dashboard");
    } catch (err) {
        console.error(err);
        setToast(req, "error", "שגיאת שרת.");
        return res.redirect("/login");
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
