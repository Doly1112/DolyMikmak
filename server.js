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


// Create table if not exists
async function initDb() {
    await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);
}
initDb().catch((e) => console.error("DB init error:", e));

function requireLogin(req, res, next) {
    if (req.session && req.session.user) return next();
    res.redirect("/login");
}

app.get("/", (req, res) => {
    const isLoggedIn = !!(req.session && req.session.user);

    res.send(`
    <h1>Home</h1>
    <p>Status: ${isLoggedIn ? "Logged in" : "Not logged in"}</p>
    <p>
      <a href="/me">My Account</a> |
      <a href="/register">Register</a> |
      <a href="/login">Login</a> |
      <a href="/dashboard">Dashboard</a> |
      <a href="/logout">Logout</a>
    </p>
  `);
});

app.get("/register", (req, res) => {
    res.send(`
    <h1>Register</h1>
    <form method="POST" action="/register">
      <input name="username" placeholder="Username" /><br/><br/>
      <input name="password" type="password" placeholder="Password" /><br/><br/>
      <button type="submit">Create account</button>
    </form>
    <p><a href="/login">Already have an account?</a></p>
  `);
});

app.post("/register", async (req, res) => {
    try {
        const username = (req.body.username || "").trim();
        const password = req.body.password || "";

        if (username.length < 3) return res.send("Username too short (min 3).");
        if (password.length < 4) return res.send("Password too short (min 4).");

        const passwordHash = await bcrypt.hash(password, 10);

        // insert user
        await pool.query(
            `INSERT INTO users (username, password_hash) VALUES ($1, $2)`,
            [username, passwordHash]
        );

        res.send("Account created. <a href='/login'>Go to login</a>");
    } catch (err) {
        // unique violation
        if (err && err.code === "23505") {
            return res.send("User already exists. <a href='/register'>Back</a>");
        }
        console.error(err);
        res.status(500).send("Server error");
    }
});

app.get("/login", (req, res) => {
    res.send(`
    <h1>Login</h1>
    <form method="POST" action="/login">
      <input name="username" placeholder="Username" /><br/><br/>
      <input name="password" type="password" placeholder="Password" /><br/><br/>
      <button type="submit">Login</button>
    </form>
    <p><a href="/register">Create account</a></p>
  `);
});

app.post("/login", async (req, res) => {
    try {
        const username = (req.body.username || "").trim();
        const password = req.body.password || "";

        const result = await pool.query(
            `SELECT username, password_hash FROM users WHERE LOWER(username)=LOWER($1) LIMIT 1`,
            [username]
        );

        if (result.rowCount === 0) return res.send("Wrong login. <a href='/login'>Try again</a>");

        const user = result.rows[0];
        const ok = await bcrypt.compare(password, user.password_hash);
        if (!ok) return res.send("Wrong login. <a href='/login'>Try again</a>");

        req.session.user = { username: user.username };
        res.redirect("/dashboard");
    } catch (err) {
        console.error(err);
        res.status(500).send("Server error");
    }
});

app.get("/dashboard", requireLogin, (req, res) => {
    res.send(`
    <h1>Dashboard</h1>
    <p>Welcome, ${req.session.user.username}</p>
    <p><a href="/logout">Logout</a></p>
  `);
});

app.get("/me", requireLogin, (req, res) => {
    res.send(`
    <h1>My Account</h1>
    <p>Username: ${req.session.user.username}</p>
    <p><a href="/dashboard">Back</a></p>
  `);
});

app.get("/logout", (req, res) => {
    req.session.destroy(() => res.redirect("/"));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Running on http://localhost:${PORT}`);
});
