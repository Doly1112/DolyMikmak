const express = require("express");
const session = require("express-session");
const bcrypt = require("bcrypt");
const fs = require("fs");
const path = require("path");

const app = express();
app.use(express.urlencoded({ extended: true }));

app.use(
    session({
        secret: "mySuperSecretKey",
        resave: false,
        saveUninitialized: false,
    })
);

const USERS_FILE = path.join(__dirname, "users.json");

function loadUsers() {
    try {
        return JSON.parse(fs.readFileSync(USERS_FILE, "utf8"));
    } catch {
        return [];
    }
}

function saveUsers(users) {
    fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2), "utf8");
}

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
    const username = (req.body.username || "").trim();
    const password = req.body.password || "";

    if (username.length < 3) return res.send("Username too short (min 3).");
    if (password.length < 4) return res.send("Password too short (min 4).");

    const users = loadUsers();
    const exists = users.some((u) => u.username.toLowerCase() === username.toLowerCase());
    if (exists) return res.send("User already exists. <a href='/register'>Back</a>");

    const passwordHash = await bcrypt.hash(password, 10);
    users.push({ username, passwordHash });
    saveUsers(users);

    res.send("Account created. <a href='/login'>Go to login</a>");
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
    const username = (req.body.username || "").trim();
    const password = req.body.password || "";

    const users = loadUsers();
    const user = users.find((u) => u.username.toLowerCase() === username.toLowerCase());
    if (!user) return res.send("Wrong login. <a href='/login'>Try again</a>");

    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return res.send("Wrong login. <a href='/login'>Try again</a>");

    req.session.user = { username: user.username };
    res.redirect("/dashboard");
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


