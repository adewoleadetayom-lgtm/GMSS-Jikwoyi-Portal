#!/data/data/com.termux/files/usr/bin/bash

set -e

echo "=========================================="
echo " GMSS JIKWOYI PORTAL UPGRADE"
echo "=========================================="

mkdir -p data public/uploads public/library

cat > server.js <<'SERVER'
const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const multer = require("multer");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;
const ROOT = __dirname;

const DATA = path.join(ROOT, "data");
const UPLOADS = path.join(ROOT, "public", "uploads");
const LIBRARY = path.join(ROOT, "public", "library");
const DB = path.join(DATA, "db.json");

[DATA, UPLOADS, LIBRARY].forEach(x => fs.mkdirSync(x, { recursive: true }));

const freshDB = () => ({
  users: [],
  announcements: [],
  library: [],
  messages: []
});

function loadDB() {
  if (!fs.existsSync(DB)) return freshDB();
  try {
    return JSON.parse(fs.readFileSync(DB, "utf8"));
  } catch {
    return freshDB();
  }
}

let db = loadDB();

function saveDB() {
  const temp = DB + ".tmp";
  fs.writeFileSync(temp, JSON.stringify(db, null, 2));
  fs.renameSync(temp, DB);
}

const id = () => crypto.randomUUID();
const now = () => new Date().toISOString();

function publicUser(u) {
  if (!u) return null;

  return {
    id: u.id,
    name: u.name,
    email: u.email,
    className: u.className || "",
    phone: u.phone || "",
    studentId: u.studentId || "",
    role: u.role,
    status: u.status,
    photo: u.photo || "",
    createdAt: u.createdAt
  };
}

function getUser(userId) {
  return db.users.find(u => u.id === userId);
}

function requireLogin(req, res, next) {
  const u = getUser(req.session.userId);

  if (!u) {
    return res.status(401).json({
      error: "Please log in first."
    });
  }

  if (u.status !== "active") {
    return res.status(403).json({
      error: "Your account has been disabled."
    });
  }

  next();
}

function requireAdmin(req, res, next) {
  const u = getUser(req.session.userId);

  if (!u || u.role !== "admin" || u.status !== "active") {
    return res.status(403).json({
      error: "Administrator access required."
    });
  }

  next();
}

/* Default administrator */
if (!db.users.some(u => u.email === "admin@gmssjikwoyi.edu.ng")) {
  db.users.push({
    id: id(),
    name: "GMSS Jikwoyi Administrator",
    email: "admin@gmssjikwoyi.edu.ng",
    password: bcrypt.hashSync("admin123", 12),
    className: "Administration",
    phone: "",
    studentId: "GMSS-ADMIN",
    role: "admin",
    status: "active",
    photo: "",
    createdAt: now()
  });

  saveDB();
}

app.use(express.json({ limit: "5mb" }));
app.use(express.urlencoded({ extended: true }));

app.use(session({
  secret: process.env.SESSION_SECRET || "GMSS-JIKWOYI-SECURE-SESSION",
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    maxAge: 7 * 24 * 60 * 60 * 1000
  }
}));

app.use(express.static(path.join(ROOT, "public")));

/* Student photo uploads */
const photoStorage = multer.diskStorage({
  destination: UPLOADS,
  filename: (req, file, cb) => {
    cb(
      null,
      req.session.userId +
      "-" +
      Date.now() +
      path.extname(file.originalname).toLowerCase()
    );
  }
});

const photoUpload = multer({
  storage: photoStorage,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowed = [
      "image/jpeg",
      "image/png",
      "image/webp"
    ];

    if (!allowed.includes(file.mimetype)) {
      return cb(new Error("Only JPG, PNG and WEBP images are allowed."));
    }

    cb(null, true);
  }
});

/* Library uploads */
const libraryStorage = multer.diskStorage({
  destination: LIBRARY,
  filename: (req, file, cb) => {
    const safe = file.originalname
      .replace(/[^a-zA-Z0-9._-]/g, "_")
      .slice(0, 100);

    cb(null, Date.now() + "-" + safe);
  }
});

const libraryUpload = multer({
  storage: libraryStorage,
  limits: { fileSize: 15 * 1024 * 1024 }
});

/* =========================
   AUTH
========================= */

app.get("/api/me", (req, res) => {
  res.json({
    user: publicUser(getUser(req.session.userId))
  });
});

app.post("/api/register", async (req, res) => {
  const {
    name,
    email,
    password,
    className,
    phone
  } = req.body;

  if (!name || !email || !password) {
    return res.status(400).json({
      error: "Name, email and password are required."
    });
  }

  if (password.length < 6) {
    return res.status(400).json({
      error: "Password must contain at least 6 characters."
    });
  }

  const cleanEmail = email.trim().toLowerCase();

  if (db.users.some(u => u.email === cleanEmail)) {
    return res.status(409).json({
      error: "This email is already registered. Please log in."
    });
  }

  const studentNumber =
    "GMSS-" +
    new Date().getFullYear() +
    "-" +
    String(db.users.length + 1).padStart(4, "0");

  const user = {
    id: id(),
    name: name.trim(),
    email: cleanEmail,
    password: await bcrypt.hash(password, 12),
    className: (className || "").trim(),
    phone: (phone || "").trim(),
    studentId: studentNumber,
    role: "member",
    status: "active",
    photo: "",
    createdAt: now()
  };

  db.users.push(user);
  saveDB();

  req.session.userId = user.id;

  res.json({
    user: publicUser(user)
  });
});

app.post("/api/login", async (req, res) => {
  const email = (req.body.email || "").trim().toLowerCase();
  const password = req.body.password || "";

  const user = db.users.find(u => u.email === email);

  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({
      error: "Invalid email or password."
    });
  }

  if (user.status !== "active") {
    return res.status(403).json({
      error: "Your account has been disabled by the administrator."
    });
  }

  req.session.userId = user.id;

  res.json({
    user: publicUser(user)
  });
});

app.post("/api/logout", (req, res) => {
  req.session.destroy(() => {
    res.json({ ok: true });
  });
});

/* =========================
   PROFILE / STUDENT ID
========================= */

app.put("/api/profile", requireLogin, (req, res) => {
  const u = getUser(req.session.userId);

  u.name = (req.body.name || u.name).trim();
  u.className = (req.body.className || "").trim();
  u.phone = (req.body.phone || "").trim();

  saveDB();

  res.json({
    user: publicUser(u)
  });
});

app.post(
  "/api/profile/photo",
  requireLogin,
  photoUpload.single("photo"),
  (req, res) => {
    if (!req.file) {
      return res.status(400).json({
        error: "Please choose an image."
      });
    }

    const u = getUser(req.session.userId);

    u.photo = "/uploads/" + req.file.filename;

    saveDB();

    res.json({
      user: publicUser(u)
    });
  }
);

/* =========================
   ANNOUNCEMENTS
========================= */

app.get("/api/announcements", (req, res) => {
  res.json(
    [...db.announcements].sort(
      (a, b) => b.createdAt.localeCompare(a.createdAt)
    )
  );
});

app.post("/api/announcements", requireAdmin, (req, res) => {
  if (!req.body.title || !req.body.body) {
    return res.status(400).json({
      error: "Title and announcement text are required."
    });
  }

  const item = {
    id: id(),
    title: req.body.title.trim(),
    body: req.body.body.trim(),
    author: getUser(req.session.userId).name,
    createdAt: now()
  };

  db.announcements.push(item);
  saveDB();

  res.json(item);
});

app.delete("/api/announcements/:id", requireAdmin, (req, res) => {
  db.announcements =
    db.announcements.filter(x => x.id !== req.params.id);

  saveDB();

  res.json({ ok: true });
});

/* =========================
   LIBRARY
========================= */

app.get("/api/library", (req, res) => {
  res.json(
    [...db.library].sort(
      (a, b) => b.createdAt.localeCompare(a.createdAt)
    )
  );
});

app.post(
  "/api/library/upload",
  requireAdmin,
  libraryUpload.single("file"),
  (req, res) => {
    if (!req.file) {
      return res.status(400).json({
        error: "Please choose a file."
      });
    }

    const item = {
      id: id(),
      title: (req.body.title || req.file.originalname).trim(),
      description: (req.body.description || "").trim(),
      category: (req.body.category || "General").trim(),
      filename: req.file.originalname,
      url: "/library/" + req.file.filename,
      mimeType: req.file.mimetype,
      size: req.file.size,
      createdAt: now()
    };

    db.library.push(item);
    saveDB();

    res.json(item);
  }
);

app.post("/api/library", requireAdmin, (req, res) => {
  if (!req.body.title) {
    return res.status(400).json({
      error: "Title is required."
    });
  }

  const item = {
    id: id(),
    title: req.body.title.trim(),
    description: (req.body.description || "").trim(),
    category: (req.body.category || "General").trim(),
    url: (req.body.url || "").trim(),
    filename: "",
    mimeType: "",
    size: 0,
    createdAt: now()
  };

  db.library.push(item);
  saveDB();

  res.json(item);
});

app.delete("/api/library/:id", requireAdmin, (req, res) => {
  const item = db.library.find(x => x.id === req.params.id);

  if (item && item.url && item.url.startsWith("/library/")) {
    const file = path.join(
      LIBRARY,
      path.basename(item.url)
    );

    if (fs.existsSync(file)) {
      fs.unlinkSync(file);
    }
  }

  db.library =
    db.library.filter(x => x.id !== req.params.id);

  saveDB();

  res.json({ ok: true });
});

/* =========================
   CONTACT
========================= */

app.post("/api/messages", requireLogin, (req, res) => {
  const {
    name,
    email,
    subject,
    message
  } = req.body;

  if (!name || !email || !message) {
    return res.status(400).json({
      error: "Name, email and message are required."
    });
  }

  db.messages.push({
    id: id(),
    name,
    email,
    subject: subject || "",
    message,
    status: "unread",
    createdAt: now()
  });

  saveDB();

  res.json({ ok: true });
});

app.get("/api/messages", requireAdmin, (req, res) => {
  res.json(
    [...db.messages].sort(
      (a, b) => b.createdAt.localeCompare(a.createdAt)
    )
  );
});

app.patch("/api/messages/:id", requireAdmin, (req, res) => {
  const item = db.messages.find(x => x.id === req.params.id);

  if (!item) {
    return res.status(404).json({
      error: "Message not found."
    });
  }

  item.status = "read";
  saveDB();

  res.json(item);
});

app.delete("/api/messages/:id", requireAdmin, (req, res) => {
  db.messages =
    db.messages.filter(x => x.id !== req.params.id);

  saveDB();

  res.json({ ok: true });
});

/* =========================
   ADMIN USERS
========================= */

app.get("/api/admin/users", requireAdmin, (req, res) => {
  res.json(
    db.users
      .map(publicUser)
      .sort((a, b) =>
        b.createdAt.localeCompare(a.createdAt)
      )
  );
});

app.patch("/api/admin/users/:id", requireAdmin, (req, res) => {
  const u = getUser(req.params.id);

  if (!u) {
    return res.status(404).json({
      error: "User not found."
    });
  }

  if (
    u.email === "admin@gmssjikwoyi.edu.ng" &&
    req.body.role === "member"
  ) {
    return res.status(400).json({
      error: "Main administrator cannot be demoted."
    });
  }

  if (["admin", "member"].includes(req.body.role)) {
    u.role = req.body.role;
  }

  if (["active", "disabled"].includes(req.body.status)) {
    u.status = req.body.status;
  }

  saveDB();

  res.json(publicUser(u));
});

app.delete("/api/admin/users/:id", requireAdmin, (req, res) => {
  const u = getUser(req.params.id);

  if (!u) {
    return res.status(404).json({
      error: "User not found."
    });
  }

  if (u.email === "admin@gmssjikwoyi.edu.ng") {
    return res.status(400).json({
      error: "Main administrator cannot be deleted."
    });
  }

  db.users = db.users.filter(x => x.id !== req.params.id);

  saveDB();

  res.json({ ok: true });
});

app.get("/api/admin/stats", requireAdmin, (req, res) => {
  res.json({
    users: db.users.length,
    members: db.users.filter(x => x.role === "member").length,
    admins: db.users.filter(x => x.role === "admin").length,
    announcements: db.announcements.length,
    library: db.library.length,
    messages: db.messages.length,
    unreadMessages:
      db.messages.filter(x => x.status === "unread").length
  });
});

/* Express 5 compatible catch-all */
app.get("/{*splat}", (req, res) => {
  res.sendFile(path.join(ROOT, "public", "index.html"));
});

app.use((err, req, res, next) => {
  console.error(err);

  res.status(400).json({
    error: err.message || "Request failed."
  });
});

app.listen(PORT, () => {
  console.log("");
  console.log("==========================================");
  console.log(" GMSS JIKWOYI PORTAL IS RUNNING");
  console.log(" http://localhost:" + PORT);
  console.log("==========================================");
});
SERVER

cat > public/index.html <<'HTML'
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>GMSS Jikwoyi Portal</title>

<style>
:root{
 --purple:#6b0aa8;
 --purple2:#3d0563;
 --purple3:#8d20ca;
 --light:#f6f2f9;
 --white:#fff;
 --dark:#21162a;
 --muted:#746b79;
 --green:#15803d;
 --red:#b91c1c;
 --shadow:0 10px 30px rgba(42,10,55,.10);
}

*{box-sizing:border-box}

html{scroll-behavior:smooth}

body{
 margin:0;
 font-family:Arial,Helvetica,sans-serif;
 background:var(--light);
 color:var(--dark);
}

button,input,textarea,select{
 font:inherit;
}

button{
 cursor:pointer;
}

.hidden{
 display:none!important;
}

.top{
 position:sticky;
 top:0;
 z-index:100;
 background:linear-gradient(135deg,var(--purple2),var(--purple));
 color:white;
 box-shadow:0 3px 15px #0003;
}

.nav{
 max-width:1200px;
 margin:auto;
 padding:10px 16px;
 display:flex;
 align-items:center;
 gap:12px;
}

.logo{
 width:58px;
 height:58px;
 object-fit:contain;
 background:#fff;
 border-radius:12px;
 padding:4px;
}

.brand h1{
 margin:0;
 font-size:20px;
}

.brand small{
 opacity:.9;
}

.spacer{
 flex:1;
}

.hamb{
 border:1px solid #ffffff55;
 background:#ffffff18;
 color:white;
 border-radius:10px;
 padding:9px 13px;
 font-size:20px;
}

.btn{
 border:0;
 border-radius:10px;
 padding:11px 16px;
 background:var(--purple);
 color:white;
 font-weight:bold;
}

.btn.light{
 background:white;
 color:var(--purple);
}

.btn.gray{
 background:#eee;
 color:#222;
}

.btn.red{
 background:#c62828;
}

.btn.green{
 background:var(--green);
}

.container{
 max-width:1200px;
 margin:auto;
 padding:20px;
}

.home{
 min-height:calc(100vh - 80px);
 background:
 linear-gradient(135deg,rgba(61,5,99,.96),rgba(107,10,168,.90)),
 url("/school-logo.jpg");
 background-size:cover;
 background-position:center;
 color:white;
 display:flex;
 align-items:center;
}

.home-inner{
 max-width:1200px;
 width:100%;
 margin:auto;
 padding:60px 25px;
 display:grid;
 grid-template-columns:1.3fr .7fr;
 gap:40px;
 align-items:center;
}

.home h1{
 font-size:clamp(38px,7vw,70px);
 margin:0 0 15px;
 line-height:1.02;
}

.home p{
 font-size:19px;
 line-height:1.7;
 opacity:.95;
}

.home-logo{
 width:180px;
 height:180px;
 object-fit:contain;
 background:white;
 border-radius:30px;
 padding:12px;
 box-shadow:0 20px 50px #0005;
}

.home-card{
 background:#ffffff15;
 border:1px solid #ffffff35;
 backdrop-filter:blur(10px);
 padding:28px;
 border-radius:25px;
 text-align:center;
}

.features{
 max-width:1200px;
 margin:auto;
 padding:45px 20px;
}

.feature-grid{
 display:grid;
 grid-template-columns:repeat(3,1fr);
 gap:18px;
}

.feature{
 background:white;
 padding:22px;
 border-radius:18px;
 box-shadow:var(--shadow);
}

.feature-icon{
 font-size:35px;
}

.auth{
 min-height:calc(100vh - 80px);
 display:grid;
 place-items:center;
 padding:25px;
}

.authbox{
 width:min(480px,100%);
 background:white;
 border-radius:24px;
 padding:28px;
 box-shadow:var(--shadow);
}

.authbox .logo{
 width:100px;
 height:100px;
 display:block;
 margin:auto;
}

.field{
 display:flex;
 flex-direction:column;
 gap:6px;
}

.form{
 display:grid;
 grid-template-columns:1fr 1fr;
 gap:12px;
}

.full{
 grid-column:1/-1;
}

input,textarea,select{
 width:100%;
 border:1px solid #d9cedf;
 border-radius:10px;
 padding:12px;
 outline:none;
 background:white;
}

input:focus,textarea:focus,select:focus{
 border-color:var(--purple);
 box-shadow:0 0 0 3px #7800b522;
}

textarea{
 min-height:120px;
 resize:vertical;
}

.layout{
 max-width:1250px;
 margin:auto;
 padding:20px;
 display:grid;
 grid-template-columns:235px 1fr;
 gap:20px;
}

.side{
 background:white;
 border-radius:18px;
 padding:12px;
 height:max-content;
 position:sticky;
 top:85px;
 box-shadow:var(--shadow);
}

.side button{
 display:block;
 width:100%;
 border:0;
 background:none;
 text-align:left;
 padding:13px;
 border-radius:10px;
 margin-bottom:3px;
}

.side button:hover{
 background:#f3e6fa;
 color:var(--purple);
 font-weight:bold;
}

.card{
 background:white;
 border-radius:20px;
 padding:22px;
 margin-bottom:18px;
 box-shadow:var(--shadow);
}

.hero{
 background:linear-gradient(135deg,var(--purple2),var(--purple3));
 color:white;
 border-radius:22px;
 padding:28px;
 display:flex;
 gap:20px;
 align-items:center;
 margin-bottom:18px;
}

.hero img{
 width:105px;
 height:105px;
 background:white;
 border-radius:17px;
 object-fit:contain;
 padding:5px;
}

.grid{
 display:grid;
 grid-template-columns:repeat(3,1fr);
 gap:15px;
}

.stat{
 background:#fbf7fd;
 border:1px solid #eadcf1;
 padding:18px;
 border-radius:15px;
}

.stat b{
 font-size:28px;
 color:var(--purple);
}

.item{
 border:1px solid #e8deed;
 padding:15px;
 border-radius:14px;
 margin:12px 0;
}

.badge{
 display:inline-block;
 padding:5px 9px;
 border-radius:50px;
 background:#eee;
 font-size:12px;
 font-weight:bold;
}

.green{
 background:#dcfce7;
 color:#166534;
}

.redbadge{
 background:#fee2e2;
 color:#991b1b;
}

.table{
 overflow:auto;
}

table{
 width:100%;
 border-collapse:collapse;
}

th,td{
 padding:10px;
 border-bottom:1px solid #eee;
 text-align:left;
 white-space:nowrap;
}

.id-card{
 width:min(430px,100%);
 margin:20px auto;
 border-radius:20px;
 overflow:hidden;
 background:white;
 box-shadow:0 12px 35px #0002;
 border:1px solid #ddd;
}

.id-head{
 background:linear-gradient(135deg,var(--purple2),var(--purple));
 color:white;
 padding:16px;
 text-align:center;
}

.id-head img{
 width:65px;
 height:65px;
 background:white;
 padding:3px;
 border-radius:10px;
 object-fit:contain;
}

.id-body{
 padding:20px;
 display:flex;
 gap:18px;
 align-items:center;
}

.id-photo{
 width:115px;
 height:140px;
 object-fit:cover;
 border-radius:10px;
 border:3px solid var(--purple);
 background:#eee;
}

.id-info{
 flex:1;
}

.id-info strong{
 display:block;
 margin-bottom:6px;
}

.id-footer{
 background:#f4e9f8;
 padding:10px;
 text-align:center;
 font-size:12px;
}

.toast{
 position:fixed;
 bottom:20px;
 right:20px;
 z-index:200;
 background:#222;
 color:white;
 padding:13px 18px;
 border-radius:10px;
 display:none;
 box-shadow:0 8px 25px #0004;
}

.footer{
 background:#26053c;
 color:white;
 text-align:center;
 padding:30px 20px;
 margin-top:40px;
}

@media(max-width:800px){
 .home-inner{
  grid-template-columns:1fr;
  text-align:center;
  padding:45px 18px;
 }

 .home-card{
  max-width:400px;
  margin:auto;
 }

 .feature-grid,
 .grid,
 .form{
  grid-template-columns:1fr;
 }

 .full{
  grid-column:auto;
 }

 .layout{
  grid-template-columns:1fr;
  padding:12px;
 }

 .side{
  display:none;
  position:fixed;
  left:10px;
  right:10px;
  top:78px;
  z-index:90;
 }

 .side.open{
  display:block;
 }

 .hero{
  flex-direction:column;
  text-align:center;
 }

 .brand small{
  display:none;
 }

 .who{
  display:none;
 }

 .id-body{
  flex-direction:column;
  text-align:center;
 }

 .home-logo{
  width:140px;
  height:140px;
 }
}

@media print{
 body *{
  visibility:hidden!important;
 }

 #printArea,
 #printArea *{
  visibility:visible!important;
 }

 #printArea{
  position:absolute;
  left:0;
  top:0;
  width:100%;
 }

 .id-card{
  box-shadow:none;
  margin:0 auto;
 }
}
</style>
</head>

<body>

<header class="top">
 <div class="nav">

  <button class="hamb" onclick="menu()">☰</button>

  <img class="logo" src="/school-logo.jpg">

  <div class="brand">
   <h1>GMSS JIKWOYI</h1>
   <small>Knowledge sets you on Eagle's wing</small>
  </div>

  <div class="spacer"></div>

  <span id="who" class="who"></span>

  <button id="loginBtn" class="btn light" onclick="showAuth('login')">
   Login
  </button>

 </div>
</header>

<!-- HOME -->
<section id="homePage">

 <section class="home">

  <div class="home-inner">

   <div>
    <h1>Government Secondary School Jikwoyi</h1>

    <p>
     Welcome to the official GMSS Jikwoyi School Portal.
     Access school announcements, learning resources,
     student services and your digital school ID in one place.
    </p>

    <button class="btn light" onclick="showAuth('register')">
     Create Student Account
    </button>

    <button class="btn" onclick="showAuth('login')">
     Student Login
    </button>
   </div>

   <div class="home-card">
    <img class="home-logo" src="/school-logo.jpg">

    <h2>GMSS Jikwoyi Portal</h2>

    <p>
     A modern digital platform for students,
     staff and school administration.
    </p>
   </div>

  </div>

 </section>

 <section class="features">

  <h2 style="text-align:center">
   Portal Services
  </h2>

  <div class="feature-grid">

   <div class="feature">
    <div class="feature-icon">📢</div>
    <h3>Announcements</h3>
    <p>Stay updated with important school information.</p>
   </div>

   <div class="feature">
    <div class="feature-icon">📚</div>
    <h3>School Library</h3>
    <p>Access learning materials and school documents.</p>
   </div>

   <div class="feature">
    <div class="feature-icon">🪪</div>
    <h3>Digital Student ID</h3>
    <p>View, update and print your student ID card.</p>
   </div>

  </div>

 </section>

 <footer class="footer">
  <strong>GMSS Jikwoyi</strong>
  <br>
  Knowledge sets you on Eagle's wing
 </footer>

</section>

<!-- AUTH -->
<section id="auth" class="auth hidden">

 <div class="authbox">

  <img class="logo" src="/school-logo.jpg">

  <h2 id="authTitle" style="text-align:center">
   Welcome Back
  </h2>

  <p style="text-align:center;color:var(--muted)">
   GMSS Jikwoyi Student Portal
  </p>

  <div id="loginBox">

   <div class="field">
    <label>Email</label>
    <input id="le" type="email">
   </div>

   <br>

   <div class="field">
    <label>Password</label>
    <input id="lp" type="password">
   </div>

   <br>

   <button class="btn" style="width:100%" onclick="doLogin()">
    Sign In
   </button>

   <p style="text-align:center">
    New student?
    <button class="btn gray" onclick="switchMode('register')">
     Register
    </button>
   </p>

   <button class="btn gray" style="width:100%" onclick="goHome()">
    ← Back to Home
   </button>

  </div>

  <div id="regBox" class="hidden">

   <div class="form">

    <div class="field full">
     <label>Full Name</label>
     <input id="rn">
    </div>

    <div class="field">
     <label>Class</label>
     <input id="rc" placeholder="JSS 1A">
    </div>

    <div class="field">
     <label>Phone</label>
     <input id="rp">
    </div>

    <div class="field full">
     <label>Email</label>
     <input id="re" type="email">
    </div>

    <div class="field full">
     <label>Password</label>
     <input id="rpass" type="password">
    </div>

   </div>

   <br>

   <button class="btn" style="width:100%" onclick="doRegister()">
    Create Account
   </button>

   <p style="text-align:center">
    Already registered?
    <button class="btn gray" onclick="switchMode('login')">
     Login
    </button>
   </p>

   <button class="btn gray" style="width:100%" onclick="goHome()">
    ← Back to Home
   </button>

  </div>

 </div>

</section>

<!-- APP -->
<div id="app" class="layout hidden">

 <aside id="side" class="side">

  <button onclick="page('home')">🏠 Dashboard</button>

  <button onclick="page('profile')">👤 My Profile</button>

  <button onclick="page('id')">🪪 My Student ID</button>

  <button onclick="page('ann')">📢 Announcements</button>

  <button onclick="page('lib')">📚 Library</button>

  <button onclick="page('contact')">✉️ Contact School</button>

  <button
   id="adminLink"
   class="hidden"
   onclick="page('admin')">
   ⚙️ Admin Panel
  </button>

  <button onclick="logout()">🚪 Logout</button>

 </aside>

 <main id="main"></main>

</div>

<div id="toast" class="toast"></div>

<script>

let ME = null;
let LIB = [];

const $ = id => document.getElementById(id);

const esc = value =>
 String(value ?? "")
 .replace(/[&<>"']/g, m => ({
  "&":"&amp;",
  "<":"&lt;",
  ">":"&gt;",
  '"':"&quot;",
  "'":"&#039;"
 }[m]));

async function api(url, options = {}){

 const response = await fetch(url,{
  headers:{
   "Content-Type":"application/json",
   ...(options.headers || {})
  },
  ...options
 });

 let data = {};

 try{
  data = await response.json();
 }catch{}

 if(!response.ok){
  throw Error(data.error || "Request failed");
 }

 return data;
}

function toast(message){

 $("toast").textContent = message;
 $("toast").style.display = "block";

 setTimeout(()=>{
  $("toast").style.display = "none";
 },3000);
}

function menu(){

 $("side").classList.toggle("open");

}

function goHome(){

 $("homePage").classList.remove("hidden");
 $("auth").classList.add("hidden");
 $("app").classList.add("hidden");

}

function showAuth(mode = "login"){

 $("homePage").classList.add("hidden");
 $("auth").classList.remove("hidden");
 $("app").classList.add("hidden");

 switchMode(mode);

}

function switchMode(mode){

 $("loginBox").classList.toggle(
  "hidden",
  mode !== "login"
 );

 $("regBox").classList.toggle(
  "hidden",
  mode !== "register"
 );

 $("authTitle").textContent =
  mode === "login"
  ? "Welcome Back"
  : "Create Your Account";

}

async function doLogin(){

 try{

  const data = await api("/api/login",{
   method:"POST",
   body:JSON.stringify({
    email:$("le").value,
    password:$("lp").value
   })
  });

  ME = data.user;

  start();

  toast("Login successful");

 }catch(error){

  toast(error.message);

 }

}

async function doRegister(){

 try{

  const data = await api("/api/register",{
   method:"POST",
   body:JSON.stringify({
    name:$("rn").value,
    className:$("rc").value,
    email:$("re").value,
    phone:$("rp").value,
    password:$("rpass").value
   })
  });

  ME = data.user;

  start();

  toast("Account created successfully");

 }catch(error){

  toast(error.message);

 }

}

async function logout(){

 await api("/api/logout",{
  method:"POST"
 });

 location.reload();

}

function start(){

 $("homePage").classList.add("hidden");
 $("auth").classList.add("hidden");
 $("app").classList.remove("hidden");

 $("who").textContent = ME.name;

 $("loginBtn").textContent = "Online";

 $("adminLink").classList.toggle(
  "hidden",
  ME.role !== "admin"
 );

 page("home");

}

async function boot(){

 try{

  const data = await api("/api/me");

  if(data.user){

   ME = data.user;
   start();
   return;

  }

 }catch{}

 goHome();

}

function page(name){

 if($("side")) $("side").classList.remove("open");

 const pages = {
  home,
  profile,
  id,
  ann,
  lib,
  contact,
  admin
 };

 (pages[name] || home)();

}

/* DASHBOARD */

async function home(){

 const announcements =
  await api("/api/announcements");

 $("main").innerHTML = `

  <div class="hero">

   <img src="/school-logo.jpg">

   <div>

    <h1>
     Welcome, ${esc(ME.name)}
    </h1>

    <p>
     Welcome to your GMSS Jikwoyi student dashboard.
    </p>

    <button class="btn light"
     onclick="page('id')">
     View My ID
    </button>

   </div>

  </div>

  <div class="grid">

   <div class="stat">
    <b>${announcements.length}</b>
    <br>
    Announcements
   </div>

   <div class="stat">
    <b>${esc(ME.studentId)}</b>
    <br>
    Student ID
   </div>

   <div class="stat">
    <b>${esc(ME.role)}</b>
    <br>
    Account
   </div>

  </div>

  <div class="card">

   <h2>📢 Latest Announcement</h2>

   ${
    announcements[0]
    ?
    `
    <h3>${esc(announcements[0].title)}</h3>
    <p>${esc(announcements[0].body)}</p>
    `
    :
    "<p>No announcements yet.</p>"
   }

  </div>

 `;

}

/* PROFILE */

function profile(){

 $("main").innerHTML = `

  <div class="card">

   <h2>👤 My Profile</h2>

   <div style="display:flex;gap:18px;align-items:center;flex-wrap:wrap">

    <img
     class="logo"
     src="${ME.photo || "/school-logo.jpg"}"
    >

    <div>

     <strong>${esc(ME.name)}</strong>

     <p>${esc(ME.email)}</p>

     <input
      type="file"
      id="photo"
      accept="image/jpeg,image/png,image/webp"
     >

     <br><br>

     <button class="btn"
      onclick="uploadPhoto()">
      Upload Photo
     </button>

    </div>

   </div>

   <hr>

   <div class="form">

    <div class="field">
     <label>Full Name</label>
     <input id="pn" value="${esc(ME.name)}">
    </div>

    <div class="field">
     <label>Class</label>
     <input id="pc" value="${esc(ME.className)}">
    </div>

    <div class="field">
     <label>Phone</label>
     <input id="pp" value="${esc(ME.phone)}">
    </div>

   </div>

   <br>

   <button class="btn"
    onclick="saveProfile()">
    Save Changes
   </button>

  </div>

 `;

}

async function saveProfile(){

 try{

  const data = await api("/api/profile",{
   method:"PUT",
   body:JSON.stringify({
    name:$("pn").value,
    className:$("pc").value,
    phone:$("pp").value
   })
  });

  ME = data.user;

  $("who").textContent = ME.name;

  toast("Profile saved");

  page("profile");

 }catch(error){

  toast(error.message);

 }

}

async function uploadPhoto(){

 const file = $("photo").files[0];

 if(!file){
  return toast("Please choose a photo.");
 }

 const form = new FormData();

 form.append("photo",file);

 const response = await fetch(
  "/api/profile/photo",
  {
   method:"POST",
   body:form
  }
 );

 const data = await response.json();

 if(!response.ok){
  return toast(data.error || "Upload failed.");
 }

 ME = data.user;

 profile();

 toast("Photo uploaded successfully");

}

/* STUDENT ID */

function id(){

 $("main").innerHTML = `

  <div class="card">

   <h2>🪪 My Student ID Card</h2>

   <p>
    This is your digital GMSS Jikwoyi student identity card.
   </p>

   <div id="printArea">

    <div class="id-card">

     <div class="id-head">

      <img src="/school-logo.jpg">

      <h2>GMSS JIKWOYI</h2>

      <small>
       GOVERNMENT SECONDARY SCHOOL JIKWOYI
      </small>

     </div>

     <div class="id-body">

      <img
       class="id-photo"
       src="${ME.photo || "/school-logo.jpg"}"
      >

      <div class="id-info">

       <strong>${esc(ME.name)}</strong>

       <div>
        Student ID:
        <b>${esc(ME.studentId)}</b>
       </div>

       <div>
        Class:
        ${esc(ME.className || "Not set")}
       </div>

       <div>
        Phone:
        ${esc(ME.phone || "Not set")}
       </div>

       <div>
        Email:
        ${esc(ME.email)}
       </div>

      </div>

     </div>

     <div class="id-footer">
      Knowledge sets you on Eagle's wing
     </div>

    </div>

   </div>

   <div style="text-align:center">

    <button class="btn"
     onclick="printID()">
     🖨️ Print ID Card
    </button>

    <button class="btn gray"
     onclick="page('profile')">
     ✏️ Edit Information
    </button>

   </div>

  </div>

 `;

}

function printID(){

 window.print();

}

/* ANNOUNCEMENTS */

async function ann(){

 const data =
  await api("/api/announcements");

 $("main").innerHTML = `

  <div class="card">

   <h2>📢 School Announcements</h2>

   ${
    data.map(x => `
     <div class="item">

      <h3>${esc(x.title)}</h3>

      <p>${esc(x.body)}</p>

      <small>
       ${new Date(x.createdAt).toLocaleString()}
       ·
       ${esc(x.author)}
      </small>

     </div>
    `).join("")
    ||
    "<p>No announcements yet.</p>"
   }

  </div>

 `;

}

/* LIBRARY */

async function lib(){

 LIB = await api("/api/library");

 $("main").innerHTML = `

  <div class="card">

   <h2>📚 School Library</h2>

   <input
    id="search"
    placeholder="Search library..."
    oninput="filterLibrary()"
   >

   <div id="libraryItems"></div>

  </div>

 `;

 filterLibrary();

}

function filterLibrary(){

 const query =
  ($("search").value || "").toLowerCase();

 const results = LIB.filter(item =>
  (
   item.title +
   " " +
   item.description +
   " " +
   item.category
  ).toLowerCase().includes(query)
 );

 $("libraryItems").innerHTML =
  results.map(item => `

   <div class="item">

    <span class="badge">
     ${esc(item.category)}
    </span>

    <h3>${esc(item.title)}</h3>

    <p>${esc(item.description)}</p>

    ${
     item.url
     ?
     `
     <a
      href="${esc(item.url)}"
      target="_blank"
      class="btn"
      style="display:inline-block;text-decoration:none"
     >
      ${
       item.mimeType &&
       item.mimeType.startsWith("image/")
       ? "🖼️ View Picture"
       : "📄 Open File"
      }
     </a>
     `
     :
     ""
    }

   </div>

  `).join("")
  ||
  "<p>No resources found.</p>";

}

/* CONTACT */

function contact(){

 $("main").innerHTML = `

  <div class="card">

   <h2>✉️ Contact School Administration</h2>

   <div class="form">

    <div class="field">
     <label>Name</label>
     <input id="cn" value="${esc(ME.name)}">
    </div>

    <div class="field">
     <label>Email</label>
     <input id="ce" value="${esc(ME.email)}">
    </div>

    <div class="field full">
     <label>Subject</label>
     <input id="cs">
    </div>

    <div class="field full">
     <label>Message</label>
     <textarea id="cm"></textarea>
    </div>

   </div>

   <br>

   <button class="btn"
    onclick="sendMessage()">
    Send Message
   </button>

  </div>

 `;

}

async function sendMessage(){

 try{

  await api("/api/messages",{
   method:"POST",
   body:JSON.stringify({
    name:$("cn").value,
    email:$("ce").value,
    subject:$("cs").value,
    message:$("cm").value
   })
  });

  $("cm").value = "";

  toast("Message sent to administration");

 }catch(error){

  toast(error.message);

 }

}

/* ADMIN */

async function admin(){

 if(ME.role !== "admin"){
  return toast("Administrator access required.");
 }

 const [
  stats,
  users,
  announcements,
  library,
  messages
 ] = await Promise.all([
  api("/api/admin/stats"),
  api("/api/admin/users"),
  api("/api/announcements"),
  api("/api/library"),
  api("/api/messages")
 ]);

 $("main").innerHTML = `

  <div class="card">

   <h2>⚙️ Administrator Dashboard</h2>

   <div class="grid">

    <div class="stat">
     <b>${stats.users}</b>
     <br>Total Users
    </div>

    <div class="stat">
     <b>${stats.members}</b>
     <br>Students
    </div>

    <div class="stat">
     <b>${stats.announcements}</b>
     <br>Announcements
    </div>

    <div class="stat">
     <b>${stats.library}</b>
     <br>Library Resources
    </div>

    <div class="stat">
     <b>${stats.messages}</b>
     <br>Messages
    </div>

    <div class="stat">
     <b>${stats.unreadMessages}</b>
     <br>Unread
    </div>

   </div>

  </div>

  <div class="card">

   <h3>📢 Publish Announcement</h3>

   <div class="field">
    <label>Title</label>
    <input id="at">
   </div>

   <br>

   <div class="field">
    <label>Announcement</label>
    <textarea id="ab"></textarea>
   </div>

   <br>

   <button class="btn"
    onclick="addAnnouncement()">
    Publish
   </button>

  </div>

  <div class="card">

   <h3>📚 Upload Library File / Picture</h3>

   <div class="form">

    <div class="field">
     <label>Title</label>
     <input id="lt">
    </div>

    <div class="field">
     <label>Category</label>
     <input id="lc" value="General">
    </div>

    <div class="field full">
     <label>Description</label>
     <textarea id="ld"></textarea>
    </div>

    <div class="field full">
     <label>Select File</label>
     <input
      type="file"
      id="lf"
      accept="image/*,.pdf,.doc,.docx,.ppt,.pptx,.xls,.xlsx,.txt"
     >
    </div>

   </div>

   <br>

   <button class="btn green"
    onclick="uploadLibraryFile()">
    📤 Upload to Library
   </button>

   <p style="color:var(--muted)">
    Maximum file size: 15 MB.
   </p>

  </div>

  <div class="card">

   <h3>👥 Manage Students</h3>

   <div class="table">

    <table>

     <tr>
      <th>Name</th>
      <th>Student ID</th>
      <th>Email</th>
      <th>Role</th>
      <th>Status</th>
      <th>Action</th>
     </tr>

     ${
      users.map(u => `

       <tr>

        <td>${esc(u.name)}</td>

        <td>${esc(u.studentId)}</td>

        <td>${esc(u.email)}</td>

        <td>${esc(u.role)}</td>

        <td>${esc(u.status)}</td>

        <td>

         ${
          u.email === "admin@gmssjikwoyi.edu.ng"
          ?
          "Main Admin"
          :
          `
          <button
           class="btn gray"
           onclick="toggleUser('${u.id}','${u.status === "active" ? "disabled" : "active"}')">
           ${u.status === "active" ? "Disable" : "Enable"}
          </button>

          <button
           class="btn red"
           onclick="deleteUser('${u.id}')">
           Delete
          </button>
          `
         }

        </td>

       </tr>

      `).join("")
     }

    </table>

   </div>

  </div>

  <div class="card">

   <h3>📢 Manage Announcements</h3>

   ${
    announcements.map(x => `

     <div class="item">

      <b>${esc(x.title)}</b>

      <button
       class="btn red"
       style="float:right"
       onclick="deleteAnnouncement('${x.id}')">
       Delete
      </button>

      <p>${esc(x.body)}</p>

     </div>

    `).join("")
    ||
    "No announcements."

   }

  </div>

  <div class="card">

   <h3>📚 Manage Library</h3>

   ${
    library.map(x => `

     <div class="item">

      <b>${esc(x.title)}</b>

      <button
       class="btn red"
       style="float:right"
       onclick="deleteLibrary('${x.id}')">
       Delete
      </button>

      <p>${esc(x.description)}</p>

     </div>

    `).join("")
    ||
    "No library resources."

   }

  </div>

  <div class="card">

   <h3>✉️ Contact Messages</h3>

   ${
    messages.map(x => `

     <div class="item">

      <span class="badge ${
       x.status === "unread"
       ? "redbadge"
       : "green"
      }">

       ${esc(x.status)}

      </span>

      <h3>${esc(x.subject || "No subject")}</h3>

      <p>${esc(x.message)}</p>

      <small>
       ${esc(x.name)} · ${esc(x.email)}
      </small>

      <br><br>

      <button
       class="btn gray"
       onclick="readMessage('${x.id}')">
       Mark Read
      </button>

      <button
       class="btn red"
       onclick="deleteMessage('${x.id}')">
       Delete
      </button>

     </div>

    `).join("")
    ||
    "No messages."

   }

  </div>

 `;

}

async function addAnnouncement(){

 try{

  await api("/api/announcements",{
   method:"POST",
   body:JSON.stringify({
    title:$("at").value,
    body:$("ab").value
   })
  });

  toast("Announcement published");

  admin();

 }catch(error){

  toast(error.message);

 }

}

async function uploadLibraryFile(){

 const file = $("lf").files[0];

 if(!file){
  return toast("Please choose a file.");
 }

 const form = new FormData();

 form.append("file",file);
 form.append("title",$("lt").value || file.name);
 form.append("category",$("lc").value);
 form.append("description",$("ld").value);

 try{

  const response = await fetch(
   "/api/library/upload",
   {
    method:"POST",
    body:form
   }
  );

  const data = await response.json();

  if(!response.ok){
   throw Error(data.error || "Upload failed.");
  }

  toast("Library file uploaded");

  admin();

 }catch(error){

  toast(error.message);

 }

}

async function toggleUser(id,status){

 try{

  await api("/api/admin/users/" + id,{
   method:"PATCH",
   body:JSON.stringify({status})
  });

  admin();

 }catch(error){

  toast(error.message);

 }

}

async function deleteUser(id){

 if(!confirm("Delete this student account?")){
  return;
 }

 try{

  await api("/api/admin/users/" + id,{
   method:"DELETE"
  });

  admin();

 }catch(error){

  toast(error.message);

 }

}

async function deleteAnnouncement(id){

 if(!confirm("Delete this announcement?")){
  return;
 }

 await api("/api/announcements/" + id,{
  method:"DELETE"
 });

 admin();

}

async function deleteLibrary(id){

 if(!confirm("Delete this library resource?")){
  return;
 }

 await api("/api/library/" + id,{
  method:"DELETE"
 });

 admin();

}

async function readMessage(id){

 await api("/api/messages/" + id,{
  method:"PATCH",
  body:"{}"
 });

 admin();

}

async function deleteMessage(id){

 if(!confirm("Delete this message?")){
  return;
 }

 await api("/api/messages/" + id,{
  method:"DELETE"
 });

 admin();

}

boot();

</script>

</body>
</html>
HTML

chmod +x upgrade.sh

echo ""
echo "=========================================="
echo " INSTALLATION COMPLETE"
echo "=========================================="
echo ""
echo "Starting GMSS Jikwoyi Portal..."
echo ""

npm install

node -c server.js

echo ""
echo "SERVER CODE CHECK PASSED"
echo ""

npm start
