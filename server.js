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
