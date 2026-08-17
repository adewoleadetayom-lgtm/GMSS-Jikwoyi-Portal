const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const multer = require("multer");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { Pool } = require("pg");

const app = express();
const PORT = process.env.PORT || 3000;
const ROOT = __dirname;

const UPLOADS = path.join(ROOT, "public", "uploads");
const LIBRARY = path.join(ROOT, "public", "library");

[UPLOADS, LIBRARY].forEach(x => fs.mkdirSync(x, { recursive: true }));

if (!process.env.DATABASE_URL) {
  console.error("ERROR: DATABASE_URL is not set.");
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === "production"
    ? { rejectUnauthorized: false }
    : false
});

const id = () => crypto.randomUUID();
const now = () => new Date().toISOString();

async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      class_name TEXT DEFAULT '',
      phone TEXT DEFAULT '',
      student_id TEXT UNIQUE,
      role TEXT DEFAULT 'member',
      status TEXT DEFAULT 'active',
      photo TEXT DEFAULT '',
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS announcements (
      id TEXT PRIMARY KEY,
      title TEXT NOT NULL,
      body TEXT NOT NULL,
      author TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS library (
      id TEXT PRIMARY KEY,
      title TEXT NOT NULL,
      description TEXT DEFAULT '',
      category TEXT DEFAULT 'General',
      filename TEXT DEFAULT '',
      url TEXT DEFAULT '',
      mime_type TEXT DEFAULT '',
      size BIGINT DEFAULT 0,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS messages (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT NOT NULL,
      subject TEXT DEFAULT '',
      message TEXT NOT NULL,
      status TEXT DEFAULT 'unread',
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);

  // Safe migration for existing PostgreSQL databases
  await pool.query(`
    ALTER TABLE users ADD COLUMN IF NOT EXISTS name TEXT DEFAULT '';
    ALTER TABLE users ADD COLUMN IF NOT EXISTS class_name TEXT DEFAULT '';
    ALTER TABLE users ADD COLUMN IF NOT EXISTS phone TEXT DEFAULT '';
    ALTER TABLE users ADD COLUMN IF NOT EXISTS student_id TEXT;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS role TEXT DEFAULT 'member';
    ALTER TABLE users ADD COLUMN IF NOT EXISTS status TEXT DEFAULT 'active';
    ALTER TABLE users ADD COLUMN IF NOT EXISTS photo TEXT DEFAULT '';
    ALTER TABLE users ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT NOW();
  `);

  await pool.query(`
    UPDATE users
    SET name = COALESCE(NULLIF(name, ''), 'GMSS Student')
    WHERE name IS NULL OR name = '';
  `);

  const admin = await pool.query(
    "SELECT id FROM users WHERE email=$1",
    ["admin@gmssjikwoyi.edu.ng"]
  );

  if (admin.rowCount === 0) {
    await pool.query(`
      INSERT INTO users
      (id,name,email,password,class_name,phone,student_id,role,status,photo)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
    `, [
      id(),
      "GMSS Jikwoyi Administrator",
      "admin@gmssjikwoyi.edu.ng",
      bcrypt.hashSync("admin123", 12),
      "Administration",
      "",
      "GMSS-ADMIN",
      "admin",
      "active",
      ""
    ]);

    console.log("Default administrator created.");
  }

  console.log("PostgreSQL database ready.");
}

function publicUser(u) {
  if (!u) return null;

  return {
    id: u.id,
    name: u.name,
    email: u.email,
    className: u.class_name || "",
    phone: u.phone || "",
    studentId: u.student_id || "",
    role: u.role,
    status: u.status,
    photo: u.photo || "",
    createdAt: u.created_at
  };
}

async function getUser(userId) {
  if (!userId) return null;

  const r = await pool.query(
    "SELECT * FROM users WHERE id=$1",
    [userId]
  );

  return r.rows[0] || null;
}

async function requireLogin(req,res,next) {
  try {
    const u = await getUser(req.session.userId);

    if (!u)
      return res.status(401).json({error:"Please log in first."});

    if (u.status !== "active")
      return res.status(403).json({error:"Your account has been disabled."});

    req.currentUser = u;
    next();
  } catch(e) {
    next(e);
  }
}

async function requireAdmin(req,res,next) {
  try {
    const u = await getUser(req.session.userId);

    if (!u || u.role !== "admin" || u.status !== "active")
      return res.status(403).json({error:"Administrator access required."});

    req.currentUser = u;
    next();
  } catch(e) {
    next(e);
  }
}

app.use(express.json({limit:"5mb"}));
app.use(express.urlencoded({extended:true}));

app.use(session({
  secret: process.env.SESSION_SECRET || "GMSS-JIKWOYI-SECURE-SESSION",
  resave:false,
  saveUninitialized:false,
  cookie:{
    httpOnly:true,
    sameSite:"lax",
    maxAge:7*24*60*60*1000
  }
}));

app.use(express.static(path.join(ROOT,"public")));
app.use("/uploads",express.static(UPLOADS));
app.use("/library",express.static(LIBRARY));

const photoStorage = multer.diskStorage({
  destination: UPLOADS,
  filename:(req,file,cb)=>{
    cb(
      null,
      req.session.userId+"-"+Date.now()+path.extname(file.originalname).toLowerCase()
    );
  }
});

const photoUpload = multer({
  storage:photoStorage,
  limits:{fileSize:5*1024*1024},
  fileFilter:(req,file,cb)=>{
    const allowed=["image/jpeg","image/png","image/webp"];

    if(!allowed.includes(file.mimetype))
      return cb(new Error("Only JPG, PNG and WEBP images are allowed."));

    cb(null,true);
  }
});

const libraryStorage = multer.diskStorage({
  destination:LIBRARY,
  filename:(req,file,cb)=>{
    const safe=file.originalname
      .replace(/[^a-zA-Z0-9._-]/g,"_")
      .slice(0,100);

    cb(null,Date.now()+"-"+safe);
  }
});

const libraryUpload = multer({
  storage:libraryStorage,
  limits:{fileSize:15*1024*1024}
});

/* AUTH */

app.get("/api/me",async(req,res,next)=>{
  try {
    const u=await getUser(req.session.userId);
    res.json({user:publicUser(u)});
  } catch(e){next(e);}
});

app.post("/api/register",async(req,res,next)=>{
  try {
    const {name,email,password,className,phone}=req.body;

    if(!name||!email||!password)
      return res.status(400).json({
        error:"Name, email and password are required."
      });

    if(password.length<6)
      return res.status(400).json({
        error:"Password must contain at least 6 characters."
      });

    const cleanEmail=email.trim().toLowerCase();

    const existing=await pool.query(
      "SELECT id FROM users WHERE email=$1",
      [cleanEmail]
    );

    if(existing.rowCount)
      return res.status(409).json({
        error:"This email is already registered. Please log in."
      });

    const count=await pool.query(
      "SELECT COUNT(*)::int AS count FROM users"
    );

    const studentId=
      "GMSS-"+new Date().getFullYear()+"-"+
      String(count.rows[0].count+1).padStart(4,"0");

    const u={
      id:id(),
      name:name.trim(),
      email:cleanEmail,
      password:await bcrypt.hash(password,12),
      className:(className||"").trim(),
      phone:(phone||"").trim(),
      studentId,
      role:"member",
      status:"active",
      photo:"",
      createdAt:now()
    };

    await pool.query(`
      INSERT INTO users
      (id,name,email,password,class_name,phone,student_id,role,status,photo)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
    `,[
      u.id,u.name,u.email,u.password,u.className,u.phone,
      u.studentId,u.role,u.status,u.photo
    ]);

    req.session.userId=u.id;

    res.json({user:publicUser({
      ...u,
      class_name:u.className,
      student_id:u.studentId,
      created_at:u.createdAt
    })});

  } catch(e){next(e);}
});

app.post("/api/login",async(req,res,next)=>{
  try {
    const email=(req.body.email||"").trim().toLowerCase();
    const password=req.body.password||"";

    const r=await pool.query(
      "SELECT * FROM users WHERE email=$1",
      [email]
    );

    const u=r.rows[0];

    if(!u || !(await bcrypt.compare(password,u.password)))
      return res.status(401).json({
        error:"Invalid email or password."
      });

    if(u.status!=="active")
      return res.status(403).json({
        error:"Your account has been disabled by the administrator."
      });

    req.session.userId=u.id;

    res.json({user:publicUser(u)});
  } catch(e){next(e);}
});

app.post("/api/logout",(req,res)=>{
  req.session.destroy(()=>res.json({ok:true}));
});

/* PROFILE */

app.put("/api/profile",requireLogin,async(req,res,next)=>{
  try {
    const u=req.currentUser;

    await pool.query(`
      UPDATE users
      SET name=$1,class_name=$2,phone=$3
      WHERE id=$4
    `,[
      (req.body.name||u.name).trim(),
      (req.body.className||"").trim(),
      (req.body.phone||"").trim(),
      u.id
    ]);

    res.json({user:publicUser(await getUser(u.id))});
  } catch(e){next(e);}
});

app.post(
  "/api/profile/photo",
  requireLogin,
  photoUpload.single("photo"),
  async(req,res,next)=>{
    try {
      if(!req.file)
        return res.status(400).json({
          error:"Please choose an image."
        });

      await pool.query(
        "UPDATE users SET photo=$1 WHERE id=$2",
        ["/uploads/"+req.file.filename,req.currentUser.id]
      );

      res.json({
        user:publicUser(await getUser(req.currentUser.id))
      });
    } catch(e){next(e);}
  }
);

/* ANNOUNCEMENTS */

app.get("/api/announcements",async(req,res,next)=>{
  try {
    const r=await pool.query(
      "SELECT * FROM announcements ORDER BY created_at DESC"
    );

    res.json(r.rows.map(x=>({
      id:x.id,
      title:x.title,
      body:x.body,
      author:x.author,
      createdAt:x.created_at
    })));
  } catch(e){next(e);}
});

app.post("/api/announcements",requireAdmin,async(req,res,next)=>{
  try {
    if(!req.body.title||!req.body.body)
      return res.status(400).json({
        error:"Title and announcement text are required."
      });

    const item={
      id:id(),
      title:req.body.title.trim(),
      body:req.body.body.trim(),
      author:req.currentUser.name,
      createdAt:now()
    };

    await pool.query(`
      INSERT INTO announcements(id,title,body,author,created_at)
      VALUES($1,$2,$3,$4,$5)
    `,[item.id,item.title,item.body,item.author,item.createdAt]);

    res.json(item);
  } catch(e){next(e);}
});

app.delete("/api/announcements/:id",requireAdmin,async(req,res,next)=>{
  try {
    await pool.query(
      "DELETE FROM announcements WHERE id=$1",
      [req.params.id]
    );

    res.json({ok:true});
  } catch(e){next(e);}
});

/* LIBRARY */

app.get("/api/library",async(req,res,next)=>{
  try {
    const r=await pool.query(
      "SELECT * FROM library ORDER BY created_at DESC"
    );

    res.json(r.rows.map(x=>({
      id:x.id,
      title:x.title,
      description:x.description,
      category:x.category,
      filename:x.filename,
      url:x.url,
      mimeType:x.mime_type,
      size:Number(x.size||0),
      createdAt:x.created_at
    })));
  } catch(e){next(e);}
});

app.post(
  "/api/library/upload",
  requireAdmin,
  libraryUpload.single("file"),
  async(req,res,next)=>{
    try {
      if(!req.file)
        return res.status(400).json({
          error:"Please choose a file."
        });

      const item={
        id:id(),
        title:(req.body.title||req.file.originalname).trim(),
        description:(req.body.description||"").trim(),
        category:(req.body.category||"General").trim(),
        filename:req.file.originalname,
        url:"/library/"+req.file.filename,
        mimeType:req.file.mimetype,
        size:req.file.size,
        createdAt:now()
      };

      await pool.query(`
        INSERT INTO library
        (id,title,description,category,filename,url,mime_type,size,created_at)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)
      `,[
        item.id,item.title,item.description,item.category,
        item.filename,item.url,item.mimeType,item.size,item.createdAt
      ]);

      res.json(item);
    } catch(e){next(e);}
  }
);

app.post("/api/library",requireAdmin,async(req,res,next)=>{
  try {
    if(!req.body.title)
      return res.status(400).json({error:"Title is required."});

    const item={
      id:id(),
      title:req.body.title.trim(),
      description:(req.body.description||"").trim(),
      category:(req.body.category||"General").trim(),
      url:(req.body.url||"").trim(),
      filename:"",
      mimeType:"",
      size:0,
      createdAt:now()
    };

    await pool.query(`
      INSERT INTO library
      (id,title,description,category,filename,url,mime_type,size,created_at)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)
    `,[
      item.id,item.title,item.description,item.category,
      "",item.url,"",0,item.createdAt
    ]);

    res.json(item);
  } catch(e){next(e);}
});

app.delete("/api/library/:id",requireAdmin,async(req,res,next)=>{
  try {
    const r=await pool.query(
      "SELECT url FROM library WHERE id=$1",
      [req.params.id]
    );

    const item=r.rows[0];

    if(item?.url?.startsWith("/library/")){
      const file=path.join(
        LIBRARY,
        path.basename(item.url)
      );

      if(fs.existsSync(file)) fs.unlinkSync(file);
    }

    await pool.query(
      "DELETE FROM library WHERE id=$1",
      [req.params.id]
    );

    res.json({ok:true});
  } catch(e){next(e);}
});

/* CONTACT */

app.post("/api/messages",requireLogin,async(req,res,next)=>{
  try {
    const {name,email,subject,message}=req.body;

    if(!name||!email||!message)
      return res.status(400).json({
        error:"Name, email and message are required."
      });

    await pool.query(`
      INSERT INTO messages
      (id,name,email,subject,message,status,created_at)
      VALUES($1,$2,$3,$4,$5,$6,$7)
    `,[
      id(),name,email,subject||"",message,
      "unread",now()
    ]);

    res.json({ok:true});
  } catch(e){next(e);}
});

app.get("/api/messages",requireAdmin,async(req,res,next)=>{
  try {
    const r=await pool.query(
      "SELECT * FROM messages ORDER BY created_at DESC"
    );

    res.json(r.rows.map(x=>({
      id:x.id,
      name:x.name,
      email:x.email,
      subject:x.subject,
      message:x.message,
      status:x.status,
      createdAt:x.created_at
    })));
  } catch(e){next(e);}
});

app.patch("/api/messages/:id",requireAdmin,async(req,res,next)=>{
  try {
    const r=await pool.query(
      "UPDATE messages SET status='read' WHERE id=$1 RETURNING *",
      [req.params.id]
    );

    if(!r.rowCount)
      return res.status(404).json({
        error:"Message not found."
      });

    res.json(r.rows[0]);
  } catch(e){next(e);}
});

app.delete("/api/messages/:id",requireAdmin,async(req,res,next)=>{
  try {
    await pool.query(
      "DELETE FROM messages WHERE id=$1",
      [req.params.id]
    );

    res.json({ok:true});
  } catch(e){next(e);}
});

/* ADMIN USERS */

app.get("/api/admin/users",requireAdmin,async(req,res,next)=>{
  try {
    const r=await pool.query(
      "SELECT * FROM users ORDER BY created_at DESC"
    );

    res.json(r.rows.map(publicUser));
  } catch(e){next(e);}
});

app.patch("/api/admin/users/:id",requireAdmin,async(req,res,next)=>{
  try {
    const r=await pool.query(
      "SELECT * FROM users WHERE id=$1",
      [req.params.id]
    );

    const u=r.rows[0];

    if(!u)
      return res.status(404).json({error:"User not found."});

    if(
      u.email==="admin@gmssjikwoyi.edu.ng" &&
      req.body.role==="member"
    )
      return res.status(400).json({
        error:"Main administrator cannot be demoted."
      });

    if(["admin","member"].includes(req.body.role)){
      await pool.query(
        "UPDATE users SET role=$1 WHERE id=$2",
        [req.body.role,u.id]
      );
    }

    if(["active","disabled"].includes(req.body.status)){
      await pool.query(
        "UPDATE users SET status=$1 WHERE id=$2",
        [req.body.status,u.id]
      );
    }

    res.json(publicUser(await getUser(u.id)));
  } catch(e){next(e);}
});

app.delete("/api/admin/users/:id",requireAdmin,async(req,res,next)=>{
  try {
    const r=await pool.query(
      "SELECT * FROM users WHERE id=$1",
      [req.params.id]
    );

    const u=r.rows[0];

    if(!u)
      return res.status(404).json({error:"User not found."});

    if(u.email==="admin@gmssjikwoyi.edu.ng")
      return res.status(400).json({
        error:"Main administrator cannot be deleted."
      });

    await pool.query(
      "DELETE FROM users WHERE id=$1",
      [req.params.id]
    );

    res.json({ok:true});
  } catch(e){next(e);}
});

app.get("/api/admin/stats",requireAdmin,async(req,res,next)=>{
  try {
    const r=await pool.query(`
      SELECT
      (SELECT COUNT(*) FROM users) AS users,
      (SELECT COUNT(*) FROM users WHERE role='member') AS members,
      (SELECT COUNT(*) FROM users WHERE role='admin') AS admins,
      (SELECT COUNT(*) FROM announcements) AS announcements,
      (SELECT COUNT(*) FROM library) AS library,
      (SELECT COUNT(*) FROM messages) AS messages,
      (SELECT COUNT(*) FROM messages WHERE status='unread') AS unread
    `);

    const x=r.rows[0];

    res.json({
      users:Number(x.users),
      members:Number(x.members),
      admins:Number(x.admins),
      announcements:Number(x.announcements),
      library:Number(x.library),
      messages:Number(x.messages),
      unreadMessages:Number(x.unread)
    });
  } catch(e){next(e);}
});

app.get("/{*splat}",(req,res)=>{
  res.sendFile(path.join(ROOT,"public","index.html"));
});

app.use((err,req,res,next)=>{
  console.error(err);
  res.status(500).json({
    error:err.message||"Server error."
  });
});

initDB()
  .then(()=>{
    app.listen(PORT,()=>{
      console.log("GMSS Jikwoyi Portal running on port "+PORT);
    });
  })
  .catch(err=>{
    console.error("DATABASE STARTUP ERROR:",err);
    process.exit(1);
  });
