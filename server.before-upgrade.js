const express=require("express");
const session=require("express-session");
const bcrypt=require("bcryptjs");
const multer=require("multer");
const fs=require("fs");
const path=require("path");
const crypto=require("crypto");

const app=express(), PORT=process.env.PORT||3000, ROOT=__dirname;
const DATA=path.join(ROOT,"data"), UP=path.join(ROOT,"public","uploads"), DB=path.join(DATA,"db.json");
[DATA,UP].forEach(x=>fs.mkdirSync(x,{recursive:true}));
const fresh=()=>({users:[],announcements:[],library:[],messages:[]});
function load(){if(!fs.existsSync(DB))return fresh();try{return JSON.parse(fs.readFileSync(DB,"utf8"))}catch{return fresh()}}
let db=load();
function save(){const t=DB+".tmp";fs.writeFileSync(t,JSON.stringify(db,null,2));fs.renameSync(t,DB)}
const id=()=>crypto.randomUUID(), now=()=>new Date().toISOString();
const user=u=>u&&({id:u.id,name:u.name,email:u.email,className:u.className||"",phone:u.phone||"",role:u.role,status:u.status,photo:u.photo||"",createdAt:u.createdAt});
const getUser=i=>db.users.find(x=>x.id===i);
function login(req,res,next){if(!req.session.userId)return res.status(401).json({error:"Please log in first."});next()}
function admin(req,res,next){const u=getUser(req.session.userId);if(!u||u.role!=="admin"||u.status!=="active")return res.status(403).json({error:"Administrator access required."});next()}

if(!db.users.some(x=>x.email==="admin@gmssjikwoyi.edu.ng")){
 db.users.push({id:id(),name:"GMSS Jikwoyi Administrator",email:"admin@gmssjikwoyi.edu.ng",password:bcrypt.hashSync("admin123",12),className:"Administration",phone:"",role:"admin",status:"active",photo:"",createdAt:now()});save();
}
app.use(express.json({limit:"2mb"}));app.use(express.urlencoded({extended:true}));
app.use(session({secret:process.env.SESSION_SECRET||"GMSS-JIKWOYI-PORTAL-SECRET",resave:false,saveUninitialized:false,cookie:{httpOnly:true,sameSite:"lax",maxAge:604800000}}));
app.use("/uploads",express.static(UP));app.use(express.static(path.join(ROOT,"public")));

const storage=multer.diskStorage({destination:UP,filename:(req,f,cb)=>cb(null,req.session.userId+"-"+Date.now()+path.extname(f.originalname).toLowerCase())});
const upload=multer({storage,limits:{fileSize:3*1024*1024},fileFilter:(r,f,cb)=>cb(["image/jpeg","image/png","image/webp"].includes(f.mimetype)?null:new Error("Only JPG, PNG or WEBP images are allowed."))});

app.get("/api/me",(req,res)=>res.json({user:user(getUser(req.session.userId))}));
app.post("/api/register",async(req,res)=>{
 const {name,email,password,className,phone}=req.body;if(!name||!email||!password)return res.status(400).json({error:"Name, email and password are required."});
 if(password.length<6)return res.status(400).json({error:"Password must be at least 6 characters."});
 const e=email.trim().toLowerCase();if(db.users.some(x=>x.email===e))return res.status(409).json({error:"Email already registered."});
 const u={id:id(),name:name.trim(),email:e,password:await bcrypt.hash(password,12),className:(className||"").trim(),phone:(phone||"").trim(),role:"member",status:"active",photo:"",createdAt:now()};
 db.users.push(u);save();req.session.userId=u.id;res.json({user:user(u)});
});
app.post("/api/login",async(req,res)=>{
 const e=(req.body.email||"").trim().toLowerCase(),p=req.body.password||"",u=db.users.find(x=>x.email===e);
 if(!u||!(await bcrypt.compare(p,u.password)))return res.status(401).json({error:"Invalid email or password."});
 if(u.status!=="active")return res.status(403).json({error:"Account disabled by administrator."});
 req.session.userId=u.id;res.json({user:user(u)});
});
app.post("/api/logout",(req,res)=>req.session.destroy(()=>res.json({ok:true})));

app.put("/api/profile",login,(req,res)=>{const u=getUser(req.session.userId);u.name=(req.body.name||u.name).trim();u.className=(req.body.className||"").trim();u.phone=(req.body.phone||"").trim();save();res.json({user:user(u)})});
app.post("/api/profile/photo",login,upload.single("photo"),(req,res)=>{if(!req.file)return res.status(400).json({error:"Choose an image."});const u=getUser(req.session.userId);u.photo="/uploads/"+req.file.filename;save();res.json({user:user(u)})});

app.get("/api/announcements",(req,res)=>res.json([...db.announcements].sort((a,b)=>b.createdAt.localeCompare(a.createdAt))));
app.post("/api/announcements",admin,(req,res)=>{if(!req.body.title||!req.body.body)return res.status(400).json({error:"Title and text are required."});const x={id:id(),title:req.body.title.trim(),body:req.body.body.trim(),author:getUser(req.session.userId).name,createdAt:now()};db.announcements.push(x);save();res.json(x)});
app.delete("/api/announcements/:id",admin,(req,res)=>{db.announcements=db.announcements.filter(x=>x.id!==req.params.id);save();res.json({ok:true})});

app.get("/api/library",(req,res)=>res.json([...db.library].sort((a,b)=>b.createdAt.localeCompare(a.createdAt))));
app.post("/api/library",admin,(req,res)=>{if(!req.body.title)return res.status(400).json({error:"Title is required."});const x={id:id(),title:req.body.title.trim(),description:(req.body.description||"").trim(),url:(req.body.url||"").trim(),category:(req.body.category||"General").trim(),createdAt:now()};db.library.push(x);save();res.json(x)});
app.delete("/api/library/:id",admin,(req,res)=>{db.library=db.library.filter(x=>x.id!==req.params.id);save();res.json({ok:true})});

app.post("/api/messages",(req,res)=>{const {name,email,subject,message}=req.body;if(!name||!email||!message)return res.status(400).json({error:"Name, email and message are required."});db.messages.push({id:id(),name,email,subject:subject||"",message,status:"unread",createdAt:now()});save();res.json({ok:true})});
app.get("/api/messages",admin,(req,res)=>res.json([...db.messages].sort((a,b)=>b.createdAt.localeCompare(a.createdAt))));
app.patch("/api/messages/:id",admin,(req,res)=>{const x=db.messages.find(x=>x.id===req.params.id);if(!x)return res.status(404).json({error:"Not found"});x.status="read";save();res.json(x)});
app.delete("/api/messages/:id",admin,(req,res)=>{db.messages=db.messages.filter(x=>x.id!==req.params.id);save();res.json({ok:true})});

app.get("/api/admin/users",admin,(req,res)=>res.json(db.users.map(user).sort((a,b)=>b.createdAt.localeCompare(a.createdAt))));
app.patch("/api/admin/users/:id",admin,(req,res)=>{const u=getUser(req.params.id);if(!u)return res.status(404).json({error:"User not found"});if(u.email==="admin@gmssjikwoyi.edu.ng"&&req.body.role==="member")return res.status(400).json({error:"Main admin cannot be demoted."});if(["admin","member"].includes(req.body.role))u.role=req.body.role;if(["active","disabled"].includes(req.body.status))u.status=req.body.status;save();res.json(user(u))});
app.delete("/api/admin/users/:id",admin,(req,res)=>{const u=getUser(req.params.id);if(!u)return res.status(404).json({error:"User not found"});if(u.email==="admin@gmssjikwoyi.edu.ng")return res.status(400).json({error:"Main admin cannot be deleted."});db.users=db.users.filter(x=>x.id!==req.params.id);save();res.json({ok:true})});
app.get("/api/admin/stats",admin,(req,res)=>res.json({users:db.users.length,members:db.users.filter(x=>x.role==="member").length,admins:db.users.filter(x=>x.role==="admin").length,announcements:db.announcements.length,library:db.library.length,unreadMessages:db.messages.filter(x=>x.status==="unread").length}));

app.get("/{*splat}",(req,res)=>res.sendFile(path.join(ROOT,"public","index.html")));
app.use((err,req,res,next)=>res.status(400).json({error:err.message||"Request failed"}));
app.listen(PORT,()=>console.log("GMSS Jikwoyi Portal running at http://localhost:"+PORT));
