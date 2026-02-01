import express from "express";
import cors from "cors";
import swaggerUi from "swagger-ui-express";
import YAML from "yaml";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { Pool } from "pg";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import multer from "multer";
import { v4 as uuidv4 } from "uuid";
import dotenv from 'dotenv';

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

const filename = fileURLToPath(import.meta.url);
const dirname = path.dirname(filename);

const swaggerPath = path.join(dirname, "../docs/openapi.yaml");
const swaggerFile = fs.readFileSync(swaggerPath, "utf8");
const swaggerDoc = YAML.parse(swaggerFile);
app.use("/swagger", swaggerUi.serve, swaggerUi.setup(swaggerDoc));

const PORT = process.env.PORT;
const JWT_SECRET = process.env.JWT_SECRET;

//Database

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

//Middlewares

const authMiddleware = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ message: "No token" });

  const token = authHeader.split(" ")[1];
  try {
    const payload = jwt.verify(token, JWT_SECRET);

    req.user = payload;
    next();
  } catch (err) {
    res.status(401).json({ message: "Invalid token" });
  }
};

//Auth routes

app.post("/api/auth/register", async (req, res) => {
  const { name, email, password } = req.body;
  const hashed = await bcrypt.hash(password, 10);
  const id = uuidv4();

  await pool.query(
    "INSERT INTO users (id, name, email, password) VALUES ($1,$2,$3,$4)",
    [id, name, email, hashed]
  );

  const token = jwt.sign({ id, email }, JWT_SECRET);

  res.status(201).json({ user: { id, name, email, avatar: null }, token });
});

app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body;
  const result = await pool.query("SELECT * FROM users WHERE email=$1", [email]);
  const user = result.rows[0];

  if (!user) return res.status(401).json({ message: "User not found!" });

  const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET);

  res.json({ user: { id: user.id, name: user.name, email: user.email, avatar: user.avatar }, token });
});

app.get("/api/auth/me", authMiddleware, async (req, res) => {
  const result = await pool.query("SELECT id, name, email, avatar FROM users WHERE id=$1", [req.user.id]);

  res.json(result.rows[0]);
});

//Users

app.get("/api/users/:id", async (req, res) => {
  const { id } = req.params;
  const result = await pool.query(
    `SELECT u.id, u.name, u.avatar, COUNT(l.id) as "locationsCount"
     FROM users u
     LEFT JOIN locations l ON l.author_id = u.id
     WHERE u.id=$1
     GROUP BY u.id`,
    [id]
  );

  res.json(result.rows[0]);
});

app.get("/api/users/:id/locations", async (req, res) => {
  const { id } = req.params;
  const result = await pool.query(
    "SELECT id, title, region, poster, rate, 0 as reviewsCount, author_id as author FROM locations WHERE author_id=$1",
    [id]
  );

  res.json(result.rows);
});

//Locations

app.get("/api/locations", async (req, res) => {
  const { search, category, region, page = 1, limit = 10 } = req.query;
  const offset = (page - 1) * limit;
  const result = await pool.query(
    `SELECT * FROM locations
     WHERE ($1::text IS NULL OR title ILIKE '%'||$1||'%')
       AND ($2::text IS NULL OR category_id=$2)
       AND ($3::text IS NULL OR region=$3)
     LIMIT $4 OFFSET $5`,
    [search, category, region, limit, offset]
  );
  const total = await pool.query("SELECT COUNT(*) FROM locations");

  res.json({ items: result.rows, total: parseInt(total.rows[0].count) });
});

app.get("/api/locations/:id", async (req, res) => {
  const { id } = req.params;
  const result = await pool.query("SELECT * FROM locations WHERE id=$1", [id]);
  
  res.json(result.rows[0]);
});

app.post("/api/locations", authMiddleware, async (req, res) => {
  const { title, region, description, categoryId, poster, gallery } = req.body;
  const id = uuidv4();
  
  await pool.query(
    "INSERT INTO locations (id, title, region, description, category_id, poster, gallery, author_id) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
    [id, title, region, description, categoryId, poster, gallery || [], req.user.id]
  );
  
  res.status(201).json({ id });
});

app.put("/api/locations/:id", authMiddleware, async (req, res) => {
  const { id } = req.params;
  const fields = Object.keys(req.body);
  const values = Object.values(req.body);
  const setString = fields.map((f, i) => `${f}=$${i + 1}`).join(",");
  
  await pool.query(`UPDATE locations SET ${setString} WHERE id=$${fields.length + 1}`, [...values, id]);
  
  res.json({ message: "Updated!" });
});

app.delete("/api/locations/:id", authMiddleware, async (req, res) => {
  const { id } = req.params;
  
  await pool.query("DELETE FROM locations WHERE id=$1", [id]);
  
  res.status(204).send();
});

//Reviews

app.post("/api/locations/:id/reviews", authMiddleware, async (req, res) => {
  const { id } = req.params;
  const { rating, text } = req.body;
  const reviewId = uuidv4();
  
  await pool.query(
    "INSERT INTO reviews (id, location_id, author_id, rating, text, created_at) VALUES ($1,$2,$3,$4,$5,NOW())",
    [reviewId, id, req.user.id, rating, text]
  );
  
  res.status(201).json({ id: reviewId });
});

app.delete("/api/reviews/:id", authMiddleware, async (req, res) => {
  const { id } = req.params;
  
  await pool.query("DELETE FROM reviews WHERE id=$1", [id]);
  
  res.status(204).send();
});

//Categories

app.get("/api/categories", async (req, res) => {
  const result = await pool.query("SELECT id, name FROM categories");
  
  res.json(result.rows);
});

//Upload

const upload = multer({ dest: "uploads/" });

app.post("/api/upload", authMiddleware, upload.single("file"), (req, res) => {
  const url = `/uploads/${req.file.filename}`;
  
  res.json({ url });
});

//Start

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
  console.log(`Swagger: http://localhost:${PORT}/swagger`);
});
