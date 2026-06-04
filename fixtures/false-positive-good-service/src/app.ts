import cors from "cors";
import express, { NextFunction, Request, Response } from "express";
import rateLimit from "express-rate-limit";
import { z } from "zod";

const app = express();
const auth = (_req: Request, _res: Response, next: NextFunction) => next();
const loginLimit = rateLimit({ windowMs: 60_000, limit: 10 });
const userParams = z.object({ id: z.string().uuid() });

app.use(cors({ origin: "https://app.example.test" }));
app.use(express.json({ limit: "1mb" }));

app.post("/login", loginLimit, async (_req, res, next) => {
  try {
    res.status(204).send();
  } catch (error) {
    next(error);
  }
});

app.get("/users/:id", auth, async (req, res, next) => {
  try {
    const params = userParams.parse(req.params);
    const rows = await db.query("SELECT id FROM users WHERE id = ?", [params.id]);
    res.json({ rows });
  } catch (error) {
    next(error);
  }
});

app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
  res.status(500).json({ error: err.message });
});

export const server = app.listen(3000);
server.setTimeout(10_000);

const db = {
  async query(sql: string, values: string[]) {
    return { sql, values };
  }
};
