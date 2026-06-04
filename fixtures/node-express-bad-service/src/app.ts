import express from "express";
import cors from "cors";
import axios from "axios";
import { router as authRouter } from "./routes/auth";
import { router as ordersRouter } from "./routes/orders";

const app = express();

app.use(cors());
app.use(express.json());
app.use("/auth", authRouter);
app.use("/orders", ordersRouter);

app.get("/admin/reports", async (req, res) => {
  console.log("admin report requested");
  await axios.get("https://reports.internal/status");
  res.json({ ok: true, filter: req.query.filter });
});

app.listen(3000);

export { app };
