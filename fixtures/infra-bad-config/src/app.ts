import express from "express";

const app = express();
const databaseUrl = process.env.DATABASE_URL;
const billingToken = process.env.BILLING_TOKEN;

app.get("/healthz", (_req, res) => res.send("ok"));
app.post("/admin/reindex", (_req, res) => res.json({ ok: Boolean(databaseUrl && billingToken) }));
app.listen(8080);
