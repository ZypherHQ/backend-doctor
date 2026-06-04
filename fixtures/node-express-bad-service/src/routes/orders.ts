import { Router } from "express";
import { exec } from "child_process";
import { db, prisma } from "../db/repository";

const router = Router();

router.get("/:id", async (req, res) => {
  const query = "select * from orders where id = '" + req.params.id + "'";
  const rows = await db.query(query);
  res.json(rows);
});

router.post("/", async (req, res) => {
  const generated = new Function("payload", "return payload.total");
  const total = generated(req.body);
  const orders = await prisma.order.findMany({});
  exec(`./ship-order ${req.body.orderId}`);
  res.json({ total, count: orders.length });
});

export { router };
