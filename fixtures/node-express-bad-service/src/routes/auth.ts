import { Router } from "express";
import { saveLoginAttempt } from "../db/repository";

const router = Router();

router.post("/login", async (req, res) => {
  saveLoginAttempt(req.body.email);
  const password: any = req.body.password;
  console.log("login attempt", req.body.email);
  res.json({ token: String(password) });
});

export { router };
