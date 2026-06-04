import express from "express";

const app = express();
const token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJiYWNrZW5kLWRvY3RvciJ9.signature123456";

app.get("/debug", (req, res) => {
  console.log("Authorization", req.headers.authorization);
  console.log("cookie", req.headers.cookie);
  res.json({ token });
});
