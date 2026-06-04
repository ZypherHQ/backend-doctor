import express from "express";

const router = express.Router();

function auth(_req: express.Request, _res: express.Response, next: express.NextFunction) {
  next();
}

function validate(_req: express.Request, _res: express.Response, next: express.NextFunction) {
  next();
}

router.post("/orders", auth, validate, async (req, res, next) => {
  try {
    res.json({ id: req.body.id });
  } catch (error) {
    next(error);
  }
});

export { router };
