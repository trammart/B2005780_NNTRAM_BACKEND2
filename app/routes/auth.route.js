const express = require("express");
const users = require("../controllers/auth.controller");

const router = express.Router();

router.route("/login").post(users.login);

router.route("/register").post(users.register);

router.route("/findByEmail/:id").get(users.findByEmail);

router.route("/:id").get(users.findById);

router.route("/:id").put(users.changePassword);

module.exports = router;
