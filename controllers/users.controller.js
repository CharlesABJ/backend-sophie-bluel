const db = require("./../models");
const bcryptjs = require("bcryptjs"); // Import du module bcryptjs
const jwt = require("jsonwebtoken");
const Users = db.users;

exports.signup = async (req, res) => {
  if (!req.body.email || !req.body.password) {
    return res.status(400).send({
      message: "Must have email and password",
    });
  }
  try {
    const hash = await bcryptjs.hashSync(req.body.password, 10); // Utilisation de bcryptjs
    const user = {
      email: req.body.email,
      password: hash,
    };
    await Users.create(user);
    return res.status(201).json({ message: "User Created" });
  } catch (err) {
    return res.status(500).send({
      message: err.message,
    });
  }
};

exports.login = async (req, res) => {
  const user = await Users.findOne({ where: { email: req.body.email } });
  if (user === null) {
    return res.status(404).json({ message: "user not found" });
  } else {
    const valid = bcryptjs.compareSync(req.body.password, user.password); // Utilisation de bcryptjs
    if (!valid) {
      return res.status(401).json({ error: new Error("Not Authorized") });
    }
    return res.status(200).json({
      userId: user.id,
      token: jwt.sign({ userId: user.id }, process.env.TOKEN_SECRET, {
        expiresIn: "24h",
      }),
    });
  }
};
