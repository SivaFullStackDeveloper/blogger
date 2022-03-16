const jwt = require("jsonwebtoken");
const dotenv = require("dotenv");
dotenv.config();

let checkToken = (req, res, next) => {
  let token = req.headers["authorization"];
  console.log(token);
  token = token.slice(7, token.length);
  if (token) {
    jwt.verify(token, process.env.Token, (err, decoded) => {
      if (err) {
        return res.json({
          status: false,
          msg: "token is invalid",
        });
      } else {
        req.decoded = decoded;
        next();
      }
    });
  } else {
    return res.json({
      status: false,
      msg: "Token is not provided",
    });
  }
};


module.exports = checkToken;