const express = require("express");
const session = require("express-session");
const helmet = require("helmet");
const cors = require("cors");
const bcrypt = require("bcryptjs");

const connectSessionKnex = require("connect-session-knex");

const Users = require("./users/users-model");
const db = require("./database/dbConfig");
const server = express();
const KnexSessionStore = connectSessionKnex(session);

const sessionConfig = {
  name: "trackpad life",
  secret: "yeah right just checking",
  cookie: {
    maxAge: 1000 * 60 * 60,
    secure: false,
    httpOnly: true // browser can't access via js
  },
  resave: false,
  saveUninitialized: false,
  // where do we store our session?
  store: new KnexSessionStore({
    knex: db,
    tablename: "sessions",
    sidfieldname: "sid",
    createtable: true,
    clearInterval: 1000 * 60 * 60
  })
};

server.use(helmet());
server.use(express.json());
server.use(cors());
server.use(session(sessionConfig));

server.get("/", (req, res) => {
  res.send("It's alive!");
});

server.post("/api/register", (req, res) => {
  let user = req.body;
  // console.log("this is the user", user);

  user.password = bcrypt.hashSync(user.password, 10);

  // console.log("this is the bcrypt", user.password);
  Users.add(user)
    .then(saved => {
      req.session.user = user;
      res.status(201).json(saved);
    })
    .catch(error => {
      res.status(500).json(error);
    });
});

server.post("/api/login", (req, res) => {
  let { username, password } = req.body;

  Users.findBy({ username })
    .first()
    .then(user => {
      // console.log("db password", user.password);
      // console.log("login password", password);
      if (user && bcrypt.compareSync(password, user.password)) {
        req.session.user = user;
        res
          .status(200)
          .json({ message: `Welcome ${user.username}!, have a cookie!` });
      } else {
        res.status(401).json({ message: "Invalid Credentials" });
      }
    })
    .catch(error => {
      res.status(500).json(error);
    });
});

server.get("/api/users", restricted, (req, res) => {
  Users.find()
    .then(users => res.status(200).json(users))
    .catch(err => res.send(err));
});

server.get("/logout", (req, res) => {
  if (req.session) {
    req.session.destroy(err => {
      if (err) {
        res.json({
          message: "you can checkout but you can't leave"
        });
      } else {
        res.end();
      }
    });
  }
});

function restricted(req, res, next) {
  // the password should not belong in the headers
  // const { username, password } = req.headers;

  // if (username && password) {
  //   Users.findBy({ username })
  //     .first()
  //     .then(user => {
  //       if (user && bcrypt.compareSync(password, user.password)) {
  //         next();
  //       } else {
  //         res.status(401).json({ message: "invalid credentials" });
  //       }
  //     })
  //     .catch(err => {
  //       res.status(500).json({ message: "unexpected error" });
  //     });
  // } else {
  //   res.status(400).json({
  //     message: "please provide username and password"
  //   });
  // }

  if (req.session && req.session.user) {
    next();
  } else {
    res.status(401).json({ message: "invalid Credentials" });
  }
}

const port = 4000;
server.listen(port, console.log(`server start at ${port}`));
