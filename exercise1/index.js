const express = require("express");
const passport = require("passport");
const { BasicStrategy } = require("passport-http");
const app = express();
const port = 3000;

// Middleware for HTTP Basic Authentication
// const httpBasicAuth = (req, res, next) => {
//   const auth = req.headers["authorization"];
//   console.log("Authorization Header: ", auth);
//   if (!auth) {
//     res.status(401).send("No Authorization header");
//     return;
//   }

//   // Verify auth credentials
//   const base64Credentials = auth.split(" ")[1];
//   console.log("Base64Credentials: ", base64Credentials);
//   const credentials = Buffer.from(base64Credentials, "base64").toString(
//     "ascii"
//     );
//     console.log("Credentials: ", credentials);
//     console.log("Credentials split: ", credentials.split(":"));
//     console.log("Username: ", credentials.split(":")[0]);
//     console.log("Password: ", credentials.split(":")[1]);
//   const [username, password] = credentials.split(":");
//   if (username === "admin" && password === "admin") {
//     next();
//   } else {
//     res.status(403).send("You are not authorized");
//   }
// };

// Load credentials from environment variables or use defaults
const USERNAME = process.env.USERNAME || 'admin';
const PASSWORD = process.env.PASSWORD || 'admin';

passport.use(new BasicStrategy(
    function(username, password, done) {
    if (username === USERNAME && password === PASSWORD) {
        return done(null, { username }); // Successful authentication
    } else {
        return done(null, false); // Authentication failed
    }
}));

const authenticate = passport.authenticate('basic', { session: false });

// Private route (Authentication required)
app.get("/", authenticate, (req, res) => {
  res.send("Hello, Loved ones! :)");
});

// Public route (No authentication required)
app.get("/public", (req, res) => {
  res.send("Welcome to the public route!");
});

// Another private route (Authentication required)
app.get("/anotherhttpbasic", authenticate, (req, res) => {
  res.send("Welcome to another http basic route!");
});

app.get("/posts", (req, res) => {
  res.send("Welcome to the posts route!");
});

app.listen(port, () => {
  console.log(`Example app listening at http://localhost:${port}`);
});
