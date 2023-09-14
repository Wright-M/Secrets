 //jshint esversion:6
require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const path = require("path");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport")
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const GitHubStrategy = require("passport-github").Strategy;
const findOrCreate = require("mongoose-findorcreate");



const app = express();
const port = process.env.PORT || 3000;

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
  extended: true
}));

app.use(session({
  secret: "Our little secret.",
  resave: false,
  saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());


mongoose.connect("mongodb+srv://"+process.env.CLOUD_PASSWORD+"@cluster-secrets.24f8ag5.mongodb.net/userDB", {useNewUrlParser: true});

const userSchema = new mongoose.Schema  ({
  email: String,
  password: String,
  googleId: String,
  githubID: String,
  secret: Array
  
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate)

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function(user, cb) {
  process.nextTick(function() {
    return cb(null, {
      id: user.id,
      username: user.username,
      picture: user.picture
    });
  });
});

passport.deserializeUser(function(user, cb) {
  process.nextTick(function() {
    return cb(null, user);
  });
});

passport.use(new GoogleStrategy({
  clientID: process.env.CLIENT_ID,
  clientSecret: process.env.CLIENT_SECRET,
  callbackURL: "http://localhost:3000/auth/google/secrets",
  userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
},
function(accessToken, refreshToken, profile, cb) {
  console.log(profile);
  User.findOrCreate({ googleId: profile.id }, function (err, user) {
    return cb(err, user);
  });
}
));

passport.use(new GitHubStrategy({
  clientID: process.env.GITHUB_CLIENT_ID,
  clientSecret: process.env.GITHUB_CLIENT_SECRET,
  callbackURL: "http://localhost:3000/auth/github/secrets"
},
function(accessToken, refreshToken, profile, cb) {
  console.log(profile)
  User.findOrCreate({ githubID: profile.id, username:profile.username},
    function(err, user){
      return cb(err, user);
    });
  }
));

app.get("/", (req, res) => {
  res.render("home");
});

app.get("/auth/google", 
  passport.authenticate("google", { scope: ["profile"] })
);

app.get("/auth/google/secrets", 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect("/secrets");
  });

app.get("/auth/github",
  passport.authenticate("github")
);

app.get("/auth/github/secrets",
  passport.authenticate("github", {failureRedirect: '/login'}),
  function(req, res){
    res.redirect("/secrets");
});

app.get("/login", (req, res) => {
  res.render("login");
});

app.get("/register", function(req, res){
  res.render("register");
});

app.get("/secrets", async (req, res) => {
  if (req.isAuthenticated()){
    try {
      const result = await User.find({"secret": {$ne: null}});
      res.render("secrets", {users: result});
    } catch (error) {
      console.log(error);
    }
  }
});
  

app.get("/submit", function(req, res){
  if (req.isAuthenticated({failureRedirect: "/login" })){
    res.render("submit");
  } else {
    res.redirect("/login");
  }
});

app.post("/submit", async (req, res) => {
  try {
    const result = await User.findById(req.user.id);
    result.secret.push(req.body.secret);
    result.save();
    res.redirect("/secrets");
  } catch (error) {
    console.log(error);
  }
});

app.get('/logout', function(req, res){
  req.logout(function(err) {
    if (err) { 
      console.log(err);
    }else{
      console.log("logged out");
    }
  });
  res.redirect('/');
});

app.post("/register", function(req, res){
  User.register({username: req.body.username}, req.body.password, function(err, user){
    if (err){
      console.log(err);
      res.redirect("/register");
    } else {
      passport.authenticate("local")(req, res, function(){
        res.redirect("/secrets");
      });
    }
  });
});

app.post("/login", function(req, res){
  const user = new User({
    username: req.body.username,
    password: req.body.password
  });
  req.login(user, function(err){
    if (err){
      console.log(err);
    } else {
      passport.authenticate("local")(req, res, function(){
        res.redirect("/secrets");
      });
    }
  });
});


app.listen(port, () => console.log('server started on port ${port}!'));

