//jshint esversion:6

const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require('express-session');
const MemoryStore = require('memorystore')(session);
const passport = require("passport");
const passportLocalMongoose = require('passport-local-mongoose');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
require('dotenv').config()


const app = express();

app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

// app.use(session({
//     secret: process.env.SECRET,
//     resave: false,
//     saveUninitialized: true
// }));

app.use(session({
    cookie: { maxAge: 86400000, secure: false },
    store: new MemoryStore({
      checkPeriod: 86400000 // prune expired entries every 24h
    }),
    resave: false,
    saveUninitialized: true,
    secret: process.env.SECRET || 'defaultSecret'
}))

app.use(passport.initialize());
app.use(passport.session());

// mongoose.connect("mongodb://localhost:27017/userDB");
mongoose.connect(process.env.MONGODB_URL);

// mongoose.set("useCreateIndex", true);

const userSchema = new mongoose.Schema({
    name: String,
    email: { type: String, unique: true, sparse: true },    
    password: String,
    googleId: String,
    facebookId: String,
    provider: String,
    secret: String
});

userSchema.plugin(passportLocalMongoose,{
    usernameUnique: false 
});

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser((user, done) => {
    done(null, user);
  });
  passport.deserializeUser((id, done) => {
    done(null, id);
  });

////////////////////////////////////////////////// GOOGLE SETUP ///////////////////////////////////////

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRETS,
    callbackURL: process.env.GOOGLE_CALLBACK_URL,
  },async function(accessToken, refreshToken, profile, done) {
    try {

    // console.log(profile)
    const currentUser = await User.findOne({googleId: profile.id})

    if(currentUser) {

        return done(null, currentUser);

    } else {

        const newUser = await User.create({
            googleId: profile.id,
            // username: profile.id,
            name: profile.displayName,
            email: profile.emails[0].value,
            provider: profile.provider
        });

        return done(null, newUser);

    }
    } catch (error) {
        console.log(error.message)
    }
    
  }
));

////////////////////////////////////////////////// FACEBOOK SETUP ///////////////////////////////////////

passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_APP_ID,
    clientSecret: process.env.FACEBOOK_APP_SECRET,
    callbackURL: process.env.FACEBOOK_CALLBACK_URL
  },async function(accessToken, refreshToken, profile, done) {
    try {

    // console.log(profile)

    const currentUser = await User.findOne({facebookId: profile.id})

    if(currentUser) {

        return done(null, currentUser);

    } else {

        const newUser = await User.create({
            facebookId: profile.id,
            // username: profile.id,
            name: profile.displayName,
            // email: profile.emails[0].value,
            provider: profile.provider
        });

        return done(null, newUser);

    }
    } catch (error) {
        console.log(error.message)
    }
    
  }
));

////////////////////////////////////////////////// HOME ///////////////////////////////////////

app.get("/", (req, res) => {
    res.render("home");
});

////////////////////////////////////////////////// SECRETS ///////////////////////////////////////

app.get("/secrets", async (req, res) => {
        try {
            const foundUser = await User.find({"secret": {$ne: null}});
            if(foundUser) {
                res.render("secrets", {usersWithSecrets: foundUser});
            }
        } catch (error) {
            console.log(error.message)
        }
})

////////////////////////////////////////////////// SUBMIT ///////////////////////////////////////

app.route("/submit")
    .get((req, res) => {
        if(req.isAuthenticated()) {
            res.render("submit")
            // console.log("At submit" + req.user.id); 
        } else {
            res.redirect("/login")
        }
        })

    .post(async (req, res) => {
        const submittedSecret = req.body.secret;
        // console.log(req.user)
        
            try {
                const foundUser = await User.findById(req.user._id);
                if(foundUser) {
                    foundUser.secret = submittedSecret;
                    await foundUser.save().then(
                        res.redirect("/secrets")
                    )
                } else {
                    console.log(error)
                }
            } catch (error) {
                console.log(error.message)
            }
        
        // console.log(req.user)
    })

////////////////////////////////////////////////// LOGIN OUT ///////////////////////////////////////

app.get("/logout", (req, res) => {
    req.logout(function(err) {
        if(err) {
            console.log(err)
        } else {
            res.redirect("/")
        }
    })
})

////////////////////////////////////////////////// GOOGLE LOGIN ///////////////////////////////////////

app.get('/auth/google',
    passport.authenticate('google', { scope: ['profile', "email"] })
);

app.get('/auth/google/secrets', 
    passport.authenticate('google', { failureRedirect: '/login' }),
    function(req, res) {
      // Successful authentication, redirect secrets.
      console.log(req.user._jsub); 
      res.redirect('/secrets');
    });

////////////////////////////////////////////////// FACEBOOK LOGIN ///////////////////////////////////////

app.get('/auth/facebook',
    passport.authenticate('facebook', { scope: ["email"] })
);
  
app.get('/auth/facebook/secrets',
    passport.authenticate('facebook', { failureRedirect: '/login' }),
    function(req, res) {
      // Successful authentication, redirect home.
      res.redirect('/secrets');
    });

////////////////////////////////////////////////// LOGIN ///////////////////////////////////////

app.route("/login")

    .get((req, res) => {
        res.render("login");
    })

    .post((req, res) => {
        
        // console.log(req.body)

        const user = new User ({
            username: req.body.username,
            password: req.body.password
        });

        req.logIn(user, function(err, user) {
            if (err) {
                console.log(err)
            } else {
                passport.authenticate("local")(req, res, function() {
                    res.redirect("/secrets")
                })
            }
        })

    })

////////////////////////////////////////////////// REGISTER ///////////////////////////////////////

app.route("/register")

    .get((req, res) => {
        res.render("register");
    })

    .post((req, res) => {

        User.register({username: req.body.username}, req.body.password, function(err, user) {
            if(err){
                console.log(err)
                res.redirect("/register")
            } else {
                
                passport.authenticate('local')(req, res, function () {
                    res.redirect('/secrets')
                });
            }
        })


    });

app.listen(process.env.PORT || 3000, () => {
    console.log("Server started on port 3000");
});
