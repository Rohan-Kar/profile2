const express = require('express');
const mongoose = require('mongoose');
var serveStatic = require('serve-static');
var path = require('path') ;

const router = express.Router();
const user = require('../model/user');
const ObjectID = require('mongodb').ObjectID;
const bcryptjs = require('bcryptjs');
const passport = require('passport');
require('./passportLocal')(passport);
require('./googleAuth')(passport);

function checkAuth(req, res, next) {
    if (req.isAuthenticated()) {
        res.set('Cache-Control', 'no-cache, private, no-store, must-revalidate, post-check=0, pre-check=0');
        next();
    } else {
        res.redirect('/');
    }
}

router.get('/', (req, res) => {
    if (req.isAuthenticated()) {
        res.render("index", { logged: true });
    } else {
        res.render("index", { logged: false });
    }
});

router.get('/login', (req, res) => {
    res.render("login", { csrfToken: req.csrfToken() });
});

router.get('/signup', (req, res) => {
    res.render("signup", { csrfToken: req.csrfToken() });
});

router.post('/signup', (req, res) => {
    // get all the values 
    const { email, username, password, confirmpassword } = req.body;
    // check if the are empty 
    if (!email || !username || !password || !confirmpassword) {
        res.render("signup", { err: "All Fields Required !", csrfToken: req.csrfToken() });
    } else if (password != confirmpassword) {
        res.render("signup", { err: "Password Don't Match !", csrfToken: req.csrfToken() });
    } else {

        // validate email and username and password 
        // skipping validation
        // check if a user exists
        user.findOne({ $or: [{ email: email }, { username: username }] }, function (err, data) {
            if (err) throw err;
            if (data) {
                res.render("signup", { err: "User Exists, Try Logging In !", csrfToken: req.csrfToken() });
            } else {
                // generate a salt
                bcryptjs.genSalt(12, (err, salt) => {
                    if (err) throw err;
                    // hash the password
                    bcryptjs.hash(password, salt, (err, hash) => {
                        if (err) throw err;
                        // save user in db
                        user({
                            username: username,
                            email: email,
                            password: hash,
                            googleId: null,
                            provider: 'email',
                            hash:'',
                        }).save((err, data) => {
                            if (err) throw err;
                            // login the user
                            // use req.login
                            // redirect , if you don't want to login
                            res.redirect('/login');
                        });
                    })
                });
            }
        });
    }
});

router.post('/login', (req, res, next) => {
    passport.authenticate('local', {
        failureRedirect: '/login',
        successRedirect: '/profile',
        failureFlash: true,
    })(req, res, next);
});

router.get('/logout', (req, res) => {
    req.logout();
    req.session.destroy(function (err) {
        res.redirect('/');
    });
});
router.use(serveStatic(path.join(__dirname, 'views'))) 

router.get('/google', passport.authenticate('google', { scope: ['profile', 'email',] }));

router.get('/google/callback', passport.authenticate('google', { failureRedirect: '/login' }), (req, res) => {
    res.redirect('/profile');
});

router.get('/profile', checkAuth, (req, res) => {
     
    //res.render('profile', { username: req.user.username, email:req.user.email, _id:req.user._id , hash:req.user.hash});
    res.render('NewDashbord', { username: req.user.username, email:req.user.email, _id:req.user._id , hash:req.user.hash});
   
});
//router.post('/update1:username');
    router.post('/update1',async (req,res)=>{
        console.log(req.body.name,req.body.hash)
    try{
            const filter = { "username":req.body.username };
            const update = { $addToSet: { "hash":req.body.hash } };
            const data= await user.findOneAndUpdate(filter, update,{new: true, upsert: true});
            //const data=await certificate.create({"name":req.body.name,"hash":req.body.hash}); 
            console.log(data);
            res.send('your data wil be updated');
        }
     catch(e)
        {
            console.log('catch error:',e)
        }
    });
    router.get('/update1',checkAuth ,(req,res)=>{
        res.render('update1.ejs', {csrfToken: req.csrfToken()} )
      
    });


module.exports = router;