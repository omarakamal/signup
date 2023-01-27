const router = require('express').Router()
const bcrypt = require('bcryptjs')
const User = require('../models/User.model')
const saltRounds = 10
const mongoose = require('mongoose')
const { isLoggedIn, isLoggedOut } = require('../middleware/route-guard.js');





router.get('/signup',isLoggedOut, (req, res) => {
    console.log(req.session)
    data = {userInSession:req.session.currentUser}
    console.log(data)
    res.render('auth/signup',data)
})

router.post('/signup', (req, res,next) => {
    console.log(req.body)

    const { email, password } = req.body

    //checking if all the required fields are filled in
    if (!email || !password) {
        res.render('auth/signup', { errorMessage: "Please fill in all mandatory fields. Email and Password are required" })
        return
    }

    //validate that the user password is at least 6 characters long and has 1 capital letter and 1 lowercase letter
    const regex = /(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,}/;
    if(!regex.test(password)){
        res.render('auth/signup',{errorMessage: "Please input a password: at least 6 characters long, with a lowercase and uppercase letter"})
        return
    }


    bcrypt
        .genSalt(saltRounds)
        .then((salt) => {
            console.log("Salt: ", salt)
            //hash() is the method that hashes/encrypts our password
            //takes two arguements: 1. is the password 2. is the salt
            return bcrypt.hash(password, salt)
        })
        .then(hashedPassword => {
            console.log("Hashed Password: ", hashedPassword)
          return  User.create({
                email: email,
                passwordHash: hashedPassword
            })
        })
        .then(()=>{
            res.redirect('/profile')

        })

        .catch(error => {
            //Check if any of our mongoose validators are not being met
            if (error instanceof mongoose.Error.ValidationError) {
                res.status(500).render('auth/signup', { errorMessage: error.message });
            }
            //Check if the email is already registered with our website
            else if(error.code === 11000){
                res.render('auth/signup',{errorMessage:"There is already an account associated with this emaail please sign in or sign up with new email"})
            }
             else {
                next(error);
            }
        }); // close .catch()
}) // close .post()


router.get('/login',isLoggedOut,(req,res)=>{
    console.log(req.session)
    res.render('auth/login')
})
//custom middleware functions
router.get('/profile',isLoggedIn, (req, res) => {
    console.log('What is in my session: ',req.session.currentUser)
    res.render('user/user-profile',req.session.currentUser)
})

router.post('/login',(req,res)=>{
    console.log("SESSION =====>", req.session)
    console.log(req.body)
    const {email,password} = req.body

    //first we are checking if the user filled in all the required fields
    if(!email || !password){
        res.render('auth/login',{errorMessage:'please enter an email or password'})
    return
    }
    //second we are checking if the email is already registered with our website
    User.findOne({email})
    .then(user=>{
        console.log(user)
        //scenerio 1: user inputs an email that was never signed up for our website
        if(!user){
            res.render('auth/login',{errorMessage:"User not found please sign up. No account associated with email"})
        }
        //scenerio 2: user inputted the rigth email and the right password so we let the user into the profile page
        //compareSync() is used to compare the user inputted password with the hashed password in the database
        else if(bcrypt.compareSync(password,user.passwordHash)){
            //i can use req.session.currentUser in all my other routes
            req.session.currentUser = user
            res.redirect('/profile')
        }
        //scenerio 3: the email is already signed up but the password is incorrect
        else{
            res.render('auth/login',{errorMessage:"Incorrect Password"})
        }

    })
    .catch(error=>{
        console.log(error)
    })

})

router.get('/about-me',(req,res)=>{
    res.render('user/about-me',{userInSession:req.session.currentUser})
})

router.post('return-me',(req,res)=>{
    res.json({"name":"Omar"})
})

router.post('/logout', (req, res, next) => {
    req.session.destroy(err => {
      if (err) next(err);
      res.redirect('/login');
    });
  });

module.exports = router