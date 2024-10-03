const asyncHandler = require("express-async-handler")
const User = require("../models/userModel");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
//@desc Register a user 
//@route POST /api/users/register
//@access public 

const registerUser = asyncHandler(async(req, res) => {
    const {username,email,password} = req.body;
    if(!username || !email || !password){
        res.status(400);
        throw new Error("All fields are required")
    }
    const userAvailable = await User.findOne({email})
    if (userAvailable){
        res.status(400);
        throw new Error("user already registered")
    }

    //hash password

    const hasedPassword = await bcrypt.hash(password,10);
    console.log("hashed password:", hasedPassword);
    const user = await User.create({
        username,
        email,
        password: hasedPassword,  // hashed password instead of plain text password
    });
    console.log(`user created ${user}`)
    if(user){
        res.status(201).json({_id: user.id,email: user.email})
    } else {
        res.status(400);
        throw new Error("user data is not valid")

    }

    res.json({message: "Register the user"})
});

//@desc Login a user 
//@route POST /api/users/login
//@access public 

const loginUser = asyncHandler(async(req, res) => {
    const {email, password} = req.body;
    if(!email || !password){
        res.status(400);
        throw new Error("All fields are required")
    }
    const user = await User.findOne({email});
    //compare passsword with hashpassword

    if(user && (await bcrypt.compare(password, user.password))){
       //generate token 
       const accessToken = jwt.sign(
        {
            user: {
                username: user.username,
                email: user.email,
                id:user.id,
            },

        },
        process.env.ACCCESS_TOKEN_SECERT,
        { expiresIn: "30m"} // token expires in 30min
       );
       res.status(200).json({accessToken});
    } else {
        res.status(401);
        throw new Error("Invalid email or password")
    }
    
});


//@desc cuurent user information 
//@route POST /api/users/current
//@access private 

const currentUser = asyncHandler(async(req, res) => {
    res.json(req.user);
});

module.exports = {registerUser,
    loginUser,
    currentUser,
};