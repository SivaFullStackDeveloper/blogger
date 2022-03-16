const express = require('express');
const router  = express.Router();
const bcrypt  = require('bcryptjs');
const token   = require('../jwttoken');
const user    = require('../database/user.models');
const joi     = require('@hapi/joi');
const jwt     = require('jsonwebtoken');
const dotenv = require('dotenv');
dotenv.config();


router.get('/',async(req,res)=>{
    const msg={
        status:200,
        message:'Welcome to the API'
    }
    res.send(msg);
})

router.post('/user/register',async(req,res)=>{
     const joischema = joi.object({
        username    : joi.string().required().min(6),
        email   : joi.string().required().email(),
        password: joi.string().required().min(8),
     });
     const {error} = joischema.validate(req.body);
        if(error) return res.status(400).send(error.details[0].message);
        const userExist = await user.findOne({email:req.body.email});
        if(userExist) return res.status(400).send('user already exist');
        const salt = await bcrypt.genSalt(15);
        const hash = await bcrypt.hash(req.body.password,salt);
        const newUser = new user({
            username:req.body.username,
            email:req.body.email,
            password:hash,
        });
        const savedUser = await newUser.save();
        res.send(savedUser);
});

router.get('/checkuser/:name',async(req,res)=>{
    const userExist = await user.findOne({username:req.params.username});
  
    if(userExist) {
    res.status(200).json({
       
        status:true,

    });}else{
        res.status(200).json({
            status:false,

        });
    }
});
router.get('/checkemail/:email',async(req,res)=>{
    const userExist = await user.findOne({email:req.params.email});

    if(userExist) {
    res.status(200).json({
        status:true,
        message:userExist.name,
    });}else{
        res.status(200).json({
            status:false,
        });
    }
});


// router.route("/profile/login").post((req, res) => {
//     user.findOne({ email: req.body.email }, (err, result) => {
//       if (err) return res.status(500).json({ msg: err });
//       if (result === null) {
//         return res.status(403).json("Username incorrect");
//       }
//       const passwordIsValid = bcrypt.compare(
//         req.body.password,
//         result.password
//         );
//       if (!passwordIsValid) {
//         // here we implement the JWT token functionality
//         let token = jwt.sign({ email: req.body.email }, process.env.Token, {});
  
//         res.json({
//           token: token,
//           msg: "success",
//         });
//       } else {
//         res.status(403).json("password is incorrect");
//       }
//     });
//   });

router.post('/profile/login',async(req,res)=>{
    // const joischemaforlogin  = joi.object({
    //     email:joi.string().required().email(),
    //     password:joi.string().required().min(8),
    // });
    // const {error} = joischemaforlogin.validate(req.body);
    // if(error) {
    //     return res.status(400).send(error.details[0].message);
    // }else{
        try{
            const use = await user.findOne({email:req.body.email});
        if(!use) {
             res.status(200).json({msg:'email is not valid please check email and try again!!!',status:true});
        }
        const validatepassword = await bcrypt.compare(req.body.password,use.password);
        if(!validatepassword){
            res.status(200).json({
                msg:'password is not correct please check password and try again!!!',
                status:true,
            });
        } 
        else{
            const token  = jwt.sign({email:req.body.email},process.env.Token,{});
            res.json({
                token:token,
                mes:"login sucessfull",
                status:false,
            });
        } 

        }catch(e){
            console.log(e);
        }
     
              
})
    

router.put('/update/:name',token,async(req,res)=>{
    const {error} = joi.object({
     
        password: joi.string().required().min(8),
    }).validate(req.body);
    if(error) return res.status(400).send(error.details[0].message);
    const salt = await bcrypt.genSalt(10);
    const hash = await bcrypt.hash(req.body.password,salt);
     await user.findOneAndUpdate(req.params.username,{$set:{
        
        password:hash,
    }},{new:true,},

    
    (err,doc)=>{
        if(err) return res.status(400).send(err,{
            message:'error in updating'
        });
        const msg={
            message:'password updated successfully',
        }
        res.send(msg);
    })

})

router.delete('/delete/:name',async(req,res)=>{
    await user.findOneAndDelete(req.params.username,(err,doc)=>{
        if(err) return res.status(400).send(err,{
            message:'error in deleting'
        });
        const msg={
            message:'user deleted successfully',
        }
        res.send(msg);
    })
})



module.exports = router;