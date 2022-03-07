const express = require('express');
const bcrypt  = require('bcryptjs');
const router  = express.Router();
const token   = require('../jwttoken');
const user    = require('../database/user.models');
const joi     = require('@hapi/joi');
const jwt     = require('jsonwebtoken');


router.get('/',async(req,res)=>{
    const msg={
        status:200,
        message:'Welcome to the API'
    }
    res.send(msg);
})

router.post('/user/register',async(req,res)=>{
     const joischema = joi.object({
        name    : joi.string().required().min(6),
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
            name:req.body.name,
            email:req.body.email,
            password:hash,
        });
        const savedUser = await newUser.save();
        res.send(savedUser);
});

router.get('/checkuser/:name',async(req,res)=>{
    const userExist = await user.findOne({email:req.params.name});
  
    if(userExist) {
    res.status(200).json({
        status:true,

    });}else{
        res.status(200).json({
            status:false,

        });
    }
});
router.get('/checkuser/:email',async(req,res)=>{
    const userExist = await user.findOne({name:req.params.email});

    if(userExist) {
    res.status(200).json({
        status:true,
    });}else{
        res.status(200).json({
            status:false,
        });
    }
});


router.post('/profile/login',async(req,res)=>{
    const {error} = joi.object({
        email   : joi.string().required().email(),
        password: joi.string().required().min(8),
    }).validate(req.body);
    if(error) return res.status(400).send(error.details[0].message);
    const userExist = await user.findOne({email:req.body.email});
    if(!userExist) return res.status(400).send('user does not exist');
    const validPass = await bcrypt.compare(req.body.password,userExist.password);
    if(!validPass){ 
        return res.status(400).send('invalid password');
    }else{
        const token = jwt.sign({_id:userExist._id},process.env.Token,{expiresIn:'24h'});
        res.json({
            token,
            msg:'login successful',  
        });

    }
    // const token = jwt.sign({_id:userExist._id},process.env.TOKEN_SECRET);
    // res.header('auth-token',token).send(token);
    // const msg={
    //     message:'log in successfully',
    // }
    // res.send(msg);
});

router.put('/update/:name',token,async(req,res)=>{
    const {error} = joi.object({
     
        password: joi.string().required().min(8),
    }).validate(req.body);
    if(error) return res.status(400).send(error.details[0].message);
    const salt = await bcrypt.genSalt(10);
    const hash = await bcrypt.hash(req.body.password,salt);
     await user.findOneAndUpdate(req.params.name,{$set:{
        
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


router.get('/:name',async(req,res)=>{
    const userExist = await user.findOne({name:req.params.name});
    if(!userExist) return res.status(400).send('user does not exist! create an account');
    res.json({
        data:userExist,
        name:req.params.name,
    });
})



module.exports = router;