const express = require('express');
const router  = express.Router();
const profile = require('../database/profile.model');
const token   = require('../jwttoken');
const path = require('path');
const multer = require('multer');

const storage =  multer.diskStorage({
    destination: (req,file,cb)=>{
      cb(null, './uploads');
    },
    filename: (req,file,cb)=>{
      cb(null,Date.now()+ req.decoded.email+".jpg");
    },
 


})

const upload = multer({
  storage :storage,
  limits:{
    fileSize: 1024 * 1024 * 1,
  },
  fileFilter: (req,file,cb)=>{
    if(file.mimetype=='image/jpeg' || file.mimetype=='image/png'){
      cb(null,true);
    }else{
      cb(null,false);
    }
  }
})

router.patch('/add/image',token,upload.single("img"),async(req,res)=>{
  await profile.findOneAndUpdate({email:req.decoded.email},
    {$set:{img:req.file.path}},(err,result)=>{
    if(err){
      res.send(err);
    }else{
      const response = {
        message: "Image Uploaded Successfully",
        data: result};
      res.status(200).send(response);
    }
  }
  );

})



router.post("/",async(req,res)=>{
    try{
   res.json("hello");

    }catch(err){
        res.status(400).send(err);
    }
       
})

router.route("/add").post(token,(req,res)=>{
    
    const pro = profile({
       email:req.decoded.email,
       name:req.body.name,
        profession:req.body.profession,
        DOB:req.body.DOB,
        titleline:req.body.titleline,
        aboutme:req.body.aboutme,
        img:req.body.img,
        
    
    });
    try{
          pro.save().then(()=>{
            res.json("profile details  added");
        })
    }catch(err){
        res.status(400).send(err);
    }
 
})
router.route("/checkProfile").get(token,async (req, res) => {
   await  profile.findOne({ email: req.decoded.email }, (err, result) => {
      if (err) return res.json({ err: err });
      else if (result == null) {
        return res.json({ status: false, email: req.decoded.email });
      } else {
        return res.json({ status: true, email: req.decoded.email });
      }
    });
  });

module.exports = router;
