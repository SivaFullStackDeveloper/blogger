const mongoose = require('mongoose');

const schema = mongoose.Schema;

const profile = new schema({
    email:{
       type:String,
         required:true,
            unique:true,

      
    },
    name: {
        type:String},
    
    profession:{
        type:String,
    
    },
    DOB:{
        type:String,
    },
    titleline:{
        type:String,
    },
    aboutme:{
        type:String,
    },
    img:{
        type:String,
        default:'',
    },
},
{
    timestamps:true,
}

);

const exporting = mongoose.model('profile',profile);
module.exports = exporting;