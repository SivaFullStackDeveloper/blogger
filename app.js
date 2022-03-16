const express  = require('express');
const mongoose = require('mongoose');
const dotenv   = require('dotenv');
const authuse  = require('./routers/router');
const profiler = require('./routers/profile');
const token = require('./jwttoken');


dotenv.config();

let app  = null;
let url  = null;
let port = null;
let webport=null;


const initialvar = async()=>{
app  = express();
app.use(express.json());
app.use(express.urlencoded({extended:false}));
url  = process.env.MONGO_URL;
port = process.env.PORT;
webport=process.env.Port;

}

const connecttodb = async()=>{
  
    try{
        await mongoose.connect(url,{
            autoIndex:false,
            useUnifiedTopology: true,
            bufferCommands:false,
            useNewUrlParser:true, 
        });
        console.log('connected to db');
    }catch(err){
        console.log(err);
    }
   
}

const middleware = async()=>{
    app.use('/',authuse);
    app.use('/user/register',authuse);
    app.use('/profile/login',authuse);
    app.use('/',profiler);
    app.use('/add',profiler);
    app.use('/add/image',profiler);
}
const listentoport = async()=>{
    app.listen(webport||port,()=>{
    console.log('connected to port',port);
    });

}

initialvar().then(()=>{
    listentoport().then(()=>{
        middleware().then(()=>{
            connecttodb();
        })
    })
})


