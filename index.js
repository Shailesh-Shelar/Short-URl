require("dotenv").config();
const express = require("express")
const nodemailer = require("nodemailer");
const cors = require("cors");
const jwt=require("jsonwebtoken");
const bcrypt = require("bcrypt");
const mongodb=require("mongodb");
const cryptoRandomString = require("crypto-random-string");
const { async } = require("crypto-random-string");
const app=express()
app.use(express.json())
app.use(cors())


const mongoClient=mongodb.MongoClient;
const objectID = mongodb.ObjectID;
const dbURL=process.env.DB_URl;
const DBName=process.env.bdname;
const port = process.env.PORT || 3000;
app.post("/register",cors(),async(req,res)=>{
    try{
        let clientInfo = await mongoClient.connect(dbURL);
        let db = clientInfo.db(DBName);
        let data = await db.collection("users").findOne({
            email: req.body.email
        });
        if (data) {
            res.status(200).json({
                status: "failed",
                message: "Email is already registered"
            });
        } else {
            if (req.body.password != req.body.confirm_password) 
            {
                res.status(200).json({
                    status: "failed",
                    message: "Passwords Dosent matche"
                });
            }
            else
            {
                let salt = await bcrypt.genSalt(15);
                let hashValue = await bcrypt.hash(`${req.body.password}`, salt);
                req.body.password=hashValue;
                req.body.isactive=false;
                delete req.body.confirm_password;
                
                let transporter = nodemailer.createTransport({
                    host: "smtp.gmail.com",
                    port: 587,
                    secure: false, 
                    auth: {
                        user:"shaileshshelar6918@gmail.com",
                        pass: "shailesh@1217",
                    },
                });
                let str = cryptoRandomString({
                    length: 32,
                    type: 'url-safe'
                });
                req.body.active_string=str;

                let api="https://shailesh-shorturl.herokuapp.com/active?active_string"
                await db.collection("users").insertOne(req.body)
                await transporter.sendMail({
                    from:"shaileshshelar6918@gmail.com", 
                    to: `${req.body.email}`, 
                    subject: "Active Your Account", 
                    html: `<b>Click the Link to Activate Your Account.</b><br><p>${api}=${str}</p>`,
                });

                clientInfo.close();
            }
        }
    }
    catch(error)
    {
        console.log(error);
    }
})


app.get("/active",async(req,res)=>{
    try{
        let clientInfo = await mongoClient.connect(dbURL);
        let db = clientInfo.db(DBName);
        let data = await db.collection("users").findOne({
            active_string: req.query.active_string
        });

        if(data)
        {
            await db.collection("users").updateOne({
                _id:objectID(data._id)
            },
            {
                $set:{
                    isactive:true,
                    active_string:""
                }
            })
            res.send("<p>Account Activated Go And Login</p>")
        }
        else{
            res.send("<p>Link is no more available... please register again</p>")
        }
        clientInfo.close();
    }
    catch(error){
        console.log(error)
    }
})


app.post("/login",async(req,res)=>{
    try {
        let clientInfo = await mongoClient.connect(dbURL);
        let db = clientInfo.db(DBName);
        let data = await db.collection("users").findOne({
            email: req.body.email
        });
        if(data)
        {
            if(data.isactive==true)
            {
                let pass=await bcrypt.compare(req.body.password,data.password);
                if(pass)
                {
                    let token = jwt.sign({
                        userId: data._id,
                        iat: Date.now()
                    }, process.env.JWT_KEY);
                    res.json({
                        status: "success",
                        message: "Login successful",
                        userId: data._id,
                        token
                    });
                }
                else{
                    res.json({
                        status: "failed",
                        message: "Incorrect Password"
                    });
                }
            }
            else{
                res.status(200).json({
                    status: "failed",
                    message: "Account is Not activated yet.. check your email for activation link"
                });
            }
        }
        else {
            res.status(200).json({
                status: "failed",
                message: "Email is not registered."
            });
        }
        clientInfo.close();
    } catch (error) {
        console.log(error)
    }
})

app.post("/forget-password",async(req,res)=>{
    try{

        let clientInfo = await mongoClient.connect(dbURL);
        let db = clientInfo.db(DBName);
        let data = await db.collection("users").findOne({
            email: req.body.email
        });
       // console.log(data)
        if (data) {
            let transporter = nodemailer.createTransport({
                host: "smtp.gmail.com",
                port: 587,
                secure: false, // true for 465, false for other ports
                auth: {
                    user:"shaileshshelar6918@gmail.com",
                    pass: "shailesh@1217",
                },
            });
            let str1 = cryptoRandomString({
                length: 32,
                type: 'url-safe'
            });
            let str = `${str1}_._${data._id}`;
                
                let api="https://shailesh-shorturl.herokuapp.com/checkpassword?reset_string"
                await transporter.sendMail({
                    from: `Short URL <${process.env.MAIL_USERNAME}>`, // sender address
                    to: `${req.body.email}`, // list of receivers
                    subject: "Change Password", // Subject line
                    html: `<b>Click the Link to reset your password.</b><br><p>${api}=${str}</p>`,
                });

                await db.collection("users").updateOne({
                    _id: data._id
                }, {
                    $set: {
                        reset_string:str1
                    }
                });

    
                res.status(200).json({
                    status: "success",
                    message: "Reset password link is sent to your email account."
                });
        }
        else{
            res.status(200).json({
                status:"failed",
                message:"Email is Not registered"
            })
        }



        clientInfo.close()
    }
    catch(error)
    {
        console.log(error);
    }
})


app.get("/checkpassword",async(req,res)=>{
    try {
        let str=req.query.reset_string.split("_._")
        
        let resetstring=str[0]
        // console.log("reset string is"+resetstring);
        let uid=str[1];
        // console.log("User Id string is"+uid);
        let clientInfo = await mongoClient.connect(dbURL);
        let db = clientInfo.db(DBName);
        let result = await db.collection("users").findOne({
            $and: [{
                _id: objectID(uid)
            }, {
                reset_string: resetstring
            }]
        });

        if(result){
                    res.redirect(`http://127.0.0.1:5500/shorturl/frontend/reset-password.html?uid=${uid}`)
        }
        else{
            res.send("link is not available");
        }

    } catch (error) {
        console.log(error)
    }
})


app.post("/resetpassword/:uid",async(req,res)=>{
    try{
        let clientInfo = await mongoClient.connect(dbURL);
        let db = clientInfo.db(DBName);
        console.log(db);
        let result = await db.collection("users").findOne({
            _id: objectID(req.params.uid)
        });

        if(result)
        {
            if (req.body.password != req.body.confirm_password) 
            {
                res.status(200).json({
                    status: "failed",
                    message: "Passwords Dosent matche"
                });
            }
            else{
                let salt = await bcrypt.genSalt(15);
                let hashValue = await bcrypt.hash(`${req.body.password}`, salt);
                req.body.password=hashValue;
                delete req.body.confirm_password;
                await db.collection("users").updateOne({
                    _id:objectID(req.params.uid)
                },{
                    $set:{
                        reset_string:"",
                        password:req.body.password

                }
                });
                res.status(200).json({
                    status: 'success',
                    message: 'password changed successfully'
                });
            }
        }
        else{
            res.status(200).json({
                status:"failed",
                message:"User not found"
            })
        }
    }
    catch(error){
        console.log(error);
    }
});

app.post("/short-url", async (req, res) => {
    try {
        let decodedData = jwt.verify(req.headers.authorization, process.env.JWT_KEY);
        let str = cryptoRandomString({
            length: 8,
            type: 'url-safe'
        });
        console.log("shorturlstr="+str);
        let clientInfo = await mongoClient.connect(dbURL);
        let db = clientInfo.db(DBName);
        let data = await db.collection('urls').insertOne({
            uid: objectID(decodedData.userId),
            long_url: req.body.long_url,
            short_url_code: str
        });
        res.json({
            shorturl:str,
            status: "success",
            message: "short url generated"
        })
    } catch (error) {
        console.log(error);
        res.status(500).json({
            error
        });
    }
});


app.get("/verify/:id",async(req,res)=>{
    try {
        let decodedData = jwt.verify(req.headers.authorization, process.env.JWT_KEY);
        if (decodedData.userId == req.params.id) {
            let clientInfo = await mongoClient.connect(dbURL);
            let db = clientInfo.db(DBName);
            let data = await db.collection('users').findOne({
                _id: objectID(req.params.id)
            });
            if (data) {
                res.status(200).json({
                    status: "success",
                    is_loggedIn: true
                });
            } else {
                res.status(400).json({
                    status: "failed",
                    is_loggedIn: false
                });
            }
            clientInfo.close();
        } else {
            res.status(400).json({
                status: "failed",
                is_loggedIn: false
            });
        }
    } catch (error) {
        // console.log(error);
        res.status(400).json({
            status: "failed",
            error
        });
    }
});

app.get("/:url",async(req,res)=>{
    try {
        let clientInfo = await mongoClient.connect(dbURL);
        let db = clientInfo.db(DBName);
        let data = await db.collection('urls').findOne({
            short_url_code: req.params.url
        });
        if(data){
            res.redirect(data.long_url)
        } else {
            res.status(400).json({
                status: "failed",
                message: "wrong short-url"
            })
        }
        clientInfo.close();
    } catch (error) {
        console.log(error);
    }
})
app.listen(port,()=>{
    console.log(`App is running on port ${port}`);
})