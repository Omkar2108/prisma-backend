const express = require('express');
const cors = require('cors');
const {PrismaClient} = require('@prisma/client');
const argon2 = require('argon2');
const jwt = require('jsonwebtoken');


const port = process.env.PORT || 4000;

const app = express();
const prisma = new PrismaClient();
app.use(express.json());

app.use(cors());

function check(req, res, next) {
    const token = req.headers['authorization'];
    const user = req.headers['user'];
    if (!token) {
        return res.status(200).send({
            auth:false,
            message: 'Access denied. No token provided.'
        });
    }
    try {
        const decoded = jwt.verify(token, user);
        next();
    } catch (ex) {
        return res.status(200).send({
            auth:false,
            message: 'Access denied. Invalid token.'
        });
    }
}

app.post('/register', async(req, res)=>{
    const {username, password} = req.body;
    await prisma.user.create({
        data:{
            username,
            password: await argon2.hash(password) 
        }
    }).then(user =>{
        const token = jwt.sign({}, username, {expiresIn: '1h'});
        user && res.status(200).json({
            auth:true,
            token,
            username,
            message: 'User created',
        })
    }).catch(err =>{
        res.status(500).json({
            message: 'Error creating user',
            error: err
        })
    })
})

app.post('/login', async(req, res)=>{
    const {username, password} = req.body;
    await prisma.user.findUnique({
        where:{
            username
        }
    }).then(user =>{
        if(user){
            argon2.verify(user.password, password).then(match =>{
                if(match){
                    const token = jwt.sign({}, username, {expiresIn: '1h'});
                    res.status(200).json({
                        message: 'User logged in',
                        auth: true,
                        token,
                        username
                    })
                }else{
                    res.status(401).json({
                        message: 'Invalid credentials',
                    })
                }
            })
        }else{
            res.status(401).json({
                message: 'Invalid credentials'
            })
        }
    }).catch(err =>{
        res.status(500).json({
            message: 'Error logging in',
            error: err
        })
    })
});

app.post('/forgotpassword', async(req, res)=>{
    const {username} = req.body;
    await prisma.user.findUnique({
        where:{
            username
        }
    }).then(user =>{
        if(user){
            res.status(200).json({
                message: 'Password reset link sent',
                user: true,
            })
        }else{
            res.status(401).json({
                user:false,
                message: 'Invalid credentials',
            })
        }
    }).catch(err =>{
        res.status(500).json({
            message: 'Error logging in',
            error: err,
            user:false
        })
    })
})

app.post('/resetpassword', async(req, res)=>{
    const {username, password }= req.body;
    await prisma.user.update({
        where:{
            username
        },
        data :{
            password: await argon2.hash(password)
        }
    }).then(async user =>{
        if(user){
            res.status(200).json({
                message: 'Password reset',
                user: true,
            })
        }else{
            res.status(401).json({
                user:false,
                message: 'Invalid credentials',
            })
        }
    }).catch(err =>{
        res.status(500).json({
            message: 'Error logging in',
            error: err,
            user:false
        })
    })
})


app.get('/getall', async(req, res)=>{
    await prisma.user.findMany().then(users =>{
        res.status(200).json({
            users
        })
    }).catch(err =>{
        res.status(500).json({
            message: 'Error getting users',
            error: err
        })
    })
})

app.get('/auth', check, async(req, res)=>{
    res.status(200).json({
        auth:true
    })
})

app.listen(port, ()=>{
    console.log(`Server is running on port ${port}`);
})