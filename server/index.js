require('dotenv').config();

const express = require('express');
const massive = require('massive');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const {SERVER_PORT, CONNECTION_STRING, SESSION_SECRET} = process.env;
const app = express();
app.use(express.json());

app.use(session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: {
        maxAge: 1000 * 60 * 60 * 24
    }
}));

massive(CONNECTION_STRING)
.then(db => {
    app.set("db", db)
    console.log('connected to db')
}).catch(err => console.log(err));


// auth endpoints
app.post('/auth/register', (req, res) => {
    const {username, password} = req.body
    const db = req.app.get('db');
    db.checkForUser(username).then(user => {
        if(!user[0]){
            const salt = bcrypt.genSaltSync(10);
            bcrypt.hash(password, salt).then(hash => {
                db.addUser(username, hash).then(user => {
                    req.session.user = {...user[0]};
                    res.status(200).json(req.session.user)
                })
            })
        } else {
            res.status(409).json({error: "Username is taken"})
        }
    })
});
app.post('/auth/login', async (req, res) => {
    const {username, password} = req.body
    const db = req.app.get('db');
    
    const hash = await db.checkUser(username);
    console.log(hash)

    const doesMatch = bcrypt.compareSync(password, hash[0].hash);

    if(doesMatch) {
        const foundUser = await db.checkForUser(username);
        req.session.user = {...foundUser[0]}
        res.status(200).json(req.session.user)
    } else {
        res.status(409).json({error: "Username or Password incorrect"})
    }
});


app.listen(SERVER_PORT, () => console.log(`Servin up some 🔥 🔥 🔥 on Port ${SERVER_PORT}`))