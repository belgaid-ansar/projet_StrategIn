const express = require('express')
const path = require('path')
const bodyParser = require('body-parser')
const mongoose = require('mongoose')
const User = require('./model/user')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const session = require('express-session')
const open = require('open')

const JWT_SECRET = 'vcxncvhdgvcdcssdhsdgjfgehfgdghdfjhdgefhjhfhgfhdfgd'
const URI = 'mongodb+srv://root:root@cluster0.oizuy.mongodb.net/login-app-db?retryWrites=true&w=majority' 


open('http://localhost:9999');

mongoose.connect(
    URI, 
    {
        useNewUrlParser: true,
        useUnifiedTopology: true
    },
    (err) => {
        if(!err)
            console.log("Mongodb connected");
        else
            console.log("Connection error: "+ err);
    }
)

const app = express()
app.use('/', express.static(path.join(__dirname, 'static')))
app.use(bodyParser.json())

app.use(
    session({
        secret: "key that will sign cookie",
        resave: false,
        saveUninitialized: false,
    })
);

app.get('/api/users', function(req, res) {
    if(req.session.isAuth == true ){
        User.find({}, function(err, users) {
            var userConnect = [];
        
            users.forEach(function(user) {
                userConnect.push(user.username);
            });
            return res.json(userConnect)
        });
    }
    else{
        res.send("not connected");
    }  
});

app.post('/api/login', async (req, res) => {
	const { username, password } = req.body
	const user = await User.findOne({ username }).lean()

	if (!user) {
		return res.json({ status: 'error', error: 'Invalid username/password' })
	}
	if (await bcrypt.compare(password, user.password)) {
		// the username, password combination is successful
		const token = jwt.sign(
			{
				id: user._id,
				username: user.username
			},
			JWT_SECRET
		)
        req.session.isAuth = true;
		return res.json({ status: 'ok', data: token })
	}
	res.json({ status: 'error', error: 'Invalid username/password' })
})

app.post('/api/register', async (req,res) => {
    const { username, password: plainTextPassword } = req.body

	if (!username || typeof username !== 'string') {
		return res.json({ status: 'error', error: 'Invalid username' })
	}
	if (!plainTextPassword || typeof plainTextPassword !== 'string') {
		return res.json({ status: 'error', error: 'Invalid password' })
	}
	if (plainTextPassword.length < 5) {
		return res.json({
			status: 'error',
			error: 'Password too small. Should be atleast 5 characters'
		})
	}
    
    const password = await bcrypt.hash(plainTextPassword, 10)

    try {
		const response = await User.create({
			username,  
			password
		})
		console.log('User created successfully: ', response)
	} 
    catch (error) {
		if (error.code === 11000) {
			// duplicate key
			return res.json({ status: 'error', error: 'Username already in use' })
		}
	    throw error	
    }
    res.json({ status: 'ok' })
})

app.get('/api/logout',(req,res) => {
    req.session.destroy();
    res.redirect('/');
});

app.listen(9999, () => {
	console.log('Server up at 9999')
})

