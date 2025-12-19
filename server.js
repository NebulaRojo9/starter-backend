require('dotenv').config()
const jwt = require('jsonwebtoken')
const bcrypt = require('bcrypt')
const cookieParser = require('cookie-parser')
const express = require('express')
const db = require('better-sqlite3')('ourApp.db')
db.pragma('journal_mode = WAL') // improve performance

// database setup starts here
const createtables = db.transaction(() => {
    db.prepare(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username STRING NOT NULL UNIQUE,
            password STRING NOT NULL
        )    
    `).run()
})
createtables()
// database setup ends here

const app = express()
app.set('view engine', 'ejs')
app.use(express.urlencoded({ extended: false }))
app.use(express.static('public'))
app.use(cookieParser())

// Middleware
app.use(function (req, res, next) {
    res.locals.errors = []

    // try to decode incoming cookie
    try {
        const decoded = jwt.verify(req.cookies.ourSimpleApp, process.env.JWTSECRET)
        req.user = decoded
    } catch (err) {
        req.user = false
    }
    res.locals.user = req.user
    console.log(req.user)

    next()
})

app.get('/', (req, res) => {
    if (req.user) {
        return res.render('dashboard')
    }
    res.render('homepage')
})

app.get('/login', (req, res) => {
    res.render('login')
})

app.get('/logout', (req, res) => {
    res.clearCookie('ourSimpleApp')
    res.redirect('/')
})

app.post('/login', (req, res) => {
    let errors = []

    if (typeof req.body.username !== 'string') req.body.username = ''
    if (typeof req.body.password !== 'string') req.body.password = ''

    if (req.body.username.trim() == '') errors = ['No username provided']
    if (req.body.password == '') errors = ['No password provided']

    if (errors.length > 0) {
        return res.render('login', { errors })
    }
    
    const userInQuestionStatement = db.prepare(`
        SELECT *
          FROM users
          WHERE USERNAME = ?
    `)
    const userInQuestion = userInQuestionStatement.get(req.body.username)

    if (!userInQuestion) {
        errors = ['Invalid username/password']
        return res.render('login', { errors })
    }

    const matchOrNot = bcrypt.compareSync(req.body.password, userInQuestion.password)
    if (!matchOrNot) {
        errors = ['Invalid username/password']
        return res.render('login', { errors})
    }

    const ourTokenValue = jwt.sign(
        { exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24, skyColor: 'skyBlue', userid: userInQuestion.id, username: userInQuestion.username }, 
        process.env.JWTSECRET
    )

    res.cookie('ourSimpleApp', ourTokenValue, {
        httpOnly: true,
        secure: true,
        sameSite: 'strict',
        maxAge: 1000 * 60 * 60 * 24
    })

    res.redirect('/')
})

app.get('/create-post', (req, res) => {
    res.render('create-post')
})

app.post('/register', (req, res) => {
    const errors = []

    if (typeof req.body.username !== 'string') req.body.username = ''
    if (typeof req.body.password !== 'string') req.body.password = ''

    if (!req.body.username) errors.push('Username is required')
    if (req.body.username && req.body.username.length < 5) errors.push('Username must be at least 5 characters long')
    if (req.body.username && req.body.username.length > 15) errors.push('Username cannot exceed 15 characters')
    if (req.body.username && !req.body.username.match(/^[a-zA-Z0-9]+$/)) errors.push('Username must contain only alphanumeric characters')

    // check if username is already taken
    const usernameStatement = db.prepare(`
        SELECT *
          FROM users
          WHERE USERNAME = ?
    `)
    const usernameCheck = usernameStatement.get(req.body.username)
    if (usernameCheck) errors.push('Username is already taken')
    
    if (!req.body.password) errors.push('Password is required')
    if (req.body.password && req.body.password.length < 8) errors.push('Password must be at least 8 characters long')
    if (req.body.password && req.body.password.length > 40) errors.push('Password cannot exceed 40 characters')

    if (errors.length > 0) {
        return res.render('homepage', { errors })
    } 

    // save the new user into a database
    const salt = bcrypt.genSaltSync(10)
    req.body.password = bcrypt.hashSync(req.body.password, salt)

    const ourStatement = db.prepare('INSERT INTO users (username, password) VALUES (?, ?)')
    const result = ourStatement.run(req.body.username, req.body.password)

    const lookupStatement = db.prepare('SELECT * FROM users WHERE ROWID = ?')
    const ourUser = lookupStatement.get(result.lastInsertRowid)

    // log the user in by giving them a cookie
    const ourTokenValue = jwt.sign(
        { exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24, skyColor: 'skyBlue', userid: ourUser.id, username: ourUser.username }, 
        process.env.JWTSECRET
    )

    res.cookie('ourSimpleApp', ourTokenValue, {
        httpOnly: true,
        secure: true,
        sameSite: 'strict',
        maxAge: 1000 * 60 * 60 * 24
    })

    res.redirect('/')
})

app.listen(4000)