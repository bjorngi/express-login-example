const express = require('express')
const bodyParser = require('body-parser')
const app = express()
const port = 3000
const cryptojs = require('crypto-js');
const session = require('express-session')


let users = {} // User database
let sessions = {}
const iterations = 1000 // Hash iterations

const jsonParser = bodyParser.json()

const getUsernameAndPasswordFromReq = (req) => {
  const username = req.body.username
  const password = req.body.password

  return [username, password]
}

const userExists = (username, users) => users[username] && true

const checkPassword = (salt, hash, password) => {
  const newHash = cryptojs.PBKDF2(password, salt, {keySize: 512 / 32, iterations: iterations})
  return newHash.toString() === hash
}

app.use(session({
  secret: 'this is secret',
  name: 'session',
  cookie: {
    session: true,
    expires: false,
  }
}))

app.get('/', (req, res) => res.send('Hello World!'))

app.post('/create-user', jsonParser, (req, res) => {
  const [username, password] = getUsernameAndPasswordFromReq(req)

  if (!username || !password) {
    return res.sendStatus(400)
  } else if (userExists(username, users)) {
    return res.send('Bruker eksisterer', 400)
  }
  const salt = cryptojs.lib.WordArray.random(128 / 8).toString();
  const passhash = cryptojs.PBKDF2(password, salt, {keySize: 512 / 32, iterations: iterations})

  users = {
    ...users,
    [username]: {
      salt: salt,
      hash: passhash.toString()
    }
  }
  return res.sendStatus(200)
})

app.post('/login', jsonParser, (req, res) => {
  const [username, password] = getUsernameAndPasswordFromReq(req)
  const localUser = users[username]

  if (!username || !password) {
    return res.sendStatus(400)
  } else if (!localUser) {
    return res.send('Ikke registert', 400)
  } else if (checkPassword(localUser.salt, localUser.hash, password)) {
    sessions = {
      ...sessions,
      [req.sessionID]: username
    }
    return res.sendStatus(200)
  }

  return res.sendStatus(401)
})

app.get('/secret', (req, res) => {
  const userSession = sessions[req.sessionID]
  if (userSession) {
    return res.send(`LOGGET INN SOM ${userSession} med sessionID ${req.sessionID}`)
  }
  return res.send(`Fu. SessionID: ${req.sessionID}`, 401)
})

app.listen(port, () => console.log(`Example app listening on port ${port}!`))
