import express from 'express'
import cors from 'cors'
import 'dotenv/config'
import jwt from 'jsonwebtoken'
import logger from 'morgan'
const app = express()
const port = process.env.PORT || 5000


//handle cors policy
app.use(cors())

// work done as middle ware body parser
app.use(express.json())
// show http activity

app.use(logger('dev'));

const users = [
    {
        id: "1",
        username: "sourov",
        password: "sourov12",
        isAdmin: false,
    },
    {
        id: "2",
        username: "trk",
        password: "trk17",
        isAdmin: true,
    },
]

let refreshTokensArray = []
const accessKey = "King"
const refreshKey = "Refresh"

// make a simple get request
app.get('/', (req, res) => {
    res.send('simple jwt server')
})
app.post('/api/refresh', (req, res) => {
    //take the refresh token from the user
    const refreshToken = req.body.token;

    //send error if there is no token, or it's invalid
    if (!refreshToken) return res.status(401).json("You are not authenticated!");
  //  console.log(refreshTokensArray)
    if (!refreshTokensArray.includes(refreshToken)) {
        return res.status(403).json("Refresh token is not valid!");
    }
    // al ok now  check the token
    jwt.verify(refreshToken, refreshKey, (err, user) => {
        err && console.log(err)
        // remove the current token
        refreshTokensArray = refreshTokensArray.filter((token) => token !== refreshToken);

        const newAccessToken = generateToken(user, accessKey)
        const newRefreshToken = generateRefreshToken(user, refreshKey)

        refreshTokensArray.push(newRefreshToken);

        res.status(200).json({
            accessToken: newAccessToken,
            refreshToken: newRefreshToken,
        });
    })

})

// generated token for refresh and sign in

const generateToken = (user, key) => {

    return jwt.sign(
        {id: user.id, isAdmin: user.isAdmin},
        key,
        {expiresIn: "5s"})
}

const generateRefreshToken = (user, key) => {
    return jwt.sign(
        {id: user.id, isAdmin: user.isAdmin},
        key);
};

app.post("/api/login", (req, res) => {

    const {username, password} = req.body
    const user = users.find(user => {
        return user.username === username && user.password === password
    })
    if (user) {
        // create an access token
        const accessToken = generateToken(user, accessKey)
        // refresh token
        const refreshToken = generateRefreshToken(user, refreshKey)
        refreshTokensArray.push(refreshToken)
      //  console.log(refreshTokensArray)
        res.status(200).json({
            username: user.username,
            isAdmin: user.isAdmin,
            accessToken,
            refreshToken,
        })

    } else {
        res.status(400).json({message: 'Invalid username or password'})
    }
})


const verify = (req, res, next) => {

    // get the token from header
    const authHeader = req.headers.authorization
    if (authHeader) {
        // the token look like Bearer eyA8...
        // so need to split bearer from the token
        const token = authHeader.split(" ")[1];
     //   console.log(token)
        // if verify the token
        jwt.verify(token, accessKey, (err, user) => {
            if (err) {
                return res.status(403).json({message: "Token is invalid"})
            }
            // if token is correct then assign the user to req
            req.user = user
            // then return to api from where it has been called
            next()
        })

    } else {
        res.status(401).json({message: 'you are not authorized'})
    }
}

app.post("/api/logout", verify,(req, res) => {

    const refreshToken = req.body.token
    refreshTokensArray = refreshTokensArray.filter( token => token !== refreshToken)
    res.status(200).json({message: 'Logged out successfully'})
})

app.delete("/api/users/:userId", verify, (req, res) => {

    if (req.user.id === req.params.userId || req.user.isAdmin) {

        res.status(200).json({message: 'Account deleted successfully'})
    } else {
        res.status(403).json({message: 'You do not have permission to delete this account'})
    }
})

//run the server
app.listen(port, () => {
    console.log(`app listening on port ${port}`)
})