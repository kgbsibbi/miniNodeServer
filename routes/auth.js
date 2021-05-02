const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const authMiddleware = require('../middleware/auth');
const db = require('../models/sqlite-db');
const sql = require('../models/user-sql');


router.post('/login', function(req, res, next) {
  const {userid, password} = req.body;
  const secret = req.app.get('jwt-secret');

  if(!userid || !password){
    return res.status(400).json({
        error: 'Invalid parameters'
    });
  }

  const login = (result) => {
    const p = new Promise((resolve, reject)=>{
      let user=null;
      if(result != null) user = result[0]
      if(user == null) reject(new Error('Login failed'))
      else{
        if(user.password == password){
          resolve(user);
        }
        else {
          reject(new Error('Login failed'));
        }
      }
    })
    return p;
  };

  const authorize = (user) => {
    const p = new Promise((resolve, reject) => {
      let exptime = Math.floor(Date.now() / 1000) + (60*60); // 1 hour
      jwt.sign(
        {
          iss: "miniServer", // token issuer
          sub: user.userid,
          name: user.name,
          aud: "miniServer", // receiver
          iat: Math.floor(Date.now() / 1000), // issued at.
          exp: exptime,
        },
        secret,
        (err, token) => {
          if (err) reject(err)
          resolve({token:token, name:user.name})
        })
    })
    return p;
  };

  const respond = (result) => {
    res.json(result);
  };

  const onError = (error) => {
    console.log('auth-done with error')
    res.status(403).json({
        error: error.message
    })
  }

  db.executeQuery(sql.selectOneUserSql(userid), (error, rows)=>{
    login(rows)
    .then(authorize)
    .then(respond)
    .catch(onError)
  });
});

router.post('/autologin', authMiddleware, function(req, res, next) {
  res.json({userid:req.userid, name:req.decodedToken.name});
});
module.exports = router;
