const express = require('express');
const router = express.Router();
const sqlite = require('../models/sqlite-db');

/* GET home page. */
router.get('/', function(req, res, next) {
  res.end('');
});

module.exports = router;
