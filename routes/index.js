const express = require('express');
const router = express.Router();
const publicController = require('../controllers/publicController');
const { ensureAuthenticated } = require('../config/auth');

// Home Page
router.get('/', publicController.getHome);

// Dashboard (Role based redirect)
router.get('/dashboard', ensureAuthenticated, publicController.getDashboard);

module.exports = router;
