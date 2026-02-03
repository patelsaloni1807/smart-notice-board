const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');

// Login Page
router.get('/login', authController.getLogin);

// Signup Page
router.get('/signup', authController.getSignup);

// Register Handle
router.post('/signup', authController.postSignup);

// Login Handle
router.post('/login', authController.postLogin);

// Logout Handle
router.get('/logout', authController.logout);

module.exports = router;
