const express = require('express');
const router = express.Router();
const { ensureAuthenticated, ensureAdmin } = require('../config/auth');
const studentController = require('../controllers/studentController');

router.get('/', ensureAuthenticated, ensureAdmin, studentController.getStudents);
router.post('/', ensureAuthenticated, ensureAdmin, studentController.createStudent);
router.delete('/:id', ensureAuthenticated, ensureAdmin, studentController.deleteStudent);

module.exports = router;
