const express = require('express');
const router = express.Router();
const { ensureAuthenticated, ensureAdmin } = require('../config/auth');
const departmentController = require('../controllers/departmentController');

router.get('/', ensureAuthenticated, ensureAdmin, departmentController.getDepartments);
router.post('/', ensureAuthenticated, ensureAdmin, departmentController.createDepartment);
router.delete('/:id', ensureAuthenticated, ensureAdmin, departmentController.deleteDepartment);

module.exports = router;
