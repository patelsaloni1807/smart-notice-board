const express = require('express');
const router = express.Router();
const { ensureAuthenticated, ensureAdmin } = require('../config/auth');
const adminController = require('../controllers/adminController');

// Dashboard
router.get('/dashboard', ensureAuthenticated, ensureAdmin, adminController.getDashboard);

// Notices
router.get('/notices', ensureAuthenticated, ensureAdmin, adminController.getNotices);
router.get('/notices/add', ensureAuthenticated, ensureAdmin, adminController.getAddNotice);
router.post('/notices', ensureAuthenticated, ensureAdmin, adminController.postAddNotice);
router.get('/notices/edit/:id', ensureAuthenticated, ensureAdmin, adminController.getEditNotice);
router.post('/notices/edit/:id', ensureAuthenticated, ensureAdmin, adminController.postEditNotice);
router.post('/notices/delete/:id', ensureAuthenticated, ensureAdmin, adminController.postDeleteNotice);

// Students
router.get('/students', ensureAuthenticated, ensureAdmin, adminController.getStudents);
router.get('/students/add', ensureAuthenticated, ensureAdmin, adminController.getAddStudent);
router.post('/students', ensureAuthenticated, ensureAdmin, adminController.postAddStudent);
router.get('/students/edit/:id', ensureAuthenticated, ensureAdmin, adminController.getEditStudent);
router.post('/students/edit/:id', ensureAuthenticated, ensureAdmin, adminController.postEditStudent);
router.post('/students/delete/:id', ensureAuthenticated, ensureAdmin, adminController.postDeleteStudent);

// Departments
router.get('/departments', ensureAuthenticated, ensureAdmin, adminController.getDepartments);
router.get('/departments/add', ensureAuthenticated, ensureAdmin, adminController.getAddDepartment);
router.post('/departments', ensureAuthenticated, ensureAdmin, adminController.postAddDepartment);
router.post('/departments/delete/:id', ensureAuthenticated, ensureAdmin, adminController.postDeleteDepartment);

module.exports = router;
