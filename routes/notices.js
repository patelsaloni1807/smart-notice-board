const express = require('express');
const router = express.Router();
const multer = require('multer');
const path = require('path');
const { ensureAuthenticated, ensureAdmin } = require('../config/auth');
const noticeController = require('../controllers/noticeController');

// Multer Config
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'public/uploads');
    },
    filename: function (req, file, cb) {
        cb(null, file.fieldname + '-' + Date.now() + path.extname(file.originalname));
    }
});

const upload = multer({
    storage: storage,
    fileFilter: function (req, file, cb) {
        const filetypes = /jpeg|jpg|png|pdf/;
        const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
        const mimetype = filetypes.test(file.mimetype);
        if (mimetype && extname) {
            return cb(null, true);
        } else {
            req.fileValidationError = 'Only images and PDFs are allowed';
            return cb(null, false, req.fileValidationError);
        }
    }
});

router.get('/', ensureAuthenticated, ensureAdmin, noticeController.getNotices);
router.post('/', ensureAuthenticated, ensureAdmin, upload.single('noticeFile'), noticeController.createNotice);
router.delete('/:id', ensureAuthenticated, ensureAdmin, noticeController.deleteNotice);

module.exports = router;
