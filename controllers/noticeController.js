const Notice = require('../models/Notice');
const Department = require('../models/Department');

exports.getNotices = async (req, res) => {
    try {
        const notices = await Notice.find().populate('department').sort({ createdAt: -1 });
        const departments = await Department.find();
        res.render('admin/notices', {
            pageTitle: 'Manage Notices',
            notices,
            departments,
            user: req.user
        });
    } catch (err) {
        console.error(err);
        req.flash('error_msg', 'Server Error');
        res.redirect('/admin/dashboard');
    }
};

exports.createNotice = async (req, res) => {
    const { title, description, department, date, expiryDate } = req.body;
    let fileUrl = '';

    // Check if file upload had error from multer
    if (req.fileValidationError) {
        req.flash('error_msg', req.fileValidationError);
        return res.redirect('/admin/notices');
    }

    if (req.file) {
        fileUrl = '/uploads/' + req.file.filename;
    }

    try {
        const newNotice = new Notice({
            title,
            description,
            department: department || null,
            date: date || Date.now(),
            expiryDate: expiryDate || null,
            fileUrl,
            isPublic: !department // If no department selected, it's public
        });

        await newNotice.save();
        req.flash('success_msg', 'Notice created successfully');
        res.redirect('/admin/notices');
    } catch (err) {
        console.error(err);
        req.flash('error_msg', 'Error creating notice');
        res.redirect('/admin/notices');
    }
};

exports.deleteNotice = async (req, res) => {
    try {
        await Notice.findByIdAndDelete(req.params.id);
        req.flash('success_msg', 'Notice deleted');
        res.redirect('/admin/notices');
    } catch (err) {
        console.error(err);
        req.flash('error_msg', 'Error deleting notice');
        res.redirect('/admin/notices');
    }
};
