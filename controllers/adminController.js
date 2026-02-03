const Notice = require('../models/Notice');
const Student = require('../models/Student');
const Department = require('../models/Department');

exports.getDashboard = async (req, res) => {
    try {
        const noticeCount = await Notice.countDocuments();
        const studentCount = await Student.countDocuments();
        const departmentCount = await Department.countDocuments();

        // Active notices (expiryDate is future or null)
        const activeNoticeCount = await Notice.countDocuments({
            $or: [
                { expiryDate: { $gte: new Date() } },
                { expiryDate: null }
            ]
        });

        // Recent Notices
        const recentNotices = await Notice.find()
            .populate('department')
            .sort({ date: -1 })
            .limit(5);

        // Department Student Counts
        const departments = await Department.find();
        const departmentData = [];
        for (let dept of departments) {
            const count = await Student.countDocuments({ department: dept._id });
            departmentData.push({ name: dept.name, count });
        }

        res.render('admin/dashboard', {
            pageTitle: 'Admin Dashboard',
            user: req.user,
            stats: {
                notices: noticeCount,
                students: studentCount,
                departments: departmentCount,
                activeNotices: activeNoticeCount
            },
            recentNotices,
            departmentData
        });
    } catch (err) {
        console.error(err);
        res.render('admin/dashboard', {
            pageTitle: 'Admin Dashboard',
            user: req.user,
            stats: { notices: 0, students: 0, departments: 0, activeNotices: 0 },
            recentNotices: [],
            departmentData: [],
            error_msg: 'Error loading stats'
        });
    }
};

// --- Notices ---
exports.getNotices = async (req, res) => {
    try {
        const notices = await Notice.find().populate('department').sort({ createdAt: -1 });
        res.render('admin/notices', {
            pageTitle: 'Manage Notices',
            user: req.user,
            notices
        });
    } catch (err) {
        console.error(err);
        res.redirect('/admin/dashboard');
    }
};

exports.getAddNotice = async (req, res) => {
    try {
        const departments = await Department.find();
        res.render('admin/add-notice', {
            pageTitle: 'Create Notice',
            user: req.user,
            departments
        });
    } catch (err) {
        console.error(err);
        res.redirect('/admin/notices');
    }
};

exports.postAddNotice = async (req, res) => {
    try {
        const { title, description, department, date, expiryDate, fileUrl } = req.body;
        // Basic validation could go here

        const newNotice = new Notice({
            title,
            description,
            department: department === 'all' ? null : department, // Handle 'all' logic if needed, or enforce department
            date: date || Date.now(),
            expiryDate,
            fileUrl
        });

        await newNotice.save();
        req.flash('success_msg', 'Notice created successfully');
        res.redirect('/admin/notices');
    } catch (err) {
        console.error(err);
        req.flash('error_msg', 'Error creating notice');
        res.redirect('/admin/notices/add');
    }
};

exports.getEditNotice = async (req, res) => {
    try {
        const notice = await Notice.findById(req.params.id);
        const departments = await Department.find();
        if (!notice) {
            req.flash('error_msg', 'Notice not found');
            return res.redirect('/admin/notices');
        }
        res.render('admin/edit-notice', {
            pageTitle: 'Edit Notice',
            user: req.user,
            notice,
            departments
        });
    } catch (err) {
        console.error(err);
        res.redirect('/admin/notices');
    }
};

exports.postEditNotice = async (req, res) => {
    try {
        const { title, description, department, date, expiryDate, fileUrl } = req.body;

        let updateData = {
            title,
            description,
            department: department === 'all' ? null : department,
            date: date,
            expiryDate: expiryDate ? expiryDate : null,
            fileUrl
        };

        await Notice.findByIdAndUpdate(req.params.id, updateData);
        req.flash('success_msg', 'Notice updated successfully');
        res.redirect('/admin/notices');
    } catch (err) {
        console.error(err);
        req.flash('error_msg', 'Error updating notice');
        res.redirect('/admin/notices');
    }
};

exports.postDeleteNotice = async (req, res) => {
    try {
        await Notice.findByIdAndDelete(req.params.id);
        req.flash('success_msg', 'Notice deleted successfully');
        res.redirect('/admin/notices');
    } catch (err) {
        console.error(err);
        req.flash('error_msg', 'Error deleting notice');
        res.redirect('/admin/notices');
    }
};

// --- Students ---
exports.getStudents = async (req, res) => {
    try {
        const students = await Student.find().populate('department').sort({ name: 1 });
        res.render('admin/students', {
            pageTitle: 'Manage Students',
            user: req.user,
            students
        });
    } catch (err) {
        console.error(err);
        res.redirect('/admin/dashboard');
    }
};

exports.getAddStudent = async (req, res) => {
    try {
        const departments = await Department.find();
        res.render('admin/add-student', {
            pageTitle: 'Add Student',
            user: req.user,
            departments
        });
    } catch (err) {
        console.error(err);
        res.redirect('/admin/students');
    }
};

exports.postAddStudent = async (req, res) => {
    try {
        const { name, rollNumber, email, mobileNumber, yearClass, department } = req.body;

        const newStudent = new Student({
            name,
            rollNumber,
            email,
            mobileNumber,
            yearClass,
            department
        });

        await newStudent.save();
        req.flash('success_msg', 'Student added successfully');
        res.redirect('/admin/students');
    } catch (err) {
        console.error(err);
        req.flash('error_msg', 'Error adding student');
        res.redirect('/admin/students/add');
    }
};

exports.getEditStudent = async (req, res) => {
    try {
        const student = await Student.findById(req.params.id);
        const departments = await Department.find();
        if (!student) {
            req.flash('error_msg', 'Student not found');
            return res.redirect('/admin/students');
        }
        res.render('admin/edit-student', {
            pageTitle: 'Edit Student',
            user: req.user,
            student,
            departments
        });
    } catch (err) {
        console.error(err);
        res.redirect('/admin/students');
    }
};

exports.postEditStudent = async (req, res) => {
    try {
        const { name, rollNumber, email, mobileNumber, yearClass, department } = req.body;

        await Student.findByIdAndUpdate(req.params.id, {
            name,
            rollNumber,
            email,
            mobileNumber,
            yearClass,
            department
        });

        req.flash('success_msg', 'Student updated successfully');
        res.redirect('/admin/students');
    } catch (err) {
        console.error(err);
        req.flash('error_msg', 'Error updating student');
        res.redirect('/admin/students');
    }
};

exports.postDeleteStudent = async (req, res) => {
    try {
        await Student.findByIdAndDelete(req.params.id);
        req.flash('success_msg', 'Student deleted successfully');
        res.redirect('/admin/students');
    } catch (err) {
        console.error(err);
        req.flash('error_msg', 'Error deleting student');
        res.redirect('/admin/students');
    }
};

// --- Departments ---
exports.getDepartments = async (req, res) => {
    try {
        const departments = await Department.find().sort({ name: 1 });
        res.render('admin/departments', {
            pageTitle: 'Manage Departments',
            user: req.user,
            departments
        });
    } catch (err) {
        console.error(err);
        res.redirect('/admin/dashboard');
    }
};

exports.getAddDepartment = async (req, res) => {
    res.render('admin/add-department', {
        pageTitle: 'Add Department',
        user: req.user
    });
};

exports.postAddDepartment = async (req, res) => {
    try {
        const { name } = req.body;
        const newDepartment = new Department({ name });
        await newDepartment.save();
        req.flash('success_msg', 'Department added successfully');
        res.redirect('/admin/departments');
    } catch (err) {
        console.error(err);
        req.flash('error_msg', 'Error adding department');
        res.redirect('/admin/departments/add');
    }
};

exports.postDeleteDepartment = async (req, res) => {
    try {
        await Department.findByIdAndDelete(req.params.id);
        req.flash('success_msg', 'Department deleted successfully');
        res.redirect('/admin/departments');
    } catch (err) {
        console.error(err);
        req.flash('error_msg', 'Error deleting department');
        res.redirect('/admin/departments');
    }
};
