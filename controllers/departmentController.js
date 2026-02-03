const Department = require('../models/Department');

exports.getDepartments = async (req, res) => {
    try {
        const departments = await Department.find().sort({ createdAt: -1 });
        res.render('admin/departments', {
            pageTitle: 'Manage Departments',
            departments,
            user: req.user
        });
    } catch (err) {
        console.error(err);
        req.flash('error_msg', 'Server Error');
        res.redirect('/admin/dashboard');
    }
};

exports.createDepartment = async (req, res) => {
    const { name } = req.body;
    if (!name) {
        req.flash('error_msg', 'Please enter a department name');
        return res.redirect('/admin/departments');
    }
    try {
        const existingDept = await Department.findOne({ name });
        if (existingDept) {
            req.flash('error_msg', 'Department already exists');
            return res.redirect('/admin/departments');
        }

        const newDept = new Department({ name });
        await newDept.save();
        req.flash('success_msg', 'Department created successfully');
        res.redirect('/admin/departments');
    } catch (err) {
        console.error(err);
        req.flash('error_msg', 'Error creating department');
        res.redirect('/admin/departments');
    }
};

exports.deleteDepartment = async (req, res) => {
    try {
        await Department.findByIdAndDelete(req.params.id);
        req.flash('success_msg', 'Department deleted');
        res.redirect('/admin/departments');
    } catch (err) {
        console.error(err);
        req.flash('error_msg', 'Error deleting department');
        res.redirect('/admin/departments');
    }
};
