const Student = require('../models/Student');
const Department = require('../models/Department');

exports.getStudents = async (req, res) => {
    try {
        const students = await Student.find().populate('department').sort({ createdAt: -1 });
        const departments = await Department.find();
        res.render('admin/students', {
            pageTitle: 'Manage Students',
            students,
            departments,
            user: req.user
        });
    } catch (err) {
        console.error(err);
        req.flash('error_msg', 'Server Error');
        res.redirect('/admin/dashboard');
    }
};

exports.createStudent = async (req, res) => {
    const { name, rollNumber, email, mobileNumber, yearClass, department } = req.body;
    let errors = [];

    if (!name || !rollNumber || !email || !mobileNumber || !yearClass || !department) {
        errors.push({ msg: 'Please enter all fields' });
    }

    if (errors.length > 0) {
        try {
            const students = await Student.find().populate('department').sort({ createdAt: -1 });
            const departments = await Department.find();
            return res.render('admin/students', {
                pageTitle: 'Manage Students',
                students,
                departments,
                user: req.user,
                errors,
                name, rollNumber, email, mobileNumber, yearClass
            });
        } catch (err) {
            console.log(err);
        }
    }

    try {
        const existingStudent = await Student.findOne({ $or: [{ email }, { rollNumber }] });
        if (existingStudent) {
            req.flash('error_msg', 'Student with this Email or Roll Number already exists');
            return res.redirect('/admin/students');
        }

        const newStudent = new Student({
            name,
            rollNumber,
            email,
            mobileNumber,
            yearClass,
            department
        });

        await newStudent.save();
        req.flash('success_msg', 'Student created successfully');
        res.redirect('/admin/students');
    } catch (err) {
        console.error(err);
        req.flash('error_msg', 'Error creating student');
        res.redirect('/admin/students');
    }
};

exports.deleteStudent = async (req, res) => {
    try {
        await Student.findByIdAndDelete(req.params.id);
        req.flash('success_msg', 'Student deleted');
        res.redirect('/admin/students');
    } catch (err) {
        console.error(err);
        req.flash('error_msg', 'Error deleting student');
        res.redirect('/admin/students');
    }
};
