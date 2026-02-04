const passport = require('passport');
const User = require('../models/User');
const Department = require('../models/Department');
const bcrypt = require('bcryptjs');

exports.getLogin = (req, res) => {
    res.render('auth/login', {
        pageTitle: 'Login',
        user: req.user
    });
};

exports.getSignup = async (req, res) => {
    try {
        const departments = await Department.find();
        res.render('auth/signup', {
            pageTitle: 'Signup',
            user: req.user,
            departments,
            role: undefined // Initialize role as undefined for new signup
        });
    } catch (err) {
        console.error(err);
        res.render('auth/signup', {
            pageTitle: 'Signup',
            user: req.user,
            departments: [],
            role: undefined // Initialize role as undefined
        });
    }
};

exports.postSignup = async (req, res) => {
    const { name, email, password, confirmPassword, department, role } = req.body;
    let errors = [];

    // Fetch departments for re-rendering if error
    let departments = [];
    try {
        departments = await Department.find();
    } catch (err) {
        console.error(err);
    }

    if (!name || !email || !password || !confirmPassword) {
        errors.push({ msg: 'Please enter all fields' });
    }

    if (password !== confirmPassword) {
        errors.push({ msg: 'Passwords do not match' });
    }

    if (password.length < 6) {
        errors.push({ msg: 'Password must be at least 6 characters' });
    }

    // Single Admin Check
    if (role === 'admin') {
        try {
            const adminExists = await User.findOne({ role: 'admin' });
            if (adminExists) {
                errors.push({ msg: 'Admin account already exists. Only one admin is allowed.' });
            }
        } catch (err) {
            console.error(err);
            errors.push({ msg: 'Error checking admin status' });
        }
    }

    if (errors.length > 0) {
        res.render('auth/signup', {
            errors,
            name,
            email,
            password,
            confirmPassword,
            department,
            role,
            departments,
            pageTitle: 'Signup',
            user: req.user
        });
    } else {
        try {
            const user = await User.findOne({ email: email });
            if (user) {
                errors.push({ msg: 'Email already exists' });
                res.render('auth/signup', {
                    errors,
                    name,
                    email,
                    password,
                    confirmPassword,
                    department,
                    role,
                    departments,
                    pageTitle: 'Signup',
                    user: req.user
                });
            } else {
                const newUser = new User({
                    name,
                    email,
                    password,
                    role: role || 'student', // Default to student
                    department: department || null
                });

                bcrypt.genSalt(10, (err, salt) => {
                    bcrypt.hash(newUser.password, salt, (err, hash) => {
                        if (err) throw err;
                        newUser.password = hash;
                        newUser.save()
                            .then(user => {
                                req.flash('success_msg', 'You are now registered and can log in');
                                res.redirect('/auth/login');
                            })
                            .catch(err => console.log(err));
                    });
                });
            }
        } catch (err) {
            console.error(err);
        }
    }
};

exports.postLogin = (req, res, next) => {
    passport.authenticate('local', (err, user, info) => {
        if (err) {
            console.error('Login Error:', err);
            return next(err);
        }
        if (!user) {
            req.flash('error_msg', info.message || 'Login failed');
            return res.redirect('/auth/login');
        }
        req.logIn(user, (err) => {
            if (err) {
                console.error('Login Session Error:', err);
                return next(err);
            }

            console.log('User logged in:', user.email, 'Role:', user.role);

            // Explicitly save session before redirecting
            req.session.save(() => {
                if (user.role === 'admin') {
                    console.log('Redirecting to admin dashboard');
                    return res.redirect('/admin/dashboard');
                } else {
                    console.log('Redirecting to home (student)');
                    return res.redirect('/');
                }
            });
        });
    })(req, res, next);
};

exports.logout = (req, res, next) => {
    req.logout((err) => {
        if (err) { return next(err); }
        req.flash('success_msg', 'You are logged out');
        res.redirect('/auth/login');
    });
};
