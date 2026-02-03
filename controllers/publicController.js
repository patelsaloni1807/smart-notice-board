const Notice = require('../models/Notice');
const Department = require('../models/Department');

exports.getHome = async (req, res) => {
    try {
        const { filter, dept } = req.query;
        const today = new Date();
        today.setHours(0, 0, 0, 0); // Start of today

        let query = {};

        // Date Filter Logic
        switch (filter) {
            case 'today':
                const tomorrow = new Date(today);
                tomorrow.setDate(today.getDate() + 1);
                query.date = { $gte: today, $lt: tomorrow };
                break;
            case 'upcoming':
                query.date = { $gt: today };
                break;
            case 'past':
                query.date = { $lt: today };
                break;
            default: // 'all' or undefined
                // Modify: Show all non-expired or simply all public notices?
                // Standard logic: Show active notices (not expired)
                query.$or = [{ expiryDate: { $gte: today } }, { expiryDate: null }];
                break;
        }

        // Department Filter Logic
        if (dept && dept !== 'all') {
            query.department = dept;
        }

        const notices = await Notice.find(query)
            .populate('department')
            .sort({ date: -1 })
            .limit(20);

        const departments = await Department.find();

        res.render('index', {
            pageTitle: 'Smart Notice Board',
            notices,
            departments,
            currentFilter: filter || 'all',
            currentDept: dept || 'all',
            user: req.user
        });
    } catch (err) {
        console.error(err);
        res.render('index', {
            pageTitle: 'Smart Notice Board',
            notices: [],
            departments: [],
            currentFilter: 'all',
            currentDept: 'all',
            user: req.user
        });
    }
};

exports.getDashboard = async (req, res) => {
    if (req.user.role === 'admin') {
        return res.redirect('/admin/dashboard');
    }

    try {
        const today = new Date();
        let query = {
            $or: [
                { expiryDate: { $gte: today } },
                { expiryDate: null }
            ],
            $and: [
                {
                    $or: [
                        { department: null }, // Public notices
                        { department: req.user.department } // Notices for user's department
                    ]
                }
            ]
        };

        if (!req.user.department) {
            query = {
                $or: [
                    { expiryDate: { $gte: today } },
                    { expiryDate: null }
                ],
                department: null
            };
        }

        const studentNotices = await Notice.find(query).populate('department').sort({ date: -1 });

        res.render('student/dashboard', {
            pageTitle: 'Student Dashboard',
            user: req.user,
            notices: studentNotices
        });
    } catch (err) {
        console.error(err);
        res.redirect('/');
    }
};
