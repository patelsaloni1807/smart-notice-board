const mongoose = require('mongoose');
const dotenv = require('dotenv');
const Department = require('./models/Department');
const Notice = require('./models/Notice');

dotenv.config();

mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log('MongoDB Connected'))
    .catch(err => console.log(err));

const seedData = async () => {
    try {
        console.log('Clearing old data...');
        // Optional: clear existing if you want fresh start, but maybe keep admin
        await Department.deleteMany({});
        await Notice.deleteMany({});

        console.log('Seeding Departments...');
        const deptNames = ['Computer Science', 'Information Technology', 'Electronics', 'Civil Engineering', 'Mechanical'];
        const depts = [];

        for (const name of deptNames) {
            const d = new Department({ name });
            await d.save();
            depts.push(d);
        }

        console.log('Seeding Notices...');

        const today = new Date();
        const yesterday = new Date(today); yesterday.setDate(yesterday.getDate() - 1);
        const tomorrow = new Date(today); tomorrow.setDate(tomorrow.getDate() + 1);
        const lastWeek = new Date(today); lastWeek.setDate(lastWeek.getDate() - 7);
        const nextWeek = new Date(today); nextWeek.setDate(nextWeek.getDate() + 7);

        const notices = [
            {
                title: 'Welcome to Smart Notice Board',
                description: 'This is a general announcement for all students. Welcome to the new semester!',
                date: today,
                department: null, // General
                expiryDate: nextWeek
            },
            {
                title: 'CS Department Meeting',
                description: 'All CS students are requested to attend the seminar hall at 2 PM.',
                date: today,
                department: depts[0]._id, // CS
                expiryDate: tomorrow
            },
            {
                title: 'Assignment Submission Deadline',
                description: 'IT students, please submit your assignments by tomorrow.',
                date: yesterday,
                department: depts[1]._id, // IT
                expiryDate: tomorrow
            },
            {
                title: 'Old Exam Results',
                description: 'Results for the last semester have been declared.',
                date: lastWeek,
                department: null,
                expiryDate: yesterday // Expired
            },
            {
                title: 'Upcoming Hackathon',
                description: 'Join the annual hackathon next month! Register now.',
                date: today,
                department: null,
                expiryDate: new Date(today.getFullYear(), today.getMonth() + 1, 1) // Future
            }
        ];

        for (const n of notices) {
            await new Notice(n).save();
        }

        console.log('Data Seeded Successfully!');
        process.exit();
    } catch (err) {
        console.error(err);
        process.exit(1);
    }
};

seedData();
