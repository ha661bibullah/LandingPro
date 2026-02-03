// server.js - ল্যান্ডিংপ্রো ব্যাকএন্ড সার্ভার

const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

// Express অ্যাপ তৈরি
const app = express();

// সিকিউরিটি মিডলওয়্যার
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://cdn.tailwindcss.com", "https://cdnjs.cloudflare.com"],
            scriptSrc: ["'self'", "'unsafe-inline'", "https://cdn.tailwindcss.com"],
            fontSrc: ["'self'", "https://fonts.googleapis.com", "https://fonts.gstatic.com"],
            imgSrc: ["'self'", "data:", "https:"],
        },
    },
}));

// CORS কনফিগারেশন
const corsOptions = {
    origin: ['https://landingpro.online', 'https://admin.landingpro.online', 'http://localhost:3000', 'http://localhost:5000'],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'Accept']
};
app.use(cors(corsOptions));

// Rate limiting
// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per windowMs
    message: {
        success: false,
        error: 'অনেক রিকোয়েস্ট করা হয়েছে, পরে চেষ্টা করুন।'
    },
    standardHeaders: true,
    legacyHeaders: false
});
app.use('/api/', limiter);

// JSON পার্সিং
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// MongoDB কানেকশন
mongoose.connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
})
.then(() => console.log('✅ MongoDB কানেক্টেড'))
.catch(err => console.error('❌ MongoDB কানেকশন ইরর:', err));

// মডেল ডিফাইনেশন
const contactSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true,
        trim: true
    },
    email: {
        type: String,
        required: true,
        lowercase: true,
        trim: true
    },
    phone: {
        type: String,
        trim: true
    },
    package: {
        type: String,
        enum: ['বেস্ট সেলার', 'স্ট্যান্ডার্ড', 'প্রিমিয়াম', 'কাস্টম', ''],
        default: ''
    },
    message: {
        type: String,
        required: true
    },
    status: {
        type: String,
        enum: ['new', 'contacted', 'in_progress', 'completed', 'cancelled'],
        default: 'new'
    },
    ipAddress: String,
    userAgent: String,
    deviceInfo: Object,
    locationInfo: Object,
    referrer: String,
    createdAt: {
        type: Date,
        default: Date.now
    },
    updatedAt: {
        type: Date,
        default: Date.now
    }
});

const analyticsSchema = new mongoose.Schema({
    sessionId: {
        type: String,
        required: true,
        unique: true
    },
    page: {
        type: String,
        required: true
    },
    ipAddress: String,
    userAgent: String,
    deviceInfo: Object,
    locationInfo: Object,
    referrer: String,
    duration: {
        type: Number,
        default: 0
    },
    events: [{
        type: String,
        element: String,
        details: Object,
        timestamp: {
            type: Date,
            default: Date.now
        }
    }],
    scrollDepth: {
        type: Number,
        default: 0
    },
    isActive: {
        type: Boolean,
        default: true
    },
    createdAt: {
        type: Date,
        default: Date.now
    },
    lastActivity: {
        type: Date,
        default: Date.now
    }
});

const contentSchema = new mongoose.Schema({
    key: {
        type: String,
        required: true,
        unique: true
    },
    page: {
        type: String,
        required: true
    },
    section: {
        type: String,
        required: true
    },
    content: {
        type: String,
        required: true
    },
    status: {
        type: String,
        enum: ['active', 'inactive', 'draft'],
        default: 'active'
    },
    updatedBy: String,
    updatedAt: {
        type: Date,
        default: Date.now
    }
});

const adminSchema = new mongoose.Schema({
    email: {
        type: String,
        required: true,
        unique: true,
        lowercase: true,
        trim: true
    },
    password: {
        type: String,
        required: true
    },
    name: {
        type: String,
        default: 'এডমিন'
    },
    role: {
        type: String,
        enum: ['super_admin', 'admin', 'editor'],
        default: 'admin'
    },
    lastLogin: Date,
    isActive: {
        type: Boolean,
        default: true
    },
    createdAt: {
        type: Date,
        default: Date.now
    }
});

// মডেল তৈরি
const Contact = mongoose.model('Contact', contactSchema);
const Analytics = mongoose.model('Analytics', analyticsSchema);
const Content = mongoose.model('Content', contentSchema);
const Admin = mongoose.model('Admin', adminSchema);

// এডমিন ইউজার তৈরি (যদি না থাকে)
async function createAdminUser() {
    try {
        const existingAdmin = await Admin.findOne({ email: process.env.ADMIN_EMAIL });
        if (!existingAdmin) {
            const hashedPassword = await bcrypt.hash(process.env.ADMIN_PASSWORD, 10);
            const admin = new Admin({
                email: process.env.ADMIN_EMAIL,
                password: hashedPassword,
                name: 'সুপার এডমিন',
                role: 'super_admin'
            });
            await admin.save();
            console.log('✅ ডিফল্ট এডমিন ইউজার তৈরি করা হয়েছে');
        }
    } catch (error) {
        console.error('❌ এডমিন ইউজার তৈরি করতে সমস্যা:', error);
    }
}

// JWT ভেরিফিকেশন মিডলওয়্যার
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ 
            success: false, 
            error: 'অ্যাক্সেস টোকেন প্রয়োজন' 
        });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ 
                success: false, 
                error: 'অবৈধ টোকেন' 
            });
        }
        req.user = user;
        next();
    });
};

// IP অ্যাড্রেস পাওয়ার ফাংশন
const getClientIp = (req) => {
    return req.headers['x-forwarded-for'] || req.connection.remoteAddress || req.ip;
};

// হেলথ চেক এন্ডপয়েন্ট
app.get('/api/health', (req, res) => {
    res.status(200).json({
        success: true,
        message: 'ল্যান্ডিংপ্রো API সচল আছে',
        timestamp: new Date().toISOString(),
        environment: process.env.NODE_ENV || 'development'
    });
});

// রুট টেস্ট
app.get('/', (req, res) => {
    res.json({
        success: true,
        message: 'ল্যান্ডিংপ্রো ব্যাকএন্ড API',
        version: '1.0.0',
        endpoints: {
            contact: '/api/contact',
            analytics: '/api/analytics',
            content: '/api/content',
            admin: '/api/admin'
        }
    });
});

// কন্টাক্ট ফর্ম সাবমিশন
app.post('/api/contact', async (req, res) => {
    try {
        const { name, email, phone, package, message } = req.body;
        
        // ভ্যালিডেশন
        if (!name || !email || !message) {
            return res.status(400).json({
                success: false,
                error: 'নাম, ইমেইল এবং মেসেজ প্রয়োজন'
            });
        }

        // ইমেইল ভ্যালিডেশন
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({
                success: false,
                error: 'সঠিক ইমেইল ঠিকানা দিন'
            });
        }

        const contact = new Contact({
            name,
            email,
            phone: phone || '',
            package: package || '',
            message,
            ipAddress: getClientIp(req),
            userAgent: req.headers['user-agent'],
            referrer: req.headers.referer || 'direct'
        });

        await contact.save();

        res.status(201).json({
            success: true,
            message: 'আপনার মেসেজ সফলভাবে পাঠানো হয়েছে। আমরা শীঘ্রই আপনার সাথে যোগাযোগ করব।',
            data: {
                id: contact._id,
                name: contact.name,
                email: contact.email,
                package: contact.package,
                status: contact.status
            }
        });

    } catch (error) {
        console.error('কন্টাক্ট সাবমিশন ইরর:', error);
        res.status(500).json({
            success: false,
            error: 'সার্ভার ইরর হয়েছে। দয়া করে আবার চেষ্টা করুন।'
        });
    }
});

// অ্যানালিটিক্স ট্র্যাকিং
app.post('/api/analytics/track', async (req, res) => {
    try {
        const { sessionId, page, deviceInfo, location, referrer } = req.body;
        
        // Check if session already exists
        let analytics = await Analytics.findOne({ sessionId });
        
        if (!analytics) {
            analytics = new Analytics({
                sessionId,
                page: page || 'home',
                ipAddress: getClientIp(req),
                userAgent: req.headers['user-agent'],
                deviceInfo: deviceInfo || {},
                locationInfo: location || {},
                referrer: referrer || 'direct',
                isActive: true,
                lastActivity: new Date()
            });
        } else {
            analytics.page = page || analytics.page;
            analytics.lastActivity = new Date();
            analytics.isActive = true;
        }

        await analytics.save();

        res.status(200).json({
            success: true,
            message: 'অ্যানালিটিক্স ট্র্যাক করা হয়েছে'
        });

    } catch (error) {
        console.error('অ্যানালিটিক্স ট্র্যাকিং ইরর:', error);
        res.status(500).json({
            success: false,
            error: 'অ্যানালিটিক্স ট্র্যাক করতে সমস্যা হয়েছে'
        });
    }
});

// অ্যানালিটিক্স ইভেন্ট ট্র্যাকিং
app.post('/api/analytics/event', async (req, res) => {
    try {
        const { sessionId, event } = req.body;
        
        if (!sessionId || !event) {
            return res.status(400).json({
                success: false,
                error: 'সেশন আইডি এবং ইভেন্ট প্রয়োজন'
            });
        }

        const analytics = await Analytics.findOneAndUpdate(
            { sessionId },
            {
                $push: {
                    events: {
                        type: event.type,
                        element: event.element,
                        details: event.details || {},
                        timestamp: event.timestamp ? new Date(event.timestamp) : new Date()
                    }
                },
                lastActivity: new Date(),
                isActive: true
            },
            { new: true, upsert: false }
        );

        if (!analytics) {
            return res.status(404).json({
                success: false,
                error: 'সেশন পাওয়া যায়নি'
            });
        }

        res.status(200).json({
            success: true,
            message: 'ইভেন্ট ট্র্যাক করা হয়েছে'
        });

    } catch (error) {
        console.error('ইভেন্ট ট্র্যাকিং ইরর:', error);
        res.status(500).json({
            success: false,
            error: 'ইভেন্ট ট্র্যাক করতে সমস্যা হয়েছে'
        });
    }
});

// অ্যানালিটিক্স আপডেট
app.post('/api/analytics/update', async (req, res) => {
    try {
        const { sessionId, duration, scrollDepth, isActive } = req.body;
        
        const updateData = {
            lastActivity: new Date()
        };

        if (duration !== undefined) updateData.duration = duration;
        if (scrollDepth !== undefined) updateData.scrollDepth = scrollDepth;
        if (isActive !== undefined) updateData.isActive = isActive;

        const analytics = await Analytics.findOneAndUpdate(
            { sessionId },
            updateData,
            { new: true }
        );

        if (!analytics) {
            return res.status(404).json({
                success: false,
                error: 'সেশন পাওয়া যায়নি'
            });
        }

        res.status(200).json({
            success: true,
            message: 'অ্যানালিটিক্স আপডেট করা হয়েছে'
        });

    } catch (error) {
        console.error('অ্যানালিটিক্স আপডেট ইরর:', error);
        res.status(500).json({
            success: false,
            error: 'অ্যানালিটিক্স আপডেট করতে সমস্যা হয়েছে'
        });
    }
});

// এডমিন লগইন
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        if (!email || !password) {
            return res.status(400).json({
                success: false,
                error: 'ইমেইল এবং পাসওয়ার্ড প্রয়োজন'
            });
        }

        const admin = await Admin.findOne({ email });
        if (!admin) {
            return res.status(401).json({
                success: false,
                error: 'ইমেইল বা পাসওয়ার্ড ভুল'
            });
        }

        if (!admin.isActive) {
            return res.status(403).json({
                success: false,
                error: 'এই অ্যাকাউন্ট নিষ্ক্রিয় করা হয়েছে'
            });
        }

        const isPasswordValid = await bcrypt.compare(password, admin.password);
        if (!isPasswordValid) {
            return res.status(401).json({
                success: false,
                error: 'ইমেইল বা পাসওয়ার্ড ভুল'
            });
        }

        // টোকেন জেনারেট
        const token = jwt.sign(
            { 
                id: admin._id, 
                email: admin.email,
                role: admin.role 
            },
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
        );

        // লাস্ট লগইন আপডেট
        admin.lastLogin = new Date();
        await admin.save();

        res.status(200).json({
            success: true,
            message: 'সফলভাবে লগইন হয়েছে',
            token,
            admin: {
                id: admin._id,
                email: admin.email,
                name: admin.name,
                role: admin.role,
                lastLogin: admin.lastLogin
            }
        });

    } catch (error) {
        console.error('লগইন ইরর:', error);
        res.status(500).json({
            success: false,
            error: 'লগইন করতে সমস্যা হয়েছে'
        });
    }
});

// এডমিন টোকেন ভেরিফিকেশন
// এডমিন টোকেন ভেরিফিকেশন - উন্নত সংস্করণ
app.get('/api/admin/verify', authenticateToken, async (req, res) => {
    try {
        const admin = await Admin.findById(req.user.id)
            .select('-password -__v');
        
        if (!admin) {
            return res.status(404).json({
                success: false,
                error: 'এডমিন ইউজার পাওয়া যায়নি'
            });
        }

        if (!admin.isActive) {
            return res.status(403).json({
                success: false,
                error: 'এই অ্যাকাউন্ট নিষ্ক্রিয় করা হয়েছে'
            });
        }

        res.status(200).json({
            success: true,
            message: 'টোকেন ভ্যালিড',
            admin: {
                id: admin._id,
                email: admin.email,
                name: admin.name,
                role: admin.role,
                lastLogin: admin.lastLogin,
                createdAt: admin.createdAt
            }
        });

    } catch (error) {
        console.error('টোকেন ভেরিফিকেশন ইরর:', error);
        
        // Specific error handling
        if (error.name === 'JsonWebTokenError') {
            return res.status(401).json({
                success: false,
                error: 'অবৈধ টোকেন'
            });
        }
        
        if (error.name === 'TokenExpiredError') {
            return res.status(401).json({
                success: false,
                error: 'টোকেন মেয়াদ উত্তীর্ণ'
            });
        }
        
        res.status(500).json({
            success: false,
            error: 'ভেরিফিকেশন ব্যর্থ'
        });
    }
});

// এডমিন স্ট্যাটিস্টিক্স
app.get('/api/admin/stats', authenticateToken, async (req, res) => {
    try {
        // মোট কন্টাক্ট
        const totalContacts = await Contact.countDocuments();
        
        // স্ট্যাটাস অনুযায়ী কন্টাক্ট
        const statusStats = await Contact.aggregate([
            {
                $group: {
                    _id: '$status',
                    count: { $sum: 1 }
                }
            }
        ]);

        // প্যাকেজ অনুযায়ী কন্টাক্ট
        const packageStats = await Contact.aggregate([
            {
                $group: {
                    _id: '$package',
                    count: { $sum: 1 }
                }
            },
            {
                $match: {
                    _id: { $ne: '' }
                }
            }
        ]);

        // অ্যানালিটিক্স স্ট্যাটস
        const activeVisitors = await Analytics.countDocuments({ 
            isActive: true,
            lastActivity: { $gte: new Date(Date.now() - 15 * 60 * 1000) } // Last 15 minutes
        });

        const todayVisitors = await Analytics.countDocuments({
            createdAt: { $gte: new Date().setHours(0, 0, 0, 0) }
        });

        const totalPageviews = await Analytics.countDocuments();
        
        const avgSession = await Analytics.aggregate([
            {
                $group: {
                    _id: null,
                    avgDuration: { $avg: '$duration' }
                }
            }
        ]);

        res.status(200).json({
            success: true,
            stats: {
                totalContacts,
                statusStats,
                packageStats,
                analytics: {
                    activeVisitors,
                    todayVisitors,
                    totalPageviews,
                    avgSessionDuration: avgSession[0]?.avgDuration || 0
                }
            },
            counts: {
                newContacts: statusStats.find(s => s._id === 'new')?.count || 0,
                contacted: statusStats.find(s => s._id === 'contacted')?.count || 0,
                inProgress: statusStats.find(s => s._id === 'in_progress')?.count || 0,
                completed: statusStats.find(s => s._id === 'completed')?.count || 0,
                cancelled: statusStats.find(s => s._id === 'cancelled')?.count || 0
            }
        });

    } catch (error) {
        console.error('স্ট্যাটিস্টিক্স লোড ইরর:', error);
        res.status(500).json({
            success: false,
            error: 'স্ট্যাটিস্টিক্স লোড করতে সমস্যা হয়েছে'
        });
    }
});

// অ্যানালিটিক্স ডেটা
app.get('/api/admin/analytics', authenticateToken, async (req, res) => {
    try {
        // Basic stats
        const activeVisitors = await Analytics.countDocuments({ 
            isActive: true,
            lastActivity: { $gte: new Date(Date.now() - 15 * 60 * 1000) }
        });

        const todayVisitors = await Analytics.countDocuments({
            createdAt: { $gte: new Date().setHours(0, 0, 0, 0) }
        });

        const totalPageviews = await Analytics.countDocuments();
        
        const avgSession = await Analytics.aggregate([
            {
                $group: {
                    _id: null,
                    avgDuration: { $avg: '$duration' }
                }
            }
        ]);

        // Page distribution
        const pageDistribution = await Analytics.aggregate([
            {
                $group: {
                    _id: '$page',
                    count: { $sum: 1 }
                }
            },
            {
                $sort: { count: -1 }
            },
            {
                $limit: 5
            }
        ]);

        // Event analytics
        const allAnalytics = await Analytics.find({}).limit(100);
        let buttonClicks = 0;
        let formSubmissions = 0;
        let successfulForms = 0;
        let totalScrollDepth = 0;
        let totalSessions = 0;
        const buttonCounts = {};

        allAnalytics.forEach(analytics => {
            if (analytics.events) {
                analytics.events.forEach(event => {
                    if (event.type === 'click' && event.element.startsWith('button:')) {
                        buttonClicks++;
                        const buttonName = event.element.replace('button:', '');
                        buttonCounts[buttonName] = (buttonCounts[buttonName] || 0) + 1;
                    }
                    if (event.type === 'form_submit') {
                        formSubmissions++;
                    }
                    if (event.type === 'form_submit_success') {
                        successfulForms++;
                    }
                });
            }
            totalScrollDepth += analytics.scrollDepth || 0;
            totalSessions++;
        });

        const topButton = Object.entries(buttonCounts)
            .sort((a, b) => b[1] - a[1])
            .map(([button, count]) => ({ button, count }))[0];

        res.status(200).json({
            success: true,
            stats: {
                activeVisitors,
                todayVisitors,
                totalPageviews,
                avgSessionDuration: avgSession[0]?.avgDuration || 0
            },
            pageDistribution: {
                labels: pageDistribution.map(p => p._id),
                values: pageDistribution.map(p => p.count)
            },
            events: {
                buttonClicks,
                formSubmissions,
                successfulForms,
                avgScrollDepth: totalSessions > 0 ? Math.round(totalScrollDepth / totalSessions) : 0,
                avgSessionLength: avgSession[0]?.avgDuration || 0,
                topButton: topButton ? topButton.button : '-'
            }
        });

    } catch (error) {
        console.error('অ্যানালিটিক্স ডেটা লোড ইরর:', error);
        res.status(500).json({
            success: false,
            error: 'অ্যানালিটিক্স ডেটা লোড করতে সমস্যা হয়েছে'
        });
    }
});

// সক্রিয় ভিজিটর লিস্ট
app.get('/api/admin/analytics/active', authenticateToken, async (req, res) => {
    try {
        const visitors = await Analytics.find({ 
            isActive: true,
            lastActivity: { $gte: new Date(Date.now() - 15 * 60 * 1000) }
        })
        .sort({ lastActivity: -1 })
        .limit(20)
        .select('-events -__v');

        res.status(200).json({
            success: true,
            visitors
        });

    } catch (error) {
        console.error('সক্রিয় ভিজিটর লোড ইরর:', error);
        res.status(500).json({
            success: false,
            error: 'সক্রিয় ভিজিটর লোড করতে সমস্যা হয়েছে'
        });
    }
});

// ইভেন্ট লিস্ট
app.get('/api/admin/analytics/events', authenticateToken, async (req, res) => {
    try {
        const limit = parseInt(req.query.limit) || 10;
        
        const analytics = await Analytics.find({
            events: { $exists: true, $not: { $size: 0 } }
        })
        .sort({ lastActivity: -1 })
        .limit(10);

        let events = [];
        analytics.forEach(a => {
            if (a.events && a.events.length > 0) {
                const sessionEvents = a.events.map(event => ({
                    ...event.toObject(),
                    sessionId: a.sessionId,
                    timestamp: event.timestamp || a.lastActivity
                }));
                events = events.concat(sessionEvents);
            }
        });

        // Sort by timestamp and limit
        events.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
        events = events.slice(0, limit);

        res.status(200).json({
            success: true,
            events
        });

    } catch (error) {
        console.error('ইভেন্ট লিস্ট লোড ইরর:', error);
        res.status(500).json({
            success: false,
            error: 'ইভেন্ট লিস্ট লোড করতে সমস্যা হয়েছে'
        });
    }
});

// ভিজিটর ডিটেইলস
app.get('/api/admin/analytics/visitor/:sessionId', authenticateToken, async (req, res) => {
    try {
        const visitor = await Analytics.findOne({ sessionId: req.params.sessionId })
            .select('-__v');

        if (!visitor) {
            return res.status(404).json({
                success: false,
                error: 'ভিজিটর পাওয়া যায়নি'
            });
        }

        res.status(200).json({
            success: true,
            visitor
        });

    } catch (error) {
        console.error('ভিজিটর ডিটেইলস লোড ইরর:', error);
        res.status(500).json({
            success: false,
            error: 'ভিজিটর ডিটেইলস লোড করতে সমস্যা হয়েছে'
        });
    }
});

// লোকেশন ডেটা
app.get('/api/admin/analytics/locations', authenticateToken, async (req, res) => {
    try {
        const locations = await Analytics.aggregate([
            {
                $match: {
                    locationInfo: { $exists: true },
                    'locationInfo.country': { $ne: null }
                }
            },
            {
                $group: {
                    _id: {
                        country: '$locationInfo.country',
                        city: '$locationInfo.city'
                    },
                    visitors: { $sum: 1 },
                    avgDuration: { $avg: '$duration' }
                }
            },
            {
                $sort: { visitors: -1 }
            },
            {
                $limit: 10
            },
            {
                $project: {
                    country: '$_id.country',
                    city: '$_id.city',
                    visitors: 1,
                    avgDuration: 1,
                    _id: 0
                }
            }
        ]);

        // For chart data
        const chartData = {
            labels: locations.map(l => l.country),
            values: locations.map(l => l.visitors)
        };

        res.status(200).json({
            success: true,
            locations,
            chartData
        });

    } catch (error) {
        console.error('লোকেশন ডেটা লোড ইরর:', error);
        res.status(500).json({
            success: false,
            error: 'লোকেশন ডেটা লোড করতে সমস্যা হয়েছে'
        });
    }
});

// সকল কন্টাক্ট লিস্ট
app.get('/api/admin/contacts', authenticateToken, async (req, res) => {
    try {
        const { 
            page = 1, 
            limit = 10, 
            status, 
            package, 
            search,
            sortBy = 'createdAt',
            sortOrder = 'desc'
        } = req.query;

        // ফিল্টার তৈরি
        const filter = {};
        
        if (status && status !== 'all') {
            filter.status = status;
        }
        
        if (package && package !== 'all') {
            filter.package = package;
        }
        
        if (search) {
            filter.$or = [
                { name: { $regex: search, $options: 'i' } },
                { email: { $regex: search, $options: 'i' } },
                { message: { $regex: search, $options: 'i' } }
            ];
        }

        // পেজিনেশন
        const skip = (parseInt(page) - 1) * parseInt(limit);
        const sort = {};
        sort[sortBy] = sortOrder === 'desc' ? -1 : 1;

        // কন্টাক্ট লিস্ট
        const contacts = await Contact.find(filter)
            .sort(sort)
            .skip(skip)
            .limit(parseInt(limit))
            .select('-__v');

        // টোটাল কাউন্ট
        const total = await Contact.countDocuments(filter);

        res.status(200).json({
            success: true,
            contacts,
            pagination: {
                page: parseInt(page),
                limit: parseInt(limit),
                total,
                totalPages: Math.ceil(total / parseInt(limit))
            }
        });

    } catch (error) {
        console.error('কন্টাক্ট লিস্ট ইরর:', error);
        res.status(500).json({
            success: false,
            error: 'কন্টাক্ট লিস্ট লোড করতে সমস্যা হয়েছে'
        });
    }
});

// সিঙ্গেল কন্টাক্ট ডিটেইলস
app.get('/api/admin/contacts/:id', authenticateToken, async (req, res) => {
    try {
        const contact = await Contact.findById(req.params.id).select('-__v');
        
        if (!contact) {
            return res.status(404).json({
                success: false,
                error: 'কন্টাক্ট পাওয়া যায়নি'
            });
        }

        res.status(200).json({
            success: true,
            contact
        });

    } catch (error) {
        console.error('কন্টাক্ট ডিটেইলস ইরর:', error);
        res.status(500).json({
            success: false,
            error: 'কন্টাক্ট ডিটেইলস লোড করতে সমস্যা হয়েছে'
        });
    }
});

// কন্টাক্ট স্ট্যাটাস আপডেট
app.put('/api/admin/contacts/:id', authenticateToken, async (req, res) => {
    try {
        const { status } = req.body;
        
        if (!status) {
            return res.status(400).json({
                success: false,
                error: 'স্ট্যাটাস প্রয়োজন'
            });
        }

        const allowedStatus = ['new', 'contacted', 'in_progress', 'completed', 'cancelled'];
        if (!allowedStatus.includes(status)) {
            return res.status(400).json({
                success: false,
                error: 'অবৈধ স্ট্যাটাস'
            });
        }

        const contact = await Contact.findByIdAndUpdate(
            req.params.id,
            { 
                status,
                updatedAt: new Date()
            },
            { new: true }
        ).select('-__v');

        if (!contact) {
            return res.status(404).json({
                success: false,
                error: 'কন্টাক্ট পাওয়া যায়নি'
            });
        }

        res.status(200).json({
            success: true,
            message: 'স্ট্যাটাস সফলভাবে আপডেট করা হয়েছে',
            contact
        });

    } catch (error) {
        console.error('কন্টাক্ট আপডেট ইরর:', error);
        res.status(500).json({
            success: false,
            error: 'কন্টাক্ট আপডেট করতে সমস্যা হয়েছে'
        });
    }
});

// কন্টাক্ট ডিলিট
app.delete('/api/admin/contacts/:id', authenticateToken, async (req, res) => {
    try {
        const contact = await Contact.findByIdAndDelete(req.params.id);
        
        if (!contact) {
            return res.status(404).json({
                success: false,
                error: 'কন্টাক্ট পাওয়া যায়নি'
            });
        }

        res.status(200).json({
            success: true,
            message: 'কন্টাক্ট সফলভাবে ডিলিট করা হয়েছে'
        });

    } catch (error) {
        console.error('কন্টাক্ট ডিলিট ইরর:', error);
        res.status(500).json({
            success: false,
            error: 'কন্টাক্ট ডিলিট করতে সমস্যা হয়েছে'
        });
    }
});

// কন্টেন্ট ম্যানেজমেন্ট এন্ডপয়েন্টস
app.get('/api/admin/content', authenticateToken, async (req, res) => {
    try {
        const content = await Content.find().sort({ updatedAt: -1 });
        
        res.status(200).json({
            success: true,
            content
        });

    } catch (error) {
        console.error('কন্টেন্ট লিস্ট ইরর:', error);
        res.status(500).json({
            success: false,
            error: 'কন্টেন্ট লিস্ট লোড করতে সমস্যা হয়েছে'
        });
    }
});

app.post('/api/admin/content', authenticateToken, async (req, res) => {
    try {
        const { key, page, section, content, status } = req.body;
        
        if (!key || !page || !section || !content) {
            return res.status(400).json({
                success: false,
                error: 'সকল ফিল্ড প্রয়োজন'
            });
        }

        const existingContent = await Content.findOne({ key });
        let savedContent;

        if (existingContent) {
            // আপডেট
            existingContent.page = page;
            existingContent.section = section;
            existingContent.content = content;
            existingContent.status = status || 'active';
            existingContent.updatedBy = req.user.email;
            existingContent.updatedAt = new Date();
            
            savedContent = await existingContent.save();
        } else {
            // নতুন তৈরি
            const newContent = new Content({
                key,
                page,
                section,
                content,
                status: status || 'active',
                updatedBy: req.user.email
            });
            
            savedContent = await newContent.save();
        }

        res.status(200).json({
            success: true,
            message: existingContent ? 'কন্টেন্ট আপডেট করা হয়েছে' : 'কন্টেন্ট তৈরি করা হয়েছে',
            content: savedContent
        });

    } catch (error) {
        console.error('কন্টেন্ট সেভ ইরর:', error);
        res.status(500).json({
            success: false,
            error: 'কন্টেন্ট সেভ করতে সমস্যা হয়েছে'
        });
    }
});

app.put('/api/admin/content/:id', authenticateToken, async (req, res) => {
    try {
        const { content, status } = req.body;
        
        const updatedContent = await Content.findByIdAndUpdate(
            req.params.id,
            { 
                content,
                status: status || 'active',
                updatedBy: req.user.email,
                updatedAt: new Date()
            },
            { new: true }
        );

        if (!updatedContent) {
            return res.status(404).json({
                success: false,
                error: 'কন্টেন্ট পাওয়া যায়নি'
            });
        }

        res.status(200).json({
            success: true,
            message: 'কন্টেন্ট আপডেট করা হয়েছে',
            content: updatedContent
        });

    } catch (error) {
        console.error('কন্টেন্ট আপডেট ইরর:', error);
        res.status(500).json({
            success: false,
            error: 'কন্টেন্ট আপডেট করতে সমস্যা হয়েছে'
        });
    }
});

app.delete('/api/admin/content/:id', authenticateToken, async (req, res) => {
    try {
        const deletedContent = await Content.findByIdAndDelete(req.params.id);
        
        if (!deletedContent) {
            return res.status(404).json({
                success: false,
                error: 'কন্টেন্ট পাওয়া যায়নি'
            });
        }

        res.status(200).json({
            success: true,
            message: 'কন্টেন্ট ডিলিট করা হয়েছে'
        });

    } catch (error) {
        console.error('কন্টেন্ট ডিলিট ইরর:', error);
        res.status(500).json({
            success: false,
            error: 'কন্টেন্ট ডিলিট করতে সমস্যা হয়েছে'
        });
    }
});

// কন্টেন্ট গেট (পাবলিক)
app.get('/api/content', async (req, res) => {
    try {
        const content = await Content.find({ status: 'active' });
        
        const contentMap = {};
        content.forEach(item => {
            contentMap[item.key] = {
                content: item.content,
                page: item.page,
                section: item.section
            };
        });

        res.status(200).json({
            success: true,
            content: contentMap
        });

    } catch (error) {
        console.error('কন্টেন্ট লোড ইরর:', error);
        res.status(500).json({
            success: false,
            error: 'কন্টেন্ট লোড করতে সমস্যা হয়েছে'
        });
    }
});

// ইরর হ্যান্ডলিং মিডলওয়্যার
app.use((err, req, res, next) => {
    console.error('সার্ভার ইরর:', err);
    
    res.status(err.status || 500).json({
        success: false,
        error: process.env.NODE_ENV === 'production' 
            ? 'সার্ভার ইরর হয়েছে' 
            : err.message
    });
});

// 404 হ্যান্ডলিং
app.use((req, res) => {
    res.status(404).json({
        success: false,
        error: 'এন্ডপয়েন্ট পাওয়া যায়নি'
    });
});

// সার্ভার স্টার্ট
const PORT = process.env.PORT || 5000;
app.listen(PORT, async () => {
    await createAdminUser();
    console.log(`🚀 সার্ভার চলছে পোর্ট ${PORT} এ`);
    console.log(`📡 API বেস URL: http://localhost:${PORT}`);
    console.log(`🔐 এডমিন লগইন:`);
    console.log(`   📧 Email: ${process.env.ADMIN_EMAIL}`);
    console.log(`   🔑 Password: ${process.env.ADMIN_PASSWORD}`);
    console.log(`📊 ভিজিটর মনিটরিং: সক্রিয়`);
    console.log(`🔗 ফ্রন্টএন্ড URL: http://localhost:3000`);
    console.log(`🔗 এডমিন প্যানেল: http://localhost:3000/admin-panel/index.html`);
});