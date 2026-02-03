// backend/server.js - COMPLETE FIXED VERSION
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;

// CORS কনফিগারেশন
const corsOptions = {
    origin: '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
    allowedHeaders: ['Content-Type', 'Authorization', 'Origin', 'X-Requested-With', 'Accept'],
    credentials: true,
    optionsSuccessStatus: 200
};

app.use(cors(corsOptions));
app.use(express.json({ limit: '10mb' }));

// MongoDB Connection - WITH RETRY LOGIC
mongoose.connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
})
.then(() => console.log('✅ MongoDB Connected Successfully'))
.catch(err => console.error('❌ MongoDB Connection Error:', err));

// DISABLE Mongoose versioning to prevent VersionError
mongoose.set('versionKey', false);

// ================ SCHEMAS ================
const ContactSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true },
    phone: { type: String },
    package: { type: String },
    message: { type: String, required: true },
    status: { 
        type: String, 
        enum: ['new', 'contacted', 'in_progress', 'completed', 'cancelled'],
        default: 'new'
    },
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
}, { versionKey: false }); // Disable versioning

const AdminSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, default: 'admin' },
    lastLogin: { type: Date },
    createdAt: { type: Date, default: Date.now }
}, { versionKey: false });

// Analytics Schema for User Tracking - FIXED VERSION
const AnalyticsSchema = new mongoose.Schema({
    sessionId: { type: String, required: true, index: true },
    ipAddress: { type: String },
    userAgent: { type: String },
    pageViews: [{
        page: { type: String, required: true },
        timestamp: { type: Date, default: Date.now },
        duration: { type: Number, default: 0 },
        scrollDepth: { type: Number, default: 0 },
        referrer: { type: String }
    }],
    events: [{
        type: { type: String, required: true },
        element: { type: String },
        details: { type: mongoose.Schema.Types.Mixed },
        timestamp: { type: Date, default: Date.now }
    }],
    deviceInfo: {
        type: { type: String },
        browser: { type: String },
        os: { type: String },
        screenResolution: { type: String }
    },
    location: {
        country: { type: String },
        city: { type: String },
        timezone: { type: String }
    },
    startedAt: { type: Date, default: Date.now },
    lastActivity: { type: Date, default: Date.now },
    duration: { type: Number, default: 0 }
}, { 
    versionKey: false, // Disable versioning
    timestamps: false // Disable automatic timestamps
});

// Content Management Schema
const ContentSchema = new mongoose.Schema({
    page: { type: String, required: true },
    section: { type: String, required: true },
    type: { type: String, enum: ['text', 'image', 'video', 'list', 'card'], default: 'text' },
    key: { type: String, required: true, unique: true },
    title: { type: String },
    content: { type: mongoose.Schema.Types.Mixed },
    imageUrl: { type: String },
    altText: { type: String },
    link: { type: String },
    order: { type: Number, default: 0 },
    isActive: { type: Boolean, default: true },
    styles: {
        color: { type: String },
        bgColor: { type: String },
        fontSize: { type: String },
        fontFamily: { type: String },
        customClass: { type: String }
    },
    meta: {
        createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'Admin' },
        updatedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'Admin' },
        createdAt: { type: Date, default: Date.now },
        updatedAt: { type: Date, default: Date.now }
    }
}, { versionKey: false });

// Pricing Packages Schema
const PackageSchema = new mongoose.Schema({
    name: { type: String, required: true, unique: true },
    title: { type: String, required: true },
    price: { type: Number, required: true },
    currency: { type: String, default: 'BDT' },
    symbol: { type: String, default: '৳' },
    description: { type: String },
    features: [{ type: String }],
    isPopular: { type: Boolean, default: false },
    order: { type: Number, default: 0 },
    isActive: { type: Boolean, default: true },
    buttonText: { type: String, default: 'প্যাকেজ নির্বাচন করুন' },
    buttonColor: { type: String, default: 'bg-blue-600' },
    highlightColor: { type: String, default: 'bg-blue-500' },
    meta: {
        createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'Admin' },
        updatedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'Admin' },
        createdAt: { type: Date, default: Date.now },
        updatedAt: { type: Date, default: Date.now }
    }
}, { versionKey: false });

// Portfolio Projects Schema
const ProjectSchema = new mongoose.Schema({
    title: { type: String, required: true },
    slug: { type: String, required: true, unique: true },
    description: { type: String, required: true },
    shortDescription: { type: String },
    category: { type: String, default: 'landing-page' },
    client: { type: String },
    technologies: [{ type: String }],
    features: [{ type: String }],
    imageUrl: { type: String },
    liveUrl: { type: String },
    githubUrl: { type: String },
    colors: {
        primary: { type: String, default: '#3B82F6' },
        secondary: { type: String, default: '#8B5CF6' }
    },
    order: { type: Number, default: 0 },
    isActive: { type: Boolean, default: true },
    isFeatured: { type: Boolean, default: false },
    meta: {
        createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'Admin' },
        updatedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'Admin' },
        createdAt: { type: Date, default: Date.now },
        updatedAt: { type: Date, default: Date.now }
    }
}, { versionKey: false });

const Contact = mongoose.model('Contact', ContactSchema);
const Admin = mongoose.model('Admin', AdminSchema);
const Analytics = mongoose.model('Analytics', AnalyticsSchema);
const Content = mongoose.model('Content', ContentSchema);
const Package = mongoose.model('Package', PackageSchema);
const Project = mongoose.model('Project', ProjectSchema);

// ================ MIDDLEWARES ================
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Access token required' });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid or expired token' });
        }
        req.user = user;
        next();
    });
};

// Optimistic concurrency control middleware
const optimisticUpdate = async (Model, id, updateFn, maxRetries = 3) => {
    let retries = 0;
    
    while (retries < maxRetries) {
        try {
            const doc = await Model.findById(id);
            if (!doc) {
                throw new Error('Document not found');
            }
            
            // Apply update function
            updateFn(doc);
            
            // Save without version checking
            await doc.save();
            return doc;
        } catch (error) {
            retries++;
            if (retries >= maxRetries) {
                throw error;
            }
            // Wait a bit before retrying
            await new Promise(resolve => setTimeout(resolve, 100 * retries));
        }
    }
};

// Initialize Admin Account
const initializeAdmin = async () => {
    try {
        const adminExists = await Admin.findOne({ email: process.env.ADMIN_EMAIL });
        if (!adminExists) {
            const hashedPassword = await bcrypt.hash(process.env.ADMIN_PASSWORD, 10);
            const admin = new Admin({
                email: process.env.ADMIN_EMAIL,
                password: hashedPassword
            });
            await admin.save();
            console.log('✅ Admin account created successfully');
        } else {
            console.log('✅ Admin account already exists');
        }
    } catch (error) {
        console.error('❌ Error creating admin account:', error);
    }
};

// Initialize Default Content
const initializeDefaultContent = async () => {
    try {
        const defaultContents = [
            {
                page: 'home',
                section: 'hero',
                type: 'text',
                key: 'hero_title',
                title: 'হিরো শিরোনাম',
                content: 'পূর্ণ স্ট্যাক ল্যান্ডিং পেজ ডেভেলপমেন্ট'
            },
            {
                page: 'home',
                section: 'hero',
                type: 'text',
                key: 'hero_subtitle',
                title: 'হিরো সাবটাইটেল',
                content: 'ল্যান্ডিংপ্রো তৈরি করে উচ্চ-কনভার্শন ল্যান্ডিং পেজ HTML, Tailwind CSS, JavaScript, Node.js, Express.js এবং অন্যান্য আধুনিক টেকনোলজি ব্যবহার করে।'
            },
            {
                page: 'home',
                section: 'hero',
                type: 'text',
                key: 'hero_button_primary',
                title: 'প্রাথমিক বাটন টেক্সট',
                content: 'ফ্রি কনসাল্টেশন বুক করুন'
            },
            {
                page: 'home',
                section: 'hero',
                type: 'text',
                key: 'hero_button_secondary',
                title: 'সেকেন্ডারি বাটন টেক্সট',
                content: 'আমার কাজ দেখুন'
            },
            {
                page: 'home',
                section: 'services',
                type: 'text',
                key: 'services_title',
                title: 'সার্ভিস শিরোনাম',
                content: 'ল্যান্ডিংপ্রো এর স্পেশালাইজড সার্ভিস'
            },
            {
                page: 'home',
                section: 'contact',
                type: 'text',
                key: 'contact_phone',
                title: 'ফোন নম্বর',
                content: '+৮৮০ ১৩২৬১৯৮৪৫৬'
            },
            {
                page: 'home',
                section: 'contact',
                type: 'text',
                key: 'contact_email',
                title: 'ইমেইল',
                content: 'billaharif661@gmail.com'
            }
        ];

        for (const content of defaultContents) {
            const exists = await Content.findOne({ key: content.key });
            if (!exists) {
                await Content.create({
                    ...content,
                    meta: {
                        createdBy: null,
                        updatedBy: null
                    }
                });
            }
        }
        console.log('✅ Default content initialized');
    } catch (error) {
        console.error('❌ Error initializing content:', error);
    }
};

// Initialize Default Packages
const initializeDefaultPackages = async () => {
    try {
        const defaultPackages = [
            {
                name: 'বেস্ট সেলার',
                title: 'বেস্ট সেলার',
                price: 2999,
                description: 'প্রারম্ভিক ব্যবসার জন্য',
                features: [
                    '১ পেজ ল্যান্ডিং পেজ',
                    'HTML + Tailwind CSS',
                    'বেসিক JavaScript',
                    'রেসপনসিভ ডিজাইন',
                    'কন্টাক্ট ফর্ম',
                    '৭ দিন সাপোর্ট'
                ],
                isPopular: false,
                order: 1
            },
            {
                name: 'স্ট্যান্ডার্ড',
                title: 'স্ট্যান্ডার্ড',
                price: 12000,
                description: 'ফুল ফাংশনাল ল্যান্ডিং পেজের জন্য',
                features: [
                    '৩-৫ পেজ ল্যান্ডিং পেজ',
                    'HTML + Tailwind CSS + JS',
                    'Node.js + Express.js ব্যাকএন্ড',
                    'বেসিক REST API',
                    'ডাটাবেজ কানেকশন (MongoDB)',
                    'ফর্ম হ্যান্ডলিং ও ভ্যালিডেশন'
                ],
                isPopular: true,
                order: 2,
                highlightColor: 'bg-blue-500'
            },
            {
                name: 'প্রিমিয়াম',
                title: 'প্রিমিয়াম',
                price: 25000,
                description: 'কাস্টম ও জটিল প্রকল্পের জন্য',
                features: [
                    '৫+ পেজ ল্যান্ডিং পেজ',
                    'সম্পূর্ণ ফুল স্ট্যাক ডেভেলপমেন্ট',
                    'এডভান্সড API ডেভেলপমেন্ট',
                    'মাল্টিপল ডাটাবেজ ইন্টিগ্রেশন',
                    'অ্যাডমিন প্যানেল',
                    '৩ মাস সাপোর্ট ও মেইনটেনেন্স'
                ],
                isPopular: false,
                order: 3
            }
        ];

        for (const pkg of defaultPackages) {
            const exists = await Package.findOne({ name: pkg.name });
            if (!exists) {
                await Package.create({
                    ...pkg,
                    meta: {
                        createdBy: null,
                        updatedBy: null
                    }
                });
            }
        }
        console.log('✅ Default packages initialized');
    } catch (error) {
        console.error('❌ Error initializing packages:', error);
    }
};

// ================ ROUTES ================

// Health Check
app.get('/api/health', (req, res) => {
    const mongoStatus = mongoose.connection.readyState === 1 ? 'connected' : 'disconnected';
    res.json({ 
        success: true,
        status: 'healthy', 
        timestamp: new Date().toISOString(),
        mongodb: mongoStatus,
        service: 'LandingPro Backend API v2.1'
    });
});

// Root
app.get('/', (req, res) => {
    res.json({ 
        message: 'LandingPro API v2.1',
        version: '2.1.0',
        features: ['Content Management', 'User Analytics', 'Admin Panel', 'Contact Management'],
        endpoints: {
            public: ['/api/content', '/api/analytics/track', '/api/contact'],
            admin: ['/api/admin/*'],
            health: '/api/health'
        }
    });
});

// ================ ANALYTICS ROUTES - FIXED VERSION ================

// Track page view - SIMPLIFIED VERSION
app.post('/api/analytics/track', async (req, res) => {
    try {
        const { 
            sessionId, 
            page, 
            ipAddress, 
            userAgent, 
            deviceInfo, 
            location,
            referrer
        } = req.body;

        if (!sessionId || !page) {
            return res.status(400).json({ error: 'sessionId and page are required' });
        }

        // Use findOneAndUpdate with upsert to avoid version conflicts
        const analytics = await Analytics.findOneAndUpdate(
            { sessionId },
            {
                $setOnInsert: {
                    sessionId,
                    ipAddress,
                    userAgent,
                    deviceInfo,
                    location,
                    startedAt: new Date()
                },
                $set: {
                    lastActivity: new Date()
                },
                $push: {
                    pageViews: {
                        page,
                        timestamp: new Date(),
                        referrer,
                        duration: 0,
                        scrollDepth: 0
                    }
                }
            },
            {
                upsert: true,
                new: true,
                setDefaultsOnInsert: true
            }
        );

        res.json({ success: true, message: 'Analytics tracked successfully', sessionId });
    } catch (error) {
        console.error('Analytics tracking error:', error);
        res.status(500).json({ error: 'Failed to track analytics' });
    }
});

// Update session - FIXED VERSION
app.post('/api/analytics/update', async (req, res) => {
    try {
        const { sessionId, page, duration, scrollDepth, event } = req.body;

        if (!sessionId) {
            return res.status(400).json({ error: 'sessionId is required' });
        }

        // Create update object
        const update = {
            lastActivity: new Date()
        };

        // Calculate total duration
        const session = await Analytics.findOne({ sessionId });
        if (session) {
            const totalDuration = Math.floor((new Date() - session.startedAt) / 1000);
            update.duration = totalDuration;
        }

        // Update last page view duration and scroll depth
        if (page && (duration !== undefined || scrollDepth !== undefined)) {
            const session = await Analytics.findOne({ sessionId });
            if (session && session.pageViews.length > 0) {
                const lastPageViewIndex = session.pageViews.length - 1;
                const lastPageView = session.pageViews[lastPageViewIndex];
                
                if (lastPageView.page === page) {
                    const pageViewUpdate = {};
                    if (duration !== undefined) pageViewUpdate[`pageViews.${lastPageViewIndex}.duration`] = duration;
                    if (scrollDepth !== undefined) pageViewUpdate[`pageViews.${lastPageViewIndex}.scrollDepth`] = scrollDepth;
                    
                    await Analytics.updateOne(
                        { sessionId, [`pageViews.${lastPageViewIndex}.page`]: page },
                        { $set: pageViewUpdate }
                    );
                }
            }
        }

        // Add event if provided
        if (event) {
            update.$push = {
                events: {
                    type: event.type,
                    element: event.element,
                    details: event.details,
                    timestamp: new Date()
                }
            };
        }

        // Use updateOne instead of findOneAndUpdate for atomic updates
        await Analytics.updateOne(
            { sessionId },
            update,
            { upsert: false }
        );

        res.json({ success: true, message: 'Session updated successfully' });
    } catch (error) {
        console.error('Analytics update error:', error);
        res.status(500).json({ error: 'Failed to update analytics' });
    }
});

// Get analytics data (admin only)
app.get('/api/admin/analytics', authenticateToken, async (req, res) => {
    try {
        const { 
            startDate, 
            endDate, 
            page,
            limit = 100
        } = req.query;

        const query = {};
        
        // Date filtering
        if (startDate || endDate) {
            query.startedAt = {};
            if (startDate) query.startedAt.$gte = new Date(startDate);
            if (endDate) query.startedAt.$lte = new Date(endDate);
        }

        const analytics = await Analytics.find(query)
            .sort({ startedAt: -1 })
            .limit(parseInt(limit));

        // Calculate statistics
        const totalSessions = analytics.length;
        const totalPageViews = analytics.reduce((sum, session) => sum + session.pageViews.length, 0);
        const avgDuration = totalSessions > 0 
            ? analytics.reduce((sum, session) => sum + (session.duration || 0), 0) / totalSessions 
            : 0;

        // Get top pages
        const pageCounts = {};
        analytics.forEach(session => {
            session.pageViews.forEach(view => {
                pageCounts[view.page] = (pageCounts[view.page] || 0) + 1;
            });
        });

        const topPages = Object.entries(pageCounts)
            .map(([page, count]) => ({ page, count }))
            .sort((a, b) => b.count - a.count)
            .slice(0, 10);

        // Get device distribution
        const deviceDistribution = {};
        analytics.forEach(session => {
            const device = session.deviceInfo?.type || 'unknown';
            deviceDistribution[device] = (deviceDistribution[device] || 0) + 1;
        });

        // Get event counts
        const eventCounts = {};
        analytics.forEach(session => {
            session.events?.forEach(event => {
                eventCounts[event.type] = (eventCounts[event.type] || 0) + 1;
            });
        });

        // Today's visitors
        const today = new Date();
        today.setHours(0, 0, 0, 0);
        const visitorsToday = await Analytics.countDocuments({
            startedAt: { $gte: today }
        });

        // Active visitors (last 5 minutes)
        const fiveMinutesAgo = new Date(Date.now() - 5 * 60 * 1000);
        const activeVisitors = await Analytics.countDocuments({
            lastActivity: { $gte: fiveMinutesAgo }
        });

        res.json({
            success: true,
            stats: {
                totalSessions,
                totalPageViews,
                avgSessionDuration: Math.round(avgDuration),
                bounceRate: totalSessions > 0 ? 
                    Math.round((analytics.filter(s => s.pageViews.length <= 1).length / totalSessions) * 100) : 0,
                visitorsToday,
                activeVisitors
            },
            topPages,
            deviceDistribution,
            eventCounts,
            recentSessions: analytics.slice(0, 10).map(session => ({
                sessionId: session.sessionId.substring(0, 8),
                ipAddress: session.ipAddress,
                location: session.location,
                deviceInfo: session.deviceInfo,
                currentPage: session.pageViews.length > 0 ? session.pageViews[session.pageViews.length - 1].page : 'unknown',
                sessionDuration: session.duration || 0,
                pageViews: session.pageViews.length,
                startedAt: session.startedAt,
                lastActivity: session.lastActivity
            }))
        });
    } catch (error) {
        console.error('Get analytics error:', error);
        res.status(500).json({ error: 'Failed to fetch analytics' });
    }
});

// Get real-time visitors
app.get('/api/admin/analytics/realtime', authenticateToken, async (req, res) => {
    try {
        const fiveMinutesAgo = new Date(Date.now() - 5 * 60 * 1000);
        
        const activeSessions = await Analytics.find({
            lastActivity: { $gte: fiveMinutesAgo }
        }).sort({ lastActivity: -1 }).limit(20);

        const activeVisitors = activeSessions.length;

        res.json({
            success: true,
            activeVisitors,
            sessions: activeSessions.map(session => ({
                sessionId: session.sessionId.substring(0, 8),
                ipAddress: session.ipAddress?.substring(0, 15) || 'Unknown',
                location: session.location || { country: 'Unknown', city: 'Unknown' },
                deviceInfo: session.deviceInfo || { type: 'unknown' },
                currentPage: session.pageViews.length > 0 ? 
                    session.pageViews[session.pageViews.length - 1].page : 'unknown',
                sessionDuration: session.duration || 0,
                pageViews: session.pageViews.length,
                lastActivity: session.lastActivity
            }))
        });
    } catch (error) {
        console.error('Realtime analytics error:', error);
        res.status(500).json({ error: 'Failed to fetch realtime analytics' });
    }
});

// Clear old analytics data (optional)
app.delete('/api/admin/analytics/cleanup', authenticateToken, async (req, res) => {
    try {
        const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
        
        const result = await Analytics.deleteMany({
            startedAt: { $lt: thirtyDaysAgo }
        });

        res.json({
            success: true,
            message: `Cleaned up ${result.deletedCount} old analytics records`,
            deletedCount: result.deletedCount
        });
    } catch (error) {
        console.error('Analytics cleanup error:', error);
        res.status(500).json({ error: 'Failed to cleanup analytics' });
    }
});

// ================ CONTENT MANAGEMENT ROUTES ================

// Get all content (public)
app.get('/api/content', async (req, res) => {
    try {
        const { page, section } = req.query;
        const query = { isActive: true };
        
        if (page) query.page = page;
        if (section) query.section = section;

        const content = await Content.find(query).sort({ order: 1 });
        
        const contentMap = {};
        content.forEach(item => {
            contentMap[item.key] = {
                type: item.type,
                title: item.title,
                content: item.content,
                imageUrl: item.imageUrl,
                altText: item.altText,
                link: item.link,
                styles: item.styles
            };
        });

        res.json({ success: true, content: contentMap });
    } catch (error) {
        console.error('Get content error:', error);
        res.status(500).json({ error: 'Failed to fetch content' });
    }
});

// Get all content with admin access
app.get('/api/admin/content', authenticateToken, async (req, res) => {
    try {
        const { page, section, search } = req.query;
        const query = {};
        
        if (page && page !== 'all') query.page = page;
        if (section && section !== 'all') query.section = section;
        if (search) {
            query.$or = [
                { key: { $regex: search, $options: 'i' } },
                { title: { $regex: search, $options: 'i' } },
                { content: { $regex: search, $options: 'i' } }
            ];
        }

        const content = await Content.find(query).sort({ page: 1, section: 1, order: 1 });
        res.json({ success: true, content });
    } catch (error) {
        console.error('Get admin content error:', error);
        res.status(500).json({ error: 'Failed to fetch content' });
    }
});

// Get single content item
app.get('/api/admin/content/:id', authenticateToken, async (req, res) => {
    try {
        const content = await Content.findById(req.params.id);
        if (!content) {
            return res.status(404).json({ error: 'Content not found' });
        }
        res.json({ success: true, content });
    } catch (error) {
        console.error('Get content item error:', error);
        res.status(500).json({ error: 'Failed to fetch content item' });
    }
});

// Create/Update content
app.post('/api/admin/content', authenticateToken, async (req, res) => {
    try {
        const { key, page, section, type, title, content, imageUrl, altText, link, order, isActive, styles } = req.body;
        
        if (!key || !page || !section || !type) {
            return res.status(400).json({ error: 'Key, page, section and type are required' });
        }

        const existingContent = await Content.findOne({ key });
        let result;

        if (existingContent) {
            // Update existing
            existingContent.page = page;
            existingContent.section = section;
            existingContent.type = type;
            existingContent.title = title;
            existingContent.content = content;
            existingContent.imageUrl = imageUrl;
            existingContent.altText = altText;
            existingContent.link = link;
            existingContent.order = order || existingContent.order;
            existingContent.isActive = isActive !== undefined ? isActive : existingContent.isActive;
            existingContent.styles = styles || existingContent.styles;
            existingContent.meta.updatedAt = new Date();
            existingContent.meta.updatedBy = req.user.id;

            result = await existingContent.save();
        } else {
            // Create new
            const newContent = new Content({
                key,
                page,
                section,
                type,
                title,
                content,
                imageUrl,
                altText,
                link,
                order: order || 0,
                isActive: isActive !== undefined ? isActive : true,
                styles,
                meta: {
                    createdBy: req.user.id,
                    updatedBy: req.user.id,
                    createdAt: new Date(),
                    updatedAt: new Date()
                }
            });

            result = await newContent.save();
        }

        res.json({
            success: true,
            message: existingContent ? 'Content updated successfully' : 'Content created successfully',
            data: result
        });
    } catch (error) {
        console.error('Save content error:', error);
        res.status(500).json({ error: 'Failed to save content' });
    }
});

// Delete content
app.delete('/api/admin/content/:id', authenticateToken, async (req, res) => {
    try {
        const content = await Content.findByIdAndDelete(req.params.id);
        if (!content) {
            return res.status(404).json({ error: 'Content not found' });
        }
        res.json({ success: true, message: 'Content deleted successfully' });
    } catch (error) {
        console.error('Delete content error:', error);
        res.status(500).json({ error: 'Failed to delete content' });
    }
});

// ================ PACKAGE MANAGEMENT ROUTES ================

// Get all packages (public)
app.get('/api/packages', async (req, res) => {
    try {
        const packages = await Package.find({ isActive: true }).sort({ order: 1 });
        res.json({ success: true, packages });
    } catch (error) {
        console.error('Get packages error:', error);
        res.status(500).json({ error: 'Failed to fetch packages' });
    }
});

// Get all packages (admin)
app.get('/api/admin/packages', authenticateToken, async (req, res) => {
    try {
        const packages = await Package.find().sort({ order: 1 });
        res.json({ success: true, packages });
    } catch (error) {
        console.error('Get admin packages error:', error);
        res.status(500).json({ error: 'Failed to fetch packages' });
    }
});

// Create/Update package
app.post('/api/admin/packages', authenticateToken, async (req, res) => {
    try {
        const { 
            id,
            name, 
            title, 
            price, 
            description, 
            features, 
            isPopular, 
            order, 
            isActive,
            buttonText,
            buttonColor,
            highlightColor,
            currency,
            symbol
        } = req.body;
        
        if (!name || !title || price === undefined) {
            return res.status(400).json({ error: 'Name, title and price are required' });
        }

        let packageData;
        let isNew = false;

        if (id) {
            packageData = await Package.findById(id);
            if (!packageData) {
                return res.status(404).json({ error: 'Package not found' });
            }
        } else {
            packageData = new Package();
            isNew = true;
        }

        packageData.name = name;
        packageData.title = title;
        packageData.price = price;
        packageData.description = description;
        packageData.features = features || [];
        packageData.isPopular = isPopular || false;
        packageData.order = order || 0;
        packageData.isActive = isActive !== undefined ? isActive : true;
        packageData.buttonText = buttonText || 'প্যাকেজ নির্বাচন করুন';
        packageData.buttonColor = buttonColor || 'bg-blue-600';
        packageData.highlightColor = highlightColor || 'bg-blue-500';
        packageData.currency = currency || 'BDT';
        packageData.symbol = symbol || '৳';

        if (isNew) {
            packageData.meta = {
                createdBy: req.user.id,
                updatedBy: req.user.id,
                createdAt: new Date(),
                updatedAt: new Date()
            };
        } else {
            packageData.meta.updatedBy = req.user.id;
            packageData.meta.updatedAt = new Date();
        }

        const result = await packageData.save();

        res.json({
            success: true,
            message: isNew ? 'Package created successfully' : 'Package updated successfully',
            data: result
        });
    } catch (error) {
        console.error('Save package error:', error);
        res.status(500).json({ error: 'Failed to save package' });
    }
});

// Delete package
app.delete('/api/admin/packages/:id', authenticateToken, async (req, res) => {
    try {
        const packageData = await Package.findByIdAndDelete(req.params.id);
        if (!packageData) {
            return res.status(404).json({ error: 'Package not found' });
        }
        res.json({ success: true, message: 'Package deleted successfully' });
    } catch (error) {
        console.error('Delete package error:', error);
        res.status(500).json({ error: 'Failed to delete package' });
    }
});

// ================ PROJECT MANAGEMENT ROUTES ================

// Get all projects (public)
app.get('/api/projects', async (req, res) => {
    try {
        const projects = await Project.find({ isActive: true }).sort({ order: 1 });
        res.json({ success: true, projects });
    } catch (error) {
        console.error('Get projects error:', error);
        res.status(500).json({ error: 'Failed to fetch projects' });
    }
});

// Get all projects (admin)
app.get('/api/admin/projects', authenticateToken, async (req, res) => {
    try {
        const projects = await Project.find().sort({ order: 1 });
        res.json({ success: true, projects });
    } catch (error) {
        console.error('Get admin projects error:', error);
        res.status(500).json({ error: 'Failed to fetch projects' });
    }
});

// Create/Update project
app.post('/api/admin/projects', authenticateToken, async (req, res) => {
    try {
        const { 
            id,
            title,
            slug,
            description,
            shortDescription,
            category,
            client,
            technologies,
            features,
            imageUrl,
            liveUrl,
            githubUrl,
            colors,
            order,
            isActive,
            isFeatured
        } = req.body;
        
        if (!title || !slug || !description) {
            return res.status(400).json({ error: 'Title, slug and description are required' });
        }

        let project;
        let isNew = false;

        if (id) {
            project = await Project.findById(id);
            if (!project) {
                return res.status(404).json({ error: 'Project not found' });
            }
        } else {
            project = new Project();
            isNew = true;
        }

        project.title = title;
        project.slug = slug;
        project.description = description;
        project.shortDescription = shortDescription;
        project.category = category || 'landing-page';
        project.client = client;
        project.technologies = technologies || [];
        project.features = features || [];
        project.imageUrl = imageUrl;
        project.liveUrl = liveUrl;
        project.githubUrl = githubUrl;
        project.colors = colors || { primary: '#3B82F6', secondary: '#8B5CF6' };
        project.order = order || 0;
        project.isActive = isActive !== undefined ? isActive : true;
        project.isFeatured = isFeatured || false;

        if (isNew) {
            project.meta = {
                createdBy: req.user.id,
                updatedBy: req.user.id,
                createdAt: new Date(),
                updatedAt: new Date()
            };
        } else {
            project.meta.updatedBy = req.user.id;
            project.meta.updatedAt = new Date();
        }

        const result = await project.save();

        res.json({
            success: true,
            message: isNew ? 'Project created successfully' : 'Project updated successfully',
            data: result
        });
    } catch (error) {
        console.error('Save project error:', error);
        res.status(500).json({ error: 'Failed to save project' });
    }
});

// Delete project
app.delete('/api/admin/projects/:id', authenticateToken, async (req, res) => {
    try {
        const project = await Project.findByIdAndDelete(req.params.id);
        if (!project) {
            return res.status(404).json({ error: 'Project not found' });
        }
        res.json({ success: true, message: 'Project deleted successfully' });
    } catch (error) {
        console.error('Delete project error:', error);
        res.status(500).json({ error: 'Failed to delete project' });
    }
});

// ================ EXISTING ROUTES ================

// Login Route
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password are required' });
        }
        
        const admin = await Admin.findOne({ email });
        if (!admin) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const validPassword = await bcrypt.compare(password, admin.password);
        if (!validPassword) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        admin.lastLogin = new Date();
        await admin.save();

        const token = jwt.sign(
            { id: admin._id, email: admin.email, role: admin.role },
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
        );
        
        res.json({
            success: true,
            token,
            admin: {
                id: admin._id,
                email: admin.email,
                role: admin.role,
                lastLogin: admin.lastLogin
            }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Submit Contact Form
app.post('/api/contact', async (req, res) => {
    try {
        const { name, email, phone, package, message } = req.body;
        
        if (!name || !email || !message) {
            return res.status(400).json({ error: 'Name, email and message are required' });
        }
        
        const contact = new Contact({
            name,
            email,
            phone: phone || '+৮৮০ ১৩২৬১৯৮৪৫৬',
            package,
            message
        });

        await contact.save();
        
        console.log('📧 New contact submission:', {
            name,
            email,
            phone,
            package,
            timestamp: new Date().toISOString()
        });

        res.status(201).json({ 
            success: true, 
            message: 'Message sent successfully',
            data: contact
        });
    } catch (error) {
        console.error('Contact submission error:', error);
        res.status(500).json({ error: 'Failed to send message' });
    }
});

// Admin contact routes
app.get('/api/admin/contacts', authenticateToken, async (req, res) => {
    try {
        const { 
            page = 1, 
            limit = 10, 
            status, 
            search,
            sortBy = 'createdAt',
            sortOrder = 'desc' 
        } = req.query;

        const query = {};
        
        if (status && status !== 'all') {
            query.status = status;
        }
        
        if (search) {
            query.$or = [
                { name: { $regex: search, $options: 'i' } },
                { email: { $regex: search, $options: 'i' } },
                { message: { $regex: search, $options: 'i' } }
            ];
        }

        const skip = (page - 1) * limit;
        const sort = { [sortBy]: sortOrder === 'desc' ? -1 : 1 };

        const contacts = await Contact.find(query)
            .sort(sort)
            .skip(skip)
            .limit(parseInt(limit));

        const total = await Contact.countDocuments(query);
        const totalPages = Math.ceil(total / limit);

        res.json({
            success: true,
            contacts,
            pagination: {
                page: parseInt(page),
                limit: parseInt(limit),
                total,
                totalPages
            }
        });
    } catch (error) {
        console.error('Get contacts error:', error);
        res.status(500).json({ error: 'Failed to fetch contacts' });
    }
});

// Get single contact
app.get('/api/admin/contacts/:id', authenticateToken, async (req, res) => {
    try {
        const contact = await Contact.findById(req.params.id);
        if (!contact) {
            return res.status(404).json({ error: 'Contact not found' });
        }
        res.json({ success: true, contact });
    } catch (error) {
        console.error('Get contact error:', error);
        res.status(500).json({ error: 'Failed to fetch contact' });
    }
});

// Update contact status
app.put('/api/admin/contacts/:id', authenticateToken, async (req, res) => {
    try {
        const { status } = req.body;
        
        if (!status) {
            return res.status(400).json({ error: 'Status is required' });
        }
        
        const contact = await Contact.findByIdAndUpdate(
            req.params.id,
            { 
                status,
                updatedAt: new Date()
            },
            { new: true }
        );

        if (!contact) {
            return res.status(404).json({ error: 'Contact not found' });
        }

        res.json({
            success: true,
            message: 'Contact updated successfully',
            data: contact
        });
    } catch (error) {
        console.error('Update contact error:', error);
        res.status(500).json({ error: 'Failed to update contact' });
    }
});

// Delete contact
app.delete('/api/admin/contacts/:id', authenticateToken, async (req, res) => {
    try {
        const contact = await Contact.findByIdAndDelete(req.params.id);
        
        if (!contact) {
            return res.status(404).json({ error: 'Contact not found' });
        }

        res.json({
            success: true,
            message: 'Contact deleted successfully'
        });
    } catch (error) {
        console.error('Delete contact error:', error);
        res.status(500).json({ error: 'Failed to delete contact' });
    }
});

// Get dashboard statistics
app.get('/api/admin/stats', authenticateToken, async (req, res) => {
    try {
        const totalContacts = await Contact.countDocuments();
        const newContacts = await Contact.countDocuments({ status: 'new' });
        const contacted = await Contact.countDocuments({ status: 'contacted' });
        const inProgress = await Contact.countDocuments({ status: 'in_progress' });
        const completed = await Contact.countDocuments({ status: 'completed' });
        const cancelled = await Contact.countDocuments({ status: 'cancelled' });

        // Analytics stats
        const today = new Date();
        today.setHours(0, 0, 0, 0);
        const visitorsToday = await Analytics.countDocuments({
            startedAt: { $gte: today }
        });

        const totalVisitors = await Analytics.countDocuments();
        
        // Calculate total page views
        const analytics = await Analytics.find({});
        let totalPageViews = 0;
        analytics.forEach(session => {
            totalPageViews += session.pageViews.length;
        });

        // Content stats
        const totalContent = await Content.countDocuments();
        const activeContent = await Content.countDocuments({ isActive: true });
        const totalPackages = await Package.countDocuments();
        const totalProjects = await Project.countDocuments();

        // Package distribution
        const packageStats = await Contact.aggregate([
            { $group: { _id: '$package', count: { $sum: 1 } } },
            { $sort: { count: -1 } }
        ]);

        // Status distribution
        const statusStats = await Contact.aggregate([
            { $group: { _id: '$status', count: { $sum: 1 } } },
            { $sort: { count: -1 } }
        ]);

        res.json({
            success: true,
            totalContacts,
            newContacts,
            contacted,
            inProgress,
            completed,
            cancelled,
            packageStats,
            statusStats,
            analytics: {
                visitorsToday,
                totalVisitors,
                totalPageViews
            },
            content: {
                totalContent,
                activeContent,
                totalPackages,
                totalProjects
            }
        });
    } catch (error) {
        console.error('Get stats error:', error);
        res.status(500).json({ error: 'Failed to fetch statistics' });
    }
});

// Verify token
app.get('/api/admin/verify', authenticateToken, async (req, res) => {
    try {
        const admin = await Admin.findById(req.user.id);
        if (!admin) {
            return res.status(404).json({ error: 'Admin not found' });
        }
        
        res.json({
            success: true,
            admin: {
                id: admin._id,
                email: admin.email,
                role: admin.role,
                lastLogin: admin.lastLogin
            }
        });
    } catch (error) {
        console.error('Verify token error:', error);
        res.status(500).json({ error: 'Failed to verify token' });
    }
});

// ================ 404 HANDLER ================
app.use('*', (req, res) => {
    res.status(404).json({
        success: false,
        error: 'Endpoint not found',
        availableEndpoints: {
            home: '/',
            login: '/api/login',
            contact: '/api/contact',
            health: '/api/health',
            content: '/api/content',
            packages: '/api/packages',
            projects: '/api/projects',
            analytics: {
                track: '/api/analytics/track',
                update: '/api/analytics/update'
            },
            admin: {
                contacts: '/api/admin/contacts',
                stats: '/api/admin/stats',
                verify: '/api/admin/verify',
                content: '/api/admin/content',
                packages: '/api/admin/packages',
                projects: '/api/admin/projects',
                analytics: '/api/admin/analytics',
                analytics_realtime: '/api/admin/analytics/realtime'
            }
        }
    });
});

// ================ ERROR HANDLER ================
app.use((err, req, res, next) => {
    console.error('Server error:', err);
    res.status(500).json({
        success: false,
        error: 'Internal server error',
        message: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
});

// ================ SERVER INITIALIZATION ================
const startServer = async () => {
    await initializeAdmin();
    await initializeDefaultContent();
    await initializeDefaultPackages();
    
    app.listen(PORT, () => {
        console.log(`🚀 Server running on port ${PORT}`);
        console.log(`📊 Dashboard: http://localhost:${PORT}`);
        console.log(`📡 API Health: http://localhost:${PORT}/api/health`);
        console.log(`🔑 Admin Email: ${process.env.ADMIN_EMAIL}`);
        console.log(`🛡️ Versioning: DISABLED (to prevent VersionError)`);
        console.log(`📈 Features: Content Management, User Analytics, Admin Panel`);
    });
};

startServer();

process.on('unhandledRejection', (err) => {
    console.error('Unhandled Promise Rejection:', err);
});

module.exports = app;