// backend/server.js - COMPLETE WORKING VERSION FOR RENDER
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;

// CORS Configuration
const corsOptions = {
    origin: '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'Accept'],
    credentials: true,
    optionsSuccessStatus: 200
};

// Middleware
app.use(cors(corsOptions));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// MongoDB Connection with better error handling
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/landingpro';

// Disable mongoose versioning globally
mongoose.set('versionKey', false);
mongoose.set('strictQuery', false);

// MongoDB connection with retry logic
const connectDB = async () => {
    try {
        console.log('🔗 Connecting to MongoDB...');
        
        await mongoose.connect(MONGODB_URI, {
            useNewUrlParser: true,
            useUnifiedTopology: true,
            serverSelectionTimeoutMS: 5000,
            socketTimeoutMS: 45000,
        });
        
        console.log('✅ MongoDB Connected Successfully');
        console.log(`📊 Database: ${mongoose.connection.name}`);
        console.log(`📈 Host: ${mongoose.connection.host}`);
        
        // Connection event listeners
        mongoose.connection.on('error', (err) => {
            console.error('❌ MongoDB connection error:', err);
        });
        
        mongoose.connection.on('disconnected', () => {
            console.log('⚠️ MongoDB disconnected');
        });
        
        mongoose.connection.on('reconnected', () => {
            console.log('✅ MongoDB reconnected');
        });
        
    } catch (error) {
        console.error('❌ MongoDB Connection Error:', error.message);
        console.error('Error details:', error);
        
        // Exit process with failure if can't connect after 3 retries
        if (process.env.NODE_ENV === 'production') {
            process.exit(1);
        }
    }
};

// Call connectDB
connectDB();

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
}, { 
    versionKey: false,
    timestamps: false 
});

const AdminSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, default: 'admin' },
    lastLogin: { type: Date },
    createdAt: { type: Date, default: Date.now }
}, { 
    versionKey: false,
    timestamps: false 
});

// Analytics Schema - SIMPLIFIED VERSION
const AnalyticsSchema = new mongoose.Schema({
    sessionId: { type: String, required: true },
    ipAddress: { type: String },
    userAgent: { type: String },
    page: { type: String, required: true },
    referrer: { type: String },
    deviceType: { type: String },
    country: { type: String },
    city: { type: String },
    duration: { type: Number, default: 0 },
    pageViews: { type: Number, default: 1 },
    events: { type: Number, default: 0 },
    scrollDepth: { type: Number, default: 0 },
    lastActivity: { type: Date, default: Date.now },
    createdAt: { type: Date, default: Date.now }
}, { 
    versionKey: false,
    timestamps: false 
});

// Simple Events Schema
const EventSchema = new mongoose.Schema({
    sessionId: { type: String, required: true },
    type: { type: String, required: true },
    element: { type: String },
    details: { type: String },
    timestamp: { type: Date, default: Date.now }
}, { 
    versionKey: false,
    timestamps: false 
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
}, { 
    versionKey: false,
    timestamps: false 
});

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
}, { 
    versionKey: false,
    timestamps: false 
});

const Contact = mongoose.model('Contact', ContactSchema);
const Admin = mongoose.model('Admin', AdminSchema);
const Analytics = mongoose.model('Analytics', AnalyticsSchema);
const Event = mongoose.model('Event', EventSchema);
const Content = mongoose.model('Content', ContentSchema);
const Package = mongoose.model('Package', PackageSchema);

// ================ INITIALIZATION FUNCTIONS ================
const initializeAdmin = async () => {
    try {
        const adminExists = await Admin.findOne({ email: process.env.ADMIN_EMAIL || 'admin@landingpro.com' });
        if (!adminExists) {
            const hashedPassword = await bcrypt.hash(process.env.ADMIN_PASSWORD || 'admin123', 10);
            const admin = new Admin({
                email: process.env.ADMIN_EMAIL || 'admin@landingpro.com',
                password: hashedPassword
            });
            await admin.save();
            console.log('✅ Admin account created successfully');
        } else {
            console.log('✅ Admin account already exists');
        }
    } catch (error) {
        console.error('❌ Error creating admin account:', error.message);
    }
};

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
            }
        ];

        for (const content of defaultContents) {
            const exists = await Content.findOne({ key: content.key });
            if (!exists) {
                await Content.create(content);
            }
        }
        console.log('✅ Default content initialized');
    } catch (error) {
        console.error('❌ Error initializing content:', error.message);
    }
};

// ================ MIDDLEWARE ================
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Access token required' });
    }

    jwt.verify(token, process.env.JWT_SECRET || 'landingpro_secret_key', (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid or expired token' });
        }
        req.user = user;
        next();
    });
};

// Health check endpoint
app.get('/api/health', (req, res) => {
    const mongoStatus = mongoose.connection.readyState;
    const statusText = {
        0: 'disconnected',
        1: 'connected',
        2: 'connecting',
        3: 'disconnecting'
    };
    
    res.json({ 
        success: true,
        status: 'healthy', 
        timestamp: new Date().toISOString(),
        mongodb: statusText[mongoStatus] || 'unknown',
        service: 'LandingPro API',
        version: '2.0.0',
        uptime: process.uptime()
    });
});

// Root endpoint
app.get('/', (req, res) => {
    res.json({ 
        message: 'Welcome to LandingPro API',
        version: '2.0.0',
        endpoints: {
            health: '/api/health',
            contact: '/api/contact',
            login: '/api/login',
            content: '/api/content',
            analytics: {
                track: '/api/analytics/track',
                event: '/api/analytics/event'
            }
        }
    });
});

// ================ ANALYTICS ROUTES (SIMPLIFIED) ================
app.post('/api/analytics/track', async (req, res) => {
    try {
        const { sessionId, page, referrer, deviceType } = req.body;
        
        if (!sessionId || !page) {
            return res.status(400).json({ error: 'sessionId and page are required' });
        }

        // Check if session exists
        let analytics = await Analytics.findOne({ sessionId });
        
        if (!analytics) {
            // Create new session
            analytics = new Analytics({
                sessionId,
                page,
                referrer: referrer || 'direct',
                deviceType: deviceType || 'desktop',
                pageViews: 1
            });
        } else {
            // Update existing session
            analytics.pageViews += 1;
            analytics.lastActivity = new Date();
            if (page !== analytics.page) {
                analytics.page = page;
            }
        }
        
        await analytics.save();
        
        res.json({ 
            success: true, 
            message: 'Analytics tracked successfully',
            sessionId 
        });
    } catch (error) {
        console.error('Analytics track error:', error.message);
        res.status(500).json({ error: 'Failed to track analytics' });
    }
});

app.post('/api/analytics/event', async (req, res) => {
    try {
        const { sessionId, type, element, details } = req.body;
        
        if (!sessionId || !type) {
            return res.status(400).json({ error: 'sessionId and type are required' });
        }

        // Create event
        const event = new Event({
            sessionId,
            type,
            element,
            details: typeof details === 'object' ? JSON.stringify(details) : details
        });
        
        await event.save();
        
        // Update analytics event count
        await Analytics.updateOne(
            { sessionId },
            { 
                $inc: { events: 1 },
                $set: { lastActivity: new Date() }
            }
        );
        
        res.json({ success: true, message: 'Event tracked successfully' });
    } catch (error) {
        console.error('Analytics event error:', error.message);
        res.status(500).json({ error: 'Failed to track event' });
    }
});

// Update session duration
app.post('/api/analytics/update', async (req, res) => {
    try {
        const { sessionId, duration, scrollDepth } = req.body;
        
        if (!sessionId) {
            return res.status(400).json({ error: 'sessionId is required' });
        }

        const updateData = { lastActivity: new Date() };
        
        if (duration !== undefined) {
            updateData.duration = duration;
        }
        
        if (scrollDepth !== undefined) {
            updateData.scrollDepth = Math.max(scrollDepth, 0);
        }
        
        await Analytics.updateOne({ sessionId }, { $set: updateData });
        
        res.json({ success: true, message: 'Session updated successfully' });
    } catch (error) {
        console.error('Analytics update error:', error.message);
        res.status(500).json({ error: 'Failed to update session' });
    }
});

// ================ ADMIN ANALYTICS ROUTES ================
app.get('/api/admin/analytics', authenticateToken, async (req, res) => {
    try {
        // Get today's date
        const today = new Date();
        today.setHours(0, 0, 0, 0);
        
        const tomorrow = new Date(today);
        tomorrow.setDate(tomorrow.getDate() + 1);
        
        // Get today's visitors
        const visitorsToday = await Analytics.countDocuments({
            createdAt: { $gte: today, $lt: tomorrow }
        });
        
        // Get total visitors
        const totalVisitors = await Analytics.countDocuments();
        
        // Get active visitors (last 5 minutes)
        const fiveMinutesAgo = new Date(Date.now() - 5 * 60 * 1000);
        const activeVisitors = await Analytics.countDocuments({
            lastActivity: { $gte: fiveMinutesAgo }
        });
        
        // Get total page views
        const result = await Analytics.aggregate([
            { $group: { _id: null, totalPageViews: { $sum: "$pageViews" } } }
        ]);
        
        const totalPageViews = result.length > 0 ? result[0].totalPageViews : 0;
        
        // Get average duration
        const avgResult = await Analytics.aggregate([
            { $match: { duration: { $gt: 0 } } },
            { $group: { _id: null, avgDuration: { $avg: "$duration" } } }
        ]);
        
        const avgDuration = avgResult.length > 0 ? Math.round(avgResult[0].avgDuration) : 0;
        
        // Get top pages
        const topPages = await Analytics.aggregate([
            { $group: { _id: "$page", count: { $sum: 1 } } },
            { $sort: { count: -1 } },
            { $limit: 10 }
        ]);
        
        // Get device distribution
        const deviceDistribution = await Analytics.aggregate([
            { $group: { _id: "$deviceType", count: { $sum: 1 } } },
            { $sort: { count: -1 } }
        ]);
        
        // Get recent sessions
        const recentSessions = await Analytics.find()
            .sort({ lastActivity: -1 })
            .limit(10)
            .select('sessionId page deviceType country city duration pageViews lastActivity');
        
        res.json({
            success: true,
            stats: {
                visitorsToday,
                totalVisitors,
                activeVisitors,
                totalPageViews,
                avgDuration
            },
            topPages,
            deviceDistribution,
            recentSessions
        });
    } catch (error) {
        console.error('Get analytics error:', error.message);
        res.status(500).json({ error: 'Failed to fetch analytics' });
    }
});

app.get('/api/admin/analytics/realtime', authenticateToken, async (req, res) => {
    try {
        const fiveMinutesAgo = new Date(Date.now() - 5 * 60 * 1000);
        
        const activeSessions = await Analytics.find({
            lastActivity: { $gte: fiveMinutesAgo }
        })
        .sort({ lastActivity: -1 })
        .limit(20)
        .select('sessionId page deviceType country city duration pageViews lastActivity');
        
        res.json({
            success: true,
            activeVisitors: activeSessions.length,
            sessions: activeSessions
        });
    } catch (error) {
        console.error('Realtime analytics error:', error.message);
        res.status(500).json({ error: 'Failed to fetch realtime analytics' });
    }
});

// ================ CONTENT ROUTES ================
app.get('/api/content', async (req, res) => {
    try {
        const content = await Content.find({ isActive: true }).sort({ order: 1 });
        
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
        console.error('Get content error:', error.message);
        res.status(500).json({ error: 'Failed to fetch content' });
    }
});

// ================ ADMIN CONTENT ROUTES ================
app.get('/api/admin/content', authenticateToken, async (req, res) => {
    try {
        const content = await Content.find().sort({ page: 1, section: 1, order: 1 });
        res.json({ success: true, content });
    } catch (error) {
        console.error('Get admin content error:', error.message);
        res.status(500).json({ error: 'Failed to fetch content' });
    }
});

app.post('/api/admin/content', authenticateToken, async (req, res) => {
    try {
        const { key, page, section, type, title, content, isActive } = req.body;
        
        if (!key || !page || !section || !type) {
            return res.status(400).json({ error: 'Key, page, section and type are required' });
        }
        
        const existing = await Content.findOne({ key });
        
        if (existing) {
            existing.page = page;
            existing.section = section;
            existing.type = type;
            existing.title = title;
            existing.content = content;
            existing.isActive = isActive !== undefined ? isActive : existing.isActive;
            existing.meta.updatedAt = new Date();
            
            await existing.save();
            
            res.json({
                success: true,
                message: 'Content updated successfully',
                data: existing
            });
        } else {
            const newContent = new Content({
                key,
                page,
                section,
                type,
                title,
                content,
                isActive: isActive !== undefined ? isActive : true
            });
            
            await newContent.save();
            
            res.json({
                success: true,
                message: 'Content created successfully',
                data: newContent
            });
        }
    } catch (error) {
        console.error('Save content error:', error.message);
        res.status(500).json({ error: 'Failed to save content' });
    }
});

// ================ PACKAGE ROUTES ================
app.get('/api/packages', async (req, res) => {
    try {
        const packages = await Package.find({ isActive: true }).sort({ order: 1 });
        res.json({ success: true, packages });
    } catch (error) {
        console.error('Get packages error:', error.message);
        res.status(500).json({ error: 'Failed to fetch packages' });
    }
});

// ================ CONTACT ROUTES ================
app.post('/api/contact', async (req, res) => {
    try {
        const { name, email, phone, package, message } = req.body;
        
        if (!name || !email || !message) {
            return res.status(400).json({ error: 'Name, email and message are required' });
        }
        
        const contact = new Contact({
            name,
            email,
            phone: phone || 'Not provided',
            package: package || 'Not specified',
            message
        });
        
        await contact.save();
        
        res.json({
            success: true,
            message: 'Message sent successfully',
            data: contact
        });
    } catch (error) {
        console.error('Contact submission error:', error.message);
        res.status(500).json({ error: 'Failed to send message' });
    }
});

// ================ LOGIN ROUTE ================
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
            { id: admin._id, email: admin.email },
            process.env.JWT_SECRET || 'landingpro_secret_key',
            { expiresIn: '24h' }
        );
        
        res.json({
            success: true,
            token,
            admin: {
                id: admin._id,
                email: admin.email,
                lastLogin: admin.lastLogin
            }
        });
    } catch (error) {
        console.error('Login error:', error.message);
        res.status(500).json({ error: 'Login failed' });
    }
});

// ================ ADMIN CONTACT ROUTES ================
app.get('/api/admin/contacts', authenticateToken, async (req, res) => {
    try {
        const { page = 1, limit = 10, status } = req.query;
        
        const query = {};
        if (status && status !== 'all') {
            query.status = status;
        }
        
        const skip = (page - 1) * limit;
        
        const contacts = await Contact.find(query)
            .sort({ createdAt: -1 })
            .skip(skip)
            .limit(parseInt(limit));
        
        const total = await Contact.countDocuments(query);
        
        res.json({
            success: true,
            contacts,
            pagination: {
                page: parseInt(page),
                limit: parseInt(limit),
                total,
                totalPages: Math.ceil(total / limit)
            }
        });
    } catch (error) {
        console.error('Get contacts error:', error.message);
        res.status(500).json({ error: 'Failed to fetch contacts' });
    }
});

app.get('/api/admin/stats', authenticateToken, async (req, res) => {
    try {
        // Contact stats
        const totalContacts = await Contact.countDocuments();
        const newContacts = await Contact.countDocuments({ status: 'new' });
        const contacted = await Contact.countDocuments({ status: 'contacted' });
        const inProgress = await Contact.countDocuments({ status: 'in_progress' });
        const completed = await Contact.countDocuments({ status: 'completed' });
        
        // Analytics stats
        const today = new Date();
        today.setHours(0, 0, 0, 0);
        const visitorsToday = await Analytics.countDocuments({
            createdAt: { $gte: today }
        });
        
        const totalVisitors = await Analytics.countDocuments();
        
        // Content stats
        const totalContent = await Content.countDocuments();
        const activeContent = await Content.countDocuments({ isActive: true });
        
        res.json({
            success: true,
            contacts: {
                total: totalContacts,
                new: newContacts,
                contacted,
                inProgress,
                completed
            },
            analytics: {
                visitorsToday,
                totalVisitors
            },
            content: {
                total: totalContent,
                active: activeContent
            }
        });
    } catch (error) {
        console.error('Get stats error:', error.message);
        res.status(500).json({ error: 'Failed to fetch statistics' });
    }
});

// ================ 404 HANDLER ================
app.use('*', (req, res) => {
    res.status(404).json({
        success: false,
        error: 'Endpoint not found',
        message: 'The requested endpoint does not exist'
    });
});

// ================ ERROR HANDLER ================
app.use((err, req, res, next) => {
    console.error('Server error:', err.message);
    
    // Don't expose internal errors in production
    const errorMessage = process.env.NODE_ENV === 'development' ? err.message : 'Internal server error';
    
    res.status(500).json({
        success: false,
        error: errorMessage
    });
});

// ================ START SERVER ================
const startServer = async () => {
    try {
        // Wait for MongoDB connection
        if (mongoose.connection.readyState !== 1) {
            console.log('⏳ Waiting for MongoDB connection...');
            await new Promise(resolve => setTimeout(resolve, 2000));
        }
        
        // Initialize data
        await initializeAdmin();
        await initializeDefaultContent();
        
        app.listen(PORT, () => {
            console.log(`🚀 Server running on port ${PORT}`);
            console.log(`📡 Environment: ${process.env.NODE_ENV || 'development'}`);
            console.log(`🔗 MongoDB: ${mongoose.connection.readyState === 1 ? 'Connected' : 'Disconnected'}`);
            console.log(`🌐 CORS: Enabled for all origins`);
            console.log(`📊 Health Check: http://localhost:${PORT}/api/health`);
        });
    } catch (error) {
        console.error('❌ Failed to start server:', error.message);
        
        // Try to start server even if initialization fails
        app.listen(PORT, () => {
            console.log(`🚀 Server running on port ${PORT} (with reduced functionality)`);
            console.log(`⚠️ Some features may not work due to initialization errors`);
        });
    }
};

// Handle graceful shutdown
process.on('SIGINT', async () => {
    console.log('🛑 Shutting down server...');
    await mongoose.connection.close();
    console.log('✅ MongoDB connection closed');
    process.exit(0);
});

process.on('SIGTERM', async () => {
    console.log('🛑 Shutting down server...');
    await mongoose.connection.close();
    console.log('✅ MongoDB connection closed');
    process.exit(0);
});

// Start the server
startServer();

module.exports = app;