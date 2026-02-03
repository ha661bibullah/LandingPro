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

// MongoDB Connection
const MONGODB_URI = process.env.MONGODB_URI;

// Disable mongoose versioning
mongoose.set('versionKey', false);
mongoose.set('strictQuery', false);

// MongoDB connection
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
    } catch (error) {
        console.error('❌ MongoDB Connection Error:', error.message);
        
        if (process.env.NODE_ENV === 'production') {
            // Retry connection in production
            setTimeout(connectDB, 5000);
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

// Analytics Schema
const AnalyticsSchema = new mongoose.Schema({
    sessionId: { type: String, required: true },
    page: { type: String, required: true },
    referrer: { type: String },
    deviceType: { type: String },
    country: { type: String },
    city: { type: String },
    duration: { type: Number, default: 0 },
    pageViews: { type: Number, default: 1 },
    events: { type: Number, default: 0 },
    lastActivity: { type: Date, default: Date.now },
    createdAt: { type: Date, default: Date.now }
}, { 
    versionKey: false,
    timestamps: false 
});

// Event Schema
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

// Content Schema
const ContentSchema = new mongoose.Schema({
    page: { type: String, required: true },
    section: { type: String, required: true },
    type: { type: String, enum: ['text', 'image', 'video'], default: 'text' },
    key: { type: String, required: true, unique: true },
    title: { type: String },
    content: { type: String },
    isActive: { type: Boolean, default: true },
    order: { type: Number, default: 0 },
    updatedAt: { type: Date, default: Date.now }
}, { 
    versionKey: false,
    timestamps: false 
});

const Contact = mongoose.model('Contact', ContactSchema);
const Admin = mongoose.model('Admin', AdminSchema);
const Analytics = mongoose.model('Analytics', AnalyticsSchema);
const Event = mongoose.model('Event', EventSchema);
const Content = mongoose.model('Content', ContentSchema);

// ================ INITIALIZATION ================
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
        }
    } catch (error) {
        console.error('❌ Error creating admin account:', error.message);
    }
};

// ================ MIDDLEWARE ================
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ success: false, error: 'Access token required' });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ success: false, error: 'Invalid or expired token' });
        }
        req.user = user;
        next();
    });
};

// ================ ROUTES ================

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
        version: '2.0.0'
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
            admin: '/api/admin/*'
        }
    });
});

// ================ PUBLIC ROUTES ================

// Contact form submission
app.post('/api/contact', async (req, res) => {
    try {
        const { name, email, phone, package, message } = req.body;
        
        if (!name || !email || !message) {
            return res.status(400).json({ success: false, error: 'Name, email and message are required' });
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
        res.status(500).json({ success: false, error: 'Failed to send message' });
    }
});

// Login route
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        if (!email || !password) {
            return res.status(400).json({ success: false, error: 'Email and password are required' });
        }
        
        const admin = await Admin.findOne({ email });
        if (!admin) {
            return res.status(401).json({ success: false, error: 'Invalid credentials' });
        }
        
        const validPassword = await bcrypt.compare(password, admin.password);
        if (!validPassword) {
            return res.status(401).json({ success: false, error: 'Invalid credentials' });
        }
        
        admin.lastLogin = new Date();
        await admin.save();
        
        const token = jwt.sign(
            { id: admin._id, email: admin.email },
            process.env.JWT_SECRET,
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
        res.status(500).json({ success: false, error: 'Login failed' });
    }
});

// ================ ANALYTICS ROUTES ================

app.post('/api/analytics/track', async (req, res) => {
    try {
        const { sessionId, page, referrer, deviceType } = req.body;
        
        if (!sessionId || !page) {
            return res.status(400).json({ success: false, error: 'sessionId and page are required' });
        }

        let analytics = await Analytics.findOne({ sessionId });
        
        if (!analytics) {
            analytics = new Analytics({
                sessionId,
                page,
                referrer: referrer || 'direct',
                deviceType: deviceType || 'desktop',
                pageViews: 1
            });
        } else {
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
        res.status(500).json({ success: false, error: 'Failed to track analytics' });
    }
});

app.post('/api/analytics/event', async (req, res) => {
    try {
        const { sessionId, type, element, details } = req.body;
        
        if (!sessionId || !type) {
            return res.status(400).json({ success: false, error: 'sessionId and type are required' });
        }

        const event = new Event({
            sessionId,
            type,
            element,
            details: typeof details === 'object' ? JSON.stringify(details) : details
        });
        
        await event.save();
        
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
        res.status(500).json({ success: false, error: 'Failed to track event' });
    }
});

app.post('/api/analytics/update', async (req, res) => {
    try {
        const { sessionId, duration } = req.body;
        
        if (!sessionId) {
            return res.status(400).json({ success: false, error: 'sessionId is required' });
        }

        await Analytics.updateOne(
            { sessionId }, 
            { 
                $set: { 
                    duration: duration || 0,
                    lastActivity: new Date()
                }
            }
        );
        
        res.json({ success: true, message: 'Session updated successfully' });
    } catch (error) {
        console.error('Analytics update error:', error.message);
        res.status(500).json({ success: false, error: 'Failed to update session' });
    }
});

// ================ ADMIN ROUTES ================

// Token verification
app.get('/api/admin/verify', authenticateToken, async (req, res) => {
    try {
        const admin = await Admin.findById(req.user.id);
        if (!admin) {
            return res.status(404).json({ success: false, error: 'Admin not found' });
        }
        
        res.json({
            success: true,
            admin: {
                id: admin._id,
                email: admin.email,
                lastLogin: admin.lastLogin
            }
        });
    } catch (error) {
        res.status(500).json({ success: false, error: 'Verification failed' });
    }
});

// Dashboard statistics
app.get('/api/admin/stats', authenticateToken, async (req, res) => {
    try {
        // Contact stats
        const totalContacts = await Contact.countDocuments();
        const newContacts = await Contact.countDocuments({ status: 'new' });
        const contacted = await Contact.countDocuments({ status: 'contacted' });
        const inProgress = await Contact.countDocuments({ status: 'in_progress' });
        const completed = await Contact.countDocuments({ status: 'completed' });
        const cancelled = await Contact.countDocuments({ status: 'cancelled' });
        
        // Get package distribution
        const packageStats = await Contact.aggregate([
            { $group: { _id: "$package", count: { $sum: 1 } } },
            { $sort: { count: -1 } }
        ]);
        
        // Get status distribution
        const statusStats = await Contact.aggregate([
            { $group: { _id: "$status", count: { $sum: 1 } } }
        ]);
        
        // Analytics stats
        const today = new Date();
        today.setHours(0, 0, 0, 0);
        
        const visitorsToday = await Analytics.countDocuments({
            createdAt: { $gte: today }
        });
        
        const totalVisitors = await Analytics.countDocuments();
        
        // Active visitors (last 5 minutes)
        const fiveMinutesAgo = new Date(Date.now() - 5 * 60 * 1000);
        const activeVisitors = await Analytics.countDocuments({
            lastActivity: { $gte: fiveMinutesAgo }
        });
        
        // Total page views
        const pageViewsResult = await Analytics.aggregate([
            { $group: { _id: null, total: { $sum: "$pageViews" } } }
        ]);
        const totalPageViews = pageViewsResult[0]?.total || 0;
        
        // Average session duration
        const avgDurationResult = await Analytics.aggregate([
            { $match: { duration: { $gt: 0 } } },
            { $group: { _id: null, average: { $avg: "$duration" } } }
        ]);
        const avgSessionDuration = Math.round(avgDurationResult[0]?.average || 0);
        
        res.json({
            success: true,
            stats: {
                totalContacts,
                newContacts,
                contacted,
                inProgress,
                completed,
                cancelled,
                visitorsToday,
                totalVisitors,
                activeVisitors,
                totalPageViews,
                avgSessionDuration
            },
            packageStats,
            statusStats
        });
    } catch (error) {
        console.error('Get stats error:', error.message);
        res.status(500).json({ success: false, error: 'Failed to fetch statistics' });
    }
});

// Get contacts with pagination and filtering
app.get('/api/admin/contacts', authenticateToken, async (req, res) => {
    try {
        const { 
            page = 1, 
            limit = 10, 
            status, 
            package: packageFilter,
            search 
        } = req.query;
        
        const query = {};
        
        if (status && status !== 'all') {
            query.status = status;
        }
        
        if (packageFilter && packageFilter !== 'all') {
            query.package = packageFilter;
        }
        
        if (search) {
            query.$or = [
                { name: { $regex: search, $options: 'i' } },
                { email: { $regex: search, $options: 'i' } },
                { phone: { $regex: search, $options: 'i' } },
                { message: { $regex: search, $options: 'i' } }
            ];
        }
        
        const skip = (parseInt(page) - 1) * parseInt(limit);
        
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
        res.status(500).json({ success: false, error: 'Failed to fetch contacts' });
    }
});

// Get single contact
app.get('/api/admin/contacts/:id', authenticateToken, async (req, res) => {
    try {
        const contact = await Contact.findById(req.params.id);
        
        if (!contact) {
            return res.status(404).json({ success: false, error: 'Contact not found' });
        }
        
        res.json({
            success: true,
            contact
        });
    } catch (error) {
        console.error('Get contact error:', error.message);
        res.status(500).json({ success: false, error: 'Failed to fetch contact' });
    }
});

// Update contact status
app.put('/api/admin/contacts/:id', authenticateToken, async (req, res) => {
    try {
        const { status } = req.body;
        
        const contact = await Contact.findById(req.params.id);
        if (!contact) {
            return res.status(404).json({ success: false, error: 'Contact not found' });
        }
        
        contact.status = status;
        contact.updatedAt = new Date();
        await contact.save();
        
        res.json({
            success: true,
            message: 'Contact status updated successfully',
            contact
        });
    } catch (error) {
        console.error('Update contact error:', error.message);
        res.status(500).json({ success: false, error: 'Failed to update contact' });
    }
});

// Delete contact
app.delete('/api/admin/contacts/:id', authenticateToken, async (req, res) => {
    try {
        const contact = await Contact.findById(req.params.id);
        if (!contact) {
            return res.status(404).json({ success: false, error: 'Contact not found' });
        }
        
        await contact.deleteOne();
        
        res.json({
            success: true,
            message: 'Contact deleted successfully'
        });
    } catch (error) {
        console.error('Delete contact error:', error.message);
        res.status(500).json({ success: false, error: 'Failed to delete contact' });
    }
});

// Get recent contacts
app.get('/api/admin/contacts/recent', authenticateToken, async (req, res) => {
    try {
        const limit = parseInt(req.query.limit) || 5;
        
        const contacts = await Contact.find()
            .sort({ createdAt: -1 })
            .limit(limit);
        
        res.json({
            success: true,
            contacts
        });
    } catch (error) {
        console.error('Get recent contacts error:', error.message);
        res.status(500).json({ success: false, error: 'Failed to fetch recent contacts' });
    }
});

// ================ ANALYTICS ADMIN ROUTES ================

app.get('/api/admin/analytics', authenticateToken, async (req, res) => {
    try {
        const today = new Date();
        today.setHours(0, 0, 0, 0);
        
        // Today's visitors
        const visitorsToday = await Analytics.countDocuments({
            createdAt: { $gte: today }
        });
        
        // Total visitors
        const totalVisitors = await Analytics.countDocuments();
        
        // Active visitors (last 5 minutes)
        const fiveMinutesAgo = new Date(Date.now() - 5 * 60 * 1000);
        const activeVisitors = await Analytics.countDocuments({
            lastActivity: { $gte: fiveMinutesAgo }
        });
        
        // Total page views
        const pageViewsResult = await Analytics.aggregate([
            { $group: { _id: null, total: { $sum: "$pageViews" } } }
        ]);
        const totalPageViews = pageViewsResult[0]?.total || 0;
        
        // Average session duration
        const avgDurationResult = await Analytics.aggregate([
            { $match: { duration: { $gt: 0 } } },
            { $group: { _id: null, average: { $avg: "$duration" } } }
        ]);
        const avgSessionDuration = Math.round(avgDurationResult[0]?.average || 0);
        
        // Device distribution
        const deviceDistribution = await Analytics.aggregate([
            { $group: { _id: "$deviceType", count: { $sum: 1 } } },
            { $sort: { count: -1 } }
        ]);
        
        // Page popularity
        const topPages = await Analytics.aggregate([
            { $group: { _id: "$page", count: { $sum: 1 } } },
            { $sort: { count: -1 } },
            { $limit: 10 }
        ]);
        
        res.json({
            success: true,
            stats: {
                visitorsToday,
                totalVisitors,
                activeVisitors,
                totalPageViews,
                avgSessionDuration
            },
            deviceDistribution,
            topPages
        });
    } catch (error) {
        console.error('Get analytics error:', error.message);
        res.status(500).json({ success: false, error: 'Failed to fetch analytics' });
    }
});

// ================ CONTENT MANAGEMENT ROUTES ================

// Get all content
app.get('/api/admin/content', authenticateToken, async (req, res) => {
    try {
        const content = await Content.find().sort({ page: 1, section: 1, order: 1 });
        res.json({ success: true, content });
    } catch (error) {
        console.error('Get content error:', error.message);
        res.status(500).json({ success: false, error: 'Failed to fetch content' });
    }
});

// Create or update content
app.post('/api/admin/content', authenticateToken, async (req, res) => {
    try {
        const { key, page, section, type, title, content, isActive } = req.body;
        
        if (!key || !page || !section || !type) {
            return res.status(400).json({ success: false, error: 'Key, page, section and type are required' });
        }
        
        const existing = await Content.findOne({ key });
        
        if (existing) {
            // Update existing
            existing.page = page;
            existing.section = section;
            existing.type = type;
            existing.title = title;
            existing.content = content;
            existing.isActive = isActive !== undefined ? isActive : existing.isActive;
            existing.updatedAt = new Date();
            
            await existing.save();
            
            res.json({
                success: true,
                message: 'Content updated successfully',
                data: existing
            });
        } else {
            // Create new
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
        res.status(500).json({ success: false, error: 'Failed to save content' });
    }
});

// Get content for frontend
app.get('/api/content', async (req, res) => {
    try {
        const content = await Content.find({ isActive: true }).sort({ order: 1 });
        
        const contentMap = {};
        content.forEach(item => {
            contentMap[item.key] = {
                type: item.type,
                title: item.title,
                content: item.content,
                page: item.page,
                section: item.section
            };
        });
        
        res.json({ success: true, content: contentMap });
    } catch (error) {
        console.error('Get content error:', error.message);
        res.status(500).json({ success: false, error: 'Failed to fetch content' });
    }
});

// ================ ERROR HANDLING ================

// 404 handler
app.use('*', (req, res) => {
    res.status(404).json({
        success: false,
        error: 'Endpoint not found',
        message: 'The requested endpoint does not exist'
    });
});

// Error handler
app.use((err, req, res, next) => {
    console.error('Server error:', err.message);
    
    const errorMessage = process.env.NODE_ENV === 'development' ? err.message : 'Internal server error';
    
    res.status(500).json({
        success: false,
        error: errorMessage
    });
});

// ================ START SERVER ================
const startServer = async () => {
    try {
        // Initialize admin account
        await initializeAdmin();
        
        app.listen(PORT, () => {
            console.log(`🚀 Server running on port ${PORT}`);
            console.log(`📡 Environment: ${process.env.NODE_ENV || 'development'}`);
            console.log(`🔗 MongoDB: ${mongoose.connection.readyState === 1 ? 'Connected' : 'Disconnected'}`);
            console.log(`🌐 CORS: Enabled for all origins`);
            console.log(`📊 Health Check: http://localhost:${PORT}/api/health`);
        });
    } catch (error) {
        console.error('❌ Failed to start server:', error.message);
        
        // Start server anyway
        app.listen(PORT, () => {
            console.log(`🚀 Server running on port ${PORT} (with reduced functionality)`);
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