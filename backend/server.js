// server.js - আপডেটেড ভার্সন
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
require('dotenv').config();

const app = express();

// CORS কনফিগারেশন - সব ডোমেইন অনুমতি দিন
app.use(cors({
    origin: '*', // সব ডোমেইন থেকে অনুমতি
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'Accept']
}));

// OPTIONS রিকোয়েস্ট হ্যান্ডেল
app.options('*', cors());

// Security middleware
app.use(helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false
}));

// JSON parsing
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// MongoDB connection
mongoose.connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
})
.then(() => console.log('✅ MongoDB connected'))
.catch(err => console.error('❌ MongoDB connection error:', err));

// Schemas
const contactSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true },
    phone: String,
    package: { type: String, default: '' },
    message: { type: String, required: true },
    status: { 
        type: String, 
        enum: ['new', 'contacted', 'in_progress', 'completed', 'cancelled'],
        default: 'new' 
    },
    ipAddress: String,
    userAgent: String,
    referrer: String,
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});

const analyticsSchema = new mongoose.Schema({
    sessionId: { type: String, required: true },
    page: { type: String, required: true },
    ipAddress: String,
    userAgent: String,
    deviceInfo: Object,
    locationInfo: Object,
    referrer: String,
    duration: { type: Number, default: 0 },
    isActive: { type: Boolean, default: true },
    createdAt: { type: Date, default: Date.now },
    lastActivity: { type: Date, default: Date.now }
});

const adminSchema = new mongoose.Schema({
    email: { 
        type: String, 
        required: true, 
        unique: true 
    },
    password: { type: String, required: true },
    name: { type: String, default: 'Admin' },
    role: { 
        type: String, 
        enum: ['super_admin', 'admin', 'editor'],
        default: 'admin' 
    },
    lastLogin: Date,
    isActive: { type: Boolean, default: true },
    createdAt: { type: Date, default: Date.now }
});

const contentSchema = new mongoose.Schema({
    key: { type: String, required: true, unique: true },
    page: { type: String, required: true },
    section: { type: String, required: true },
    content: { type: String, required: true },
    status: { 
        type: String, 
        enum: ['active', 'inactive', 'draft'],
        default: 'active' 
    },
    updatedBy: String,
    updatedAt: { type: Date, default: Date.now }
});

// Models
const Contact = mongoose.model('Contact', contactSchema);
const Analytics = mongoose.model('Analytics', analyticsSchema);
const Admin = mongoose.model('Admin', adminSchema);
const Content = mongoose.model('Content', contentSchema);

// Create default admin
async function createDefaultAdmin() {
    try {
        const adminExists = await Admin.findOne({ email: process.env.ADMIN_EMAIL });
        if (!adminExists) {
            const hashedPassword = await bcrypt.hash(process.env.ADMIN_PASSWORD, 10);
            const admin = new Admin({
                email: process.env.ADMIN_EMAIL,
                password: hashedPassword,
                name: 'Super Admin',
                role: 'super_admin'
            });
            await admin.save();
            console.log('✅ Default admin created');
        } else {
            console.log('✅ Admin already exists');
        }
    } catch (error) {
        console.error('❌ Error creating admin:', error);
    }
}

// JWT Authentication middleware
const authenticateToken = (req, res, next) => {
    try {
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1];

        if (!token) {
            console.log('❌ No token provided');
            return res.status(401).json({ 
                success: false, 
                error: 'Access token required' 
            });
        }

        jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
            if (err) {
                console.log('❌ Token verification failed:', err.message);
                return res.status(403).json({ 
                    success: false, 
                    error: 'Invalid token' 
                });
            }
            console.log('✅ Token verified for user:', user.email);
            req.user = user;
            next();
        });
    } catch (error) {
        console.error('❌ Auth middleware error:', error);
        return res.status(500).json({ 
            success: false, 
            error: 'Authentication error' 
        });
    }
};

// Get client IP
const getClientIp = (req) => {
    return req.headers['x-forwarded-for'] || 
           req.connection.remoteAddress || 
           req.socket.remoteAddress || 
           req.ip;
};

// Test endpoint
app.get('/', (req, res) => {
    res.json({
        success: true,
        message: 'LandingPro Backend API',
        version: '2.0.0',
        timestamp: new Date().toISOString(),
        endpoints: {
            public: [
                'GET  /api/health',
                'POST /api/contact',
                'POST /api/analytics/track',
                'POST /api/analytics/update',
                'GET  /api/content',
                'POST /api/login'
            ],
            admin: [
                'GET  /api/admin/verify',
                'GET  /api/admin/stats',
                'GET  /api/admin/contacts',
                'GET  /api/admin/contacts/:id',
                'PUT  /api/admin/contacts/:id',
                'DELETE /api/admin/contacts/:id',
                'GET  /api/admin/content',
                'POST /api/admin/content',
                'PUT  /api/admin/content/:id',
                'DELETE /api/admin/content/:id'
            ]
        }
    });
});

// Health check
app.get('/api/health', (req, res) => {
    res.json({
        success: true,
        message: 'API is running',
        timestamp: new Date().toISOString(),
        database: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected'
    });
});

// =========== PUBLIC ENDPOINTS ===========

// Contact form submission
app.post('/api/contact', async (req, res) => {
    try {
        console.log('📧 Contact form submission received');
        
        const { name, email, phone, package, message } = req.body;
        
        if (!name || !email || !message) {
            return res.status(400).json({
                success: false,
                error: 'Name, email, and message are required'
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

        console.log(`✅ Contact saved: ${name} - ${email}`);

        res.status(201).json({
            success: true,
            message: 'Your message has been sent successfully',
            data: {
                id: contact._id,
                name: contact.name,
                email: contact.email,
                status: contact.status
            }
        });

    } catch (error) {
        console.error('❌ Contact submission error:', error);
        res.status(500).json({
            success: false,
            error: 'Server error. Please try again.'
        });
    }
});

// Analytics tracking
app.post('/api/analytics/track', async (req, res) => {
    try {
        const { sessionId, page, deviceInfo, location, referrer } = req.body;
        
        const analytics = new Analytics({
            sessionId,
            page: page || 'home',
            ipAddress: getClientIp(req),
            userAgent: req.headers['user-agent'],
            deviceInfo: deviceInfo || {},
            locationInfo: location || {},
            referrer: referrer || 'direct'
        });

        await analytics.save();

        res.json({
            success: true,
            message: 'Analytics tracked'
        });

    } catch (error) {
        console.error('Analytics tracking error:', error);
        res.status(500).json({
            success: false,
            error: 'Analytics tracking failed'
        });
    }
});

// Analytics update
app.post('/api/analytics/update', async (req, res) => {
    try {
        const { sessionId, duration } = req.body;
        
        await Analytics.findOneAndUpdate(
            { sessionId },
            { 
                duration,
                lastActivity: new Date(),
                isActive: true 
            }
        );

        res.json({
            success: true,
            message: 'Analytics updated'
        });

    } catch (error) {
        console.error('Analytics update error:', error);
        res.status(500).json({
            success: false,
            error: 'Analytics update failed'
        });
    }
});

// Get content
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

        res.json({
            success: true,
            content: contentMap
        });

    } catch (error) {
        console.error('Content load error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to load content'
        });
    }
});

// Admin login
app.post('/api/login', async (req, res) => {
    try {
        console.log('🔐 Login attempt:', req.body.email);
        
        const { email, password } = req.body;
        
        if (!email || !password) {
            return res.status(400).json({
                success: false,
                error: 'Email and password are required'
            });
        }

        const admin = await Admin.findOne({ email: email.toLowerCase().trim() });
        
        if (!admin) {
            console.log('❌ Admin not found:', email);
            return res.status(401).json({
                success: false,
                error: 'Invalid email or password'
            });
        }

        if (!admin.isActive) {
            return res.status(403).json({
                success: false,
                error: 'Account is deactivated'
            });
        }

        const isPasswordValid = await bcrypt.compare(password, admin.password);
        
        if (!isPasswordValid) {
            console.log('❌ Invalid password for:', email);
            return res.status(401).json({
                success: false,
                error: 'Invalid email or password'
            });
        }

        // Generate token
        const token = jwt.sign(
            { 
                id: admin._id, 
                email: admin.email,
                role: admin.role,
                name: admin.name
            },
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
        );

        // Update last login
        admin.lastLogin = new Date();
        await admin.save();

        console.log('✅ Login successful for:', email);

        res.json({
            success: true,
            message: 'Login successful',
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
        console.error('❌ Login error:', error);
        res.status(500).json({
            success: false,
            error: 'Login failed. Please try again.'
        });
    }
});

// =========== PROTECTED ENDPOINTS ===========

// Verify token
app.get('/api/admin/verify', authenticateToken, async (req, res) => {
    try {
        const admin = await Admin.findById(req.user.id);
        
        if (!admin || !admin.isActive) {
            return res.status(403).json({
                success: false,
                error: 'Account not found or inactive'
            });
        }

        res.json({
            success: true,
            admin: {
                id: admin._id,
                email: admin.email,
                name: admin.name,
                role: admin.role,
                lastLogin: admin.lastLogin
            }
        });

    } catch (error) {
        console.error('Token verification error:', error);
        res.status(500).json({
            success: false,
            error: 'Verification failed'
        });
    }
});

// Get admin stats
app.get('/api/admin/stats', authenticateToken, async (req, res) => {
    try {
        console.log('📊 Fetching admin stats...');
        
        // Total contacts
        const totalContacts = await Contact.countDocuments();
        
        // Status counts
        const statusCounts = await Contact.aggregate([
            {
                $group: {
                    _id: '$status',
                    count: { $sum: 1 }
                }
            }
        ]);

        // Package counts
        const packageCounts = await Contact.aggregate([
            {
                $match: {
                    package: { $ne: '' }
                }
            },
            {
                $group: {
                    _id: '$package',
                    count: { $sum: 1 }
                }
            }
        ]);

        // Analytics stats
        const activeVisitors = await Analytics.countDocuments({ 
            isActive: true,
            lastActivity: { $gte: new Date(Date.now() - 15 * 60 * 1000) }
        });

        const todayVisitors = await Analytics.countDocuments({
            createdAt: { $gte: new Date().setHours(0, 0, 0, 0) }
        });

        const totalPageviews = await Analytics.countDocuments();

        // Format response
        const stats = {
            totalContacts,
            newContacts: statusCounts.find(s => s._id === 'new')?.count || 0,
            contacted: statusCounts.find(s => s._id === 'contacted')?.count || 0,
            inProgress: statusCounts.find(s => s._id === 'in_progress')?.count || 0,
            completed: statusCounts.find(s => s._id === 'completed')?.count || 0,
            cancelled: statusCounts.find(s => s._id === 'cancelled')?.count || 0,
            packageStats: packageCounts,
            statusStats: statusCounts,
            analytics: {
                activeVisitors,
                todayVisitors,
                totalPageviews
            }
        };

        console.log('✅ Stats fetched successfully');

        res.json({
            success: true,
            ...stats
        });

    } catch (error) {
        console.error('❌ Stats fetch error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to fetch statistics'
        });
    }
});

// Get all contacts with pagination
app.get('/api/admin/contacts', authenticateToken, async (req, res) => {
    try {
        const { 
            page = 1, 
            limit = 10, 
            status, 
            package, 
            search 
        } = req.query;

        // Build filter
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

        // Pagination
        const skip = (parseInt(page) - 1) * parseInt(limit);

        // Get contacts
        const contacts = await Contact.find(filter)
            .sort({ createdAt: -1 })
            .skip(skip)
            .limit(parseInt(limit))
            .select('-__v');

        // Get total count
        const total = await Contact.countDocuments(filter);

        console.log(`✅ Fetched ${contacts.length} contacts`);

        res.json({
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
        console.error('❌ Contacts fetch error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to fetch contacts'
        });
    }
});

// Get single contact
app.get('/api/admin/contacts/:id', authenticateToken, async (req, res) => {
    try {
        const contact = await Contact.findById(req.params.id).select('-__v');
        
        if (!contact) {
            return res.status(404).json({
                success: false,
                error: 'Contact not found'
            });
        }

        res.json({
            success: true,
            contact
        });

    } catch (error) {
        console.error('Contact details error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to fetch contact details'
        });
    }
});

// Update contact status
app.put('/api/admin/contacts/:id', authenticateToken, async (req, res) => {
    try {
        const { status } = req.body;
        
        if (!status) {
            return res.status(400).json({
                success: false,
                error: 'Status is required'
            });
        }

        const validStatuses = ['new', 'contacted', 'in_progress', 'completed', 'cancelled'];
        if (!validStatuses.includes(status)) {
            return res.status(400).json({
                success: false,
                error: 'Invalid status'
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
                error: 'Contact not found'
            });
        }

        res.json({
            success: true,
            message: 'Status updated successfully',
            contact
        });

    } catch (error) {
        console.error('Contact update error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to update contact'
        });
    }
});

// Delete contact
app.delete('/api/admin/contacts/:id', authenticateToken, async (req, res) => {
    try {
        const contact = await Contact.findByIdAndDelete(req.params.id);
        
        if (!contact) {
            return res.status(404).json({
                success: false,
                error: 'Contact not found'
            });
        }

        res.json({
            success: true,
            message: 'Contact deleted successfully'
        });

    } catch (error) {
        console.error('Contact delete error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to delete contact'
        });
    }
});

// Content management endpoints
app.get('/api/admin/content', authenticateToken, async (req, res) => {
    try {
        const content = await Content.find().sort({ updatedAt: -1 });
        
        res.json({
            success: true,
            content
        });

    } catch (error) {
        console.error('Content list error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to load content'
        });
    }
});

app.post('/api/admin/content', authenticateToken, async (req, res) => {
    try {
        const { key, page, section, content, status } = req.body;
        
        if (!key || !page || !section || !content) {
            return res.status(400).json({
                success: false,
                error: 'All fields are required'
            });
        }

        const existing = await Content.findOne({ key });
        let savedContent;

        if (existing) {
            existing.page = page;
            existing.section = section;
            existing.content = content;
            existing.status = status || 'active';
            existing.updatedBy = req.user.email;
            existing.updatedAt = new Date();
            
            savedContent = await existing.save();
        } else {
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

        res.json({
            success: true,
            message: existing ? 'Content updated' : 'Content created',
            content: savedContent
        });

    } catch (error) {
        console.error('Content save error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to save content'
        });
    }
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error('Server error:', err);
    res.status(err.status || 500).json({
        success: false,
        error: process.env.NODE_ENV === 'production' 
            ? 'Server error occurred' 
            : err.message
    });
});

// 404 handler
app.use('*', (req, res) => {
    res.status(404).json({
        success: false,
        error: 'Endpoint not found'
    });
});

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, async () => {
    await createDefaultAdmin();
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`📡 API Base URL: http://localhost:${PORT}`);
    console.log(`🔐 Admin Credentials:`);
    console.log(`   📧 Email: ${process.env.ADMIN_EMAIL}`);
    console.log(`   🔑 Password: ${process.env.ADMIN_PASSWORD}`);
    console.log(`🌐 CORS enabled for all origins`);
});