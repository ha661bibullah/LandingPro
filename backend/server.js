// backend/server.js
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(cors({
    origin: ['https://landingpro.netlify.app', 'http://localhost:3000'],
    credentials: true
}));
app.use(express.json());

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
})
.then(() => console.log('✅ MongoDB Connected Successfully'))
.catch(err => console.error('❌ MongoDB Connection Error:', err));

// Contact Model
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
});

const Contact = mongoose.model('Contact', ContactSchema);

// Admin Model
const AdminSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, default: 'admin' },
    lastLogin: { type: Date },
    createdAt: { type: Date, default: Date.now }
});

const Admin = mongoose.model('Admin', AdminSchema);

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
        }
    } catch (error) {
        console.error('❌ Error creating admin account:', error);
    }
};

// Authentication Middleware
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

// Routes

// Login Route
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        const admin = await Admin.findOne({ email });
        if (!admin) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const validPassword = await bcrypt.compare(password, admin.password);
        if (!validPassword) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Update last login
        admin.lastLogin = new Date();
        await admin.save();

        // Generate JWT token
        const token = jwt.sign(
            { id: admin._id, email: admin.email, role: admin.role },
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.json({
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

// Submit Contact Form (Public)
app.post('/api/contact', async (req, res) => {
    try {
        const { name, email, phone, package, message } = req.body;
        
        const contact = new Contact({
            name,
            email,
            phone: phone || '+৮৮০ ১৩২৬১৯৮৪৫৬',
            package,
            message
        });

        await contact.save();
        
        // Log to console for debugging
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

// Admin Routes (Protected)

// Get all contacts with pagination and filtering
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
        
        // Filter by status
        if (status && status !== 'all') {
            query.status = status;
        }
        
        // Search by name, email, or message
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
        res.json(contact);
    } catch (error) {
        console.error('Get contact error:', error);
        res.status(500).json({ error: 'Failed to fetch contact' });
    }
});

// Update contact status
app.put('/api/admin/contacts/:id', authenticateToken, async (req, res) => {
    try {
        const { status, notes } = req.body;
        const updateData = { 
            status,
            updatedAt: new Date()
        };

        const contact = await Contact.findByIdAndUpdate(
            req.params.id,
            updateData,
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

        // Get last 7 days data
        const sevenDaysAgo = new Date();
        sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);

        const recentContacts = await Contact.countDocuments({
            createdAt: { $gte: sevenDaysAgo }
        });

        // Package distribution
        const packageStats = await Contact.aggregate([
            { $group: { _id: '$package', count: { $sum: 1 } } },
            { $sort: { count: -1 } }
        ]);

        res.json({
            totalContacts,
            newContacts,
            contacted,
            inProgress,
            completed,
            recentContacts,
            packageStats
        });
    } catch (error) {
        console.error('Get stats error:', error);
        res.status(500).json({ error: 'Failed to fetch statistics' });
    }
});

// Health check endpoint
app.get('/api/health', (req, res) => {
    res.json({ 
        status: 'healthy', 
        timestamp: new Date().toISOString(),
        mongodb: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected'
    });
});

// Initialize and start server
const startServer = async () => {
    await initializeAdmin();
    
    app.listen(PORT, () => {
        console.log(`🚀 Server running on port ${PORT}`);
        console.log(`📊 MongoDB URI: ${process.env.MONGODB_URI ? 'Configured' : 'Not configured'}`);
        console.log(`🔑 Admin Email: ${process.env.ADMIN_EMAIL}`);
        console.log(`🔒 JWT Secret: ${process.env.JWT_SECRET ? 'Set' : 'Not set'}`);
    });
};

startServer();

// Handle unhandled promise rejections
process.on('unhandledRejection', (err) => {
    console.error('Unhandled Promise Rejection:', err);
});

module.exports = app;