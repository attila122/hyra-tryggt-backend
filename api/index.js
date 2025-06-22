const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { PrismaClient } = require('@prisma/client');
const rateLimit = require('express-rate-limit');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');
const nodemailer = require('nodemailer');

// Initialize Express app
const app = express();

// Initialize Prisma
let prisma;
if (!global.prisma) {
  global.prisma = new PrismaClient();
}
prisma = global.prisma;

// Environment check
const isProduction = process.env.NODE_ENV === 'production';

// Configure email transporter
let emailTransporter = null;
if (process.env.EMAIL_USER && process.env.EMAIL_PASS) {
  emailTransporter = nodemailer.createTransporter({
    service: 'gmail',
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS
    }
  });
}

// Send email notification
async function sendEmail(to, subject, html) {
  if (!emailTransporter) {
    console.log('Email not configured, skipping notification');
    return;
  }
  
  try {
    await emailTransporter.sendMail({
      from: process.env.EMAIL_USER,
      to: to,
      subject: subject,
      html: html
    });
    console.log(`📧 Email sent to ${to}`);
  } catch (error) {
    console.error('❌ Email send error:', error.message);
  }
}

// Configure multer for image uploads (simplified for serverless)
const upload = multer({
  storage: multer.memoryStorage(),
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('Only image files are allowed!'), false);
    }
  },
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB limit
    files: 10 // Maximum 10 files
  }
});

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
  message: { error: 'Too many requests, please try again later' },
  standardHeaders: true,
  legacyHeaders: false
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: 'Too many login attempts, please try again later' }
});

// CORS configuration
app.use(cors({
  origin: true,
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(limiter);

// Input validation helpers
const validateEmail = (email) => {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
};

const validatePhone = (phone) => {
  if (!phone) return true;
  const phoneRegex = /^[\+]?[1-9][\d]{0,15}$/;
  return phoneRegex.test(phone.replace(/[\s\-\(\)]/g, ''));
};

const validatePassword = (password) => {
  return password && password.length >= 6;
};

// Middleware to verify JWT token
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

// Root endpoint
app.get('/', (req, res) => {
  res.json({ 
    message: 'Hyra Tryggt API is running!',
    version: '3.0.0',
    environment: isProduction ? 'production' : 'development',
    features: {
      authentication: true,
      properties: true,
      images: true,
      applications: true,
      email: !!emailTransporter
    },
    endpoints: {
      auth: ['/register', '/login', '/profile'],
      properties: ['/properties', '/properties/:id', '/my-properties'],
      images: ['/properties/:id/images', '/images/:id'],
      applications: ['/applications', '/applications/:id', '/properties/:id/apply', '/my-applications']
    }
  });
});

// Health check
app.get('/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    environment: isProduction ? 'production' : 'development',
    emailConfigured: !!emailTransporter
  });
});

// Register new user
app.post('/register', authLimiter, async (req, res) => {
  try {
    const { email, password, name, phone } = req.body;
    
    if (!email || !password || !name) {
      return res.status(400).json({ error: 'Email, password, and name are required' });
    }
    
    if (!validateEmail(email)) {
      return res.status(400).json({ error: 'Invalid email format' });
    }
    
    if (!validatePassword(password)) {
      return res.status(400).json({ error: 'Password must be at least 6 characters long' });
    }
    
    if (!validatePhone(phone)) {
      return res.status(400).json({ error: 'Invalid phone number format' });
    }
    
    const existingUser = await prisma.user.findUnique({
      where: { email: email.toLowerCase() }
    });
    
    if (existingUser) {
      return res.status(409).json({ error: 'User with this email already exists' });
    }
    
    const hashedPassword = await bcrypt.hash(password, 12);
    
    const user = await prisma.user.create({
      data: {
        email: email.toLowerCase(),
        password: hashedPassword,
        name: name.trim(),
        phone: phone ? phone.trim() : null
      }
    });
    
    res.status(201).json({ 
      message: 'User created successfully',
      user: { 
        id: user.id, 
        email: user.email, 
        name: user.name,
        createdAt: user.createdAt
      }
    });
    
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Login user
app.post('/login', authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }
    
    const user = await prisma.user.findUnique({
      where: { email: email.toLowerCase() }
    });
    
    if (!user) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }
    
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }
    
    const token = jwt.sign(
      { userId: user.id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );
    
    res.json({
      message: 'Login successful',
      token: token,
      user: { 
        id: user.id, 
        email: user.email, 
        name: user.name,
        phone: user.phone
      }
    });
    
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get user profile
app.get('/profile', authenticateToken, async (req, res) => {
  try {
    const user = await prisma.user.findUnique({
      where: { id: req.user.userId },
      select: {
        id: true,
        email: true,
        name: true,
        phone: true,
        createdAt: true,
        _count: {
          select: { 
            properties: true,
            applications: true
          }
        }
      }
    });
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    res.json(user);
  } catch (error) {
    console.error('Profile error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Create property
app.post('/properties', authenticateToken, async (req, res) => {
  try {
    const { title, description, address, city, rent, rooms, size, availableFrom } = req.body;
    
    if (!title || !address || !city || !rent || !rooms || !size) {
      return res.status(400).json({ 
        error: 'Title, address, city, rent, rooms, and size are required' 
      });
    }
    
    if (rent <= 0 || rooms <= 0 || size <= 0) {
      return res.status(400).json({ 
        error: 'Rent, rooms, and size must be positive numbers' 
      });
    }
    
    const property = await prisma.property.create({
      data: {
        title: title.trim(),
        description: description ? description.trim() : null,
        address: address.trim(),
        city: city.trim(),
        rent: parseInt(rent),
        rooms: parseInt(rooms),
        size: parseInt(size),
        availableFrom: availableFrom ? new Date(availableFrom) : new Date(),
        landlordId: req.user.userId
      }
    });
    
    res.status(201).json({
      message: 'Property created successfully',
      property
    });
    
  } catch (error) {
    console.error('Property creation error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get all properties
app.get('/properties', async (req, res) => {
  try {
    const { city, minRent, maxRent, minRooms, maxRooms, page = 1, limit = 20 } = req.query;
    
    const skip = (parseInt(page) - 1) * parseInt(limit);
    
    const where = { isAvailable: true };
    
    if (city) {
      where.city = { contains: city, mode: 'insensitive' };
    }
    
    if (minRent || maxRent) {
      where.rent = {};
      if (minRent) where.rent.gte = parseInt(minRent);
      if (maxRent) where.rent.lte = parseInt(maxRent);
    }
    
    if (minRooms || maxRooms) {
      where.rooms = {};
      if (minRooms) where.rooms.gte = parseInt(minRooms);
      if (maxRooms) where.rooms.lte = parseInt(maxRooms);
    }
    
    const [properties, total] = await Promise.all([
      prisma.property.findMany({
        where,
        include: {
          landlord: {
            select: { name: true, email: true }
          },
          images: {
            orderBy: [
              { isPrimary: 'desc' },
              { createdAt: 'asc' }
            ]
          },
          _count: {
            select: { applications: true }
          }
        },
        orderBy: { createdAt: 'desc' },
        skip,
        take: parseInt(limit)
      }),
      prisma.property.count({ where })
    ]);
    
    res.json({
      properties,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / parseInt(limit))
      }
    });
  } catch (error) {
    console.error('Get properties error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get user's properties
app.get('/my-properties', authenticateToken, async (req, res) => {
  try {
    const properties = await prisma.property.findMany({
      where: { landlordId: req.user.userId },
      include: {
        images: {
          orderBy: [
            { isPrimary: 'desc' },
            { createdAt: 'asc' }
          ]
        },
        _count: {
          select: { applications: true }
        }
      },
      orderBy: { createdAt: 'desc' }
    });
    
    res.json(properties);
  } catch (error) {
    console.error('Get my properties error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Apply for property
app.post('/properties/:id/apply', authenticateToken, async (req, res) => {
  try {
    const propertyId = parseInt(req.params.id);
    const { message } = req.body;
    
    const property = await prisma.property.findUnique({
      where: { id: propertyId },
      include: { landlord: true }
    });
    
    if (!property) {
      return res.status(404).json({ error: 'Property not found' });
    }
    
    if (!property.isAvailable) {
      return res.status(400).json({ error: 'Property is no longer available' });
    }
    
    if (property.landlordId === req.user.userId) {
      return res.status(400).json({ error: 'You cannot apply to your own property' });
    }
    
    const existingApplication = await prisma.application.findUnique({
      where: {
        userId_propertyId: {
          userId: req.user.userId,
          propertyId: propertyId
        }
      }
    });
    
    if (existingApplication) {
      return res.status(409).json({ error: 'You have already applied to this property' });
    }
    
    const applicant = await prisma.user.findUnique({
      where: { id: req.user.userId }
    });
    
    const application = await prisma.application.create({
      data: {
        userId: req.user.userId,
        propertyId: propertyId,
        message: message || null,
        status: 'PENDING'
      },
      include: {
        user: {
          select: { id: true, name: true, email: true, phone: true }
        },
        property: {
          select: { id: true, title: true, address: true, city: true, rent: true }
        }
      }
    });
    
    res.status(201).json({
      message: 'Application submitted successfully',
      application
    });
    
  } catch (error) {
    console.error('Application error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get user applications
app.get('/my-applications', authenticateToken, async (req, res) => {
  try {
    const applications = await prisma.application.findMany({
      where: { userId: req.user.userId },
      include: {
        property: {
          include: {
            landlord: {
              select: { name: true, email: true, phone: true }
            },
            images: {
              where: { isPrimary: true },
              take: 1
            }
          }
        }
      },
      orderBy: { createdAt: 'desc' }
    });
    
    res.json(applications);
  } catch (error) {
    console.error('Get my applications error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get applications for landlord's properties
app.get('/my-property-applications', authenticateToken, async (req, res) => {
  try {
    const applications = await prisma.application.findMany({
      where: {
        property: {
          landlordId: req.user.userId
        }
      },
      include: {
        user: {
          select: { id: true, name: true, email: true, phone: true, createdAt: true }
        },
        property: {
          select: { id: true, title: true, address: true, city: true, rent: true }
        }
      },
      orderBy: { createdAt: 'desc' }
    });
    
    res.json(applications);
  } catch (error) {
    console.error('Get property applications error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Update application status
app.put('/applications/:id', authenticateToken, async (req, res) => {
  try {
    const applicationId = parseInt(req.params.id);
    const { status } = req.body;
    
    if (!['PENDING', 'ACCEPTED', 'REJECTED'].includes(status)) {
      return res.status(400).json({ error: 'Invalid status. Must be PENDING, ACCEPTED, or REJECTED' });
    }
    
    const application = await prisma.application.findUnique({
      where: { id: applicationId },
      include: {
        property: { include: { landlord: true } },
        user: true
      }
    });
    
    if (!application) {
      return res.status(404).json({ error: 'Application not found' });
    }
    
    if (application.property.landlordId !== req.user.userId) {
      return res.status(403).json({ error: 'Not authorized to update this application' });
    }
    
    const updatedApplication = await prisma.application.update({
      where: { id: applicationId },
      data: { status },
      include: {
        user: {
          select: { id: true, name: true, email: true, phone: true }
        },
        property: {
          select: { id: true, title: true, address: true, city: true, rent: true }
        }
      }
    });
    
    res.json({
      message: 'Application status updated successfully',
      application: updatedApplication
    });
    
  } catch (error) {
    console.error('Update application error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Withdraw application
app.delete('/applications/:id', authenticateToken, async (req, res) => {
  try {
    const applicationId = parseInt(req.params.id);
    
    const application = await prisma.application.findUnique({
      where: { id: applicationId },
      include: {
        property: { include: { landlord: true } },
        user: true
      }
    });
    
    if (!application) {
      return res.status(404).json({ error: 'Application not found' });
    }
    
    if (application.userId !== req.user.userId) {
      return res.status(403).json({ error: 'Not authorized to withdraw this application' });
    }
    
    await prisma.application.update({
      where: { id: applicationId },
      data: { status: 'WITHDRAWN' }
    });
    
    res.json({ message: 'Application withdrawn successfully' });
    
  } catch (error) {
    console.error('Withdraw application error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Error handling
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// Export as Vercel serverless function
module.exports = app;