const cloudinary = require('cloudinary').v2;
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
const PORT = process.env.PORT || 10000;

// Add request logging for debugging
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.path} - Headers:`, req.headers);
  next();
});

// CORS configuration (ONLY ONE!)
app.options('*', cors()); // Handle preflight requests 
app.use(cors({
  origin: true, // Allow any origin
  credentials: true, // Enable credentials
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'HEAD', 'PATCH'],
  allowedHeaders: ['*'], // Allow all headers
  exposedHeaders: ['*'], // Expose all headers
  preflightContinue: false,
  optionsSuccessStatus: 200
}));

// Extra CORS headers for stubborn browsers
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  next();
});

// Initialize Prisma with error handling
let prisma;
try {
  if (!global.prisma) {
    global.prisma = new PrismaClient();
  }
  prisma = global.prisma;
  console.log('Prisma client initialized successfully');
} catch (error) {
  console.error('Prisma initialization error:', error);
}

// Environment check
const isProduction = process.env.NODE_ENV === 'production';
console.log(`Environment: ${isProduction ? 'production' : 'development'}`);

// Configure email transporter
// Replace the email configuration section in your index.js with this:

// Configure email transporter
let emailTransporter = null;

try {
  if (process.env.EMAIL_SERVICE === 'gmail') {
    // Gmail configuration
    emailTransporter = nodemailer.createTransporter({
      service: 'gmail',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
      }
    });
    console.log('📧 Gmail email service configured');
  } else if (process.env.EMAIL_SERVICE === 'sendgrid') {
    // SendGrid configuration
    emailTransporter = nodemailer.createTransporter({
      host: 'smtp.sendgrid.net',
      port: 587,
      secure: false,
      auth: {
        user: 'apikey',
        pass: process.env.SENDGRID_API_KEY
      }
    });
    console.log('📧 SendGrid email service configured');
  } else {
    console.log('📧 Email service not configured - set EMAIL_SERVICE in .env');
  }
} catch (error) {
  console.error('❌ Email configuration error:', error.message);
}
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});
// Helper function to log activities
async function logActivity(userId, action, description, metadata = null, propertyId = null) {
  try {
    await prisma.activityLog.create({
      data: {
        userId: userId,
        propertyId: propertyId,
        action: action,
        description: description,
        metadata: metadata,
        createdAt: new Date()
      }
    });
  } catch (error) {
    console.error('Activity logging error:', error);
  }
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

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(limiter);

// ADD THIS LINE RIGHT HERE:
app.use(express.static('public')); // or whatever folder contains your HTML files

// Input validation helpers...
const validateEmail = (email) => {
  // ... rest of your code continues
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

  jwt.verify(token, process.env.JWT_SECRET || 'fallback-secret-key-123', (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};


// Replace your current root endpoint with this:
app.get('/', (req, res) => {
  // Check if request accepts HTML (browser request)
  if (req.headers.accept && req.headers.accept.includes('text/html')) {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
  } else {
    // Return JSON for API requests
    res.json({ 
      message: 'Hyra Tryggt API is running!',
      version: '3.1.0',
      environment: isProduction ? 'production' : 'development',
      timestamp: new Date().toISOString(),
      features: {
        authentication: true,
        properties: true,
        images: true,
        applications: true,
        activityLogging: true,
        email: !!emailTransporter,
        prisma: !!prisma
      },
      endpoints: {
        auth: ['/register', '/login', '/profile'],
        properties: ['/properties', '/properties/:id', '/my-properties'],
        images: ['/properties/:id/images', '/images/:id'],
        applications: ['/applications', '/applications/:id', '/properties/:id/apply', '/my-applications'],
        analytics: ['/activity-logs', '/dashboard-stats']
      },
      serverInfo: {
        nodeVersion: process.version,
        platform: process.platform,
        uptime: process.uptime()
      }
    });
  }
});

// Health check
app.get('/health', (req, res) => {
  console.log('Health check called');
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    environment: isProduction ? 'production' : 'development',
    emailConfigured: !!emailTransporter,
    prismaConnected: !!prisma,
    uptime: process.uptime()
  });
});

// Register new user
app.post('/register', authLimiter, async (req, res) => {
  console.log('Register endpoint called');
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

    // Log registration activity
    await logActivity(user.id, 'REGISTER', 'User registered successfully');
    
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
    res.status(500).json({ error: 'Internal server error', details: error.message });
  }
});

// Login user
app.post('/login', authLimiter, async (req, res) => {
  console.log('Login endpoint called');
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
    
    // Update last login time
    await prisma.user.update({
      where: { id: user.id },
      data: { lastLoginAt: new Date() }
    });

    // Log login activity
    await logActivity(
      user.id, 
      'LOGIN', 
      'User logged in successfully',
      { userAgent: req.headers['user-agent'] }
    );
    
    const token = jwt.sign(
      { userId: user.id, email: user.email },
      process.env.JWT_SECRET || 'fallback-secret-key-123',
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
    res.status(500).json({ error: 'Internal server error', details: error.message });
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
        lastLoginAt: true,
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
    res.status(500).json({ error: 'Internal server error', details: error.message });
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

    // Log property creation
    await logActivity(
      req.user.userId, 
      'CREATE_PROPERTY', 
      `Created property: ${property.title}`,
      { propertyId: property.id, rent: property.rent, city: property.city },
      property.id
    );
    
    res.status(201).json({
      message: 'Property created successfully',
      property
    });
    
  } catch (error) {
    console.error('Property creation error:', error);
    res.status(500).json({ error: 'Internal server error', details: error.message });
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
    res.status(500).json({ error: 'Internal server error', details: error.message });
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
    res.status(500).json({ error: 'Internal server error', details: error.message });
  }
});

// Upload property images
app.post('/properties/:id/images', authenticateToken, upload.array('images', 10), async (req, res) => {
  try {
    const propertyId = parseInt(req.params.id);
    
    // Verify property ownership
    const property = await prisma.property.findUnique({
      where: { id: propertyId, landlordId: req.user.userId }
    });
    
    if (!property) {
      return res.status(404).json({ error: 'Property not found or not owned by you' });
    }
    
    if (!req.files || req.files.length === 0) {
      return res.status(400).json({ error: 'No images provided' });
    }
    
    // For serverless, we'll just store the image info without actual file storage
    // In production, you'd upload to cloud storage like AWS S3, Cloudinary, etc.
    const imageRecords = [];
    
    for (let i = 0; i < req.files.length; i++) {
      const file = req.files[i];
      const imageId = uuidv4();
      
      // In a real implementation, upload file to cloud storage here
      // For now, we'll just create database records
      const imageRecord = await prisma.propertyImage.create({
        data: {
          url: `/images/${imageId}`, // Placeholder URL
          alt: `Property image ${i + 1}`,
          isPrimary: i === 0, // First image is primary
          propertyId: propertyId
        }
      });
      
      imageRecords.push(imageRecord);
    }

    // Log image upload
    await logActivity(
      req.user.userId, 
      'UPLOAD_IMAGES', 
      `Uploaded ${req.files.length} images for property`,
      { imageCount: req.files.length },
      propertyId
    );
    
    res.status(201).json({
      message: 'Images uploaded successfully',
      images: imageRecords
    });
    
  } catch (error) {
    console.error('Image upload error:', error);
    res.status(500).json({ error: 'Internal server error', details: error.message });
  }
});

// Get property images
app.get('/properties/:id/images', async (req, res) => {
  try {
    const propertyId = parseInt(req.params.id);
    
    const images = await prisma.propertyImage.findMany({
      where: { propertyId: propertyId },
      orderBy: [
        { isPrimary: 'desc' },
        { createdAt: 'asc' }
      ]
    });
    
    res.json(images);
  } catch (error) {
    console.error('Get images error:', error);
    res.status(500).json({ error: 'Internal server error', details: error.message });
  }
});

// Set primary image
app.put('/images/:id/primary', authenticateToken, async (req, res) => {
  try {
    const imageId = parseInt(req.params.id);
    
    const image = await prisma.propertyImage.findUnique({
      where: { id: imageId },
      include: { property: true }
    });
    
    if (!image) {
      return res.status(404).json({ error: 'Image not found' });
    }
    
    if (image.property.landlordId !== req.user.userId) {
      return res.status(403).json({ error: 'Not authorized' });
    }
    
    // Remove primary status from other images
    await prisma.propertyImage.updateMany({
      where: { propertyId: image.propertyId },
      data: { isPrimary: false }
    });
    
    // Set this image as primary
    await prisma.propertyImage.update({
      where: { id: imageId },
      data: { isPrimary: true }
    });
    
    res.json({ message: 'Primary image updated successfully' });
  } catch (error) {
    console.error('Set primary image error:', error);
    res.status(500).json({ error: 'Internal server error', details: error.message });
  }
});

// Delete image
app.delete('/images/:id', authenticateToken, async (req, res) => {
  try {
    const imageId = parseInt(req.params.id);
    
    const image = await prisma.propertyImage.findUnique({
      where: { id: imageId },
      include: { property: true }
    });
    
    if (!image) {
      return res.status(404).json({ error: 'Image not found' });
    }
    
    if (image.property.landlordId !== req.user.userId) {
      return res.status(403).json({ error: 'Not authorized' });
    }
    
    await prisma.propertyImage.delete({
      where: { id: imageId }
    });
    
    res.json({ message: 'Image deleted successfully' });
  } catch (error) {
    console.error('Delete image error:', error);
    res.status(500).json({ error: 'Internal server error', details: error.message });
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

    // Log application
    await logActivity(
      req.user.userId, 
      'APPLY_PROPERTY', 
      `Applied for property: ${property.title}`,
      { applicationId: application.id, rent: property.rent },
      propertyId
    );
    
    // Send email notification to landlord
    if (emailTransporter) {
      const emailSubject = `New application for ${property.title}`;
      const emailBody = `
        <h2>New Rental Application</h2>
        <p><strong>Property:</strong> ${property.title}</p>
        <p><strong>Applicant:</strong> ${applicant.name}</p>
        <p><strong>Email:</strong> ${applicant.email}</p>
        ${applicant.phone ? `<p><strong>Phone:</strong> ${applicant.phone}</p>` : ''}
        ${message ? `<p><strong>Message:</strong> ${message}</p>` : ''}
        <p><strong>Applied:</strong> ${new Date().toLocaleDateString()}</p>
      `;
      
      await sendEmail(property.landlord.email, emailSubject, emailBody);
    }
    
    res.status(201).json({
      message: 'Application submitted successfully',
      application
    });
    
  } catch (error) {
    console.error('Application error:', error);
    res.status(500).json({ error: 'Internal server error', details: error.message });
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
    res.status(500).json({ error: 'Internal server error', details: error.message });
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
    res.status(500).json({ error: 'Internal server error', details: error.message });
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

    // Log application status change
    await logActivity(
      req.user.userId, 
      'UPDATE_APPLICATION', 
      `Updated application status to ${status}`,
      { applicationId: applicationId, status: status, applicantName: application.user.name },
      application.property.id
    );
    
    // Send email notification to applicant
    if (emailTransporter) {
      const statusText = status === 'ACCEPTED' ? 'accepted' : 'rejected';
      const emailSubject = `Your application has been ${statusText}`;
      const emailBody = `
        <h2>Application Update</h2>
        <p>Your application for <strong>${application.property.title}</strong> has been <strong>${statusText}</strong>.</p>
        ${status === 'ACCEPTED' ? `
          <p>Congratulations! Please contact the landlord to proceed:</p>
          <p><strong>Landlord:</strong> ${application.property.landlord.name}</p>
          <p><strong>Email:</strong> ${application.property.landlord.email}</p>
        ` : ''}
        <p><strong>Property:</strong> ${application.property.address}, ${application.property.city}</p>
        <p><strong>Rent:</strong> ${application.property.rent} SEK/month</p>
      `;
      
      await sendEmail(application.user.email, emailSubject, emailBody);
    }
    
    res.json({
      message: 'Application status updated successfully',
      application: updatedApplication
    });
    
  } catch (error) {
    console.error('Update application error:', error);
    res.status(500).json({ error: 'Internal server error', details: error.message });
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

    // Log application withdrawal
    await logActivity(
      req.user.userId, 
      'WITHDRAW_APPLICATION', 
      `Withdrew application for property: ${application.property.title}`,
      { applicationId: applicationId },
      application.property.id
    );
    
    res.json({ message: 'Application withdrawn successfully' });
    
  } catch (error) {
    console.error('Withdraw application error:', error);
    res.status(500).json({ error: 'Internal server error', details: error.message });
  }
});

// NEW: Get activity logs
app.get('/activity-logs', authenticateToken, async (req, res) => {
  try {
    const { page = 1, limit = 50 } = req.query;
    const skip = (parseInt(page) - 1) * parseInt(limit);
    
    const [logs, total] = await Promise.all([
      prisma.activityLog.findMany({
        where: { userId: req.user.userId },
        include: {
          property: {
            select: { id: true, title: true, address: true }
          }
        },
        orderBy: { createdAt: 'desc' },
        skip,
        take: parseInt(limit)
      }),
      prisma.activityLog.count({ where: { userId: req.user.userId } })
    ]);
    
    res.json({
      logs,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / parseInt(limit))
      }
    });
  } catch (error) {
    console.error('Get activity logs error:', error);
    res.status(500).json({ error: 'Internal server error', details: error.message });
  }
});

// NEW: Dashboard statistics
app.get('/dashboard-stats', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    
    const [
      totalProperties,
      activeProperties,
      totalApplications,
      pendingApplications,
      recentActivity
    ] = await Promise.all([
      prisma.property.count({ where: { landlordId: userId } }),
      prisma.property.count({ where: { landlordId: userId, isAvailable: true } }),
      prisma.application.count({ where: { userId: userId } }),
      prisma.application.count({ where: { userId: userId, status: 'PENDING' } }),
      prisma.activityLog.findMany({
        where: { userId: userId },
        orderBy: { createdAt: 'desc' },
        take: 10,
        include: {
          property: {
            select: { title: true }
          }
        }
      })
    ]);
    
    res.json({
      properties: {
        total: totalProperties,
        active: activeProperties
      },
      applications: {
        total: totalApplications,
        pending: pendingApplications
      },
      recentActivity: recentActivity
    });
  } catch (error) {
    console.error('Dashboard stats error:', error);
    res.status(500).json({ error: 'Internal server error', details: error.message });
  }
});

// NEW: Update property notes
app.put('/properties/:id/notes', authenticateToken, async (req, res) => {
  try {
    const propertyId = parseInt(req.params.id);
    const { notes } = req.body;
    
    const property = await prisma.property.findUnique({
      where: { id: propertyId, landlordId: req.user.userId }
    });
    
    if (!property) {
      return res.status(404).json({ error: 'Property not found or not owned by you' });
    }
    
    const updatedProperty = await prisma.property.update({
      where: { id: propertyId },
      data: { notes: notes || null }
    });

    // Log notes update
    await logActivity(
      req.user.userId, 
      'UPDATE_NOTES', 
      'Updated property notes',
      { hasNotes: !!notes },
      propertyId
    );
    
    res.json({
      message: 'Property notes updated successfully',
      property: updatedProperty
    });
    
  } catch (error) {
    console.error('Update property notes error:', error);
    res.status(500).json({ error: 'Internal server error', details: error.message });
  }
});

// NEW: Add internal notes to applications
app.put('/applications/:id/notes', authenticateToken, async (req, res) => {
  try {
    const applicationId = parseInt(req.params.id);
    const { internalNotes } = req.body;
    
    const application = await prisma.application.findUnique({
      where: { id: applicationId },
      include: { property: true }
    });
    
    if (!application) {
      return res.status(404).json({ error: 'Application not found' });
    }
    
    if (application.property.landlordId !== req.user.userId) {
      return res.status(403).json({ error: 'Not authorized to update this application' });
    }
    
    const updatedApplication = await prisma.application.update({
      where: { id: applicationId },
      data: { internalNotes: internalNotes || null },
      include: {
        user: {
          select: { id: true, name: true, email: true, phone: true }
        },
        property: {
          select: { id: true, title: true, address: true, city: true, rent: true }
        }
      }
    });

    // Log notes update
    await logActivity(
      req.user.userId, 
      'UPDATE_APPLICATION_NOTES', 
      'Updated application internal notes',
      { applicationId: applicationId, hasNotes: !!internalNotes },
      application.property.id
    );
    
    res.json({
      message: 'Application notes updated successfully',
      application: updatedApplication
    });
    
  } catch (error) {
    console.error('Update application notes error:', error);
    res.status(500).json({ error: 'Internal server error', details: error.message });
  }
});

// Add a catch-all route for debugging
app.use('*', (req, res) => {
  console.log(`404 - Route not found: ${req.method} ${req.originalUrl}`);
  res.status(404).json({ 
    error: 'Endpoint not found',
    path: req.originalUrl,
    method: req.method,
    timestamp: new Date().toISOString(),
    availableEndpoints: [
      'GET /',
      'GET /health',
      'POST /register',
      'POST /login',
      'GET /profile',
      'GET /properties',
      'POST /properties',
      'GET /my-properties',
      'POST /properties/:id/images',
      'GET /properties/:id/images',
      'POST /properties/:id/apply',
      'GET /my-applications',
      'GET /my-property-applications',
      'GET /activity-logs',
      'GET /dashboard-stats',
      'PUT /properties/:id/notes',
      'PUT /applications/:id/notes'
    ]
  });
});

// Error handling
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ 
    error: 'Internal server error',
    details: err.message,
    timestamp: new Date().toISOString()
  });
});

// Graceful shutdown handling
process.on('SIGTERM', async () => {
  console.log('SIGTERM received, shutting down gracefully');
  if (prisma) {
    await prisma.$disconnect();
  }
  process.exit(0);
});

console.log('Server initialized successfully');

// Start server
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`📊 Prisma: ${prisma ? 'Connected' : 'Not connected'}`);
  console.log(`📧 Email: ${emailTransporter ? 'Enabled' : 'Disabled'}`);
  console.log(`✨ Features: Activity Logging, Performance Indexes, Notes System`);
});

// Export as Vercel serverless function
module.exports = app;