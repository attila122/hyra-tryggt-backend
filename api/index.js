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
require('dotenv').config();

console.log('Starting Hyra Tryggt server...');

const app = express();
const prisma = new PrismaClient();

// Serve static files AFTER app is declared
app.use(express.static('public'));

// Production environment check
const isProduction = process.env.NODE_ENV === 'production';
const PORT = process.env.PORT || 3000;

// Create uploads directory if it doesn't exist (for local development)
const uploadsDir = path.join(__dirname, 'uploads', 'properties');
if (!isProduction && !fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

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
  console.log('✅ Email notifications enabled');
} else {
  console.log('⚠️ Email not configured - add EMAIL_USER and EMAIL_PASS for notifications');
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

// Configure multer for image uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadsDir);
  },
  filename: (req, file, cb) => {
    const uniqueName = `${uuidv4()}-${Date.now()}${path.extname(file.originalname)}`;
    cb(null, uniqueName);
  }
});

const fileFilter = (req, file, cb) => {
  if (file.mimetype.startsWith('image/')) {
    cb(null, true);
  } else {
    cb(new Error('Only image files are allowed!'), false);
  }
};

const upload = multer({
  storage: storage,
  fileFilter: fileFilter,
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB limit
    files: 10 // Maximum 10 files
  }
});

// Rate limiting - more lenient in production
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: isProduction ? 200 : 100,
  message: { error: 'Too many requests, please try again later' },
  standardHeaders: true,
  legacyHeaders: false
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: 'Too many login attempts, please try again later' }
});

// Middleware
app.use(limiter);

// CORS configuration for production
const allowedOrigins = [
  'https://hyratryggt.se',
  'https://www.hyratryggt.se',
  'https://hyra-tryggt-backend-z5kb.vercel.app',
  'http://localhost:3000',
  'http://localhost:8080',
  'null',
  process.env.NEXT_PUBLIC_API_URL
].filter(Boolean);

app.use(cors({
  origin: isProduction ? allowedOrigins : true,
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Serve uploaded images statically
if (!isProduction) {
  app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
} else {
  // In production, you might want to use cloud storage
  app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
}

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

console.log('Express app created');

// Root endpoint
app.get('/', (req, res) => {
  console.log('GET / called');
  res.json({ 
    message: 'Hyra Tryggt API is running!',
    version: '2.0.0',
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

// Register new user
app.post('/register', authLimiter, async (req, res) => {
  console.log('POST /register called');
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
  console.log('POST /login called');
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

// Create property (protected route)
app.post('/properties', authenticateToken, async (req, res) => {
  console.log('POST /properties called');
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

// Apply for a property
app.post('/properties/:id/apply', authenticateToken, async (req, res) => {
  try {
    const propertyId = parseInt(req.params.id);
    const { message } = req.body;
    
    // Check if property exists and is available
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
    
    // Check if user is not the landlord
    if (property.landlordId === req.user.userId) {
      return res.status(400).json({ error: 'You cannot apply to your own property' });
    }
    
    // Check if user has already applied
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
    
    // Get applicant details
    const applicant = await prisma.user.findUnique({
      where: { id: req.user.userId }
    });
    
    // Create application
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
    
    // Send email notification to landlord
    const emailSubject = `New Application for ${property.title}`;
    const emailHtml = `
      <h2>🏠 New Property Application</h2>
      <p>You have received a new application for your property:</p>
      
      <h3>Property Details:</h3>
      <ul>
        <li><strong>Title:</strong> ${property.title}</li>
        <li><strong>Address:</strong> ${property.address}, ${property.city}</li>
        <li><strong>Rent:</strong> ${property.rent.toLocaleString()} SEK/month</li>
      </ul>
      
      <h3>Applicant Details:</h3>
      <ul>
        <li><strong>Name:</strong> ${applicant.name}</li>
        <li><strong>Email:</strong> ${applicant.email}</li>
        ${applicant.phone ? `<li><strong>Phone:</strong> ${applicant.phone}</li>` : ''}
      </ul>
      
      ${message ? `
        <h3>Application Message:</h3>
        <p style="background: #f5f5f5; padding: 15px; border-radius: 5px;">${message}</p>
      ` : ''}
      
      <p>Please log in to your Hyra Tryggt account to manage this application.</p>
      <p><em>This is an automated message from Hyra Tryggt.</em></p>
    `;
    
    await sendEmail(property.landlord.email, emailSubject, emailHtml);
    
    res.status(201).json({
      message: 'Application submitted successfully',
      application
    });
    
  } catch (error) {
    console.error('Application error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get applications for a property (landlord only)
app.get('/properties/:id/applications', authenticateToken, async (req, res) => {
  try {
    const propertyId = parseInt(req.params.id);
    
    // Check if property belongs to user
    const property = await prisma.property.findFirst({
      where: { id: propertyId, landlordId: req.user.userId }
    });
    
    if (!property) {
      return res.status(404).json({ error: 'Property not found or not authorized' });
    }
    
    const applications = await prisma.application.findMany({
      where: { propertyId },
      include: {
        user: {
          select: { id: true, name: true, email: true, phone: true, createdAt: true }
        }
      },
      orderBy: { createdAt: 'desc' }
    });
    
    res.json(applications);
  } catch (error) {
    console.error('Get applications error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Update application status (landlord only)
app.put('/applications/:id', authenticateToken, async (req, res) => {
  try {
    const applicationId = parseInt(req.params.id);
    const { status } = req.body;
    
    if (!['PENDING', 'ACCEPTED', 'REJECTED'].includes(status)) {
      return res.status(400).json({ error: 'Invalid status. Must be PENDING, ACCEPTED, or REJECTED' });
    }
    
    // Get application with property and user details
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
    
    // Check if user is the landlord
    if (application.property.landlordId !== req.user.userId) {
      return res.status(403).json({ error: 'Not authorized to update this application' });
    }
    
    // Update application
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
    
    // Send email notification to applicant
    const statusText = status === 'ACCEPTED' ? 'accepted' : 'rejected';
    const emailSubject = `Application ${statusText} for ${application.property.title}`;
    const emailHtml = `
      <h2>🏠 Application Update</h2>
      <p>Your application has been <strong style="color: ${status === 'ACCEPTED' ? 'green' : 'red'};">${statusText}</strong>.</p>
      
      <h3>Property Details:</h3>
      <ul>
        <li><strong>Title:</strong> ${application.property.title}</li>
        <li><strong>Address:</strong> ${application.property.address}, ${application.property.city}</li>
        <li><strong>Rent:</strong> ${application.property.rent.toLocaleString()} SEK/month</li>
      </ul>
      
      ${status === 'ACCEPTED' ? `
        <div style="background: #d4edda; padding: 15px; border-radius: 5px; margin: 10px 0;">
          <p><strong>🎉 Congratulations!</strong> Please contact the landlord to proceed with the rental process.</p>
          <p><strong>Landlord Contact:</strong> ${application.property.landlord.email}</p>
        </div>
      ` : `
        <p>Thank you for your interest. Keep looking for other great properties!</p>
      `}
      
      <p><em>This is an automated message from Hyra Tryggt.</em></p>
    `;
    
    await sendEmail(application.user.email, emailSubject, emailHtml);
    
    res.json({
      message: 'Application status updated successfully',
      application: updatedApplication
    });
    
  } catch (error) {
    console.error('Update application error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get user's applications
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

// Get all applications for landlord's properties
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

// Withdraw application (applicant only)
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
    
    // Check if user is the applicant
    if (application.userId !== req.user.userId) {
      return res.status(403).json({ error: 'Not authorized to withdraw this application' });
    }
    
    // Update status to withdrawn instead of deleting
    await prisma.application.update({
      where: { id: applicationId },
      data: { status: 'WITHDRAWN' }
    });
    
    // Notify landlord
    const emailSubject = `Application withdrawn for ${application.property.title}`;
    const emailHtml = `
      <h2>🏠 Application Withdrawn</h2>
      <p>${application.user.name} has withdrawn their application for:</p>
      
      <h3>Property:</h3>
      <p><strong>${application.property.title}</strong><br>
      ${application.property.address}, ${application.property.city}</p>
      
      <p><em>This is an automated message from Hyra Tryggt.</em></p>
    `;
    
    await sendEmail(application.property.landlord.email, emailSubject, emailHtml);
    
    res.json({ message: 'Application withdrawn successfully' });
    
  } catch (error) {
    console.error('Withdraw application error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Upload images for a property
app.post('/properties/:id/images', authenticateToken, upload.array('images', 10), async (req, res) => {
  try {
    const propertyId = parseInt(req.params.id);
    
    const property = await prisma.property.findFirst({
      where: { id: propertyId, landlordId: req.user.userId }
    });
    
    if (!property) {
      return res.status(404).json({ error: 'Property not found or not authorized' });
    }
    
    if (!req.files || req.files.length === 0) {
      return res.status(400).json({ error: 'No images uploaded' });
    }
    
    const imagePromises = req.files.map((file, index) => {
      const imageUrl = `/uploads/properties/${file.filename}`;
      return prisma.propertyImage.create({
        data: {
          url: imageUrl,
          alt: req.body.alt || `${property.title} - Image ${index + 1}`,
          isPrimary: index === 0,
          propertyId: propertyId
        }
      });
    });
    
    const images = await Promise.all(imagePromises);
    
    res.status(201).json({
      message: 'Images uploaded successfully',
      images
    });
    
  } catch (error) {
    console.error('Image upload error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get images for a property
app.get('/properties/:id/images', async (req, res) => {
  try {
    const propertyId = parseInt(req.params.id);
    
    const images = await prisma.propertyImage.findMany({
      where: { propertyId },
      orderBy: [
        { isPrimary: 'desc' },
        { createdAt: 'asc' }
      ]
    });
    
    res.json(images);
  } catch (error) {
    console.error('Get images error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Delete an image
app.delete('/images/:id', authenticateToken, async (req, res) => {
  try {
    const imageId = parseInt(req.params.id);
    
    const image = await prisma.propertyImage.findFirst({
      where: { id: imageId },
      include: { property: true }
    });
    
    if (!image) {
      return res.status(404).json({ error: 'Image not found' });
    }
    
    if (image.property.landlordId !== req.user.userId) {
      return res.status(403).json({ error: 'Not authorized to delete this image' });
    }
    
    const filePath = path.join(__dirname, 'uploads', 'properties', path.basename(image.url));
    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
    }
    
    await prisma.propertyImage.delete({
      where: { id: imageId }
    });
    
    res.json({ message: 'Image deleted successfully' });
    
  } catch (error) {
    console.error('Delete image error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Set primary image
app.put('/images/:id/primary', authenticateToken, async (req, res) => {
  try {
    const imageId = parseInt(req.params.id);
    
    const image = await prisma.propertyImage.findFirst({
      where: { id: imageId },
      include: { property: true }
    });
    
    if (!image) {
      return res.status(404).json({ error: 'Image not found' });
    }
    
    if (image.property.landlordId !== req.user.userId) {
      return res.status(403).json({ error: 'Not authorized' });
    }
    
    await prisma.propertyImage.updateMany({
      where: { propertyId: image.propertyId },
      data: { isPrimary: false }
    });
    
    const updatedImage = await prisma.propertyImage.update({
      where: { id: imageId },
      data: { isPrimary: true }
    });
    
    res.json({
      message: 'Primary image updated successfully',
      image: updatedImage
    });
    
  } catch (error) {
    console.error('Set primary image error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get all properties (public route with filtering)
app.get('/properties', async (req, res) => {
  try {
    const { city, minRent, maxRent, minRooms, maxRooms, page = 1, limit = 20 } = req.query;
    
    const skip = (parseInt(page) - 1) * parseInt(limit);
    
    const where = { isAvailable: true }; // Only show available properties
    
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

// Get single property
app.get('/properties/:id', async (req, res) => {
  try {
    const property = await prisma.property.findUnique({
      where: { id: parseInt(req.params.id) },
      include: {
        landlord: {
          select: { name: true, email: true, phone: true }
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
      }
    });
    
    if (!property) {
      return res.status(404).json({ error: 'Property not found' });
    }
    
    res.json(property);
  } catch (error) {
    console.error('Get property error:', error);
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

// Update property
app.put('/properties/:id', authenticateToken, async (req, res) => {
  try {
    const propertyId = parseInt(req.params.id);
    const { title, description, address, city, rent, rooms, size, availableFrom, isAvailable } = req.body;
    
    const existingProperty = await prisma.property.findFirst({
      where: { id: propertyId, landlordId: req.user.userId }
    });
    
    if (!existingProperty) {
      return res.status(404).json({ error: 'Property not found or not authorized' });
    }
    
    const updateData = {};
    if (title) updateData.title = title.trim();
    if (description !== undefined) updateData.description = description ? description.trim() : null;
    if (address) updateData.address = address.trim();
    if (city) updateData.city = city.trim();
    if (rent) updateData.rent = parseInt(rent);
    if (rooms) updateData.rooms = parseInt(rooms);
    if (size) updateData.size = parseInt(size);
    if (availableFrom) updateData.availableFrom = new Date(availableFrom);
    if (typeof isAvailable === 'boolean') updateData.isAvailable = isAvailable;
    
    const property = await prisma.property.update({
      where: { id: propertyId },
      data: updateData
    });
    
    res.json({
      message: 'Property updated successfully',
      property
    });
    
  } catch (error) {
    console.error('Update property error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Delete property
app.delete('/properties/:id', authenticateToken, async (req, res) => {
  try {
    const propertyId = parseInt(req.params.id);
    
    const existingProperty = await prisma.property.findFirst({
      where: { id: propertyId, landlordId: req.user.userId },
      include: { images: true }
    });
    
    if (!existingProperty) {
      return res.status(404).json({ error: 'Property not found or not authorized' });
    }
    
    // Delete all associated images from filesystem
    existingProperty.images.forEach(image => {
      const filePath = path.join(__dirname, 'uploads', 'properties', path.basename(image.url));
      if (fs.existsSync(filePath)) {
        fs.unlinkSync(filePath);
      }
    });
    
    await prisma.property.delete({
      where: { id: propertyId }
    });
    
    res.json({ message: 'Property deleted successfully' });
    
  } catch (error) {
    console.error('Delete property error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    environment: isProduction ? 'production' : 'development',
    emailConfigured: !!emailTransporter
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    if (err.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({ error: 'File too large. Maximum size is 5MB.' });
    }
    if (err.code === 'LIMIT_FILE_COUNT') {
      return res.status(400).json({ error: 'Too many files. Maximum is 10 images.' });
    }
  }
  
  if (err.message === 'Only image files are allowed!') {
    return res.status(400).json({ error: 'Only image files are allowed!' });
  }
  
  console.error('Unhandled error:', err);
  res.status(500).json({ error: isProduction ? 'Internal server error' : err.message });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Endpoint not found' });
});

// For local development only
if (!isProduction) {
  app.listen(PORT, () => {
    console.log(`🚀 Hyra Tryggt server running on port ${PORT}`);
    console.log(`📧 Email notifications: ${emailTransporter ? 'Enabled' : 'Disabled'}`);
    console.log(`🌍 Environment: ${isProduction ? 'Production' : 'Development'}`);
  });
  
  // Graceful shutdown
  process.on('SIGTERM', async () => {
    console.log('SIGTERM received, shutting down gracefully');
    await prisma.$disconnect();
    process.exit(0);
  });

  process.on('SIGINT', async () => {
    console.log('SIGINT received, shutting down gracefully');
    await prisma.$disconnect();
    process.exit(0);
  });
}

// Export for Vercel - this is the key change for serverless
module.exports = app;