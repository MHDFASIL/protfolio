import express from 'express';
import path from 'path';
import fs from 'fs';
import crypto from 'crypto';
import dotenv from 'dotenv';
import { createServer as createViteServer } from 'vite';
import { PROJECTS as INITIAL_PROJECTS, Project } from './src/data/projectsData.ts';

dotenv.config();

const app = express();
const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 3000;

// Body parsing with 25MB limit for image uploads
app.use(express.json({ limit: '25mb' }));
app.use(express.urlencoded({ extended: true, limit: '25mb' }));

// Paths
const DATA_DIR = path.resolve(process.cwd(), 'data');
const PROJECTS_FILE = path.join(DATA_DIR, 'projects.json');
const AUTH_FILE = path.join(DATA_DIR, 'auth.json');
const UPLOADS_DIR = path.resolve(process.cwd(), 'public', 'uploads');

// Ensure directories exist
if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}
if (!fs.existsSync(UPLOADS_DIR)) {
  fs.mkdirSync(UPLOADS_DIR, { recursive: true });
}

// Ensure public uploads static serving
app.use('/uploads', express.static(UPLOADS_DIR));

// Admin credentials & security configuration
const DEFAULT_ADMIN_EMAIL = 'mhdfasilkt85@gmail.com';
const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || DEFAULT_ADMIN_EMAIL).toLowerCase().trim();
const DEFAULT_ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'FasilDesign@2026!';
const JWT_SECRET = process.env.ADMIN_JWT_SECRET || 'fasil-creative-portfolio-secret-2026';

// Helper: Password hashing
function hashPassword(password: string, salt: string): string {
  return crypto.pbkdf2Sync(password, salt, 10000, 64, 'sha512').toString('hex');
}

// Initialize Auth store
function getStoredAuth() {
  if (fs.existsSync(AUTH_FILE)) {
    try {
      const data = JSON.parse(fs.readFileSync(AUTH_FILE, 'utf-8'));
      return data;
    } catch {
      // ignore
    }
  }
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = hashPassword(DEFAULT_ADMIN_PASSWORD, salt);
  const initialAuth = {
    email: ADMIN_EMAIL,
    salt,
    hash,
    updatedAt: new Date().toISOString(),
  };
  fs.writeFileSync(AUTH_FILE, JSON.stringify(initialAuth, null, 2), 'utf-8');
  return initialAuth;
}

// Token creation (stateless signed token)
function generateToken(email: string): string {
  const payload = {
    email,
    exp: Date.now() + 7 * 24 * 60 * 60 * 1000, // 7 days
    nonce: crypto.randomBytes(8).toString('hex'),
  };
  const payloadB64 = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const signature = crypto
    .createHmac('sha256', JWT_SECRET)
    .update(payloadB64)
    .digest('base64url');
  return `${payloadB64}.${signature}`;
}

// Token verification
function verifyToken(token: string): { email: string } | null {
  try {
    const [payloadB64, signature] = token.split('.');
    if (!payloadB64 || !signature) return null;
    const expectedSig = crypto
      .createHmac('sha256', JWT_SECRET)
      .update(payloadB64)
      .digest('base64url');
    if (!crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expectedSig))) {
      return null;
    }
    const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf-8'));
    if (payload.exp < Date.now()) return null;
    if (payload.email.toLowerCase() !== ADMIN_EMAIL) return null;
    return { email: payload.email };
  } catch {
    return null;
  }
}

// Middleware: Require Admin
function requireAdmin(req: express.Request, res: express.Response, next: express.NextFunction) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Authentication required. Please sign in to access admin area.' });
  }
  const token = authHeader.substring(7);
  const user = verifyToken(token);
  if (!user) {
    return res.status(403).json({ error: 'Session expired or unauthorized. Please sign in again.' });
  }
  (req as any).user = user;
  next();
}

// Load and persist projects
function loadProjects(): Project[] {
  if (fs.existsSync(PROJECTS_FILE)) {
    try {
      const content = fs.readFileSync(PROJECTS_FILE, 'utf-8');
      const parsed = JSON.parse(content);
      if (Array.isArray(parsed) && parsed.length > 0) {
        return parsed;
      }
    } catch (e) {
      console.error('Error reading projects.json, falling back to initial data:', e);
    }
  }

  // Seed with initial 20 projects, marking status as 'published'
  const seeded = INITIAL_PROJECTS.map((p) => ({
    ...p,
    status: p.status || 'published',
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  }));

  saveProjects(seeded);
  return seeded;
}

function saveProjects(projects: Project[]) {
  const tempFile = `${PROJECTS_FILE}.tmp`;
  fs.writeFileSync(tempFile, JSON.stringify(projects, null, 2), 'utf-8');
  fs.renameSync(tempFile, PROJECTS_FILE);
}

// Initialize on boot
getStoredAuth();
loadProjects();

// ========================
// API ROUTES
// ========================

// 1. Public: Get published projects
app.get('/api/projects', (req, res) => {
  try {
    const all = loadProjects();
    const published = all.filter((p) => p.status !== 'draft');
    res.json({ success: true, projects: published });
  } catch (err: any) {
    res.status(500).json({ error: 'Failed to retrieve projects', details: err.message });
  }
});

// 2. Auth: Sign In
app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required.' });
  }

  const normalizedEmail = String(email).toLowerCase().trim();
  if (normalizedEmail !== ADMIN_EMAIL) {
    return res.status(403).json({ error: 'Access restricted: Only the authorized portfolio owner can sign in.' });
  }

  const authData = getStoredAuth();
  const testHash = hashPassword(password, authData.salt);
  if (!crypto.timingSafeEqual(Buffer.from(testHash), Buffer.from(authData.hash))) {
    return res.status(401).json({ error: 'Invalid password. Please check your credentials.' });
  }

  const token = generateToken(normalizedEmail);
  res.json({
    success: true,
    token,
    user: {
      email: normalizedEmail,
      name: 'Muhammed Fasil KT',
      role: 'admin',
    },
  });
});

// 3. Auth: Verify current session
app.get('/api/auth/me', requireAdmin, (req, res) => {
  res.json({
    authenticated: true,
    user: {
      email: (req as any).user.email,
      name: 'Muhammed Fasil KT',
      role: 'admin',
    },
  });
});

// 4. Auth: Update admin password
app.post('/api/auth/change-password', requireAdmin, (req, res) => {
  const { currentPassword, newPassword } = req.body;
  if (!currentPassword || !newPassword) {
    return res.status(400).json({ error: 'Current and new password are required.' });
  }
  if (newPassword.length < 8) {
    return res.status(400).json({ error: 'New password must be at least 8 characters long.' });
  }

  const authData = getStoredAuth();
  const testHash = hashPassword(currentPassword, authData.salt);
  if (!crypto.timingSafeEqual(Buffer.from(testHash), Buffer.from(authData.hash))) {
    return res.status(401).json({ error: 'Current password is incorrect.' });
  }

  const newSalt = crypto.randomBytes(16).toString('hex');
  const newHash = hashPassword(newPassword, newSalt);
  const updatedAuth = {
    email: ADMIN_EMAIL,
    salt: newSalt,
    hash: newHash,
    updatedAt: new Date().toISOString(),
  };

  fs.writeFileSync(AUTH_FILE, JSON.stringify(updatedAuth, null, 2), 'utf-8');
  res.json({ success: true, message: 'Password updated successfully.' });
});

// 5. Admin: Get all projects (including drafts)
app.get('/api/admin/projects', requireAdmin, (req, res) => {
  try {
    const all = loadProjects();
    res.json({ success: true, projects: all });
  } catch (err: any) {
    res.status(500).json({ error: 'Failed to retrieve admin projects', details: err.message });
  }
});

// Helper: Normalize & Validate Palette Colors
function sanitizePalette(input: any): (string | { hex: string; label?: string })[] {
  if (!Array.isArray(input)) return [];
  const validHexRegex = /^#([0-9A-Fa-f]{3}|[0-9A-Fa-f]{6})$/;
  const result: (string | { hex: string; label?: string })[] = [];

  for (const item of input) {
    if (!item) continue;
    if (typeof item === 'string') {
      let hex = item.trim();
      if (!hex.startsWith('#')) hex = '#' + hex;
      if (validHexRegex.test(hex)) {
        if (hex.length === 4) {
          hex = '#' + hex[1] + hex[1] + hex[2] + hex[2] + hex[3] + hex[3];
        }
        result.push(hex.toUpperCase());
      }
    } else if (typeof item === 'object' && item.hex) {
      let hex = String(item.hex).trim();
      if (!hex.startsWith('#')) hex = '#' + hex;
      if (validHexRegex.test(hex)) {
        if (hex.length === 4) {
          hex = '#' + hex[1] + hex[1] + hex[2] + hex[2] + hex[3] + hex[3];
        }
        const label = item.label ? String(item.label).trim() : undefined;
        result.push(label ? { hex: hex.toUpperCase(), label } : hex.toUpperCase());
      }
    }
  }
  return result;
}

// 6. Admin: Create a new project
app.post('/api/admin/projects', requireAdmin, (req, res) => {
  try {
    const body = req.body;
    if (!body.title || !body.title.trim()) {
      return res.status(400).json({ error: 'Project title is required.' });
    }
    if (!body.description || !body.description.trim()) {
      return res.status(400).json({ error: 'Project summary / description is required.' });
    }

    const projects = loadProjects();

    // Generate safe unique ID
    const slugBase = body.title
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/(^-|-$)+/g, '');
    let uniqueId = slugBase || 'project';
    let counter = 1;
    while (projects.some((p) => p.id === uniqueId)) {
      uniqueId = `${slugBase}-${counter++}`;
    }

    const newProject: Project = {
      id: uniqueId,
      title: body.title.trim(),
      client: body.client?.trim() || 'Private Commission',
      year: body.year?.trim() || new Date().getFullYear().toString(),
      category: body.category?.trim() || 'Poster & Promotional Designs',
      categoryKey: (body.categoryKey as any) || 'poster',
      tags: Array.isArray(body.tags) ? body.tags.filter(Boolean) : (body.tags ? String(body.tags).split(',').map(s => s.trim()).filter(Boolean) : ['Graphic Design']),
      description: body.description.trim(),
      fullDescription: body.fullDescription?.trim() || body.description.trim(),
      image: body.image?.trim() || '/assets/aistudio/image_b679dcd3.png',
      beforeImage: body.beforeImage?.trim() || undefined,
      galleryImages: Array.isArray(body.galleryImages) ? body.galleryImages : [],
      projectUrl: body.projectUrl?.trim() || undefined,
      completionDate: body.completionDate?.trim() || undefined,
      status: body.status === 'draft' ? 'draft' : 'published',
      aspectRatio: body.aspectRatio?.trim() || '4/5',
      headline: body.headline?.trim() || undefined,
      objectives: body.objectives?.trim() || 'Deliver strategic visual communication that elevates brand recognition.',
      concept: body.concept?.trim() || 'Thoughtful composition combining high-contrast typography and intentional visual storytelling.',
      tools: Array.isArray(body.tools) ? body.tools : (body.tools ? String(body.tools).split(',').map(s => s.trim()).filter(Boolean) : ['Adobe Photoshop', 'Adobe Illustrator']),
      deliverables: Array.isArray(body.deliverables) ? body.deliverables : (body.deliverables ? String(body.deliverables).split(',').map(s => s.trim()).filter(Boolean) : ['High-Resolution Digital Assets']),
      palette: body.palette !== undefined ? sanitizePalette(body.palette) : undefined,
      featured: Boolean(body.featured),
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };

    // Prepend to list so new projects appear prominently
    projects.unshift(newProject);
    saveProjects(projects);

    res.status(201).json({ success: true, project: newProject });
  } catch (err: any) {
    res.status(500).json({ error: 'Failed to create project', details: err.message });
  }
});

// 7. Admin: Update an existing project
app.put('/api/admin/projects/:id', requireAdmin, (req, res) => {
  try {
    const { id } = req.params;
    const body = req.body;
    const projects = loadProjects();
    const index = projects.findIndex((p) => p.id === id);

    if (index === -1) {
      return res.status(404).json({ error: `Project with ID "${id}" was not found.` });
    }

    const existing = projects[index];
    const updated: Project = {
      ...existing,
      title: body.title?.trim() ?? existing.title,
      client: body.client?.trim() ?? existing.client,
      year: body.year?.trim() ?? existing.year,
      category: body.category?.trim() ?? existing.category,
      categoryKey: (body.categoryKey as any) ?? existing.categoryKey,
      tags: Array.isArray(body.tags) ? body.tags.filter(Boolean) : (body.tags ? String(body.tags).split(',').map(s => s.trim()).filter(Boolean) : existing.tags),
      description: body.description?.trim() ?? existing.description,
      fullDescription: body.fullDescription?.trim() ?? existing.fullDescription,
      image: body.image?.trim() ?? existing.image,
      beforeImage: body.beforeImage !== undefined ? (body.beforeImage?.trim() || undefined) : existing.beforeImage,
      galleryImages: Array.isArray(body.galleryImages) ? body.galleryImages : existing.galleryImages,
      projectUrl: body.projectUrl !== undefined ? (body.projectUrl?.trim() || undefined) : existing.projectUrl,
      completionDate: body.completionDate !== undefined ? (body.completionDate?.trim() || undefined) : existing.completionDate,
      status: body.status === 'draft' ? 'draft' : 'published',
      aspectRatio: body.aspectRatio?.trim() ?? existing.aspectRatio,
      headline: body.headline !== undefined ? (body.headline?.trim() || undefined) : existing.headline,
      objectives: body.objectives?.trim() ?? existing.objectives,
      concept: body.concept?.trim() ?? existing.concept,
      tools: Array.isArray(body.tools) ? body.tools : (body.tools ? String(body.tools).split(',').map(s => s.trim()).filter(Boolean) : existing.tools),
      deliverables: Array.isArray(body.deliverables) ? body.deliverables : (body.deliverables ? String(body.deliverables).split(',').map(s => s.trim()).filter(Boolean) : existing.deliverables),
      palette: body.palette !== undefined ? sanitizePalette(body.palette) : existing.palette,
      featured: body.featured !== undefined ? Boolean(body.featured) : existing.featured,
      updatedAt: new Date().toISOString(),
    };

    projects[index] = updated;
    saveProjects(projects);

    res.json({ success: true, project: updated });
  } catch (err: any) {
    res.status(500).json({ error: 'Failed to update project', details: err.message });
  }
});

// 8. Admin: Toggle publish / unpublish status
app.patch('/api/admin/projects/:id/status', requireAdmin, (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body;
    if (status !== 'published' && status !== 'draft') {
      return res.status(400).json({ error: 'Status must be "published" or "draft".' });
    }

    const projects = loadProjects();
    const project = projects.find((p) => p.id === id);
    if (!project) {
      return res.status(404).json({ error: 'Project not found.' });
    }

    project.status = status;
    project.updatedAt = new Date().toISOString();
    saveProjects(projects);

    res.json({ success: true, project });
  } catch (err: any) {
    res.status(500).json({ error: 'Failed to change project status', details: err.message });
  }
});

// 9. Admin: Delete project
app.delete('/api/admin/projects/:id', requireAdmin, (req, res) => {
  try {
    const { id } = req.params;
    const projects = loadProjects();
    const initialLength = projects.length;
    const filtered = projects.filter((p) => p.id !== id);

    if (filtered.length === initialLength) {
      return res.status(404).json({ error: 'Project not found.' });
    }

    saveProjects(filtered);
    res.json({ success: true, message: `Project "${id}" successfully deleted.` });
  } catch (err: any) {
    res.status(500).json({ error: 'Failed to delete project', details: err.message });
  }
});

// 10. Admin: Upload image
app.post('/api/admin/upload', requireAdmin, (req, res) => {
  try {
    const { filename, data, contentType } = req.body;
    if (!data || !contentType) {
      return res.status(400).json({ error: 'Missing image data or contentType.' });
    }

    const allowedTypes = ['image/jpeg', 'image/png', 'image/webp', 'image/svg+xml', 'image/gif'];
    if (!allowedTypes.includes(contentType.toLowerCase())) {
      return res.status(400).json({ error: 'Invalid file format. Supported formats: JPEG, PNG, WebP, SVG, GIF.' });
    }

    // Extract base64
    const matches = data.match(/^data:([A-Za-z-+/]+);base64,(.+)$/);
    const base64Data = matches ? matches[2] : data;
    const buffer = Buffer.from(base64Data, 'base64');

    // 10MB limit
    if (buffer.length > 10 * 1024 * 1024) {
      return res.status(400).json({ error: 'File size exceeds maximum 10MB limit.' });
    }

    // Extension resolution
    let ext = '.png';
    if (contentType.includes('jpeg') || contentType.includes('jpg')) ext = '.jpg';
    else if (contentType.includes('webp')) ext = '.webp';
    else if (contentType.includes('svg')) ext = '.svg';
    else if (contentType.includes('gif')) ext = '.gif';

    const safeBaseName = (filename || 'project_image')
      .replace(/[^a-zA-Z0-9_-]/g, '_')
      .substring(0, 30);
    const uniqueFilename = `${safeBaseName}_${Date.now()}_${crypto.randomBytes(4).toString('hex')}${ext}`;
    const targetPath = path.join(UPLOADS_DIR, uniqueFilename);

    fs.writeFileSync(targetPath, buffer);

    const publicUrl = `/uploads/${uniqueFilename}`;
    res.json({ success: true, url: publicUrl, filename: uniqueFilename, size: buffer.length });
  } catch (err: any) {
    res.status(500).json({ error: 'Failed to process image upload', details: err.message });
  }
});

// 11. Admin: Reset to default seeded projects
app.post('/api/admin/reset-default-projects', requireAdmin, (req, res) => {
  try {
    const seeded = INITIAL_PROJECTS.map((p) => ({
      ...p,
      status: 'published' as const,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    }));
    saveProjects(seeded);
    res.json({ success: true, count: seeded.length });
  } catch (err: any) {
    res.status(500).json({ error: 'Failed to reset projects', details: err.message });
  }
});

// ========================
// VITE OR STATIC SERVING
// ========================
async function startServer() {
  const isProd = process.env.NODE_ENV === 'production';

  if (isProd) {
    const distPath = path.resolve(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  } else {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[Muhammed Fasil KT Portfolio] Server running on http://0.0.0.0:${PORT}`);
  });
}

startServer();
