/**
 * مسارات المصادقة وإدارة المستخدمين
 * Authentication and User Management Routes
 */

const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
const { query, transaction } = require('../config/database');
const { authenticateToken, requireAdmin, logAuditTrail } = require('../middleware/auth');

const router = express.Router();

/**
 * تسجيل الدخول
 * POST /api/auth/login
 */
router.post('/login', [
  body('username').notEmpty().withMessage('اسم المستخدم مطلوب'),
  body('password').isLength({ min: 6 }).withMessage('كلمة المرور يجب أن تكون 6 أحرف على الأقل')
], async (req, res) => {
  try {
    // التحقق من صحة البيانات
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        message: 'بيانات غير صحيحة',
        errors: errors.array()
      });
    }

    const { username, password } = req.body;

    // البحث عن المستخدم
    const userResult = await query(
      'SELECT * FROM users WHERE username = $1 AND is_active = true',
      [username]
    );

    if (userResult.rows.length === 0) {
      return res.status(401).json({
        success: false,
        message: 'اسم المستخدم أو كلمة المرور غير صحيحة',
        code: 'INVALID_CREDENTIALS'
      });
    }

    const user = userResult.rows[0];

    // التحقق من كلمة المرور
    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) {
      return res.status(401).json({
        success: false,
        message: 'اسم المستخدم أو كلمة المرور غير صحيحة',
        code: 'INVALID_CREDENTIALS'
      });
    }

    // إنشاء JWT Token
    const tokenPayload = {
      userId: user.id,
      username: user.username,
      role: user.role
    };

    const accessToken = jwt.sign(tokenPayload, process.env.JWT_SECRET, {
      expiresIn: process.env.JWT_EXPIRES_IN || '24h'
    });

    const refreshToken = jwt.sign(
      { userId: user.id },
      process.env.JWT_REFRESH_SECRET,
      { expiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '7d' }
    );

    // تحديث آخر تسجيل دخول
    await query(
      'UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = $1',
      [user.id]
    );

    // إرجاع البيانات
    res.json({
      success: true,
      message: 'تم تسجيل الدخول بنجاح',
      data: {
        user: {
          id: user.id,
          username: user.username,
          email: user.email,
          fullName: user.full_name,
          role: user.role,
          permissions: user.permissions || {}
        },
        tokens: {
          accessToken,
          refreshToken,
          expiresIn: process.env.JWT_EXPIRES_IN || '24h'
        }
      }
    });

  } catch (error) {
    console.error('❌ خطأ في تسجيل الدخول:', error);
    res.status(500).json({
      success: false,
      message: 'خطأ داخلي في الخادم',
      code: 'LOGIN_ERROR'
    });
  }
});

/**
 * تجديد Token
 * POST /api/auth/refresh
 */
router.post('/refresh', async (req, res) => {
  try {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      return res.status(401).json({
        success: false,
        message: 'Refresh token مطلوب',
        code: 'NO_REFRESH_TOKEN'
      });
    }

    // التحقق من صحة Refresh Token
    const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
    
    // التحقق من المستخدم
    const userResult = await query(
      'SELECT id, username, role FROM users WHERE id = $1 AND is_active = true',
      [decoded.userId]
    );

    if (userResult.rows.length === 0) {
      return res.status(401).json({
        success: false,
        message: 'المستخدم غير موجود',
        code: 'USER_NOT_FOUND'
      });
    }

    const user = userResult.rows[0];

    // إنشاء Access Token جديد
    const newAccessToken = jwt.sign(
      { userId: user.id, username: user.username, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN || '24h' }
    );

    res.json({
      success: true,
      message: 'تم تجديد التوكن بنجاح',
      data: {
        accessToken: newAccessToken,
        expiresIn: process.env.JWT_EXPIRES_IN || '24h'
      }
    });

  } catch (error) {
    if (error.name === 'JsonWebTokenError' || error.name === 'TokenExpiredError') {
      return res.status(401).json({
        success: false,
        message: 'Refresh token غير صالح أو منتهي الصلاحية',
        code: 'INVALID_REFRESH_TOKEN'
      });
    }

    console.error('❌ خطأ في تجديد التوكن:', error);
    res.status(500).json({
      success: false,
      message: 'خطأ في تجديد التوكن',
      code: 'REFRESH_ERROR'
    });
  }
});

/**
 * الحصول على بيانات المستخدم الحالي
 * GET /api/auth/me
 */
router.get('/me', authenticateToken, async (req, res) => {
  try {
    const userResult = await query(
      'SELECT id, username, email, full_name, role, permissions, created_at, last_login FROM users WHERE id = $1',
      [req.user.id]
    );

    if (userResult.rows.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'المستخدم غير موجود',
        code: 'USER_NOT_FOUND'
      });
    }

    const user = userResult.rows[0];

    res.json({
      success: true,
      data: {
        id: user.id,
        username: user.username,
        email: user.email,
        fullName: user.full_name,
        role: user.role,
        permissions: user.permissions || {},
        createdAt: user.created_at,
        lastLogin: user.last_login
      }
    });

  } catch (error) {
    console.error('❌ خطأ في جلب بيانات المستخدم:', error);
    res.status(500).json({
      success: false,
      message: 'خطأ في جلب بيانات المستخدم',
      code: 'GET_USER_ERROR'
    });
  }
});

/**
 * إنشاء مستخدم جديد (أدمن فقط)
 * POST /api/auth/users
 */
router.post('/users', [
  authenticateToken,
  requireAdmin,
  body('username').isLength({ min: 3 }).withMessage('اسم المستخدم يجب أن يكون 3 أحرف على الأقل'),
  body('email').isEmail().withMessage('البريد الإلكتروني غير صالح'),
  body('password').isLength({ min: 6 }).withMessage('كلمة المرور يجب أن تكون 6 أحرف على الأقل'),
  body('fullName').notEmpty().withMessage('الاسم الكامل مطلوب'),
  body('role').isIn(['admin', 'evaluator']).withMessage('الدور يجب أن يكون admin أو evaluator')
], async (req, res) => {
  try {
    // التحقق من صحة البيانات
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        message: 'بيانات غير صحيحة',
        errors: errors.array()
      });
    }

    const { username, email, password, fullName, role, permissions } = req.body;

    // التحقق من عدم تكرار اسم المستخدم أو البريد الإلكتروني
    const existingUser = await query(
      'SELECT id FROM users WHERE username = $1 OR email = $2',
      [username, email]
    );

    if (existingUser.rows.length > 0) {
      return res.status(409).json({
        success: false,
        message: 'اسم المستخدم أو البريد الإلكتروني موجود بالفعل',
        code: 'USER_EXISTS'
      });
    }

    // تشفير كلمة المرور
    const saltRounds = parseInt(process.env.BCRYPT_SALT_ROUNDS) || 12;
    const passwordHash = await bcrypt.hash(password, saltRounds);

    // إنشاء المستخدم
    const newUser = await query(
      `INSERT INTO users (username, email, password_hash, full_name, role, permissions)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING id, username, email, full_name, role, permissions, created_at`,
      [username, email, passwordHash, fullName, role, permissions || {}]
    );

    const user = newUser.rows[0];

    // تسجيل العملية
    await logAuditTrail(req, 'CREATE', 'users', user.id, null, user, `إنشاء مستخدم جديد: ${username}`);

    res.status(201).json({
      success: true,
      message: 'تم إنشاء المستخدم بنجاح',
      data: {
        id: user.id,
        username: user.username,
        email: user.email,
        fullName: user.full_name,
        role: user.role,
        permissions: user.permissions || {},
        createdAt: user.created_at
      }
    });

  } catch (error) {
    console.error('❌ خطأ في إنشاء المستخدم:', error);
    res.status(500).json({
      success: false,
      message: 'خطأ في إنشاء المستخدم',
      code: 'CREATE_USER_ERROR'
    });
  }
});

/**
 * الحصول على جميع المستخدمين (أدمن فقط)
 * GET /api/auth/users
 */
router.get('/users', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 10, role, search } = req.query;
    const offset = (parseInt(page) - 1) * parseInt(limit);

    // بناء الاستعلام
    let whereClause = 'WHERE 1=1';
    const queryParams = [];
    let paramIndex = 1;

    if (role) {
      whereClause += ` AND role = $${paramIndex}`;
      queryParams.push(role);
      paramIndex++;
    }

    if (search) {
      whereClause += ` AND (full_name ILIKE $${paramIndex} OR username ILIKE $${paramIndex} OR email ILIKE $${paramIndex})`;
      queryParams.push(`%${search}%`);
      paramIndex++;
    }

    // إحصاء إجمالي
    const countQuery = `SELECT COUNT(*) as total FROM users ${whereClause}`;
    const countResult = await query(countQuery, queryParams);
    const total = parseInt(countResult.rows[0].total);

    // جلب البيانات
    queryParams.push(parseInt(limit), offset);
    const usersQuery = `
      SELECT id, username, email, full_name, role, permissions, is_active, created_at, last_login
      FROM users ${whereClause}
      ORDER BY created_at DESC
      LIMIT $${paramIndex} OFFSET $${paramIndex + 1}
    `;

    const usersResult = await query(usersQuery, queryParams);

    res.json({
      success: true,
      data: {
        users: usersResult.rows,
        pagination: {
          page: parseInt(page),
          limit: parseInt(limit),
          total,
          pages: Math.ceil(total / parseInt(limit))
        }
      }
    });

  } catch (error) {
    console.error('❌ خطأ في جلب المستخدمين:', error);
    res.status(500).json({
      success: false,
      message: 'خطأ في جلب المستخدمين',
      code: 'GET_USERS_ERROR'
    });
  }
});

/**
 * تحديث صلاحيات مستخدم (أدمن فقط)
 * PUT /api/auth/users/:id/permissions
 */
router.put('/users/:id/permissions', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { permissions } = req.body;

    // التحقق من وجود المستخدم
    const userResult = await query('SELECT * FROM users WHERE id = $1', [id]);
    if (userResult.rows.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'المستخدم غير موجود',
        code: 'USER_NOT_FOUND'
      });
    }

    const oldUser = userResult.rows[0];

    // تحديث الصلاحيات
    const updatedUser = await query(
      'UPDATE users SET permissions = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2 RETURNING *',
      [permissions || {}, id]
    );

    const newUser = updatedUser.rows[0];

    // تسجيل العملية
    await logAuditTrail(req, 'UPDATE', 'users', id, oldUser, newUser, `تحديث صلاحيات المستخدم: ${oldUser.username}`);

    res.json({
      success: true,
      message: 'تم تحديث الصلاحيات بنجاح',
      data: {
        id: newUser.id,
        username: newUser.username,
        permissions: newUser.permissions || {}
      }
    });

  } catch (error) {
    console.error('❌ خطأ في تحديث الصلاحيات:', error);
    res.status(500).json({
      success: false,
      message: 'خطأ في تحديث الصلاحيات',
      code: 'UPDATE_PERMISSIONS_ERROR'
    });
  }
});

/**
 * تسجيل الخروج
 * POST /api/auth/logout
 */
router.post('/logout', authenticateToken, async (req, res) => {
  try {
    // في التطبيقات الحقيقية، يمكن إضافة التوكن إلى blacklist
    // لكن هنا سنعتمد على العميل لحذف التوكن
    
    res.json({
      success: true,
      message: 'تم تسجيل الخروج بنجاح'
    });

  } catch (error) {
    console.error('❌ خطأ في تسجيل الخروج:', error);
    res.status(500).json({
      success: false,
      message: 'خطأ في تسجيل الخروج',
      code: 'LOGOUT_ERROR'
    });
  }
});

module.exports = router;