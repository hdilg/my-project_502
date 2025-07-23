// server.js — منصة إدارة إجازات Sicklv (نسخة Production محسّنة)

const express       = require('express');
const helmet        = require('helmet');
const compression   = require('compression');
const cors          = require('cors');
const rateLimit     = require('express-rate-limit');
const slowDown      = require('express-slow-down');
const hpp           = require('hpp');
const mongoSanitize = require('express-mongo-sanitize');
const xssClean      = require('xss-clean');
const useragent     = require('express-useragent');
const winston       = require('winston');
const path          = require('path');
const Joi           = require('joi');
const jwt           = require('jsonwebtoken');

// قراءة المنفذ والسر من process.env أو package.json config
const PORT       = process.env.PORT || process.env.npm_package_config_port || 3000;
const JWT_SECRET = process.env.JWT_SECRET || process.env.npm_package_config_jwt_secret;

// تحقق من وجود JWT_SECRET شعور خطأ في حال الإعداد ناقص
if (!JWT_SECRET) {
  console.error('ERROR: JWT_SECRET is not defined!');
  process.exit(1);
}

const app = express();

// ===== Logger مركّز =====
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.printf(
      info => `[${info.timestamp}] ${info.level.toUpperCase()}: ${info.message}`
    )
  ),
  transports: [
    new winston.transports.File({ filename: 'activity.log', maxsize: 5_000_000, maxFiles: 3 }),
    new winston.transports.Console()
  ]
});

// ===== إعدادات الأمان العامة =====
app.disable('x-powered-by');
app.set('trust proxy', true);

// Helmet مع CSP صارم
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc:  ["'self'"],
      styleSrc:   ["'self'"],
      imgSrc:     ["'self'", "data:"],
      objectSrc:  ["'none'"],
      frameAncestors: ["'none'"]
    }
  }
}));
app.use(helmet.hsts({ maxAge: 31536000, preload: true }));
app.use(helmet.noSniff());
app.use(helmet.referrerPolicy({ policy: 'strict-origin' }));
app.use(helmet.permittedCrossDomainPolicies());

app.use(compression());
app.use(hpp());
app.use(xssClean());
app.use(mongoSanitize());

// Body parser بحجم محدود
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: false, limit: '10kb' }));

// CORS — السماح لدومينين فقط
app.use(cors({
  origin: ['https://sicklv.shop', 'https://sicklv.life'],
  credentials: true
}));

// تسجيل نوع الجهاز والطلبات
app.use(useragent.express());
app.use((req, res, next) => {
  logger.info(`${req.ip} | ${req.useragent.platform} | ${req.method} ${req.originalUrl}`);
  next();
});

// استضافة ملفات ثابتة مع منع الفهرسة وdotfiles
app.use(express.static(path.join(__dirname, 'public'), {
  dotfiles: 'deny',
  index: false
}));

// ===== Helpers =====
const calcDays = (start, end) => {
  const s = new Date(start), e = new Date(end);
  if (isNaN(s) || isNaN(e) || e < s) return 0;
  return Math.floor((e - s) / (24 * 60 * 60 * 1000)) + 1;
};

// بيانات Mock في الذاكرة
const leavesRaw = [
  /* مثال:
  { serviceCode: 'ABCD1234', idNumber: '1234567890', name: 'أحمد علي', reportDate: '2025-07-20',
    startDate: '2025-07-20', endDate: '2025-07-22', doctorName: 'د. خالد', jobTitle: 'مهندس' }
  */
];
const leaves = leavesRaw.map(r => ({ ...r, days: calcDays(r.startDate, r.endDate) }));

// ===== Middlewares خاصة بالمسارات =====
// Rate Limiting لكل مسار
const leaveLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  message: { success: false, message: 'Too many requests on /api/leave.' }
});
const addLeaveLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 3,
  message: { success: false, message: 'Too many requests on /api/add-leave.' }
});
const leaveSlowDown = slowDown({
  windowMs: 60 * 1000,
  delayAfter: 5,
  delayMs: 500
});

// مصادقة JWT للمسارات الحساسة
const authenticate = (req, res, next) => {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ success: false, message: 'Missing auth token.' });

  const token = header.split(' ')[1];
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(403).json({ success: false, message: 'Invalid auth token.' });
  }
};

// Schemas للتحقق بالـJoi
const leaveSchema = Joi.object({
  serviceCode: Joi.string().alphanum().min(8).max(20).required(),
  idNumber:    Joi.string().pattern(/^[0-9]{10}$/).required()
});
const addLeaveSchema = Joi.object({
  serviceCode: Joi.string().alphanum().min(8).max(20).required(),
  idNumber:    Joi.string().pattern(/^[0-9]{10}$/).required(),
  name:        Joi.string().min(3).max(100).required(),
  reportDate:  Joi.date().iso().required(),
  startDate:   Joi.date().iso().required(),
  endDate:     Joi.date().iso().required(),
  doctorName:  Joi.string().min(3).max(100).required(),
  jobTitle:    Joi.string().min(3).max(100).needed()
});

// ===== Routes =====

// استعلام إجازة مُحدد
app.post(
  '/api/leave',
  leaveLimiter,
  leaveSlowDown,
  (req, res, next) => {
    const { error, value } = leaveSchema.validate(req.body);
    if (error) return res.status(400).json({ success: false, message: 'Invalid input.' });
    req.validated = value;
    next();
  },
  (req, res) => {
    const { serviceCode, idNumber } = req.validated;
    const record = leaves.find(l => l.serviceCode === serviceCode && l.idNumber === idNumber);
    if (!record) return res.status(404).json({ success: false, message: 'No matching record.' });
    res.json({ success: true, record });
  }
);

// إضافة إجازة جديدة — محمي بمصادقة
app.post(
  '/api/add-leave',
  authenticate,
  addLeaveLimiter,
  leaveSlowDown,
  (req, res, next) => {
    const { error, value } = addLeaveSchema.validate(req.body);
    if (error) return res.status(400).json({ success: false, message: 'Invalid input.' });
    req.validated = value;
    next();
  },
  (req, res) => {
    const r = req.validated;
    leaves.push({ ...r, days: calcDays(r.startDate, r.endDate) });
    res.json({ success: true, message: 'Leave added.' });
  }
);

// استعراض جميع الإجازات — محمي بمصادقة
app.get('/api/leaves', authenticate, (req, res) => {
  res.json({ success: true, leaves });
});

// ===== Handlers نهائية =====
// 404 Not Found
app.use((req, res) => {
  res.status(404).json({ success: false, message: 'Not found.' });
});

// Error Handler
app.use((err, req, res, next) => {
  logger.error(err.stack);
  const status = err.status || 500;
  const msg = status < 500 ? err.message : 'Internal server error.';
  res.status(status).json({ success: false, message: msg });
});

// Graceful Shutdown
process.on('SIGTERM', () => {
  logger.info('SIGTERM received: shutting down.');
  process.exit(0);
});

// بدء الاستماع
app.listen(PORT, () => {
  logger.info(`✅ Secure API listening on port ${PORT}`);
});
