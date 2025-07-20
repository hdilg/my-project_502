// server.js — منصة إدارة إجازات "عبدالإله سليمان عبدالله الهديلج"

require('dotenv').config();
const express       = require('express');
const helmet        = require('helmet');
const cors          = require('cors');
const rateLimit     = require('express-rate-limit');
const hpp           = require('hpp');
const useragent     = require('express-useragent');
const winston       = require('winston');
const axios         = require('axios');
const xssClean      = require('xss-clean');
const mongoSanitize = require('express-mongo-sanitize');
const path          = require('path');

const app               = express();
const PORT              = process.env.PORT || 3000;
const RECAPTCHA_SECRET  = process.env.RECAPTCHASECRETKEY || '';

// الدومينات المسموح لها بالوصول للـ API
const ALLOWED_ORIGINS = [
  'https://sicklv.shop',
  'https://www.sicklv.shop',
  'https://my-project-502.onrender.com'
];

// إعداد Winston للتسجيل في ملف والكونسول
const logger = winston.createLogger({
  transports: [
    new winston.transports.File({ filename: 'activity.log' }),
    new winston.transports.Console()
  ]
});

// ===== رؤوس الأمان =====
app.use(helmet());
app.use(helmet.hsts({
  maxAge: 2 * 365 * 24 * 60 * 60, // سنتان بالثواني
  includeSubDomains: true,
  preload: true
}));
app.use(helmet.contentSecurityPolicy({
  directives: {
    defaultSrc:      ["'self'"],
    scriptSrc:       ["'self'", "https://www.google.com", "https://www.gstatic.com"],
    styleSrc:        ["'self'", "'unsafe-inline'"],
    imgSrc:          ["'self'", "data:"],
    objectSrc:       ["'none'"],
    frameAncestors:  ["'none'"],
    upgradeInsecureRequests: [],
    baseUri:         ["'self'"],
    formAction:      ["'self'"]
  }
}));

// ===== ضبط CORS =====
app.use(cors({
  origin(origin, callback) {
    if (!origin || ALLOWED_ORIGINS.includes(origin)) {
      return callback(null, true);
    }
    logger.warn(`[CORS Blocked] Origin: ${origin}`);
    callback(new Error('الدخول مرفوض من هذا المصدر'));
  },
  credentials: true,
  optionsSuccessStatus: 200
}));

// ===== حماية إضافية =====
app.use(hpp());
app.use(xssClean());
app.use(mongoSanitize());
app.use(express.json({ limit: '16kb' }));
app.use(useragent.express());

// ===== تحديد الحد الأعلى للطلبات =====
app.use(rateLimit({
  windowMs: 15 * 60 * 1000, // 15 دقيقة
  max: 30,                  // 30 طلب لكل IP
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    message: "تم تقييد طلبك مؤقتاً."
  }
}));

// ===== تسجيل حركة كل طلب =====
app.use((req, res, next) => {
  logger.info(
    `[${new Date().toISOString()}] [IP: ${req.ip}] [UA: ${req.useragent.source}] ${req.method} ${req.originalUrl}`
  );
  next();
});

// ===== تقديم ملفات الواجهة الثابتة =====
app.use(express.static(path.join(__dirname, 'public')));

// ===== دالة لحساب عدد الأيام =====
function calcDays(start, end) {
  try {
    const s = new Date(start);
    const e = new Date(end);
    if (isNaN(s) || isNaN(e) || e < s) return 0;
    return Math.floor((e - s) / (1000 * 60 * 60 * 24)) + 1;
  } catch {
    return 0;
  }
}

// ===== بيانات الإجازات الافتراضية =====
const leavesRaw = [
  {
    serviceCode: "GSL25021372778", idNumber: "1088576044",
    name: "عبدالإله سليمان عبدالله الهديلج",
    reportDate: "2025-02-09", startDate: "2025-02-09",
    endDate: "2025-02-24", doctorName: "هدى مصطفى خضر دحبور",
    jobTitle: "استشاري"
  },
  {
    serviceCode: "GSL25021898579", idNumber: "1088576044",
    name: "عبدالإله سليمان عبدالله الهديلج",
    reportDate: "2025-02-25", startDate: "2025-02-25",
    endDate: "2025-03-26", doctorName: "جمال راشد السر محمد احمد",
    jobTitle: "استشاري"
  },
  {
    serviceCode: "GSL25022385036", idNumber: "1088576044",
    name: "عبدالإله سليمان عبدالله الهديلج",
    reportDate: "2025-03-27", startDate: "2025-03-27",
    endDate: "2025-04-17", doctorName: "جمال راشد السر محمد احمد",
    jobTitle: "استشاري"
  },
  {
    serviceCode: "GSL25022884602", idNumber: "1088576044",
    name: "عبدالإله سليمان عبدالله الهديلج",
    reportDate: "2025-04-18", startDate: "2025-04-18",
    endDate: "2025-05-15", doctorName: "هدى مصطفى خضر دحبور",
    jobTitle: "استشاري"
  },
  {
    serviceCode: "GSL25023345012", idNumber: "1088576044",
    name: "عبدالإله سليمان عبدالله الهديلج",
    reportDate: "2025-05-16", startDate: "2025-05-16",
    endDate: "2025-06-12", doctorName: "هدى مصطفى خضر دحبور",
    jobTitle: "استشاري"
  },
  {
    serviceCode: "GSL25062955824", idNumber: "1088576044",
    name: "عبدالإله سليمان عبدالله الهديلج",
    reportDate: "2025-06-13", startDate: "2025-06-13",
    endDate: "2025-07-11", doctorName: "هدى مصطفى خضر دحبور",
    jobTitle: "استشاري"
  },
  {
    serviceCode: "GSL25071678945", idNumber: "1088576044",
    name: "عبدالإله سليمان عبدالله الهديلج",
    reportDate: "2025-07-12", startDate: "2025-07-12",
    endDate: "2025-07-17", doctorName: "عبدالعزيز فهد هميجان الروقي",
    jobTitle: "استشاري"
  }
];

const leaves = leavesRaw.map(rec => ({
  ...rec,
  days: calcDays(rec.startDate, rec.endDate)
}));

// ===== مسار استعلام الإجازة =====
app.post('/api/leave', async (req, res) => {
  const { serviceCode, idNumber, captchaToken } = req.body;

  // التحقق من صحة المدخلات
  if (
    typeof serviceCode !== 'string' ||
    !/^[A-Za-z0-9]{8,20}$/.test(serviceCode) ||
    typeof idNumber !== 'string' ||
    !/^[0-9]{10}$/.test(idNumber)
  ) {
    return res.status(400).json({ success: false, message: "البيانات غير صحيحة." });
  }

  // التحقق اختياري عبر reCAPTCHA
  if (RECAPTCHA_SECRET && captchaToken) {
    try {
      const resp = await axios.post(
        'https://www.google.com/recaptcha/api/siteverify',
        new URLSearchParams({
          secret: RECAPTCHA_SECRET,
          response: captchaToken
        }).toString(),
        { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
      );
      if (!resp.data.success || (resp.data.score !== undefined && resp.data.score < 0.5)) {
        logger.warn(`[reCAPTCHA Failed] IP: ${req.ip}`);
        return res.status(403).json({ success: false, message: "فشل التحقق الأمني." });
      }
    } catch (err) {
      logger.error(`[reCAPTCHA Error] ${err.message}`);
      return res.status(500).json({ success: false, message: "خطأ أثناء التحقق الأمني." });
    }
  }

  // البحث عن السجل وإرجاعه
  const record = leaves.find(item =>
    item.serviceCode === serviceCode && item.idNumber === idNumber
  );
  if (record) {
    return res.json({ success: true, record });
  }
  return res.status(404).json({ success: false, message: "لا يوجد سجل مطابق." });
});

// ===== مسار إضافة إجازة جديدة =====
app.post('/api/add-leave', (req, res) => {
  const {
    serviceCode, idNumber, name,
    reportDate, startDate, endDate,
    doctorName, jobTitle
  } = req.body;

  // التحقق من صحة المدخلات
  if (
    typeof serviceCode !== 'string' || !/^[A-Za-z0-9]{8,20}$/.test(serviceCode) ||
    typeof idNumber   !== 'string' || !/^[0-9]{10}$/.test(idNumber) ||
    typeof name       !== 'string' ||
    typeof reportDate !== 'string' ||
    typeof startDate  !== 'string' ||
    typeof endDate    !== 'string' ||
    typeof doctorName !== 'string' ||
    typeof jobTitle   !== 'string'
  ) {
    return res.status(400).json({ success: false, message: "مدخلات غير صحيحة." });
  }

  leaves.push({
    serviceCode, idNumber, name,
    reportDate, startDate, endDate,
    doctorName, jobTitle,
    days: calcDays(startDate, endDate)
  });
  return res.json({ success: true, message: "تمت إضافة الإجازة بنجاح." });
});

// ===== مسار 404 لجميع المسارات الأخرى =====
app.use((req, res) => {
  res.status(404).json({ success: false, message: "الصفحة غير موجودة." });
});

// ===== إيقاف آمن =====
process.on('SIGTERM', () => {
  logger.info("تم إيقاف الخدمة بأمان.");
  process.exit(0);
});

// ===== بدء الاستماع =====
app.listen(PORT, () => {
  logger.info(`✅ SickLV API تعمل على المنفذ ${PORT}`);
});
