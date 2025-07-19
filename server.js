
// server.js — منصة إدارة إجازات "عبدالإله سليمان عبدالله الهديلج"

const express       = require('express');
const helmet        = require('helmet');
const cors          = require('cors');
const rateLimit     = require('express-rate-limit');
const geoip         = require('geoip-lite');
const axios         = require('axios');
require('dotenv').config();

const app                  = express();
const PORT                 = process.env.PORT || 3000;
const ALLOWED_ORIGINS      = ['https://sicklv.shop'];
const ALLOWED_COUNTRIES    = ['SA', 'AE', 'KW', 'QA', 'OM', 'BH', 'EG', 'JO', 'SD'];
const RECAPTCHA_SECRET_KEY = process.env.RECAPTCHA_SECRET_KEY || "";

// إعداد الحماية
app.use(helmet());
app.use(cors({
  origin: (origin, callback) => {
    if (!origin || ALLOWED_ORIGINS.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('غير مسموح'));
    }
  },
  credentials: true
}));
app.use(express.json({ limit: '10kb' }));

// تحديد الحد الأعلى للطلبات
app.use(rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 50,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, message: "تم تقييد طلبك مؤقتًا." }
}));

// الحجب الجغرافي
app.use((req, res, next) => {
  const geo = geoip.lookup(req.ip);
  if (!geo || !ALLOWED_COUNTRIES.includes(geo.country)) {
    return res.status(403).json({ success: false, message: "الوصول مرفوض من منطقتك." });
  }
  next();
});

// دالة لحساب عدد الأيام
function calcDays(start, end) {
  const s = new Date(start);
  const e = new Date(end);
  if (isNaN(s) || isNaN(e) || e < s) return 0;
  return Math.floor((e - s) / (1000 * 60 * 60 * 24)) + 1;
}

// بيانات الإجازات
let leaves = [
  {serviceCode: "GSL25021372778", idNumber: "1088576044", name: "عبدالإله سليمان عبدالله الهديلج", reportDate: "2025-02-09", startDate: "2025-02-09", endDate: "2025-02-24", doctorName: "هدى مصطفى خضر دحبور", jobTitle: "استشاري"},
  {serviceCode: "GSL25021898579", idNumber: "1088576044", name: "عبدالإله سليمان عبدالله الهديلج", reportDate: "2025-02-25", startDate: "2025-02-25", endDate: "2025-03-26", doctorName: "جمال راشد السر محمد احمد", jobTitle: "استشاري"},
  {serviceCode: "GSL25022385036", idNumber: "1088576044", name: "عبدالإله سليمان عبدالله الهديلج", reportDate: "2025-03-27", startDate: "2025-03-27", endDate: "2025-04-17", doctorName: "جمال راشد السر محمد احمد", jobTitle: "استشاري"},
  {serviceCode: "GSL25022884602", idNumber: "1088576044", name: "عبدالإله سليمان عبدالله الهديلج", reportDate: "2025-04-18", startDate: "2025-04-18", endDate: "2025-05-15", doctorName: "هدى مصطفى خضر دحبور", jobTitle: "استشاري"},
  {serviceCode: "GSL25023345012", idNumber: "1088576044", name: "عبدالإله سليمان عبدالله الهديلج", reportDate: "2025-05-16", startDate: "2025-05-16", endDate: "2025-06-12", doctorName: "هدى مصطفى خضر دحبور", jobTitle: "استشاري"},
  {serviceCode: "GSL25062955824", idNumber: "1088576044", name: "عبدالإله سليمان عبدالله الهديلج", reportDate: "2025-06-13", startDate: "2025-06-13", endDate: "2025-07-11", doctorName: "هدى مصطفى خضر دحبور", jobTitle: "استشاري"},
  {serviceCode: "GSL25071678945", idNumber: "1088576044", name: "عبدالإله سليمان عبدالله الهديلج", reportDate: "2025-07-12", startDate: "2025-07-12", endDate: "2025-07-17", doctorName: "عبدالعزيز فهد هميجان الروقي", jobTitle: "استشاري"}
].map(l => ({ ...l, days: calcDays(l.startDate, l.endDate) }));

// دالة تحقق من صحة المدخلات
function isValidInput({ serviceCode, idNumber }) {
  return /^[A-Za-z0-9]{8,20}$/.test(serviceCode) && /^[0-9]{10}$/.test(idNumber);
}

// تحقق من reCAPTCHA إن تم تفعيله
async function verifyRecaptcha(token, ip) {
  if (!RECAPTCHA_SECRET_KEY || !token) return true;

  try {
    const params = new URLSearchParams({
      secret: RECAPTCHA_SECRET_KEY,
      response: token
    });

    const { data } = await axios.post('https://www.google.com/recaptcha/api/siteverify', params);
    return data.success && (!data.score || data.score >= 0.5);
  } catch {
    return false;
  }
}

// استعلام عن إجازة
app.post('/api/leave', async (req, res) => {
  const { serviceCode, idNumber, captchaToken } = req.body;

  if (!isValidInput({ serviceCode, idNumber })) {
    return res.status(400).json({ success: false, message: "بيانات غير صحيحة." });
  }

  const recaptchaPassed = await verifyRecaptcha(captchaToken, req.ip);
  if (!recaptchaPassed) {
    return res.status(403).json({ success: false, message: "فشل التحقق الأمني." });
  }

  const record = leaves.find(l => l.serviceCode === serviceCode && l.idNumber === idNumber);
  return record ? res.json({ success: true, record }) :
    res.status(404).json({ success: false, message: "لا يوجد سجل مطابق." });
});

// إضافة إجازة جديدة
app.post('/api/add-leave', (req, res) => {
  const { serviceCode, idNumber, name, reportDate, startDate, endDate, doctorName, jobTitle } = req.body;

  if (![serviceCode, idNumber, name, reportDate, startDate, endDate, doctorName, jobTitle].every(val => typeof val === 'string')) {
    return res.status(400).json({ success: false, message: "مدخلات غير صحيحة." });
  }

  if (!isValidInput({ serviceCode, idNumber })) {
    return res.status(400).json({ success: false, message: "مدخلات غير صحيحة." });
  }

  leaves.push({
    serviceCode,
    idNumber,
    name,
    reportDate,
    startDate,
    endDate,
    doctorName,
    jobTitle,
    days: calcDays(startDate, endDate)
  });

  return res.json({ success: true, message: "تمت إضافة الإجازة بنجاح." });
});

// التعامل مع المسارات غير الموجودة
app.use((req, res) => {
  res.status(404).json({ success: false, message: "المسار غير موجود." });
});

// تشغيل الخادم
app.listen(PORT, () => {
  console.log(`✅ SickLV API تعمل على المنفذ ${PORT}`);
});
