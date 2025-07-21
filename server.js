
// server.js — منصة إدارة الإجازات المرضية
const express        = require('express');
const helmet         = require('helmet');
const xssClean       = require('xss-clean');
const mongoSanitize  = require('express-mongo-sanitize');
const path           = require('path');
const winston        = require('winston');
require('dotenv').config();

const app  = express();
const PORT = process.env.PORT || 3000;

// نظام التسجيل واللوجات
const logger = winston.createLogger({
  transports: [
    new winston.transports.File({ filename: 'activity.log' }),
    new winston.transports.Console()
  ]
});

// حمايات أساسية فقط
app.use(helmet());
app.use(xssClean());
app.use(mongoSanitize());
app.use(express.json({ limit: '12kb' }));

// لوج لكل طلب
app.use((req, res, next) => {
  logger.info(`[${new Date().toISOString()}] [${req.ip}] ${req.method} ${req.originalUrl}`);
  next();
});

// تقديم ملفات ثابتة (public)
app.use(express.static(path.join(__dirname, 'public')));

// دالة لحساب الأيام بين تاريخين
function calcDays(start, end) {
  try {
    const s = new Date(start);
    const e = new Date(end);
    if (isNaN(s) || isNaN(e) || e < s) return 0;
    return Math.floor((e - s) / (1000 * 60 * 60 * 24)) + 1;
  } catch { return 0; }
}

// بيانات الإجازات الافتراضية (تقدر تغيرها لقواعد بيانات أو ملف JSON)
const leavesRaw = [
  {serviceCode: "GSL25021372778", idNumber: "1088576044", name: "عبدالإله سليمان عبدالله الهديلج", reportDate: "2025-02-09", startDate: "2025-02-09", endDate: "2025-02-24", doctorName: "هدى مصطفى خضر دحبور", jobTitle: "استشاري"},
  {serviceCode: "GSL25021898579", idNumber: "1088576044", name: "عبدالإله سليمان عبدالله الهديلج", reportDate: "2025-02-25", startDate: "2025-02-25", endDate: "2025-03-26", doctorName: "جمال راشد السر محمد احمد", jobTitle: "استشاري"},
  {serviceCode: "GSL25022385036", idNumber: "1088576044", name: "عبدالإله سليمان عبدالله الهديلج", reportDate: "2025-03-27", startDate: "2025-03-27", endDate: "2025-04-17", doctorName: "جمال راشد السر محمد احمد", jobTitle: "استشاري"},
  {serviceCode: "GSL25022884602", idNumber: "1088576044", name: "عبدالإله سليمان عبدالله الهديلج", reportDate: "2025-04-18", startDate: "2025-04-18", endDate: "2025-05-15", doctorName: "هدى مصطفى خضر دحبور", jobTitle: "استشاري"},
  {serviceCode: "GSL25023345012", idNumber: "1088576044", name: "عبدالإله سليمان عبدالله الهديلج", reportDate: "2025-05-16", startDate: "2025-05-16", endDate: "2025-06-12", doctorName: "هدى مصطفى خضر دحبور", jobTitle: "استشاري"},
  {serviceCode: "GSL25062955824", idNumber: "1088576044", name: "عبدالإله سليمان عبدالله الهديلج", reportDate: "2025-06-13", startDate: "2025-06-13", endDate: "2025-07-11", doctorName: "هدى مصطفى خضر دحبور", jobTitle: "استشاري"},
  {serviceCode: "GSL25071678945", idNumber: "1088576044", name: "عبدالإله سليمان عبدالله الهديلج", reportDate: "2025-07-12", startDate: "2025-07-12", endDate: "2025-07-17", doctorName: "عبدالعزيز فهد هميجان الروقي", jobTitle: "استشاري"}
];
const leaves = leavesRaw.map(rec => ({
  ...rec,
  days: calcDays(rec.startDate, rec.endDate)
}));

// استعلام عن الإجازة
app.post('/api/leave', (req, res) => {
  const { serviceCode, idNumber } = req.body;
  if (
    typeof serviceCode !== 'string' || !/^[A-Za-z0-9]{8,20}$/.test(serviceCode) ||
    typeof idNumber !== 'string' || !/^[0-9]{10}$/.test(idNumber)
  ) {
    return res.status(400).json({ success: false, message: "البيانات غير صحيحة." });
  }
  const record = leaves.find(
    item => item.serviceCode === serviceCode && item.idNumber === idNumber
  );
  if (record) {
    return res.json({ success: true, record });
  }
  res.status(404).json({ success: false, message: "لا يوجد سجل مطابق." });
});

// إضافة إجازة جديدة (للاختبار فقط)
app.post('/api/add-leave', (req, res) => {
  const { serviceCode, idNumber, name, reportDate, startDate, endDate, doctorName, jobTitle } = req.body;
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

// صفحة غير موجودة
app.use((req, res) => {
  res.status(404).json({ success: false, message: "الصفحة غير موجودة." });
});

// shutdown آمن
process.on('SIGTERM', () => {
  logger.info("تم إيقاف الخدمة بنجاح.");
  process.exit(0);
});

app.listen(PORT, () => {
  logger.info(`✅ SickLV API is running on port ${PORT}`);
});
