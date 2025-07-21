// server.js — دمج شامل مع تدقيق الإدخالات وتنظيف البيانات ودعم SPA
const express       = require('express');
const cors          = require('cors');
// تنظيف المدخلات من XSS
const xssClean      = require('xss-clean');
// إزالة الحقول غير المرغوب فيها لطلبات Mongo
const mongoSanitize = require('express-mongo-sanitize');
const path          = require('path');
const winston       = require('winston');
require('dotenv').config();

const app  = express();
const PORT = process.env.PORT || 3000;

// Logger لتسجيل النشاط في ملف وConsole
const logger = winston.createLogger({
  transports: [
    new winston.transports.File({ filename: 'activity.log' }),
    new winston.transports.Console()
  ]
});

// 1. تفعيل CORS لجميع الدومينات بدون قيود
app.use(cors({
  origin: '*',
  methods: ['GET','POST','PUT','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type','Authorization','x-csrf-token']
}));

// 2. تنظيف مدخلات المستخدم من XSS وحقن Mongo
app.use(xssClean());
app.use(mongoSanitize());

// 3. قراءة JSON من body بحجم محدود
app.use(express.json({ limit: '15kb' }));

// 4. تسجيل كل طلب وارد
app.use((req, res, next) => {
  logger.info(`[${new Date().toISOString()}] [${req.ip}] ${req.method} ${req.originalUrl}`);
  next();
});

// 5. تقديم الملفات الثابتة للواجهة من مجلد public
app.use(express.static(path.join(__dirname, 'public')));

// 6. دالة لحساب عدد الأيام بين تاريخين (شاملة اليومين)
function calcDays(start, end) {
  const s = new Date(start);
  const e = new Date(end);
  if (isNaN(s) || isNaN(e) || e < s) return 0;
  const msPerDay = 1000 * 60 * 60 * 24;
  return Math.floor((e - s) / msPerDay) + 1;
}

// 7. بيانات تجريبية للإجازات
const leavesRaw = [
  { serviceCode: "GSL25021372778", idNumber: "1088576044", name: "عبدالإله سليمان عبدالله الهديلج", reportDate: "2025-02-09", startDate: "2025-02-09", endDate: "2025-02-24", doctorName: "هدى مصطفى خضر دحبور", jobTitle: "استشاري" },
  { serviceCode: "GSL25021898579", idNumber: "1088576044", name: "عبدالإله سليمان عبدالله الهديلج", reportDate: "2025-02-25", startDate: "2025-02-25", endDate: "2025-03-26", doctorName: "جمال راشد السر محمد أحمد", jobTitle: "استشاري" },
  { serviceCode: "GSL25022385036", idNumber: "1088576044", name: "عبدالإله سليمان عبدالله الهديلج", reportDate: "2025-03-27", startDate: "2025-03-27", endDate: "2025-04-17", doctorName: "جمال راشد السر محمد أحمد", jobTitle: "استشاري" },
  { serviceCode: "GSL25022884602", idNumber: "1088576044", name: "عبدالإله سليمان عبدالله الهديلج", reportDate: "2025-04-18", startDate: "2025-04-18", endDate: "2025-05-15", doctorName: "هدى مصطفى خضر دحبور", jobTitle: "استشاري" },
  { serviceCode: "GSL25023345012", idNumber: "1088576044", name: "عبدالإله سليمان عبدالله الهديلج", reportDate: "2025-05-16", startDate: "2025-05-16", endDate: "2025-06-12", doctorName: "هدى مصطفى خضر دحبور", jobTitle: "استشاري" },
  { serviceCode: "GSL25062955824", idNumber: "1088576044", name: "عبدالإله سليمان عبدالله الهديلج", reportDate: "2025-06-13", startDate: "2025-06-13", endDate: "2025-07-11", doctorName: "هدى مصطفى خضر دحبور", jobTitle: "استشاري" },
  { serviceCode: "GSL25071678945", idNumber: "1088576044", name: "عبدالإله سليمان عبدالله الهديلج", reportDate: "2025-07-12", startDate: "2025-07-12", endDate: "2025-07-17", doctorName: "عبدالعزيز فهد هميجان الروقي", jobTitle: "استشاري" }
];
const leaves = leavesRaw.map(rec => ({ ...rec, days: calcDays(rec.startDate, rec.endDate) }));

// 8. API: استعلام عن الإجازة المرضية
app.post('/api/leave', (req, res) => {
  const { serviceCode, idNumber } = req.body;

  // تدقيق المدخلات
  if (
    typeof serviceCode !== 'string' ||
    !/^[A-Za-z0-9]{8,20}$/.test(serviceCode) ||
    typeof idNumber !== 'string' ||
    !/^[0-9]{10}$/.test(idNumber)
  ) {
    return res.status(400).json({ success: false, message: "البيانات المدخلة غير صحيحة." });
  }

  const record = leaves.find(item =>
    item.serviceCode === serviceCode && item.idNumber === idNumber
  );

  if (record) {
    return res.json({ success: true, record });
  } else {
    return res.status(404).json({ success: false, message: "لا يوجد سجل مطابق." });
  }
});

// 9. API: إضافة إجازة جديدة
app.post('/api/add-leave', (req, res) => {
  const {
    serviceCode, idNumber, name,
    reportDate, startDate, endDate,
    doctorName, jobTitle
  } = req.body;

  // تدقيق شامل للمدخلات
  if (
    typeof serviceCode !== 'string' ||
    !/^[A-Za-z0-9]{8,20}$/.test(serviceCode) ||

    typeof idNumber !== 'string' ||
    !/^[0-9]{10}$/.test(idNumber) ||

    typeof name !== 'string' ||
    typeof reportDate !== 'string' ||
    typeof startDate !== 'string' ||
    typeof endDate !== 'string' ||

    typeof doctorName !== 'string' ||
    typeof jobTitle !== 'string'
  ) {
    return res.status(400).json({ success: false, message: "مدخلات غير صالحة." });
  }

  const newRec = {
    serviceCode,
    idNumber,
    name,
    reportDate,
    startDate,
    endDate,
    doctorName,
    jobTitle,
    days: calcDays(startDate, endDate)
  };

  leaves.push(newRec);
  logger.info(`Leave added: ${serviceCode} | ${idNumber}`);
  return res.json({ success: true, message: "تمت الإضافة بنجاح.", record: newRec });
});

// 10. توجيه أي طلب غير موجود للواجهة (SPA routing)
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// 11. إنهاء آمن عند SIGTERM
process.on('SIGTERM', () => {
  logger.info("🔴 Received SIGTERM — shutting down gracefully");
  process.exit(0);
});

// 12. بدء السيرفر
app.listen(PORT, () => {
  logger.info(`✅ Server running on port ${PORT}`);
});
