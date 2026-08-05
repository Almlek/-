/**
 * مُحضِّر — الخلفية الإنتاجية (Cloudflare Worker + D1 + R2)
 * التشغيل: wrangler deploy
 * الأسرار: wrangler secret put AI_API_KEY && wrangler secret put AUTH_SECRET
 *
 * ── wrangler.toml ─────────────────────────────
 * name = "muhaddir-api"
 * main = "src/index.js"
 * compatibility_date = "2026-07-15"
 * [vars]
 * AI_PROVIDER = "gemini"            # gemini | openai | openrouter
 * AI_MODEL    = "gemini-2.0-flash"
 * [[d1_databases]]
 * binding = "DB"
 * database_name = "muhaddir"
 * database_id = "xxxx"
 * [[r2_buckets]]
 * binding = "FILES"
 * bucket_name = "muhaddir-files"
 *
 * ── database/schema.sql ───────────────────────
 * CREATE TABLE IF NOT EXISTS users(
 *   id TEXT PRIMARY KEY, name TEXT NOT NULL, email TEXT UNIQUE NOT NULL,
 *   pass_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'teacher',
 *   school TEXT, created_at TEXT DEFAULT (datetime('now')));
 * CREATE TABLE IF NOT EXISTS plans(
 *   id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id),
 *   title TEXT NOT NULL, status TEXT DEFAULT 'مسودة',
 *   json TEXT NOT NULL,
 *   quality INTEGER DEFAULT 0,
 *   created_at TEXT DEFAULT (datetime('now')),
 *   updated_at TEXT DEFAULT (datetime('now')));
 * CREATE INDEX IF NOT EXISTS idx_plans_user ON plans(user_id, updated_at DESC);
 * CREATE TABLE IF NOT EXISTS curricula(
 *   id TEXT PRIMARY KEY, name TEXT NOT NULL,
 *   tree TEXT NOT NULL);
 */

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type,Authorization'
};

const JSON_HEADERS = { 'Content-Type': 'application/json; charset=utf-8' };

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: CORS });
    }

    try {
      // Health check
      if (url.pathname === '/api/health') {
        return json({ ok: true, provider: env.AI_PROVIDER || 'mock', time: new Date().toISOString() });
      }

      // Login (مبسّط)
      if (url.pathname === '/api/auth/login' && request.method === 'POST') {
        return login(request, env);
      }

      // مصادقة لبقية الطلبات
      const user = await auth(request, env);
      if (!user) {
        return json({ error: 'غير مصرّح — يلزم تسجيل الدخول' }, 401);
      }

      // توليد تحضير
      if (url.pathname === '/api/generate' && request.method === 'POST') {
        return generate(request, env, user);
      }

      // قائمة التحاضير
      if (url.pathname === '/api/plans' && request.method === 'GET') {
        return listPlans(env, user);
      }
      if (url.pathname === '/api/plans' && request.method === 'POST') {
        return savePlan(request, env, user);
      }

      // تحضير فردي
      const match = url.pathname.match(/^\/api\/plans\/([\w-]+)$/);
      if (match) {
        const planId = match[1];
        if (request.method === 'GET') return getPlan(env, user, planId);
        if (request.method === 'DELETE') return delPlan(env, user, planId);
        if (request.method === 'PUT') return updatePlan(request, env, user, planId);
      }

      return json({ error: 'مسار غير موجود' }, 404);
    } catch (e) {
      console.error(e);
      return json({ error: 'خطأ داخلي', detail: String(e).slice(0, 200) }, 500);
    }
  }
};

// ---------- مساعدات ----------
function json(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: { ...JSON_HEADERS, ...CORS } });
}

function cors(env, res) {
  const headers = { ...CORS };
  return new Response(res.body, { status: res.status, headers: { ...headers, ...res.headers } });
}

// ---------- مصادقة مبسّطة (HMAC مع Secret) ----------
async function auth(request, env) {
  const auth = request.headers.get('Authorization');
  if (!auth || !auth.startsWith('Bearer ')) return null;
  const token = auth.slice(7).trim();
  if (!token || !env.AUTH_SECRET) return null;

  // تنسيق: userId:hmac
  const parts = token.split(':');
  if (parts.length !== 2) return null;
  const [userId, hmac] = parts;
  const encoder = new TextEncoder();
  const keyData = encoder.encode(env.AUTH_SECRET);
  const msg = encoder.encode(userId);
  const cryptoKey = await crypto.subtle.importKey('raw', keyData, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', cryptoKey, msg);
  const computed = Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, '0')).join('');
  if (hmac !== computed) return null;

  return { id: userId };
}

async function login(request, env) {
  const body = await request.json().catch(() => ({}));
  const { email, password } = body;
  if (!email || !password) return json({ error: 'البريد وكلمة المرور مطلوبان' }, 400);

  // في الإنتاج: استخدم D1 للتحقق من المستخدم
  // هنا نستخدم مستخدم وهمي للتوضيح
  if (email === 'teacher@school.edu' && password === 'demo123') {
    const userId = 'user_demo';
    const encoder = new TextEncoder();
    const keyData = encoder.encode(env.AUTH_SECRET || 'fallback-secret-change-me');
    const msg = encoder.encode(userId);
    const cryptoKey = await crypto.subtle.importKey('raw', keyData, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const sig = await crypto.subtle.sign('HMAC', cryptoKey, msg);
    const hmac = Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, '0')).join('');
    return json({ token: userId + ':' + hmac, user: { id: userId, name: 'أحمد المعلم', email } });
  }

  return json({ error: 'بيانات الدخول غير صحيحة' }, 401);
}

// ---------- توليد التحضير ----------
async function generate(request, env, user) {
  const body = await request.json().catch(() => ({}));

  // التحقق من صحة المدخلات
  const required = ['curriculum', 'grade', 'subject', 'unit', 'lesson', 'duration'];
  for (const f of required) {
    if (!body[f]) return json({ error: `الحقل "${f}" مطلوب` }, 400);
  }

  const prompt = buildPrompt(body);
  const result = await AIAdapter.generate(env, prompt);

  // استخراج JSON من الرد
  let data;
  try {
    const cleaned = result.replace(/```json\s*|\s*```/g, '').trim();
    data = JSON.parse(cleaned);
  } catch (e) {
    return json({ error: 'فشل تحليل JSON من الذكاء الاصطناعي', raw: result.slice(0, 500) }, 500);
  }

  // التحقق من صحة المخطط
  if (!data.objectives || !data.stages || !data.meta) {
    return json({ error: 'البيانات المُولَّدة لا تتطابق مع المخطط المطلوب' }, 500);
  }

  // حساب الجودة في الخادم
  data.quality = qualityCheck(data);

  // حفظ في D1
  const stmt = await env.DB.prepare(`
    INSERT INTO plans (id, user_id, title, status, json, quality, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))
  `);
  const planId = 'P' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
  await stmt.bind(planId, user.id, data.meta.lesson || 'تحضير جديد', 'مسودة', JSON.stringify(data), data.quality.total || 0)
    .run();

  return json({ success: true, id: planId, data });
}

// ---------- بناء النص الموجه (System Prompt) ----------
function buildPrompt(p) {
  const bloomLevels = p.band === 'high' ? 'تطبيق، تحليل، تقويم، إبداع' :
    p.band === 'mid' ? 'فهم، تطبيق، تحليل' : 'تذكّر، فهم، تطبيق';

  return `
أنت خبير تربوي محترف. المطلوب: إنشاء تحضير درس كامل على شكل JSON وفق المخطط التالي.

بيانات الدرس:
- المنهج: ${p.curriculum}
- الصف: ${p.grade}
- المادة: ${p.subject}
- الوحدة: ${p.unit}
- عنوان الدرس: ${p.lesson}
- الزمن: ${p.duration} دقيقة
- مستوى الطلاب: ${p.level || 'متفاوت'}
- الاستراتيجيات: ${(p.strategies || []).join('، ')}

متطلبات الجودة التربوية:
1. الأهداف: 3-5 أهداف وفق مستويات بلوم (${bloomLevels})، صياغة: "أن يَفعَلَ الطالبُ ..."
2. توزيع الزمن: تمهيد (10%)، استكشاف وعرض (38%)، تطبيق (30%)، تقويم (14%)، ختام (8%)
3. كل مرحلة تحتوي: نشاط المعلم، نشاط الطالب، استراتيجية، تقويم
4. وسائل تعليمية مناسبة للمادة
5. تقويم ختامي + واجب منزلي
6. معالجة الفروق الفردية (متقدمون + متعثرون)

أخرج JSON فقط بهذا المخطط:
{
  "meta": {
    "curriculum": "${p.curriculum}",
    "grade": "${p.grade}",
    "subject": "${p.subject}",
    "unit": "${p.unit}",
    "lesson": "${p.lesson}",
    "duration": ${p.duration},
    "level": "${p.level || 'متفاوت'}",
    "strategies": ${JSON.stringify(p.strategies || [])},
    "date": "${new Date().toISOString().slice(0,10)}",
    "period": "1",
    "section": "أ",
    "teacher": "",
    "school": ""
  },
  "objectives": [{ "text": "أن ي...", "bloom": "understand", "domain": "معرفي" }],
  "stages": [
    { "name": "التمهيد", "duration": 5, "teacher": "...", "student": "...", "strategy": "...", "assessment": "..." }
  ],
  "resources": ["وسيلة 1", "وسيلة 2"],
  "assessment": { "formative": ["أداة 1"], "summative": "...", "homework": "..." },
  "differentiation": { "advanced": "...", "support": "..." },
  "reflection": ""
}

لا تخرج أي نص خارج JSON.
`;
}

// ---------- محول الذكاء الاصطناعي ----------
const AIAdapter = {
  async generate(env, prompt) {
    const provider = env.AI_PROVIDER || 'gemini';
    const model = env.AI_MODEL || 'gemini-2.0-flash';

    if (provider === 'openai') {
      return callOpenAI(env, prompt, model);
    }
    if (provider === 'openrouter') {
      return callOpenRouter(env, prompt, model);
    }
    return callGemini(env, prompt, model);
  }
};

async function callGemini(env, prompt, model) {
  const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${env.AI_API_KEY}`;
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      contents: [{ parts: [{ text: prompt }] }],
      generationConfig: { temperature: 0.3, maxOutputTokens: 4096 }
    })
  });
  if (!res.ok) throw new Error('Gemini API error: ' + res.status);
  const json = await res.json();
  return json.candidates?.[0]?.content?.parts?.[0]?.text || '';
}

async function callOpenAI(env, prompt, model) {
  const url = 'https://api.openai.com/v1/chat/completions';
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + env.AI_API_KEY },
    body: JSON.stringify({
      model: model || 'gpt-4o-mini',
      messages: [{ role: 'user', content: prompt }],
      temperature: 0.3,
      max_tokens: 4096
    })
  });
  if (!res.ok) throw new Error('OpenAI API error: ' + res.status);
  const json = await res.json();
  return json.choices?.[0]?.message?.content || '';
}

async function callOpenRouter(env, prompt, model) {
  const url = 'https://openrouter.ai/api/v1/chat/completions';
  const res = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': 'Bearer ' + env.AI_API_KEY,
      'HTTP-Referer': 'https://muhaddir.tech',
      'X-Title': 'Muhaddir AI'
    },
    body: JSON.stringify({
      model: model || 'google/gemini-2.0-flash-exp:free',
      messages: [{ role: 'user', content: prompt }],
      temperature: 0.3,
      max_tokens: 4096
    })
  });
  if (!res.ok) throw new Error('OpenRouter API error: ' + res.status);
  const json = await res.json();
  return json.choices?.[0]?.message?.content || '';
}

// ---------- فحص الجودة (خادم) ----------
function qualityCheck(d) {
  const notes = [];
  let total = 0;

  // الأهداف
  const obs = (d.objectives || []).filter(o => o.text && o.text.trim());
  if (obs.length >= 3) total += 30;
  else if (obs.length === 2) { total += 20;
    notes.push('يُفضّل 3 أهداف فأكثر'); } else { total += 10;
    notes.push('الأهداف قليلة جدًا'); }

  // الزمن
  const sum = (d.stages || []).reduce((a, s) => a + (+s.duration || 0), 0);
  const dur = +d.meta?.duration || 45;
  if (Math.abs(sum - dur) <= 2) total += 20;
  else if (Math.abs(sum - dur) <= 5) { total += 14;
    notes.push(`مجموع الأزمنة (${sum} د) قريب من زمن الحصة (${dur} د)`); } else { total += 8;
    notes.push(`فجوة زمنية: ${sum} د مقابل ${dur} د`); }

  // المراحل
  const stages = d.stages || [];
  if (stages.length >= 4) total += 15;
  else { total += 8;
    notes.push('يُفضّل 4-5 مراحل'); }
  if (stages.every(s => s.teacher && s.teacher.trim() && s.student && s.student.trim())) total += 10;
  else notes.push('بعض المراحل تفتقر لنشاط المعلم أو الطالب');

  // التقويم والفروق
  if (d.assessment?.summative) total += 10;
  if (d.differentiation?.advanced && d.differentiation?.support) total += 10;
  else notes.push('أكمل معالجة الفروق الفردية');

  // وسائل واستراتيجيات
  if ((d.resources || []).length >= 2) total += 5;
  const strats = new Set(stages.map(s => s.strategy).filter(Boolean));
  if (strats.size >= 2) total += 5;

  const grade = total >= 90 ? 'ممتاز' : total >= 75 ? 'جيد جدًا' : total >= 60 ? 'جيد' : 'يحتاج تحسين';
  return { total, notes, grade };
}

// ---------- عمليات قاعدة البيانات ----------
async function listPlans(env, user) {
  const stmt = await env.DB.prepare(`
    SELECT id, title, status, json, quality, created_at, updated_at
    FROM plans WHERE user_id = ? ORDER BY updated_at DESC
  `).bind(user.id);
  const res = await stmt.all();
  const plans = res.results.map(r => ({
    id: r.id,
    title: r.title,
    status: r.status,
    quality: r.quality,
    createdAt: r.created_at,
    updatedAt: r.updated_at,
    data: JSON.parse(r.json)
  }));
  return json({ plans });
}

async function getPlan(env, user, planId) {
  const stmt = await env.DB.prepare(`
    SELECT id, title, status, json, quality, created_at, updated_at
    FROM plans WHERE id = ? AND user_id = ?
  `).bind(planId, user.id);
  const res = await stmt.first();
  if (!res) return json({ error: 'التحضير غير موجود' }, 404);
  return json({
    id: res.id,
    title: res.title,
    status: res.status,
    quality: res.quality,
    createdAt: res.created_at,
    updatedAt: res.updated_at,
    data: JSON.parse(res.json)
  });
}

async function savePlan(request, env, user) {
  const body = await request.json().catch(() => ({}));
  if (!body.data) return json({ error: 'البيانات مطلوبة' }, 400);

  const planId = 'P' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
  const data = body.data;
  const quality = qualityCheck(data);

  const stmt = await env.DB.prepare(`
    INSERT INTO plans (id, user_id, title, status, json, quality, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))
  `);
  await stmt.bind(planId, user.id, data.meta?.lesson || 'تحضير جديد', 'مسودة', JSON.stringify(data), quality.total || 0)
    .run();

  return json({ success: true, id: planId });
}

async function updatePlan(request, env, user, planId) {
  const body = await request.json().catch(() => ({}));
  if (!body.data) return json({ error: 'البيانات مطلوبة' }, 400);

  const data = body.data;
  const quality = qualityCheck(data);

  const stmt = await env.DB.prepare(`
    UPDATE plans SET json = ?, quality = ?, updated_at = datetime('now'), status = ?
    WHERE id = ? AND user_id = ?
  `);
  await stmt.bind(JSON.stringify(data), quality.total || 0, body.status || 'مسودة', planId, user.id).run();

  return json({ success: true });
}

async function delPlan(env, user, planId) {
  const stmt = await env.DB.prepare(`DELETE FROM plans WHERE id = ? AND user_id = ?`).bind(planId, user.id);
  await stmt.run();
  return json({ success: true });
}