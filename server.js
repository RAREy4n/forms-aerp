require('dotenv').config();
const express    = require('express');
const axios      = require('axios');
const cors       = require('cors');
const helmet     = require('helmet');
const rateLimit  = require('express-rate-limit');
const path       = require('path');
const multer     = require('multer');
const { google } = require('googleapis');
const { Readable } = require('stream');

// ── Variáveis obrigatórias ────────────────────────────────────────────────────
const REQUIRED_ENV = [
  'CLICKSIGN_TOKEN',
  'TEMPLATE_FISICA', 'TEMPLATE_JURIDICA',
  'RD_TOKEN', 'RD_PIPELINE_ID', 'RD_STAGE_ID',
  'GOOGLE_CLIENT_ID', 'GOOGLE_CLIENT_SECRET', 'GOOGLE_REFRESH_TOKEN',
  'DRIVE_FOLDER_ID', 'ALLOWED_ORIGIN',
];
const missingEnv = REQUIRED_ENV.filter(k => !process.env[k]);
if (missingEnv.length > 0) {
  console.error('❌ Variáveis ausentes:', missingEnv.join(', '));
  process.exit(1);
}

const app = express();
app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false }));

const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGIN || '').split(',').map(o => o.trim()).filter(Boolean);
app.use(cors({
  origin: (origin, cb) => {
    if (!origin || ALLOWED_ORIGINS.includes(origin)) cb(null, true);
    else cb(new Error(`CORS bloqueado: ${origin}`));
  },
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type'],
}));

app.use(express.json({ limit: '1mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// ── Rate limit ────────────────────────────────────────────────────────────────
const apiLimiter = rateLimit({ windowMs: 15*60*1000, max: 30, standardHeaders: true, legacyHeaders: false, message: { error: 'Muitas requisições.' } });
const contratoLimiter = rateLimit({ windowMs: 60*60*1000, max: 10, standardHeaders: true, legacyHeaders: false, message: { error: 'Limite de contratos atingido.' } });

// ── Multer ────────────────────────────────────────────────────────────────────
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    ['application/pdf','image/jpeg','image/png'].includes(file.mimetype)
      ? cb(null, true) : cb(new Error('Tipo não permitido.'));
  },
});

// ── Sanitização ───────────────────────────────────────────────────────────────
function sanitize(str = '')      { return String(str).trim().replace(/[<>"'`]/g, '').substring(0, 500); }
function sanitizeCPF(str = '')   { return String(str).replace(/\D/g, '').substring(0, 11); }
function sanitizeCNPJ(str = '')  { return String(str).replace(/\D/g, '').substring(0, 14); }
function sanitizePhone(str = '') { return String(str).replace(/\D/g, '').substring(0, 15); }

// ── Constantes ────────────────────────────────────────────────────────────────
const TOKEN    = process.env.CLICKSIGN_TOKEN;
const BASE_URL = process.env.CLICKSIGN_BASE_URL || 'https://app.clicksign.com';

// 2 templates: fisica e juridica (plano fixo: Ouro 40%)
const TEMPLATES = {
  fisica:   process.env.TEMPLATE_FISICA,
  juridica: process.env.TEMPLATE_JURIDICA,
};
const PLANO_LABEL = 'Plano Ouro — AERP;

const RD_TOKEN        = process.env.RD_TOKEN;
const RD_PIPELINE_ID  = process.env.RD_PIPELINE_ID;
const RD_STAGE_ID     = process.env.RD_STAGE_ID;
const RD_STAGE_SIGNED = process.env.RD_STAGE_SIGNED;
const RD_BASE         = 'https://crm.rdstation.com/api/v1';
const DRIVE_FOLDER_ID = process.env.DRIVE_FOLDER_ID;

const RESPONSAVEL = {
  nome:       process.env.RESPONSAVEL_NOME  || '',
  cpf:        process.env.RESPONSAVEL_CPF   || '',
  nascimento: process.env.RESPONSAVEL_NASC  || '',
  email:      process.env.RESPONSAVEL_EMAIL || '',
};

// Campos RD Station
const RD_FIELDS = {
  TELEFONE:  '679a61bd8d3989001bb1db85',
  EMAIL:     '67b326253c2b70001c4111fc',
  VALOR:     '68f94144733b55001f2233a7',
  URL:       '679d3dcd757a9f001e53ab7c',
  ENDERECO:  '679a61e4b33db00014c07a54',
  NUMERO:    '67f3c9781d840c0014710b91',
  BAIRRO:    '68cac15c9e595a00140e2ec9',
  MUNICIPIO: '67b325fcee87d10014376def',
  ESTADO:    '67b480a136771a001efb48e7',
  CEP:       '68f92b5ea7e4430016b3187e',
  CNPJ:      '67b325674d1060001ee1cfaa',
  PLANO:     process.env.RD_FIELD_PLANO || '',
};

const pendingDeals = new Map();

// ── Google Drive ──────────────────────────────────────────────────────────────
function getDriveClient() {
  const auth = new google.auth.OAuth2(
    process.env.GOOGLE_CLIENT_ID,
    process.env.GOOGLE_CLIENT_SECRET,
    'http://localhost:3001/oauth2callback'
  );
  auth.setCredentials({ refresh_token: process.env.GOOGLE_REFRESH_TOKEN });
  return google.drive({ version: 'v3', auth });
}

async function uploadParaDrive(buffer, filename, mimetype) {
  try {
    const drive = getDriveClient();
    const res = await drive.files.create({
      requestBody: { name: filename, parents: [DRIVE_FOLDER_ID] },
      media: { mimeType: mimetype, body: Readable.from(buffer) },
      fields: 'id, webViewLink',
    });
    await drive.permissions.create({
      fileId: res.data.id,
      requestBody: { role: 'reader', type: 'anyone' },
    });
    console.log(`[Drive] ✓ ${res.data.webViewLink}`);
    return res.data.webViewLink;
  } catch (err) {
    console.error('[Drive] Erro:', err.message);
    return null;
  }
}

// ── RD Station ────────────────────────────────────────────────────────────────
async function salvarLinkNoCRM(dealId, link) {
  if (!dealId || !link) return;
  try {
    await axios.put(
      `${RD_BASE}/deals/${dealId}?token=${RD_TOKEN}`,
      { deal: { deal_custom_fields: [{ custom_field_id: RD_FIELDS.URL, value: link }] } },
      { headers: { 'Content-Type': 'application/json' } }
    );
  } catch (err) {
    console.error('[RD] Erro URL:', err.response?.data || err.message);
  }
}

async function moverCardCRM(dealId, stageId) {
  if (!dealId || !RD_TOKEN) return;
  try {
    await axios.patch(
      `${RD_BASE}/deals/${dealId}?token=${RD_TOKEN}`,
      { deal: { deal_stage_id: stageId } },
      { headers: { 'Content-Type': 'application/json' } }
    );
    console.log(`[RD] ✓ Card movido: ${stageId}`);
  } catch (err) {
    console.error('[RD] Erro mover card:', err.response?.data || err.message);
  }
}

async function enviarParaRD({ nome, email, telefone, valorConta }) {
  try {
    console.log(`[RD] Enviando lead ACED: ${nome}`);
    const contactRes = await axios.post(
      `${RD_BASE}/contacts?token=${RD_TOKEN}`,
      { contact: { name: nome, email, ...(telefone && { phones: [{ phone: telefone }] }) } },
      { headers: { 'Content-Type': 'application/json' } }
    );
    const contactId = contactRes.data?.contact?._id || contactRes.data?._id;

    const campos = [
      { custom_field_id: RD_FIELDS.TELEFONE, value: telefone   || '' },
      { custom_field_id: RD_FIELDS.EMAIL,    value: email      || '' },
      { custom_field_id: RD_FIELDS.VALOR,    value: valorConta || '' },
    ];
    if (RD_FIELDS.PLANO) campos.push({ custom_field_id: RD_FIELDS.PLANO, value: PLANO_LABEL });

    const dealRes = await axios.post(
      `${RD_BASE}/deals?token=${RD_TOKEN}`,
      {
        deal: {
          name: `${nome} — ${PLANO_LABEL}`,
          deal_stage_id: RD_STAGE_ID,
          deal_pipeline_id: RD_PIPELINE_ID,
          ...(contactId && { contacts_ids: [contactId] }),
          deal_custom_fields: campos.filter(f => f.value !== ''),
        }
      },
      { headers: { 'Content-Type': 'application/json' } }
    );
    const dealId = dealRes.data?.deal?._id || dealRes.data?._id;
    console.log(`[RD] ✓ Negociação: ${dealId}`);
    return dealId;
  } catch (err) {
    console.error('[RD] Erro:', err.response?.data || err.message);
    return null;
  }
}

async function atualizarDadosStep2(dealId, { endereco, numero, bairro, cidade, uf, cep, cnpj }) {
  if (!dealId) return;
  try {
    const campos = [
      { custom_field_id: RD_FIELDS.ENDERECO,  value: endereco || '' },
      { custom_field_id: RD_FIELDS.NUMERO,    value: numero   || '' },
      { custom_field_id: RD_FIELDS.BAIRRO,    value: bairro   || '' },
      { custom_field_id: RD_FIELDS.MUNICIPIO, value: cidade   || '' },
      { custom_field_id: RD_FIELDS.ESTADO,    value: uf       || '' },
      { custom_field_id: RD_FIELDS.CEP,       value: cep      || '' },
      { custom_field_id: RD_FIELDS.CNPJ,      value: cnpj     || '' },
    ];
    await axios.put(
      `${RD_BASE}/deals/${dealId}?token=${RD_TOKEN}`,
      { deal: { deal_custom_fields: campos.filter(f => f.value !== '') } },
      { headers: { 'Content-Type': 'application/json' } }
    );
    console.log(`[RD] ✓ Dados step 2 salvos`);
  } catch (err) {
    console.error('[RD] Erro step2:', err.response?.data || err.message);
  }
}

// ── POST /api/rd-lead ─────────────────────────────────────────────────────────
app.post('/api/rd-lead', apiLimiter, upload.single('fatura'), async (req, res) => {
  const nome     = sanitize(req.body.nome);
  const email    = sanitize(req.body.email);
  const telefone = sanitizePhone(req.body.telefone);
  const valorFatura = sanitize(req.body.valorFatura);

  if (!nome || !email)
    return res.status(400).json({ error: 'Nome e e-mail são obrigatórios.' });
  if (!email.includes('@') || !email.includes('.'))
    return res.status(400).json({ error: 'E-mail inválido.' });
  if (nome.trim().split(/\s+/).length < 2)
    return res.status(400).json({ error: 'Informe nome e sobrenome.' });

  const dealId = await enviarParaRD({ nome, email, telefone, valorConta: valorFatura });

  if (req.file) {
    const ext = path.extname(req.file.originalname).replace(/[^a-zA-Z0-9.]/g, '');
    const nomeArq = `fatura_aced_${nome.replace(/\s+/g,'_')}_${Date.now()}${ext}`;
    const link = await uploadParaDrive(req.file.buffer, nomeArq, req.file.mimetype);
    await salvarLinkNoCRM(dealId, link);
  }

  return res.json({ success: true, rd_deal_id: dealId });
});

// ── POST /api/assinar ─────────────────────────────────────────────────────────
app.post('/api/assinar', contratoLimiter, async (req, res) => {
  const tipo        = sanitize(req.body.tipo);
  const nome        = sanitize(req.body.nome);
  const email       = sanitize(req.body.email);
  const cpf         = sanitizeCPF(req.body.cpf);
  const cnpj        = sanitizeCNPJ(req.body.cnpj);
  const telefone    = sanitizePhone(req.body.telefone);
  const razaoSocial = sanitize(req.body.razaoSocial);
  const cep         = sanitize(req.body.cep).replace(/\D/g,'').substring(0,8);
  const endereco    = sanitize(req.body.endereco);
  const numero      = sanitize(req.body.numero);
  const bairro      = sanitize(req.body.bairro);
  const cidade      = sanitize(req.body.cidade);
  const uf          = sanitize(req.body.uf).substring(0,2).toUpperCase();
  const rdDealId    = req.body.rd_deal_id || null;
  const apelido     = sanitize(req.body.apelido || '');
  const complemento = sanitize(req.body.complemento || '');
  const uc          = sanitize(req.body.uc || '');

  if (!['fisica','juridica'].includes(tipo))
    return res.status(400).json({ error: 'Tipo inválido.' });
  if (!nome || !email)
    return res.status(400).json({ error: 'Nome e e-mail obrigatórios.' });

  const templateId = TEMPLATES[tipo];
  if (!templateId)
    return res.status(400).json({ error: `Template não configurado: ${tipo}` });

  const nomeArquivo = `aced-${tipo}-${nome.replace(/\s+/g,'-').toLowerCase().replace(/[^a-z0-9-]/g,'')}-${Date.now()}.docx`;

  try {
    console.log(`[1/4] Contrato ACED: ${tipo} | ${nome}`);

    const docRes = await axios.post(
      `${BASE_URL}/api/v1/templates/${templateId}/documents?access_token=${TOKEN}`,
      {
        document: {
          path: `/contratos/aced/${nomeArquivo}`,
          template: {
            data: {
              'Nome ou Razão Social': tipo === 'juridica' ? razaoSocial : nome,
              'Nome Fantasia ou Apelido': apelido,
              'CPF': cpf,
              'CNPJ': cnpj,
              'Responsável': tipo === 'juridica' ? nome : '',
              'E-mail': email,
              'Email' : email,
              'Telefone': telefone,
              'Logradouro': endereco,
              'nº': numero,
              'Complemento': complemento,
              'Bairro': bairro,
              'Cidade': cidade,
              'Estado': uf,
              'CEP': cep,
              'nº UC': uc,
              'RG': '',
              'Data de Nascimento': '',
              'Profissão/Objeto Social': '',
              'Nacionalidade': '',
              'Email alternativo': '',
              'Telefone Alternativo': '',
              'Distribuidora': '',
              'PLANO': PLANO_LABEL,
              'DATA': new Date().toLocaleDateString('pt-BR'),
            }
          },
          deadline_at: new Date(Date.now() + 30*24*60*60*1000).toISOString(),
          auto_close: true,
          locale: 'pt-BR',
        }
      },
      { headers: { 'Content-Type': 'application/json' } }
    );
    const documentKey = docRes.data.document.key;
    console.log(`[1/4] ✓ Documento: ${documentKey}`);
    console.log(`[DEBUG] tipo:${tipo} | email:${email} | nome:${nome} | cnpj:${cnpj}`);

  console.log(`[2/4] Signatário cliente...`);
const signerRes = await axios.post(
  `${BASE_URL}/api/v1/signers?access_token=${TOKEN}`,
  { signer: { email, name: nome, auths: ['email'], delivery: 'email', has_documentation: !!(cpf||cnpj), ...(cpf && {documentation:cpf}), ...(telefone && {phone_number:telefone}) } },
  { headers: { 'Content-Type': 'application/json' } }
);
const signerKey = signerRes.data.signer.key;
const listRes = await axios.post(
  `${BASE_URL}/api/v1/lists?access_token=${TOKEN}`,
  { list: { document_key: documentKey, signer_key: signerKey, sign_as: 'sign', message: `Olá ${nome}, seu contrato Sion (${PLANO_LABEL}) está pronto para assinatura.` } },
  { headers: { 'Content-Type': 'application/json' } }
);
const requestSignatureKey = listRes.data.list.request_signature_key;
console.log(`[2/4] ✓ Cliente: ${requestSignatureKey}`);

    console.log(`[3/4] Signatário responsável...`);
    const signerRes2 = await axios.post(
  `${BASE_URL}/api/v1/signers?access_token=${TOKEN}`,
    { signer: { email: RESPONSAVEL.email, name: RESPONSAVEL.nome, auths: ['email'], delivery: 'email', has_documentation: false } },
    { headers: { 'Content-Type': 'application/json' } }
);
    await axios.post(
      `${BASE_URL}/api/v1/lists?access_token=${TOKEN}`,
      { list: { document_key: documentKey, signer_key: signerRes2.data.signer.key, sign_as: 'sign', message: `Novo contrato ACED aguarda assinatura — ${nome}.` } },
      { headers: { 'Content-Type': 'application/json' } }
    );
    console.log(`[4/4] ✓ Responsável vinculado`);

    if (rdDealId) pendingDeals.set(documentKey, rdDealId);
    await atualizarDadosStep2(rdDealId, { endereco, numero, bairro, cidade, uf, cep, cnpj });

    return res.json({ success: true, request_signature_key: requestSignatureKey, document_key: documentKey, tipo });

  } catch (error) {
    console.error('[Clicksign] Erro:', JSON.stringify(error.response?.data || error.message, null, 2));
    return res.status(500).json({ error: 'Erro ao processar contrato. Tente novamente.' });
  }
});

// ── Webhook ───────────────────────────────────────────────────────────────────
app.get('/api/webhook/clicksign', (req, res) => res.json({ status: 'ok' }));
app.post('/api/webhook/clicksign', express.json(), async (req, res) => {
  try {
    const event  = req.body?.event?.name;
    const docKey = req.body?.document?.key;
    const status = req.body?.document?.status;
    const isFullySigned = event==='Event::AutoClose'||event==='Event::DocumentClosed'||status==='closed';
    if (isFullySigned && docKey) {
      const rdDealId = pendingDeals.get(docKey);
      if (rdDealId) { await moverCardCRM(rdDealId, RD_STAGE_SIGNED); pendingDeals.delete(docKey); }
    }
    return res.status(200).json({ received: true });
  } catch (err) {
    console.error('[Webhook] Erro:', err.message);
    return res.status(500).json({ error: 'Erro interno.' });
  }
});

// ── Health ────────────────────────────────────────────────────────────────────
app.get('/api/health', (req, res) => {
  const secret = process.env.HEALTH_SECRET;
  if (secret && req.headers['x-health-secret'] !== secret)
    return res.status(403).json({ error: 'Acesso negado.' });
  return res.json({
    status: 'ok',
    service: 'sion-aced-dourados',
    templates: {
      fisica:   TEMPLATES.fisica   ? '✓' : '⚠ AUSENTE',
      juridica: TEMPLATES.juridica ? '✓' : '⚠ AUSENTE',
    },
    plano: PLANO_LABEL,
    rd_crm:    RD_TOKEN        ? '✓' : '⚠',
    drive:     DRIVE_FOLDER_ID ? '✓' : '⚠',
    clicksign: TOKEN           ? '✓' : '⚠',
  });
});

// ── Error handler ─────────────────────────────────────────────────────────────
app.use((err, req, res, next) => {
  if (err.code === 'LIMIT_FILE_SIZE') return res.status(400).json({ error: 'Arquivo muito grande. Máximo 10MB.' });
  if (err.message?.includes('não permitido')) return res.status(400).json({ error: err.message });
  console.error('Erro:', err.message);
  return res.status(500).json({ error: 'Erro interno.' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`\n🚀 Sion ACED Dourados: http://localhost:${PORT}`);
  console.log(`📋 Clicksign: ${BASE_URL}`);
  console.log(`🏅 Plano: ${PLANO_LABEL}`);
  console.log(`📄 Templates: fisica=${TEMPLATES.fisica?'✓':'⚠'} | juridica=${TEMPLATES.juridica?'✓':'⚠'}\n`);
});
 
