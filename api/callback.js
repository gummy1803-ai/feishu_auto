import fetch from 'node-fetch';
import * as nacl from 'tweetnacl';

const FEISHU_APP_ID     = process.env.FEISHU_APP_ID;
const FEISHU_APP_SECRET = process.env.FEISHU_APP_SECRET;
const GITHUB_TOKEN      = process.env.GH_PAT;
const GITHUB_REPO       = "gummy1803-ai/blogger-tracker";

async function getAppToken() {
  const r = await fetch("https://open.feishu.cn/open-apis/auth/v3/app_access_token/internal", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ app_id: FEISHU_APP_ID, app_secret: FEISHU_APP_SECRET })
  });
  const d = await r.json();
  return d.app_access_token;
}

async function getUserToken(code, appToken) {
  const r = await fetch("https://open.feishu.cn/open-apis/authen/v1/oidc/access_token", {
    method: "POST",
    headers: { "Authorization": `Bearer ${appToken}`, "Content-Type": "application/json" },
    body: JSON.stringify({ grant_type: "authorization_code", code })
  });
  return await r.json();
}

async function getRepoPublicKey() {
  const r = await fetch(`https://api.github.com/repos/${GITHUB_REPO}/actions/secrets/public-key`, {
    headers: { "Authorization": `Bearer ${GITHUB_TOKEN}`, "X-GitHub-Api-Version": "2022-11-28" }
  });
  return await r.json();
}

function encryptSecret(publicKeyB64, secretValue) {
  const key = Buffer.from(publicKeyB64, 'base64');
  const msg = Buffer.from(secretValue, 'utf8');
  const encrypted = nacl.box.before ? 
    nacl.seal(msg, key) :
    (() => {
      // tweetnacl sealed box
      const ephemeralKeyPair = nacl.box.keyPair();
      const nonce = nacl.randomBytes(nacl.box.nonceLength);
      const shared = nacl.box.before(key, ephemeralKeyPair.secretKey);
      const encrypted = nacl.box.after(msg, nonce, shared);
      const result = new Uint8Array(ephemeralKeyPair.publicKey.length + nonce.length + encrypted.length);
      result.set(ephemeralKeyPair.publicKey);
      result.set(nonce, ephemeralKeyPair.publicKey.length);
      result.set(encrypted, ephemeralKeyPair.publicKey.length + nonce.length);
      return result;
    })();
  return Buffer.from(encrypted).toString('base64');
}

async function updateSecret(name, value, keyData) {
  const encrypted = encryptSecret(keyData.key, value);
  const r = await fetch(`https://api.github.com/repos/${GITHUB_REPO}/actions/secrets/${name}`, {
    method: "PUT",
    headers: { 
      "Authorization": `Bearer ${GITHUB_TOKEN}`, 
      "X-GitHub-Api-Version": "2022-11-28", 
      "Content-Type": "application/json" 
    },
    body: JSON.stringify({ encrypted_value: encrypted, key_id: keyData.key_id })
  });
  return r.status;
}

export default async function handler(req, res) {
  const { code } = req.query;
  if (!code) {
    return res.status(400).send("缺少 code 参数");
  }

  try {
    const appToken = await getAppToken();
    const tokenData = await getUserToken(code, appToken);

    if (!tokenData.data) {
      return res.status(400).send(`飞书授权失败: ${JSON.stringify(tokenData)}`);
    }

    const userToken    = tokenData.data.access_token;
    const refreshToken = tokenData.data.refresh_token;

    const keyData = await getRepoPublicKey();
    const s1 = await updateSecret("FEISHU_USER_TOKEN",    userToken,    keyData);
    const s2 = await updateSecret("FEISHU_REFRESH_TOKEN", refreshToken, keyData);

    res.setHeader("Content-Type", "text/html; charset=utf-8");
    res.send(`
      <!DOCTYPE html>
      <html lang="zh-CN">
      <head><meta charset="UTF-8"><title>授权成功</title>
      <style>
        body { font-family: sans-serif; display:flex; justify-content:center; align-items:center; height:100vh; margin:0; background:#0d0f14; color:#e8eaf2; }
        .box { text-align:center; padding:40px; background:#141720; border-radius:16px; border:1px solid rgba(255,255,255,0.07); }
        h2 { color:#43d9a4; font-size:24px; margin-bottom:12px; }
        p { color:#6b7280; font-size:14px; }
      </style>
      </head>
      <body>
        <div class="box">
          <h2>✅ 授权成功</h2>
          <p>飞书 Token 已更新，系统将在下一次运行时生效。</p>
          <p style="margin-top:8px">可以关闭此页面了。</p>
        </div>
      </body>
      </html>
    `);
  } catch (e) {
    res.status(500).send(`服务器错误: ${e.message}\n${e.stack}`);
  }
}
