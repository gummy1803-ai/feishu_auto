import fetch from 'node-fetch';
import { createHash } from 'crypto';
import nacl from 'tweetnacl';

const FEISHU_APP_ID     = process.env.FEISHU_APP_ID;
const FEISHU_APP_SECRET = process.env.FEISHU_APP_SECRET;
const GITHUB_TOKEN      = process.env.GH_PAT;
const REDIRECT_URI      = process.env.REDIRECT_URI;
const GITHUB_REPO       = "gummy1803-ai/blogger-tracker";

// 手动实现 libsodium sealed box（只用 tweetnacl + Node 内置 crypto）
function sealedBox(message, recipientPublicKey) {
  const ephemeral = nacl.box.keyPair();
  const nonceInput = Buffer.concat([
    Buffer.from(ephemeral.publicKey),
    Buffer.from(recipientPublicKey)
  ]);
  const nonce = createHash('sha512').update(nonceInput).digest().slice(0, 24);
  const msgBytes = typeof message === 'string' ? Buffer.from(message, 'utf8') : message;
  const encrypted = nacl.box(new Uint8Array(msgBytes), new Uint8Array(nonce), recipientPublicKey, ephemeral.secretKey);
  return Buffer.concat([Buffer.from(ephemeral.publicKey), Buffer.from(encrypted)]);
}

async function getAppToken() {
  const r = await fetch("https://open.feishu.cn/open-apis/auth/v3/app_access_token/internal", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ app_id: FEISHU_APP_ID, app_secret: FEISHU_APP_SECRET })
  });
  const d = await r.json();
  if (!d.app_access_token) throw new Error(`获取app_token失败: ${JSON.stringify(d)}`);
  return d.app_access_token;
}

async function getUserToken(code, appToken) {
  const r = await fetch("https://open.feishu.cn/open-apis/authen/v1/oidc/access_token", {
    method: "POST",
    headers: { "Authorization": `Bearer ${appToken}`, "Content-Type": "application/json" },
    body: JSON.stringify({ grant_type: "authorization_code", code })
  });
  const d = await r.json();
  if (d.code !== 0) throw new Error(`获取user_token失败: ${JSON.stringify(d)}`);
  return d.data;
}

async function getRepoPublicKey() {
  const r = await fetch(`https://api.github.com/repos/${GITHUB_REPO}/actions/secrets/public-key`, {
    headers: {
      "Authorization": `Bearer ${GITHUB_TOKEN}`,
      "X-GitHub-Api-Version": "2022-11-28"
    }
  });
  const d = await r.json();
  if (!d.key) throw new Error(`获取GitHub公钥失败: ${JSON.stringify(d)}`);
  return d;
}

async function updateSecret(name, value, keyData) {
  const pk = new Uint8Array(Buffer.from(keyData.key, 'base64'));
  const encrypted = sealedBox(value, pk);
  const r = await fetch(`https://api.github.com/repos/${GITHUB_REPO}/actions/secrets/${name}`, {
    method: "PUT",
    headers: {
      "Authorization": `Bearer ${GITHUB_TOKEN}`,
      "X-GitHub-Api-Version": "2022-11-28",
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      encrypted_value: encrypted.toString('base64'),
      key_id: keyData.key_id
    })
  });
  if (r.status !== 201 && r.status !== 204) {
    const t = await r.text();
    throw new Error(`更新Secret ${name} 失败(${r.status}): ${t}`);
  }
}

export default async function handler(req, res) {
  const { code, error } = req.query || {};

  if (error) {
    res.status(400).send(`飞书授权拒绝: ${error}`);
    return;
  }
  if (!code) {
    res.status(400).send('缺少 code 参数');
    return;
  }

  try {
    const appToken = await getAppToken();
    const tokenData = await getUserToken(code, appToken);
    const keyData = await getRepoPublicKey();
    await updateSecret("FEISHU_USER_TOKEN", tokenData.access_token, keyData);
    await updateSecret("FEISHU_REFRESH_TOKEN", tokenData.refresh_token, keyData);

    res.setHeader("Content-Type", "text/html; charset=utf-8");
    res.send(`<!DOCTYPE html>
<html lang="zh-CN">
<head><meta charset="UTF-8"><title>授权成功</title>
<style>
  body{font-family:sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;background:#0d0f14;color:#e8eaf2}
  .box{text-align:center;padding:48px 56px;background:#141720;border-radius:16px;border:1px solid rgba(255,255,255,0.07)}
  h2{color:#43d9a4;font-size:26px;margin-bottom:12px}
  p{color:#6b7280;font-size:14px;margin:6px 0}
</style>
</head>
<body>
  <div class="box">
    <h2>✅ 授权成功</h2>
    <p>飞书 Token 已写入，系统将在下次运行时生效。</p>
    <p>可以关闭此页面了。</p>
  </div>
</body>
</html>`);
  } catch (e) {
    res.status(500).send(`授权失败: ${e.message}`);
  }
}
