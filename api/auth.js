export default function handler(req, res) {
  const APP_ID = process.env.FEISHU_APP_ID;
  const REDIRECT_URI = encodeURIComponent(process.env.REDIRECT_URI);
  const scope = encodeURIComponent("wiki:wiki:readonly sheets:spreadsheet:readonly");
  const url = `https://open.feishu.cn/open-apis/authen/v1/authorize?app_id=${APP_ID}&redirect_uri=${REDIRECT_URI}&scope=${scope}`;
  res.redirect(url);
}
