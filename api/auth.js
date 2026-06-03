export default function handler(req, res) {
  const FEISHU_APP_ID = process.env.FEISHU_APP_ID;
  const REDIRECT_URI  = process.env.REDIRECT_URI;
  const scope = "wiki:wiki:readonly sheets:spreadsheet";
  const url = `https://open.feishu.cn/open-apis/authen/v1/authorize?app_id=${FEISHU_APP_ID}&redirect_uri=${encodeURIComponent(REDIRECT_URI)}&scope=${encodeURIComponent(scope)}`;
  res.redirect(url);
}
