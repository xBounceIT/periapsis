export function isolateTemplatePreview(html: string): string {
  const policy =
    "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; base-uri 'none'; form-action 'none'; img-src data: cid:; font-src data:; style-src 'unsafe-inline'\">";
  const head = /<head(?:\s[^>]*)?>/iu.exec(html);
  if (!head || head.index === undefined) return `${policy}${html}`;
  const insertion = head.index + head[0].length;
  return `${html.slice(0, insertion)}${policy}${html.slice(insertion)}`;
}
