import { Fragment, type ReactNode } from "react";

interface SafeMarkdownProps {
  markdown: string;
}

const inlineTokenPattern =
  /(\[[^\]\n]{1,160}\]\([^\s)\n]{1,512}\)|`[^`\n]{1,200}`|\*\*[^*\n]{1,200}\*\*|\*[^*\n]{1,200}\*)/gu;

export function SafeMarkdown({
  markdown,
}: SafeMarkdownProps): React.JSX.Element {
  const lines = markdown.replaceAll("\r\n", "\n").split("\n");
  const blocks: ReactNode[] = [];
  let list: string[] = [];

  function flushList(): void {
    if (list.length === 0) return;
    const items = list;
    list = [];
    const occurrences = new Map<string, number>();
    blocks.push(
      <ul key={`list-${blocks.length}`}>
        {items.map((item) => {
          const occurrence = occurrences.get(item) ?? 0;
          occurrences.set(item, occurrence + 1);
          return <li key={`${item}:${occurrence}`}>{renderInline(item)}</li>;
        })}
      </ul>,
    );
  }

  for (const line of lines) {
    const listItem = /^\s*[-*]\s+(.+)$/u.exec(line);
    if (listItem?.[1]) {
      list.push(listItem[1]);
      continue;
    }
    flushList();
    if (line.trim() === "") {
      continue;
    }
    const heading = /^(#{1,3})\s+(.+)$/u.exec(line);
    if (heading?.[2]) {
      blocks.push(
        <strong className="safe-markdown__heading" key={`h-${blocks.length}`}>
          {renderInline(heading[2])}
        </strong>,
      );
      continue;
    }
    blocks.push(<p key={`p-${blocks.length}`}>{renderInline(line)}</p>);
  }
  flushList();

  return <div className="safe-markdown">{blocks}</div>;
}

function renderInline(line: string): ReactNode[] {
  const nodes: ReactNode[] = [];
  let cursor = 0;
  for (const match of line.matchAll(inlineTokenPattern)) {
    const token = match[0];
    const index = match.index;
    if (index > cursor) nodes.push(line.slice(cursor, index));
    nodes.push(renderToken(token, nodes.length));
    cursor = index + token.length;
  }
  if (cursor < line.length) nodes.push(line.slice(cursor));
  return nodes;
}

function renderToken(token: string, key: number): ReactNode {
  if (token.startsWith("`")) {
    return <code key={key}>{token.slice(1, -1)}</code>;
  }
  if (token.startsWith("**")) {
    return <strong key={key}>{token.slice(2, -2)}</strong>;
  }
  if (token.startsWith("*")) {
    return <em key={key}>{token.slice(1, -1)}</em>;
  }
  const link = /^\[([^\]]+)\]\(([^)]+)\)$/u.exec(token);
  if (!link?.[1] || !link[2]) return <Fragment key={key}>{token}</Fragment>;
  const href = safeLink(link[2]);
  return href ? (
    <a href={href} key={key} rel="nofollow noopener noreferrer" target="_blank">
      {link[1]}
    </a>
  ) : (
    <Fragment key={key}>{link[1]}</Fragment>
  );
}

function safeLink(value: string): string | null {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    return null;
  }
  return parsed.protocol === "https:" || parsed.protocol === "http:"
    ? parsed.href
    : null;
}
