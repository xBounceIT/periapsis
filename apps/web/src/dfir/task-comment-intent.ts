const uuidV7Pattern =
  /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;

export function parseTaskCommentIntent(
  input: string,
  root: "Alert" | "Case",
): string[] {
  const ids = input
    .split(/[\r\n,]+/u)
    .map((value) => value.trim())
    .filter(Boolean);
  if (ids.length > 1_000) {
    throw new Error(`${root} tasks support at most 1000 comment links.`);
  }
  if (ids.some((id) => !uuidV7Pattern.test(id))) {
    throw new Error(`Use one canonical UUIDv7 comment ID per line.`);
  }
  if (new Set(ids).size !== ids.length) {
    throw new Error(`Each ${root} task comment link must be unique.`);
  }
  return ids.toSorted();
}
