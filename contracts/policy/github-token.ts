// Keep this structural check local. Installation tokens are opaque to clients.
const fineGrained = 'github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}';
const opaque = 'gh(?:[our]_[A-Za-z0-9]{36,255}|s_[A-Za-z0-9]{36})';
const stateless = 'ghs_[A-Za-z0-9]{1,32}_[A-Za-z0-9_-]{8,512}\\.[A-Za-z0-9_-]{8,4096}\\.[A-Za-z0-9_-]{16,1024}(?!\\.[A-Za-z0-9_-])';
const tokenCharacter = '[\\p{L}\\p{N}\\p{M}\\p{Pc}-]';
const githubToken = new RegExp(`(?<!${tokenCharacter})(?:${fineGrained}|${stateless}|${opaque})(?!${tokenCharacter})`, 'u');
const allGithubTokens = new RegExp(githubToken.source, 'gu');

export function containsGithubToken(text: string) {
  return githubToken.test(text);
}

export function redactGithubTokens(text: string, replacement: string) {
  return text.replaceAll(allGithubTokens, replacement);
}
