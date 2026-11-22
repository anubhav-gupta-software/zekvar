export const fixtureApp = 'local-prompt-fixture';
export const chatGptApp = 'chatgpt';
export const geminiApp = 'gemini';
export const claudeApp = 'claude';
export const aiPromptApps = [chatGptApp, claudeApp, geminiApp] as const;
export const promptAppLabels = { [fixtureApp]: 'Local prompt fixture', [chatGptApp]: 'ChatGPT', [claudeApp]: 'Claude', [geminiApp]: 'Gemini' };
export type AiPromptApp = typeof aiPromptApps[number];
export type AppId = typeof fixtureApp | AiPromptApp;

export function isPromptApp(value: unknown): value is AppId {
  return value === fixtureApp || value === chatGptApp || value === claudeApp || value === geminiApp;
}
