import { chatGptApp, chatGptRoute } from './protocol';
import { composerDiagnostics, inspectComposer } from './chatgpt-composer';
import { bindPromptGuard } from './prompt-guard';

bindPromptGuard({ appId: chatGptApp, route: chatGptRoute, inspect: inspectComposer, diagnostics: composerDiagnostics });
