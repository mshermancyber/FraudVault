// ── AI Provider Abstraction ─────────────────────────────────────────────────
// Providers receive ONLY analysis artifacts (results, IOCs, technique mappings).
// AI must NEVER receive actual malware samples or binary content.

export interface AIOptions {
  maxTokens?: number;
  temperature?: number;
  systemPrompt?: string;
}

export interface AIProvider {
  readonly name: string;
  isConfigured(): boolean;
  generateCompletion(prompt: string, options?: AIOptions): Promise<string>;
}

// ── Anthropic Provider ──────────────────────────────────────────────────────

export class AnthropicProvider implements AIProvider {
  readonly name = 'anthropic';
  private readonly apiKey: string | undefined;
  private readonly model = 'claude-sonnet-4-6';

  constructor() {
    this.apiKey = process.env['ANTHROPIC_API_KEY'];
  }

  isConfigured(): boolean {
    return typeof this.apiKey === 'string' && this.apiKey.length > 0;
  }

  async generateCompletion(prompt: string, options?: AIOptions): Promise<string> {
    if (!this.isConfigured()) {
      throw new Error('Anthropic API key is not configured');
    }

    // Dynamic import to keep the dependency optional
    const { default: Anthropic } = await import('@anthropic-ai/sdk');

    const client = new Anthropic({ apiKey: this.apiKey });

    const message = await client.messages.create({
      model: this.model,
      max_tokens: options?.maxTokens ?? 2048,
      ...(options?.systemPrompt ? { system: options.systemPrompt } : {}),
      messages: [
        {
          role: 'user',
          content: prompt,
        },
      ],
    });

    const textBlock = message.content.find((block) => block.type === 'text');
    if (!textBlock || textBlock.type !== 'text') {
      throw new Error('No text content in Anthropic response');
    }
    return textBlock.text;
  }
}

// ── OpenAI Provider ─────────────────────────────────────────────────────────

export class OpenAIProvider implements AIProvider {
  readonly name = 'openai';
  private readonly apiKey: string | undefined;
  private readonly model = 'gpt-4o';

  constructor() {
    this.apiKey = process.env['OPENAI_API_KEY'];
  }

  isConfigured(): boolean {
    return typeof this.apiKey === 'string' && this.apiKey.length > 0;
  }

  async generateCompletion(prompt: string, options?: AIOptions): Promise<string> {
    if (!this.isConfigured()) {
      throw new Error('OpenAI API key is not configured');
    }

    // Dynamic import to keep the dependency optional
    const { default: OpenAI } = await import('openai');

    const client = new OpenAI({ apiKey: this.apiKey });

    const messages: Array<{ role: 'system' | 'user'; content: string }> = [];

    if (options?.systemPrompt) {
      messages.push({ role: 'system', content: options.systemPrompt });
    }

    messages.push({ role: 'user', content: prompt });

    const response = await client.chat.completions.create({
      model: this.model,
      max_tokens: options?.maxTokens ?? 2048,
      temperature: options?.temperature ?? 0.3,
      messages,
    });

    const choice = response.choices[0];
    if (!choice?.message?.content) {
      throw new Error('No content in OpenAI response');
    }
    return choice.message.content;
  }
}

// ── OpenAI-Compatible Provider (Ollama, LM Studio, vLLM, etc.) ─────────────

export class OpenAICompatibleProvider implements AIProvider {
  readonly name: string;
  private readonly baseUrl: string | undefined;
  private readonly apiKey: string;
  private readonly model: string;

  constructor() {
    const rawUrl = process.env['OPENAI_COMPATIBLE_URL'];
    if (rawUrl) {
      try {
        const parsed = new URL(rawUrl);
        if (parsed.protocol === 'http:' || parsed.protocol === 'https:') {
          this.baseUrl = rawUrl.replace(/\/+$/, '');
        }
      } catch {
        // Invalid URL — leave baseUrl undefined so isConfigured() returns false.
      }
    }
    this.apiKey = process.env['OPENAI_COMPATIBLE_API_KEY'] ?? 'not-needed';
    this.model = process.env['OPENAI_COMPATIBLE_MODEL'] ?? 'llama3';
    this.name = `openai-compatible:${this.model}`;
  }

  isConfigured(): boolean {
    return typeof this.baseUrl === 'string' && this.baseUrl.length > 0;
  }

  async generateCompletion(prompt: string, options?: AIOptions): Promise<string> {
    if (!this.baseUrl) {
      throw new Error('OpenAI-compatible base URL is not configured');
    }

    const messages: Array<{ role: 'system' | 'user'; content: string }> = [];

    if (options?.systemPrompt) {
      messages.push({ role: 'system', content: options.systemPrompt });
    }
    messages.push({ role: 'user', content: prompt });

    const response = await fetch(`${this.baseUrl}/v1/chat/completions`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${this.apiKey}`,
      },
      body: JSON.stringify({
        model: this.model,
        messages,
        max_tokens: options?.maxTokens ?? 2048,
        temperature: options?.temperature ?? 0.3,
        stream: false,
      }),
    });

    if (!response.ok) {
      const text = await response.text();
      throw new Error(`OpenAI-compatible API error (${response.status}): ${text}`);
    }

    const data = await response.json() as {
      choices?: Array<{ message?: { content?: string } }>;
    };

    const content = data.choices?.[0]?.message?.content;
    if (!content) {
      throw new Error('No content in OpenAI-compatible response');
    }
    return content;
  }
}

// ── Provider Resolution ─────────────────────────────────────────────────────

const providers: AIProvider[] = [
  new OpenAICompatibleProvider(),
  new AnthropicProvider(),
  new OpenAIProvider(),
];

/**
 * Returns the first configured AI provider, or null if none are configured.
 * Provider priority: OpenAI-compatible (Ollama/etc.) > Anthropic > OpenAI.
 */
export function getConfiguredProvider(): AIProvider | null {
  for (const provider of providers) {
    if (provider.isConfigured()) {
      return provider;
    }
  }
  return null;
}

/** Returns all configured providers. */
export function getAllConfiguredProviders(): AIProvider[] {
  return providers.filter((p) => p.isConfigured());
}
