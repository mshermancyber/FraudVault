// ── Docker sandbox image builder ────────────────────────────────────────────
//
// Ensures the `scanboy-sandbox:latest` Docker image exists. The image must be
// pre-built via `docker compose --profile build-only build scanboy-sandbox`.
// If neither scanboy-sandbox nor REMnux is available, the service fails loudly
// rather than silently degrading with a crippled fallback image.

import { execFile } from 'node:child_process';

const IMAGE_TAG = 'latest';

const REMNUX_IMAGE = `remnux/remnux-distro:${IMAGE_TAG}`;
const SCANBOY_IMAGE = `scanboy-sandbox:${IMAGE_TAG}`;

let resolvedImage: string | null = null;

function dockerExec(args: readonly string[], timeoutMs: number = 300_000): Promise<string> {
  return new Promise<string>((resolve, reject) => {
    execFile(
      'docker',
      args as string[],
      { timeout: timeoutMs, maxBuffer: 50 * 1024 * 1024 },
      (error, stdout, stderr) => {
        if (error) {
          const msg = stderr ? stderr.trim() : error.message;
          reject(new Error(`docker ${args[0] ?? ''} failed: ${msg}`));
          return;
        }
        resolve(stdout);
      },
    );
  });
}

async function imageExists(imageName: string): Promise<boolean> {
  try {
    const output = await dockerExec(['image', 'inspect', imageName]);
    return output.trim().startsWith('[');
  } catch {
    return false;
  }
}

/**
 * Ensure a sandbox Docker image exists.
 * Priority: 1) scanboy-sandbox (pre-built from Dockerfile.sandbox), 2) REMnux distro
 * Fails hard if neither is available — no silent fallback to a crippled image.
 */
export async function ensureSandboxImage(): Promise<string> {
  if (resolvedImage) return resolvedImage;

  if (await imageExists(SCANBOY_IMAGE)) {
    resolvedImage = SCANBOY_IMAGE;
    return resolvedImage;
  }

  if (await imageExists(REMNUX_IMAGE)) {
    resolvedImage = REMNUX_IMAGE;
    return resolvedImage;
  }

  throw new Error(
    'No sandbox image found. Build it first: docker compose --profile build-only build scanboy-sandbox',
  );
}

export function getImageName(): string {
  return resolvedImage ?? SCANBOY_IMAGE;
}
