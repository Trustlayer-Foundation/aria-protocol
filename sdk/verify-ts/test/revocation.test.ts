import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { checkRevocation } from '../src/revocation';
import { RevocationCheckError } from '../src/errors';

describe('checkRevocation', () => {
  const originalFetch = globalThis.fetch;

  afterEach(() => {
    globalThis.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  it('returns active status for valid DID', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ status: 'active', did: 'did:aria:example.com:test-agent' }),
    }) as unknown as typeof fetch;

    const result = await checkRevocation('did:aria:example.com:test-agent');

    expect(result.did).toBe('did:aria:example.com:test-agent');
    expect(result.status).toBe('active');
    expect(result.checkedAt).toBeDefined();
  });

  it('returns revoked status', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ status: 'revoked' }),
    }) as unknown as typeof fetch;

    const result = await checkRevocation('did:aria:example.com:revoked-agent');

    expect(result.status).toBe('revoked');
  });

  it('throws RevocationCheckError on HTTP error', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 404,
      statusText: 'Not Found',
    }) as unknown as typeof fetch;

    await expect(
      checkRevocation('did:aria:example.com:unknown-agent'),
    ).rejects.toThrow(RevocationCheckError);
  });

  it('throws RevocationCheckError on network failure', async () => {
    globalThis.fetch = vi.fn().mockRejectedValue(
      new Error('Network error'),
    ) as unknown as typeof fetch;

    await expect(
      checkRevocation('did:aria:example.com:test-agent'),
    ).rejects.toThrow(RevocationCheckError);
  });

  it('uses custom API URL', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ status: 'active' }),
    }) as unknown as typeof fetch;

    await checkRevocation('did:aria:example.com:test-agent', {
      apiUrl: 'https://custom-api.example.com',
    });

    expect(globalThis.fetch).toHaveBeenCalledWith(
      expect.stringContaining('https://custom-api.example.com/v1/verify/'),
      expect.any(Object),
    );
  });
});
