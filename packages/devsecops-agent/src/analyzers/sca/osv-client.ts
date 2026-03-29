export interface OsvVulnerability {
  id: string;
  summary: string;
  severity?: Array<{ type: string; score: string }>;
  affected: Array<{
    ranges?: Array<{ type: string; events: Array<{ introduced?: string; fixed?: string }> }>;
  }>;
}

export interface OsvResponse {
  vulns?: OsvVulnerability[];
}

export async function queryOsv(packageName: string, version: string): Promise<OsvVulnerability[]> {
  try {
    const response = await fetch('https://api.osv.dev/v1/query', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        package: { name: packageName, ecosystem: 'npm' },
        version,
      }),
      signal: AbortSignal.timeout(5000),
    });

    if (!response.ok) return [];
    const data = (await response.json()) as OsvResponse;
    return data.vulns ?? [];
  } catch {
    return [];
  }
}
