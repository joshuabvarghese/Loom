export interface UIConfig {
  proxyAddr: string
}

/**
 * The original inspector had proxyAddr baked into the server-rendered HTML
 * template. Now that the UI is a static SPA, the backend exposes it here
 * instead so the same `-ui` flag still surfaces in the header.
 */
export async function fetchConfig(): Promise<UIConfig> {
  const res = await fetch('/api/config')
  if (!res.ok) throw new Error(`GET /api/config: ${res.status}`)
  return res.json()
}
