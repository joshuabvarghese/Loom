import type { Monaco } from '@monaco-editor/react'

/**
 * Monaco's JSON language service takes its schema list via a single global
 * call — `jsonDefaults.setDiagnosticsOptions({ schemas: [...] })` — that
 * *replaces* the whole list every time it's called. If two
 * <MonacoPayloadEditor/> instances (e.g. a Replay modal open behind a
 * Mutation Rule Builder panel) each naively called `setDiagnosticsOptions`
 * with just their own schema, the second call would silently blow away the
 * first editor's validation.
 *
 * This module keeps a registry of every schema currently in use, keyed by
 * the model URI it applies to, and re-applies the full set on every
 * register/unregister so all live editors keep working regardless of
 * mount/unmount order.
 */

interface SchemaAssociation {
  uri: string
  fileMatch: string[]
  schema: unknown
}

const registry = new Map<string, SchemaAssociation>()

function flush(monaco: Monaco) {
  monaco.languages.json.jsonDefaults.setDiagnosticsOptions({
    validate: true,
    allowComments: false,
    schemas: Array.from(registry.values()),
  })
}

/** Associates `schema` with `uri` (the exact Monaco model path/URI it should apply to) and re-applies the global schema list. */
export function registerSchema(monaco: Monaco, uri: string, schema: unknown): void {
  registry.set(uri, { uri, fileMatch: [uri], schema })
  flush(monaco)
}

/** Removes the schema for `uri` — call this on editor unmount to avoid leaking entries across navigations. */
export function unregisterSchema(monaco: Monaco, uri: string): void {
  if (registry.delete(uri)) flush(monaco)
}
