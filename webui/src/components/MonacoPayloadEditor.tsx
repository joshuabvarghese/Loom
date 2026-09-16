import Editor, { useMonaco } from '@monaco-editor/react'
import { useEffect, useRef, useState } from 'react'
import { fetchMethodSchema } from '../lib/api'
import { registerSchema, unregisterSchema } from '../lib/monacoSchemaRegistry'

interface Props {
  /** Full gRPC method path, e.g. "/user.UserService/GetUser". */
  methodName: string
  /** Which side of the call this payload represents. Defaults to "request". */
  schemaType?: 'request' | 'response'
  value: string
  onChange: (val: string | undefined) => void
  height?: string
  readOnly?: boolean
}

/**
 * A JSON editor for one gRPC method's request/response payload, wired up to
 * Monaco's JSON language service so the schema derived from the backend's
 * live proto descriptors (GET /api/v1/schema) drives real-time validation
 * and autocomplete — undefined fields, wrong types, and missing required
 * fields are flagged before the call ever reaches `replay`.
 *
 * Each instance gets its own synthetic model path so multiple editors (e.g.
 * one per open Replay modal) don't stomp on each other's schemas — see
 * lib/monacoSchemaRegistry.
 */
export default function MonacoPayloadEditor({
  methodName,
  schemaType = 'request',
  value,
  onChange,
  height = '300px',
  readOnly = false,
}: Props) {
  const monaco = useMonaco()
  const [schemaError, setSchemaError] = useState<string | null>(null)
  const [loadingSchema, setLoadingSchema] = useState(true)

  const pathRef = useRef(
    `loom://payload/${encodeURIComponent(methodName)}-${schemaType}-${Math.random().toString(36).slice(2)}.json`,
  )

  useEffect(() => {
    if (!monaco || !methodName) return
    let cancelled = false
    const uri = pathRef.current

    setLoadingSchema(true)
    fetchMethodSchema(methodName, schemaType)
      .then((schema) => {
        if (cancelled) return
        setSchemaError(null)
        registerSchema(monaco, uri, schema)
      })
      .catch((e) => {
        if (cancelled) return
        // Reflection can legitimately fail (server restarted, method not
        // found, reflection disabled) — degrade to a plain JSON editor
        // rather than blocking editing entirely.
        setSchemaError(e instanceof Error ? e.message : String(e))
      })
      .finally(() => {
        if (!cancelled) setLoadingSchema(false)
      })

    return () => {
      cancelled = true
      unregisterSchema(monaco, uri)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [monaco, methodName, schemaType])

  return (
    <div className="monaco-payload-editor">
      <div className="monaco-payload-status">
        {loadingSchema && <span className="monaco-status-loading">Loading schema…</span>}
        {!loadingSchema && !schemaError && <span className="monaco-status-ok">Schema loaded — validating live</span>}
        {schemaError && (
          <span className="monaco-status-warn" title={schemaError}>
            No schema available — editing without validation
          </span>
        )}
      </div>
      <Editor
        height={height}
        defaultLanguage="json"
        theme="vs-dark"
        path={pathRef.current}
        value={value}
        onChange={onChange}
        options={{
          minimap: { enabled: false },
          fontSize: 13,
          readOnly,
          scrollBeyondLastLine: false,
          automaticLayout: true,
          tabSize: 2,
        }}
      />
    </div>
  )
}
