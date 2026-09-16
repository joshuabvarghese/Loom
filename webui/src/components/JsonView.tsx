import { Fragment, type ReactNode } from 'react'

type JSONValue = string | number | boolean | null | JSONValue[] | { [k: string]: JSONValue }

/** Recursively renders a parsed JSON value with the original inspector's
 * key/string/number/bool/null/punctuation color classes. */
function renderValue(val: JSONValue, depth: number): ReactNode {
  const ind1 = '  '.repeat(depth + 1)

  if (val === null) return <span className="json-null">null</span>
  if (val === true) return <span className="json-bool">true</span>
  if (val === false) return <span className="json-bool">false</span>
  if (typeof val === 'number') return <span className="json-num">{val}</span>
  if (typeof val === 'string') return <span className="json-str">{JSON.stringify(val)}</span>

  if (Array.isArray(val)) {
    if (val.length === 0) return <span className="json-punc">[]</span>
    return (
      <>
        <span className="json-punc">[</span>
        {'\n'}
        {val.map((v, i) => (
          <Fragment key={i}>
            {ind1}
            {renderValue(v, depth + 1)}
            {i < val.length - 1 && <span className="json-punc">,</span>}
            {'\n'}
          </Fragment>
        ))}
        {'  '.repeat(depth)}
        <span className="json-punc">]</span>
      </>
    )
  }

  const keys = Object.keys(val)
  if (keys.length === 0) return <span className="json-punc">{'{}'}</span>
  return (
    <>
      <span className="json-punc">{'{'}</span>
      {'\n'}
      {keys.map((k, i) => (
        <Fragment key={k}>
          {ind1}
          <span className="json-key">{JSON.stringify(k)}</span>
          <span className="json-punc">: </span>
          {renderValue(val[k], depth + 1)}
          {i < keys.length - 1 && <span className="json-punc">,</span>}
          {'\n'}
        </Fragment>
      ))}
      {'  '.repeat(depth)}
      <span className="json-punc">{'}'}</span>
    </>
  )
}

export default function JsonView({ json }: { json: string }) {
  let parsed: JSONValue
  try {
    parsed = JSON.parse(json)
  } catch {
    return <pre className="code">{json}</pre>
  }
  return <pre className="code">{renderValue(parsed, 0)}</pre>
}
