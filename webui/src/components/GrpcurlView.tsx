import { Fragment } from 'react'

interface Token {
  text: string
  cls?: 'cmd-bin' | 'cmd-flag' | 'cmd-value'
}

/** Tokenizes a grpcurl command line for coloring, mirroring the original
 * inspector's colorGrpcurl() regex passes (binary name, -flags, quoted values). */
function tokenize(cmd: string): Token[] {
  const tokens: Token[] = []
  const re = /(^grpcurl\b)|( -[\w-]+)|('[^']*'|"[^"]*")/g
  let last = 0
  let m: RegExpExecArray | null
  while ((m = re.exec(cmd)) !== null) {
    if (m.index > last) tokens.push({ text: cmd.slice(last, m.index) })
    const cls = m[1] ? 'cmd-bin' : m[2] ? 'cmd-flag' : 'cmd-value'
    tokens.push({ text: m[0], cls })
    last = re.lastIndex
  }
  if (last < cmd.length) tokens.push({ text: cmd.slice(last) })
  return tokens
}

export default function GrpcurlView({ cmd }: { cmd: string }) {
  const tokens = tokenize(cmd)
  return (
    <pre className="grpcurl">
      {tokens.map((t, i) => (
        <Fragment key={i}>{t.cls ? <span className={t.cls}>{t.text}</span> : t.text}</Fragment>
      ))}
    </pre>
  )
}
