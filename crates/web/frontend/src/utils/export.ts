/** Table export — CSV/XLSX/JSON, all client-side (`Blob` + `<a download>`), no CDN
 * libraries (the CSP blocks external scripts). Ported from the design artifact's own
 * export feature (round 9) — see `discovery-design-artifact` memory for the numeric-
 * sniffing bug found and fixed there: only genuine `typeof v === 'number'` values become
 * numeric cells, so IP addresses (`10.44.20.5`) and MACs never get mis-parsed as
 * truncated numbers.
 *
 * `rows` is always an array of flat `{ column label -> cell value }` objects — each page
 * builds this from its own current (filtered) data right before calling one of these.
 */
export type ExportRow = Record<string, string | number | boolean | null>

function downloadBlob(filename: string, blob: Blob) {
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  a.remove()
  URL.revokeObjectURL(url)
}

function csvCell(value: ExportRow[string]): string {
  const s = value === null ? '' : String(value)
  return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s
}

export function exportCsv(filename: string, rows: ExportRow[]) {
  if (rows.length === 0) {
    downloadBlob(filename, new Blob(['﻿'], { type: 'text/csv;charset=utf-8' }))
    return
  }
  const columns = Object.keys(rows[0])
  const lines = [columns.join(','), ...rows.map((row) => columns.map((c) => csvCell(row[c])).join(','))]
  // Leading BOM — Excel on Windows otherwise mis-detects encoding for Cyrillic text.
  downloadBlob(filename, new Blob(['﻿' + lines.join('\r\n')], { type: 'text/csv;charset=utf-8' }))
}

export function exportJson(filename: string, rows: ExportRow[]) {
  downloadBlob(filename, new Blob([JSON.stringify(rows, null, 2)], { type: 'application/json' }))
}

/** Direct user request 2026-08-28: export/import for a profile's metrics/alerts and a
 * discovery config's subnets (for copying into another profile/config) — arbitrary JSON,
 * not the flat `ExportRow[]` shape the table exports above are built for. */
export function downloadJsonValue(filename: string, data: unknown) {
  downloadBlob(filename, new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' }))
}

/** Reads a user-picked `.json` file (from an `<input type="file">`'s `onChange`) and
 * parses it — throws (caller's job to catch/toast) if it isn't valid JSON. */
export async function readJsonFile(file: File): Promise<unknown> {
  return JSON.parse(await file.text())
}

/** Base64-encodes a user-picked file's raw bytes for `AttachmentUploadBody.data_base64`
 * (2026-08-29, direct user request: "вложения к комментариям тревог: файл/изображение/
 * видео") — chunked `String.fromCharCode` rather than one giant call, which blows the
 * argument-count limit on anything past a few MB. */
export async function fileToBase64(file: File): Promise<string> {
  const bytes = new Uint8Array(await file.arrayBuffer())
  const CHUNK = 0x8000
  let binary = ''
  for (let i = 0; i < bytes.length; i += CHUNK) {
    binary += String.fromCharCode(...bytes.subarray(i, i + CHUNK))
  }
  return btoa(binary)
}

// ---- XLSX: minimal hand-built OOXML package, store-only ZIP (no compression needed) ----

const CRC_TABLE = (() => {
  const table = new Uint32Array(256)
  for (let n = 0; n < 256; n++) {
    let c = n
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1
    table[n] = c >>> 0
  }
  return table
})()

function crc32(bytes: Uint8Array): number {
  let crc = 0xffffffff
  for (let i = 0; i < bytes.length; i++) crc = CRC_TABLE[(crc ^ bytes[i]) & 0xff] ^ (crc >>> 8)
  return (crc ^ 0xffffffff) >>> 0
}

class ByteWriter {
  private chunks: Uint8Array[] = []
  private len = 0
  private push(bytes: Uint8Array) {
    this.chunks.push(bytes)
    this.len += bytes.length
  }
  u16(v: number) {
    this.push(new Uint8Array([v & 0xff, (v >>> 8) & 0xff]))
  }
  u32(v: number) {
    this.push(new Uint8Array([v & 0xff, (v >>> 8) & 0xff, (v >>> 16) & 0xff, (v >>> 24) & 0xff]))
  }
  bytes(b: Uint8Array) {
    this.push(b)
  }
  utf8(s: string) {
    this.push(new TextEncoder().encode(s))
  }
  get length() {
    return this.len
  }
  toUint8Array(): Uint8Array {
    const out = new Uint8Array(this.len)
    let offset = 0
    for (const c of this.chunks) {
      out.set(c, offset)
      offset += c.length
    }
    return out
  }
}

/** One uncompressed ("stored") entry in the resulting ZIP. */
function buildZip(files: { name: string; data: string }[]): Uint8Array {
  const encoder = new TextEncoder()
  const local = new ByteWriter()
  const central = new ByteWriter()
  const offsets: number[] = []
  const encodedFiles = files.map((f) => ({ name: f.name, bytes: encoder.encode(f.data) }))

  for (const file of encodedFiles) {
    offsets.push(local.length)
    const crc = crc32(file.bytes)
    const nameBytes = encoder.encode(file.name)

    local.u32(0x04034b50) // local file header signature
    local.u16(20) // version needed
    local.u16(0) // flags
    local.u16(0) // compression: store
    local.u16(0) // mod time
    local.u16(0) // mod date
    local.u32(crc)
    local.u32(file.bytes.length) // compressed size == uncompressed (store)
    local.u32(file.bytes.length)
    local.u16(nameBytes.length)
    local.u16(0) // extra length
    local.bytes(nameBytes)
    local.bytes(file.bytes)
  }

  let centralSize = 0
  for (let i = 0; i < encodedFiles.length; i++) {
    const file = encodedFiles[i]
    const crc = crc32(file.bytes)
    const nameBytes = encoder.encode(file.name)
    const startLen = central.length

    central.u32(0x02014b50) // central directory header signature
    central.u16(20) // version made by
    central.u16(20) // version needed
    central.u16(0) // flags
    central.u16(0) // compression
    central.u16(0) // mod time
    central.u16(0) // mod date
    central.u32(crc)
    central.u32(file.bytes.length)
    central.u32(file.bytes.length)
    central.u16(nameBytes.length)
    central.u16(0) // extra length
    central.u16(0) // comment length
    central.u16(0) // disk number start
    central.u16(0) // internal attrs
    central.u32(0) // external attrs
    central.u32(offsets[i]) // offset of local header
    central.bytes(nameBytes)

    centralSize += central.length - startLen
  }

  const centralOffset = local.length
  const end = new ByteWriter()
  end.u32(0x06054b50) // end of central directory signature
  end.u16(0) // disk number
  end.u16(0) // disk with central directory
  end.u16(encodedFiles.length) // entries on this disk
  end.u16(encodedFiles.length) // total entries
  end.u32(centralSize)
  end.u32(centralOffset)
  end.u16(0) // comment length

  const out = new Uint8Array(local.length + centralSize + end.length)
  out.set(local.toUint8Array(), 0)
  out.set(central.toUint8Array(), local.length)
  out.set(end.toUint8Array(), local.length + centralSize)
  return out
}

function xmlEscape(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;')
}

function colLetter(index: number): string {
  let n = index + 1
  let s = ''
  while (n > 0) {
    const rem = (n - 1) % 26
    s = String.fromCharCode(65 + rem) + s
    n = Math.floor((n - 1) / 26)
  }
  return s
}

function sheetXml(columns: string[], rows: ExportRow[]): string {
  const headerRow = `<row r="1">${columns.map((c, i) => `<c r="${colLetter(i)}1" t="inlineStr"><is><t>${xmlEscape(c)}</t></is></c>`).join('')}</row>`
  const dataRows = rows
    .map((row, r) => {
      const cells = columns
        .map((c, i) => {
          const ref = `${colLetter(i)}${r + 2}`
          const value = row[c]
          if (typeof value === 'number' && Number.isFinite(value)) {
            return `<c r="${ref}"><v>${value}</v></c>`
          }
          const text = value === null ? '' : String(value)
          return `<c r="${ref}" t="inlineStr"><is><t>${xmlEscape(text)}</t></is></c>`
        })
        .join('')
      return `<row r="${r + 2}">${cells}</row>`
    })
    .join('')
  return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>${headerRow}${dataRows}</sheetData></worksheet>`
}

export function exportXlsx(filename: string, rows: ExportRow[]) {
  const columns = rows.length > 0 ? Object.keys(rows[0]) : []
  const contentTypes = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/></Types>`
  const rootRels = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>`
  const workbook = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="Export" sheetId="1" r:id="rId1"/></sheets></workbook>`
  const workbookRels = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/></Relationships>`

  const zip = buildZip([
    { name: '[Content_Types].xml', data: contentTypes },
    { name: '_rels/.rels', data: rootRels },
    { name: 'xl/workbook.xml', data: workbook },
    { name: 'xl/_rels/workbook.xml.rels', data: workbookRels },
    { name: 'xl/worksheets/sheet1.xml', data: sheetXml(columns, rows) },
  ])

  // `Uint8Array`'s `buffer` is typed `ArrayBufferLike` (includes `SharedArrayBuffer`) in
  // recent TS DOM lib defs, which `BlobPart` rejects even though a real `Uint8Array` is
  // always a valid `Blob` constructor argument at runtime — hence the cast, not a real
  // type hazard (this array was never backed by a `SharedArrayBuffer`, see `buildZip`).
  downloadBlob(filename, new Blob([zip as BlobPart], { type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' }))
}
