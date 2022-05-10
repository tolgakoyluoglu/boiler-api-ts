function uuidv4(): string {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function (c) {
    const r = (Math.random() * 16) | 0
    const v = c === 'x' ? r : (r & 0x3) | 0x8
    return v.toString(16)
  })
}

function typeOf(input: any): string {
  let type = typeof input

  if (Array.isArray(input)) {
    type = 'array' as any
  }

  return type
}

export { uuidv4, typeOf }
