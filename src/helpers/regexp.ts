function escapeRegExp(input: string) {
  return input.replace(/[-/\\^$*+?.()|[\]{}]/g, '\\$&')
}

function validateEmail(input: string) {
  const regex = /[\w-.]+@[\w-]+[.][\w-]+([.][\w-]+)?/
  return regex.test(input)
}

const email = /(.+)@(.+){2,}\.(.+){2,}/

export { email, escapeRegExp, validateEmail }
