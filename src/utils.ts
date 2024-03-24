import https from 'node:https'
import punycode from '@tahul/punycode'

export const splitStringBy = (string: string, by: number) => [string.slice(0, by), string.slice(by + 1)]

export function requestGetBody(url: string) {
  return new Promise((resolve, reject) => {
    https
      .get(url, (resp) => {
        let data = ''
        resp.on('data', chunk => (data += chunk))
        resp.on('end', () => resolve(data))
        resp.on('error', reject)
      })
      .on('error', reject)
  })
}

export function isTld(tld: string) {
  if (tld.startsWith('.'))
    tld = tld.substring(1)

  return /^([a-z]{2,64}|xn[a-z0-9-]{5,})$/i.test(punycode.toASCII(tld))
}

export function isDomain(domain: string) {
  if (domain.endsWith('.'))
    domain = domain.substring(0, domain.length - 1)

  const labels = punycode.toASCII(domain).split('.').reverse()
  const labelTest = /^([a-z0-9-]{1,64}|xn[a-z0-9-]{5,})$/i

  return (
    labels.length > 1
    && labels.every((label, index) => {
		  return index ? labelTest.test(label) && !label.startsWith('-') && !label.endsWith('-') : isTld(label)
    })
  )
}
