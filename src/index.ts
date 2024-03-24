import net from 'node:net'
import dns from 'node:dns/promises'
import punycode from '@tahul/punycode'
import type socks from 'socks'
import { SocksClient } from 'socks'
import { parseDomainWhois, parseSimpleWhois } from './parsers'
import { isDomain, isTld, requestGetBody, splitStringBy } from './utils'

export interface Options {
  /**
   * WHOIS server to query.
   */
  host?: string

  port?: number

  /**
   * WHOIS server request timeout in ms.
   *
   * @default: 1500
   */
  timeout?: number

  /**
   * How many WHOIS server to query.
   * 1 = registry server (faster),
   * 2 = registry + registrar (more domain details).
   *
   * @default: 2
   */
  follow?: number

  /**
   * Return the raw WHOIS result in response.
   * Added to `__raw`
   */
  raw?: boolean

  domainTld?: string

  domainName?: string

  query?: string

  /**
   * Low level end of query suffix.
   *
   * @default '\r\n'
   */
  querySuffix?: string

  /**
   * Ignore the protected WHOIS data from response
   * and eplace them with empty values
   * @default true
   */
  ignorePrivacy?: boolean

  /**
   * Proxy options for SOCKS5 proxy
   */
  proxyOptions?: socks.SocksProxy
}

export type OptionsIp = Pick<Options, 'host' | 'timeout' | 'raw' | 'follow'>
export type OptionsAsn = OptionsIp
export type OptionsQuery = Omit<Options, 'raw' | 'follow'>
export type OptionsTld = Pick<Options, 'timeout' | 'raw' | 'proxyOptions' | 'domainTld' | 'domainName'>
export type OptionsDomain = Omit<Options, 'querySuffix' | 'query' | 'port'>
export type OptionsGeneric = OptionsIp | OptionsTld | OptionsDomain

export interface WhoisSearchResult {
  [key: string]: string | Array<string> | WhoisSearchResult
}

// Cache WHOIS servers
// Basic list of servers, more will be auto-discovered
const cacheTldWhoisServer: Record<string, string> = {
  com: 'whois.verisign-grs.com',
  net: 'whois.verisign-grs.com',
  org: 'whois.pir.org',

  // ccTLDs
  ai: 'whois.nic.ai',
  au: 'whois.auda.org.au',
  co: 'whois.nic.co',
  ca: 'whois.cira.ca',
  do: 'whois.nic.do',
  eu: 'whois.eu',
  gl: 'whois.nic.gl',
  in: 'whois.registry.in',
  io: 'whois.nic.io',
  it: 'whois.nic.it',
  me: 'whois.nic.me',
  ro: 'whois.rotld.ro',
  rs: 'whois.rnids.rs',
  so: 'whois.nic.so',
  us: 'whois.nic.us',
  ws: 'whois.website.ws',

  agency: 'whois.nic.agency',
  app: 'whois.nic.google',
  biz: 'whois.nic.biz',
  country: 'whois.uniregistry.net', // hardcoded because `whois.iana.org` sometimes returns 'whois.uniregistry.net' or 'whois.nic.country'
  dev: 'whois.nic.google',
  house: 'whois.nic.house',
  health: 'whois.nic.health',
  info: 'whois.nic.info',
  link: 'whois.uniregistry.net',
  live: 'whois.nic.live',
  nyc: 'whois.nic.nyc',
  one: 'whois.nic.one',
  online: 'whois.nic.online',
  shop: 'whois.nic.shop',
  site: 'whois.nic.site',
  xyz: 'whois.nic.xyz',
} as const

// misspelled whois servers..
const misspelledWhoisServer = {
  // 'whois.google.com': 'whois.nic.google',	// Why was this added??
  'www.gandi.net/whois': 'whois.gandi.net',
  'who.godaddy.com/': 'whois.godaddy.com',
  'whois.godaddy.com/': 'whois.godaddy.com',
  'www.nic.ru/whois/en/': 'whois.nic.ru',
  'www.whois.corporatedomains.com': 'whois.corporatedomains.com',
  'www.safenames.net/DomainNames/WhoisSearch.aspx': 'whois.safenames.net',
  'WWW.GNAME.COM/WHOIS': 'whois.gname.com',
} as const

export function whoisQuery({ host = undefined, port = 43, timeout = 15000, query = '', querySuffix = '\r\n', proxyOptions = undefined }: Options = {}) {
  return new Promise((resolve, reject) => {
    let data = ''

    function addSocketEvents(socket: any) {
      socket.setTimeout(timeout)
      socket.on('data', (chunk: any) => (data += chunk))
      socket.on('close', () => resolve(data))
      socket.on('timeout', () => socket.destroy(new Error('Timeout')))
      socket.on('error', reject)
    }

    const socket = proxyOptions
      ? SocksClient.createConnection(
        {
          proxy: proxyOptions,
          command: 'connect',
          destination: {
            host: host as string,
            port,
          },
        },
        (err, info) => {
          if (err) { reject(err) }
          else {
            addSocketEvents(info?.socket)
            if (info)
              info.socket.write(query + querySuffix)
          }
        },
			  )
      : net.connect({ host, port }, () => {
        	addSocketEvents(socket)
        	;(socket as any).write(query + querySuffix)
      })
  })
}

export async function allTlds() {
  const tlds = await requestGetBody('https://data.iana.org/TLD/tlds-alpha-by-domain.txt') as string

  return tlds.split('\n').filter(tld => Boolean(tld) && !tld.startsWith('#'))
}

async function whoisTldAlternate(query?: string): Promise<WhoisSearchResult> {
  const [whoisCname, whoisSrv]: any[] = await Promise.allSettled([
    // Check sources for whois server
    dns.resolveCname(`${query}.whois-servers.net`), // Queries public database for whois server
    dns.resolveSrv(`_nicname._tcp.${query}`), // Queries for whois server published by registry
  ])

  return whoisSrv?.value?.[0]?.name ?? whoisCname?.value?.[0] // Get whois server from results
}

export async function whoisTld(
  query?: string,
  { timeout = 15000, raw = false, domainTld = '', proxyOptions = undefined }: OptionsTld = {},
): Promise<WhoisSearchResult> {
  const result = await whoisQuery({ host: 'whois.iana.org', query, timeout, proxyOptions })
  const data = parseSimpleWhois(result as any)

  if (raw)
    data.__raw = result

  // if no whois server found, search in more sources
  if (!data.whois) {
    // todo
    // instead of using `domainTld`, split `query` in domain parts and request info for all tld combinations
    // example: query="example.com.tld" make 3 requests for "example.com.tld" / "com.tld" / "tld"

    const whois = await whoisTldAlternate(domainTld || query)

    if (whois) {
      data.whois = whois
      data.domain = data.domain || whois
    }
  }

  if (!data.domain && !data.whois)
    throw new Error(`TLD "${query}" not found`)

  return data
}

async function whoisDomain(
  domain: string,
  { host = undefined, timeout = 15000, follow = 2, raw = false, ignorePrivacy = true, proxyOptions = undefined }: OptionsDomain = {},
): Promise<WhoisSearchResult> {
  domain = punycode.toASCII(domain)
  const [domainName, domainTld] = splitStringBy(domain.toLowerCase(), domain.lastIndexOf('.'))
  const results: Record<string, string> = {}

  // find WHOIS server in cache
  if (!host && cacheTldWhoisServer[domainTld])
    host = cacheTldWhoisServer[domainTld]

  // find WHOIS server for TLD
  if (!host) {
    const tld = await whoisTld(
      domain,
      {
        timeout,
        domainName,
        domainTld,
        proxyOptions,
	  },
    )

    if (!tld.whois)
      throw new Error(`TLD for "${domain}" not supported`)

    host = tld.whois as string
    cacheTldWhoisServer[domainTld] = tld.whois as string
  }

  // query WHOIS servers for data
  while (host && follow) {
    let query = domain
    let result
    let resultRaw

    // hardcoded WHOIS queries..
    if (host === 'whois.denic.de')
      query = `-T dn ${punycode.toUnicode(domain)}`

    else if (host === 'whois.jprs.jp')
      query = `${query}/e`

    try {
      resultRaw = await whoisQuery({ host, query, timeout, proxyOptions })
      result = parseDomainWhois(domain, resultRaw as any, ignorePrivacy)
    }
    catch (err: any) {
      result = { error: err?.message }
    }

    if (raw)
      result.__raw = resultRaw

    results[host] = result

    follow--

    // check for next WHOIS server
    let nextWhoisServer
			= result['Registrar WHOIS Server']
			|| result['Registry WHOIS Server']
			|| result.ReferralServer
			|| result['Registrar Whois']
			|| result['Whois Server']
			|| result['WHOIS Server']
			|| false

    // fill in WHOIS servers when missing
    if (!nextWhoisServer && result['Registrar URL'] && result['Registrar URL'].includes('domains.google'))
      nextWhoisServer = 'whois.google.com'

    if (nextWhoisServer) {
      // if found, remove protocol and path
      if (nextWhoisServer.includes('://')) {
        const parsedUrl = new URL(nextWhoisServer)
        // todo use parsedUrl.port, if defined
        nextWhoisServer = parsedUrl.hostname
      }

      // check if found server is in misspelled list
      nextWhoisServer = misspelledWhoisServer[nextWhoisServer as keyof typeof misspelledWhoisServer] || nextWhoisServer

      // check if found server was queried already
      nextWhoisServer = !results[nextWhoisServer] ? nextWhoisServer : false
    }

    host = nextWhoisServer
  }

  return results
}

async function whoisIpOrAsn(
  query: string | number,
  { host = undefined, timeout = 15000, follow = 2, raw = false }: OptionsAsn = {},
): Promise<WhoisSearchResult> {
  const type = net.isIP(query?.toString() || query as string) ? 'ip' : 'asn'
  query = String(query)

  // find WHOIS server for IP
  if (!host) {
    const whoisResult = await whoisQuery({ host: 'whois.iana.org', query, timeout })
    const parsedWhoisResult = parseSimpleWhois(whoisResult as any)
    if (parsedWhoisResult.whois)
      host = parsedWhoisResult.whois
  }

  if (!host)
    throw new Error(`No WHOIS server for "${query}"`)

  let data

  while (host && follow) {
    let modifiedQuery = query

    // hardcoded custom queries..
    if (host === 'whois.arin.net' && type === 'ip')
      modifiedQuery = `+ n ${query}`

    else if (host === 'whois.arin.net' && type === 'asn')
      modifiedQuery = `+ a ${query}`

    const rawResult = await whoisQuery({ host, query: modifiedQuery, timeout })
    data = parseSimpleWhois(rawResult as any)

    if (raw)
      data.__raw = rawResult

    follow--
    host = data?.ReferralServer?.split('//')?.[1]
  }

  return data
}

export function firstResult(whoisResults: any) {
  const whoisServers = Object.keys(whoisResults)

  return whoisServers.length ? whoisResults[whoisServers[0]] : null
}

export function base(query: string, options?: OptionsGeneric): Promise<WhoisSearchResult> {
  if (net.isIP(query) || /^(as)?\d+$/i.test(query))
    return whoisIpOrAsn(query, options)

  else if (isTld(query))
    return whoisTld(query, options as any)

  else if (isDomain(query))
    return whoisDomain(query, options)

  throw new Error('Unrecognized query. Try a domain (google.com), IP (1.1.1.1) or TLD (.blog)')
}

export const query = whoisQuery
export const tld = whoisTld
export const domain = whoisDomain
export const asn = whoisIpOrAsn
export const ip = whoisIpOrAsn
