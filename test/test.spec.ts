import { assert, describe, it } from 'vitest'
import * as whoiser from '../src/index'

describe('whoiser', () => {
  describe('#whoiser()', () => {
    it('should return TLD WHOIS for "blog"', async () => {
      const whois = await whoiser.base('blog')
      assert.equal(whois.domain, 'BLOG', 'TLD doesn\'t match')
    })

    it('should return domain WHOIS for "google.com"', async () => {
      const whois = await whoiser.base('google.com')
      assert.equal(whois['whois.verisign-grs.com']['Domain Name'], 'GOOGLE.COM', 'Domain name doesn\'t match')
      assert.equal(whois['whois.verisign-grs.com']['Registry Domain ID'], '2138514_DOMAIN_COM-VRSN', 'Registry Domain ID doesn\'t match')

      for (const whoisServer in whois) {
        assert(Object.keys(whois[whoisServer]).includes('Expiry Date'), 'Whois result doesn\'t have "Expiry Date"')
      }
    })

    it('should return IP WHOIS for "1.1.1.1"', async () => {
      const whois = await whoiser.base('1.1.1.1')
      assert.equal(whois.range, '1.1.1.0 - 1.1.1.255', 'IP Range doesn\'t match')
      assert.equal(whois.route, '1.1.1.0/24', 'IP Route doesn\'t match')
    })

    it('should return AS WHOIS for "15169"', async () => {
      const whois = await whoiser.base('15169')
      assert.equal(whois.ASName, 'GOOGLE', 'AS Name doesn\'t match')
    })

    it('should reject for unrecognised query "-abc"', () => {
      assert.throws(() => whoiser.base('-abc'), Error)
    })
  })

  describe('#whoiser.asn()', () => {
    it('should return WHOIS for "15169"', async () => {
      const whois = await whoiser.asn(15169)
      assert.equal(whois.ASNumber, '15169', 'AS Number doesn\'t match')
      assert.equal(whois.ASName, 'GOOGLE', 'AS Name doesn\'t match')
    })

    it('should return WHOIS for "AS13335"', async () => {
      const whois = await whoiser.asn('AS13335')
      assert.equal(whois.ASNumber, '13335', 'AS Number doesn\'t match')
      assert.equal(whois.ASName, 'CLOUDFLARENET', 'AS Name doesn\'t match')
    })
  })

  describe('#whoiser.ip()', () => {
    it('should return WHOIS for "8.8.8.8"', async () => {
      const whois = await whoiser.ip('8.8.8.8')
      assert.equal(whois.range, '8.8.8.0 - 8.8.8.255', 'IP Range doesn\'t match')
      assert.equal(whois.route, '8.8.8.0/24', 'IP Route doesn\'t match')
    })

    it('should return WHOIS for "2606:4700:4700::1111"', async () => {
      const whois = await whoiser.ip('2606:4700:4700::1111')
      assert.equal(whois.range, '2606:4700:: - 2606:4700:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF', 'IP Range doesn\'t match')
      assert.equal(whois.route, '2606:4700::/32', 'IP Route doesn\'t match')
    })
  })
})
