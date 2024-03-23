import { assert, describe, expect, it } from 'vitest'
import * as whoiser from '../src/index'

describe.only('#whoiser.tld()', () => {
  describe('rejections', async () => {
    it('should reject for undefined tld', () => {
      expect(() => whoiser.tld()).rejects.toThrow('TLD "undefined" not found')
    })

    it('should reject for invalid TLD format', async () => {
	  expect(() => whoiser.tld('-abc')).rejects.toThrow('TLD "-abc" not found')
    })

    it('should reject for non-existing TLD', async () => {
      expect(() => whoiser.tld('thistldshouldntexist')).rejects.toThrow('TLD "thistldshouldntexist" not found')
    })
  })

  describe('data for top level domain', () => {
    it('should return WHOIS for "com"', async () => {
      const whois = await whoiser.tld('com')
      assert.equal(whois.domain, 'COM', 'TLD doesn\'t match')
      assert.equal(whois.whois, 'whois.verisign-grs.com', 'WHOIS server doesn\'t match')
    })

    it('should return WHOIS for "google"', async () => {
      const whois = await whoiser.tld('blog.google')
      assert.equal(whois.domain, 'GOOGLE', 'TLD doesn\'t match')
      assert.equal(whois.whois, 'whois.nic.google', 'WHOIS server doesn\'t match')
    })

    it('should return WHOIS for "analytics" (no whois server)', async () => {
      const whois = await whoiser.tld('analytics')
      assert.equal(whois.whois, 'whois.nic.analytics', 'WHOIS server doesn\'t match')
      assert.equal(whois.domain, 'ANALYTICS', 'TLD doesn\'t match')
      assert.equal(whois.created, '2015-11-20', 'Created date doesn\'t match')
    })

    it('should return WHOIS for ".香港" - IDN', async () => {
      const whois = await whoiser.base('.香港')
      assert.equal(whois.domain, '香港', 'TLD doesn\'t match')
      assert.equal(whois.whois, 'whois.hkirc.hk', 'WHOIS server doesn\'t match')
    })
  })

  describe('data for second level domain', () => {
    it('should return WHOIS for "com.au"', async () => {
      const whois = await whoiser.tld('com.au')
      assert.equal(whois.domain, 'AU', 'TLD doesn\'t match')
      assert.equal(whois.whois, 'whois.auda.org.au', 'WHOIS server doesn\'t match')
    })

    it('should return same WHOIS for "uk", "co.uk" and "google.co.uk"', async () => {
      const whois1 = await whoiser.tld('uk')
      const whois2 = await whoiser.tld('co.uk')
      const whois3 = await whoiser.tld('google.co.uk')

      assert.equal(whois1.whois, 'whois.nic.uk', 'WHOIS server doesn\'t match')
      assert.equal(whois2.whois, 'whois.nic.uk', 'WHOIS server doesn\'t match')
      assert.equal(whois3.whois, 'whois.nic.uk', 'WHOIS server doesn\'t match')
    })
  })
})
