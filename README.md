#  Insecure "Sender Rewriting Scheme" (SRS) implementation in Exim

# Summary:
Many exim instances acting as forwarders could be turned into open relays due to an unsafe implementation of "Sender Rewriting Scheme" (SRS).

# Initial Requirements:

- Understanding of SMTP
- Understanding of SPF / DMARC / DKIM
- Sender Rewriting Scheme SRS is a mechanism to allow Mail Transfer Agents (MTA) to forward emails without breaking SPF.

## Overview of Sender Policy Framework (SPF): 
SPF ensures that a server can use the domain set in the "Envelope From". The main benefit is for the actual owner of the domain who may receive unsolicited bounce emails.

What happens when the "Enveloppe From" address is empty (=> for bounce emails) ? Then the EHLO/HELO domain is used for the SPF check.

One issue with SPF is that it can get broken with email forwarders. The goal of SRS is to bypass SPF when a bounce email is sent back to a forwarder.


# Overview of Sender Rewrite Scheme

Example: 2 corporations communicate via email: corp1.com (Whatever MTA) <-> corp2.com (Exim MTA) -> corp2.net (Whatever MTA)

alice@corp1.com sends an email to bob@corp2.com
corp2.com (Exim MTA) forwards the email to bob@corp2.net. In order to pass the SPF checks on corp2.net, it rewrites the MAIL FROM address (enveloppe from) with SRS: SRS0=HHH=TT=corp1.com=alice@corp2.com. HHH is the SRS hash and TT the timestamp for validity.
The email coming into corp2.net is checked with SPF. Since corp2.com is allowed to use that address, the SPF is validated.
If the email coming into bob@corp2.net bounces, the @corp2.net MTA will send a bounce email to the SRS address (@corp2.com).
corp2.com will check if the SRS address of the bounce message is correct (SRS-validation) and forward the bounce back to the sender's email (alice@corp1.com), with an empty Enveloppe From (since it is a bounce message).
Attack: An external attacker wants to send a forged bounced email to alice@corp1.com, by making it appear to come from corp2.com. By sending a forged bounced email with a poisoned SRS address to corp2.com, the attacker will be able to use the corp2.com's MTA as an open relay and therefore bypass the SPF checks in corp1.com.

-> Effect on DMARC checks

The email would pass the DMARC strict SPF alignment check, which would make it likely for our email to arrive in the victim's mailbox.
If the corp2.com domain has a DMARC "relaxed" policy or a strict SPF alignment policy, then the email would bypass the checks. The email may also pass the strict DKIM alignment policy if corp2 automatically DKIM signs the forwarded emails.
The necessary elements to perform this attack are

The ability to craft a poisoned SRS address. This requires to know the secret used to calculate the SRS hash, or to bruteforce it, or to replay a valid address that was intercepted.
The forwarder's server must accepts SRS addresses for inbound emails from an external IP.
How to craft a poisoned SRS email?

**Issue: The Exim native implementation is weak and prone to bruteforce and replay attacks.** Documentation: https://www.exim.org/exim-html-current/doc/html/spec_html/ch-dkim_spf_srs_and_dmarc.html

Affected versions: 4.95 (experimental before) -> current (4.98.1 at the time of writing)

In Exim, native SRS support can be added by defining SUPPORT_SRS=yes Local/Makefile before the compilation. It seems that some packages enable it by default (ex: OpenSUSE https://github.com/bmwiedemann/openSUSE/blob/master/packages/e/exim/exim.spec), but it does not mean that the Exim's configuration will include SRS.

The SRS implementation is in the expand.c file.

Replay attack: In Exim, when encoding (and decoding) an SRS address, the SRS hash is first calculated from the "Enveloppe from" address, and then the timestamp generated. The SRS specification mentions that "The spammer cannot falsify the timestamp in an SRS address because this would cause a failure of the cryptographic check on the forwarder.". However, this requires the hash to be calculated with the timestamp. -> Therefore Exim's implementation is insecure and could be used to forge bounced mails to an user, by simply changing the timestamp of a valid SRS address. Changing the timestamp won't break the cryptographic check.

Bruteforce attack: hmac_md5(sub[1], srs_recipient, cksum, sizeof(cksum)); if (Ustrncmp(cksum, sub[0] + ovec[2], 4) != 0) -> The SRS address is checked by comparing the first 4 bytes of the supplied hash with the HMAC_MD5 hash of the email local part + the SRS secret.

However, the first 4 bytes of the hmac_md5 hash (=> the SRS hash) are insecurely generated: The character outputted hmac_md5 to build the secure hash are in the range 0123456789abcdef (hex digits). This equals to 16 possible values. 16^4 = 65536 possible hash values which is relatively easy to bruteforce compared with:

4 characters of a base_64 encoded string: 64^4: 16777216.
4 characters of a base_32 encoded string: 32^4: 1048576
 /usr/exim/bin/exim -be '${srs_encode {SRS_SECRET} {test@returnpath.com} {mta.com}}' SRS0=a201=vk=returnpath.com=test@mta.com

"a201" is the SRS hash and "vk" the timestamp.

Note: Could we get the SRS_SECRET with this method, which would make the process even easier ? Technically yes: -> Remotely bruteforce 2 SRS emails to get 2 valid [address:hash] combination and then (locally) bruteforce the hmac_md5 function to get the SRS_SECRET. This would make it easier to forge future SRS emails. However, it would take a lot of time to compute if the SRS_SECRET is very long (or if it changes regularly, but it should not).

What about the second point: "Hope that the forwarder's server accepts SRS inbound address from a controlled IP." ?

This point is greatly dependant on the server's configuration Exim's reference implementation of SRS ( https://www.exim.org/exim-html-current/doc/html/spec_html/ch-dkim_spf_srs_and_dmarc.html) mentions the following config: inbound_srs: driver = redirect senders = : domains = +my_domains # detect inbound bounces which are SRS'd, and decode them condition = ${if inbound_srs {$local_part} {SRS_SECRET}} data = $srs_recipient

The "senders =:" refers to an empty MAIL FROM (bounce emails). This means that only messages with empty "MAIL FROM" will be forwarded. We may therefore guess that many setups are vulnerable to this attack.

## How to fix:

Use 5 or 6 bytes for the SRS hash from the base64 character set (NOT hex values), to have better security.
SRS_ENCODE: Generate the SRS hash with the timestamp
For exim devs: Check if srs_recipient is considered as a tainted variable since it is generated by string_sprintf.

BATV/PRVS validation on the target server
Corp1.com may implement Bounce Address Tag Validation (BATV) (PRVS in Exim) signing for bounced emails, which would render the attack impossible since we would not be able to forge bounced emails from corp2.com.

Unless we can bruteforce a valid PRVS address. In Exim, the PRVS address is composed of the following elements:

US"^prvs\=([0-9])([0-9]{3})([A-F0-9]{6})\=(.+)\@(.+)$", uschar * key_num = string_copyn(expand_nstring[1],expand_nlength[1]); uschar * daystamp = string_copyn(expand_nstring[2],expand_nlength[2]); uschar * hash = string_copyn(expand_nstring[3],expand_nlength[3]);

Key_number: Optional and default to 0
Timestamp when the address was generated: 3 numbers
The hash itself that is hex encoded: 16 possible values and 6 characters
Which means 10 * 10^3 * 16^6 = 167772160000 possible values => It is not likely to bruteforce this hash.
