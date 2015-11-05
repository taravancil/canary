# Canary
Canary is an application for posting and tracking ["warrant canary"]()-like statements.

From [canarywatch.org](https://canarywatch.org):
> A warrant canary is a colloquial term for a regularly published statement that a service provider has not received legal process (like a national security letter) that it would be prohibited from disclosing to the public. Once a service provider does receive legal process, the speech prohibition goes into place, and the provider no longer makes the statement about the number of such process received.

Governments can compel silence by issuing gag orders, but in the United States, at least, it's much more difficult to compel speech, especially compelled *false* speech. For example, if a service provider receives a national security letter (which comes with a gag order), the government can't force the organization to post a false statement that it hasn't received any national security letters.

## Cryptographic Verification
Canary requires statements to be signed with PGP or GPG. Before a recurring statement is published, the publisher must decrypt a challenge encrypted to the same key with which the message was signed.

## Motivation
Canary hopes to make it easier for individuals, companies, and organizations to publish and manage cryptographically-verified canaries. Likewise, canary was developed with the aim of simplifying sharing and tracking canaries.

This is a work in progress, and I don't yet know if I will host canary myself, or if I will encourage organizations to host their own instance. I welcome feedback as I make this decision!

Yes, I know about [https://github.com/firstlook/autocanary](AutoCanary). I didn't learn of its existence until I was knee deep in development, but I do plan to make changes so that canary and AutoCanary can be used in tandem!

Canary does a lot (verifies canaries, sends republish reminders, tracks canary history, and more), but AutoCanary fills a glaring hole in how Canary works. AutoCanary is a desktop application that helps individuals easily *generate* signed canaries. Canary requires users to be confident signing and decrypting GPG messages as well as managing GPG keys. For many people, that's an unrealistic expectation. Autocanary makes this process much more manageable, so integrating AutoCanary, along with making the user experience seamless for users of varying levels of familiarity with GPG, is a top priority.

## Disclaimer
This is a work in progress. Please do not use Canary for purposes other than development and experimentation. I take no responsibilty for the outcome of using a premature version of Canary.

