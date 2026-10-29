.. _ansible_collections.cohesity.dataprotect.docsite.guide_faq:

Frequently Asked Questions
==========================

Do the modules support Active Directory based Cohesity accounts?
-----------------------------------------------------------------

Yes. You can configure domain specific credentials in the following formats:

* ``username@AD.domain.com``: AD user
* ``AD.domain.com/username@tenant``: AD tenant user
* ``LOCAL/username@tenant``: local tenant user
* ``Domain/username``: will be deprecated in a future release

What privileges does the Active Directory based account require?
-----------------------------------------------------------------

The Active Directory account must have administrator level privileges on the cluster.
