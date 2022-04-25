IMA and RPM in Python
=====================

These are my notes as I investigated IMA signing with RPMs and Python.

What is IMA signing?
--------------------

Useful links:

- https://fedoraproject.org/wiki/Changes/Signed_RPM_Contents
- https://lists.fedorahosted.org/archives/list/devel@lists.fedoraproject.org/thread/ME54KAOC3HXVPQCE7TW6GHXC6JV7GLUS/
- https://rpm-software-management.github.io/rpm/manual/signatures_digests.html
- For a guide to IMA, see the end of this presentation: https://ostconf.com/system/attachments/files/000/001/694/original/Karasev%E2%80%8B_Gerasimov.pdf?1570085327
- SUSE's IMA guidance: https://en.opensuse.org/SDB:Ima_evm
- For an experimental Ansible playbook, see https://github.com/myllynen/rhel-ansible-roles/blob/master/roles/ima_evm_setup/defaults/main.yml

Existing software that deals with IMA signatures:

- https://sourceforge.net/projects/linux-ima/
- https://github.com/fedora-iot/rpm-head-signing/
- https://pagure.io/sigul

How to IMA-sign an RPM package
------------------------------

Note: this only works with the ima-evm-utils 1.4 in CentOS 9 and Rawhide.
Earlier versions were very buggy, writing zeros for signature fields, etc.

::

    # You must install these packages (eg. in a rawhide container):
    yum -y install pinentry openssl rpm-sign

    # Next, we need to generate an RSA private key:
    openssl genpkey -algorithm RSA-PSS -out privatekey.pem

    # Some instructions also state that you need a DER-formatted key. I'm not
    # sure this is true with the latest ima-evm-utils. Regardless, here's how
    # to transform your PEM-formatted key to DER:
    cat privatekey.pem | openssl pkcs8 -topk8 -nocrypt -outform DER -out privatekey.der

    # And here's how to generate a public cert from that private key:
    openssl req -x509 -key privatekey.der -out certificate.pem -days 365 -keyform DER -subj "/CN=Test IMA Keypair"

    # For this test, I'll use a random SRPM from Koji,
    curl -O https://kojipkgs.fedoraproject.org//packages/bash/5.1.8/3.fc36/src/bash-5.1.8-3.fc36.src.rpm

    # Even though we care about IMA signing, not GPG signing, you must specify
    # a GPG key to rpmsign. rpmsign cannot write IMA signatures without also
    # GPG-signing an RPM too. From comments in
    # https://github.com/rpm-software-management/rpm/commit/f558e886050c4e98f6cdde391df679a411b3f62c
    # "While file signing could now be done separately to other signing, that
    # is not handled here."

    # I have already set up a GPG key on my Yubikey, and this works for me:

    rpmsign --addsign --define "_gpg_name 782096AC" --signfiles --fskpath privatekey.pem bash-5.1.8-3.fc36.src.rpm

    # If you don't have a GPG keypair for RPM signing,
    # https://docs.pagure.org/koji/signing/ explains how to do it.
    # Example in a Rawhide container:

    rpmsign --addsign --define "_gpg_name security@example.com" --signfiles --fskpath privatekey.pem bash-5.1.8-3.fc36.src.rpm

Note that rpmsign's ``--fskpath`` requires a PEM-formatted key, not a
DER-formatted one. We should probably add this to RPM's ``rpm-sign(8)``
manpage.


How to inspect IMA signatures on an RPM package
-----------------------------------------------

The CentOS 9 Stream and RHEL 9 teams have enabled IMA signing, so you can
download the latest RPMs there and look at the RPM headers.

You can read the raw signature bytes in the RPM sigheader like so::

    rpm -q --qf '[%{BASENAMES} %{FILESIGNATURES}\n]' -p bash-5.1.8-3.fc36.src.rpm

`RPM's manual
<https://rpm-software-management.github.io/rpm/manual/signatures_digests.html>`_
does not show the ``FILESIGNATURES`` header `yet
<https://github.com/rpm-software-management/rpm-web/issues/28>`_.

IMA identifies keys via "key IDs". These are short (32-bit) values that
correspond to the final bits of a public key's SKID (SubjectKeyIdentifier).

To list the key ID for a private RSA key::

    ./read.py privatekey.pem
    # Prints "b66b9fad".

*(TODO: make this work for EC keys as well as RSA keys.)*

To list the key IDs for IMA signatures in an RPM, extract the contents, then
pass the RPM file to ``read.py``::

    rpm2cpio bash-5.1.8-3.fc36.src.rpm | cpio -dium
    ./read.py bash-5.1.8-3.fc36.src.rpm

*(TODO: make this less hacky/buggy/hard-coded.. see the comments in the
code.)*

How to verify IMA signatures on an RPM package
----------------------------------------------

IMA works by signing a sha256 checksum of a file (note: true for RSA, need to
verify this is true for EC?). You can verify an RPM's IMA signature in a few
ways:

1. Set up an IMA policy on your host, then install some IMA-signed RPMs and
   verify that the kernel allows or denies executing them. This matches how
   normal users will use this system, so it's great for integration testing,
   but of course this is cost-prohibitive. We need utilities to perform IMA
   signature verification without setting up full-blown user environments.
   See `the IMA presentation
   <https://ostconf.com/system/attachments/files/000/001/694/original/Karasev%E2%80%8B_Gerasimov.pdf?1570085327>`_
   for how this works.

2. Install the RPM on your host, then run ``evmctl ima_verify`` on the RPM's
   files. This is a decent integration test, but similar to above, it's
   expensive to install a package just to read and verify the signature bytes.
   The `Fedora Change
   <https://fedoraproject.org/wiki/Changes/Signed_RPM_Contents>`_ documents
   this option.

3. Extract the RPM's files, checksum them directly, and then verify the
   signatures of your calculated checkums. This is "heavy" because you must
   extract every file in the RPM and checksum each one, but it works. This is
   also the method that I used in ``read.py`` so far.

4. Read the sha256 checksums that RPM already stores for each file
   (``FILEDIGESTS``), and verify the signatures of those checksums. This is
   "light" because you're simply trusting RPM's pre-computed checksums.

COPYING
-------

This is under the same license as ``ima-evm-utils``, GPLv2 (see ``COPYING``).
