#!/usr/bin/python

from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from binascii import hexlify
import rpm
import os
import struct
import sys
from pprint import pprint
from enum import IntEnum

"""
IMA helper methods.
"""


# Const enum values copied from imaevm.h:
class EVM_IMA_XATTR_TYPE(IntEnum):
    EVM_IMA_XATTR_DIGSIG = 3


class DIGSIG_VERSION(IntEnum):
    DIGSIG_VERSION_2 = 2


class PKEY_HASH_ALGO(IntEnum):
    PKEY_HASH_SHA256 = 4


def read_keyid(certfile):
    """
    Read the 32-bit key ID from a private key certificate file.

    This method is similar to imaevm_read_keyid() in libimaevm.

    :param str certfile: path to a PEM or DER file to load, for example
                         "privatekey.pem"
    """
    with open(certfile, 'rb') as f:
        contents = f.read()
    try:
        key = serialization.load_pem_private_key(contents, password=None)
    except ValueError:
        key = serialization.load_der_private_key(contents, password=None)
    public_key = key.public_key()
    # The "keyid" (SKID, SubjectKeyIdentifier) is the SHA1 hash of the
    # DER-encoded ASN.1 sequence of the modulus and exponent of an RSA public
    # key. (public_key.public_numbers() "n" and "e").
    public_key_id = x509.SubjectKeyIdentifier.from_public_key(public_key)
    # The IMA signature's "keyid" is the last four bytes of this SHA1 digest.
    ima_keyid = public_key_id.digest[-4:]
    ima_keyid_str = hexlify(ima_keyid).decode('ascii')
    return ima_keyid_str


def read_hdr(rpmfile):
    """
    Return the hdr object for this rpm file.

    :param str rpmfile: path to a .rpm file to load, for example
                         "bash-5.1.8-2.el9.src.rpm"
    """
    rpm.addMacro("_dbpath", '/tmp/rpmdb')
    ts = rpm.TransactionSet()
    # The temp rpmdb trusts no GPG signatures, so we have to disable signature
    # checking:
    ts.setVSFlags(rpm._RPMVSF_NOSIGNATURES)
    fd = os.open(rpmfile, os.O_RDONLY)
    hdr = ts.hdrFromFdno(fd)
    os.close(fd)
    return hdr


def parse_filesignature(sighex):
    """ Parse an individual file signature header. """
    sig = bytearray.fromhex(sighex)
    # This is from imaevm.h's signature_v2_hdr struct.
    # Read the 9-byte header for this filesignature:
    info = {
        'type':    sig[0],  # Should be EVM_IMA_XATTR_DIGSIG.
        'version': sig[1],  # Should be DIGSIG_VERSION_2.
        'alg_id':  sig[2],  # Named "hash_algo" in imaevm.h.
        'key_id':  bytes(sig[3:7]),  # Final 32-bits of SKID sha1.
        'sig_size': struct.unpack('>H', sig[7:9])[0],
        'signature': bytes(sig[9:])  # Rest of this sigheader is the signature.
    }
    assert info['type'] == EVM_IMA_XATTR_TYPE.EVM_IMA_XATTR_DIGSIG
    assert info['version'] == DIGSIG_VERSION.DIGSIG_VERSION_2
    assert info['alg_id'] == PKEY_HASH_ALGO.PKEY_HASH_SHA256
    return info


def parse_filesignatures(rpmfile):
    hdr = read_hdr(rpmfile)
    basenames = hdr[rpm.RPMTAG_BASENAMES]
    filesignatures = hdr[rpm.RPMTAG_FILESIGNATURES]

    # Assert all files are file-signed in this RPM.
    assert len(basenames) == len(filesignatures)

    # Parse the individual file signatures.
    result = {}
    for basename, sighex in zip(basenames, filesignatures):
        result[basename] = parse_filesignature(sighex)
    return result


def verify_signatures(rpmfile):
    # XXX: Need to extract files to cwd.
    # TODO: change this to optionally use the FILEDIGESTS headers. See
    # https://rpm-software-management.github.io/rpm/manual/signatures_digests.html
    # and rpm_head_signing/extract_header.py.

    certfile = 'privatekey.pem'  # XXX hardcoded our key here.
    with open(certfile, 'rb') as f:
        contents = f.read()
    private_key = serialization.load_pem_private_key(contents, password=None)
    public_key = private_key.public_key()
    cert_key_id = read_keyid(certfile)

    sigs = parse_filesignatures(rpmfile)
    for file, sig in sigs.items():
        if os.path.exists(file):
            print(file)
            rpm_key_id = hexlify(sig['key_id']).decode('ascii')
            if rpm_key_id != cert_key_id:
                err = f'rpm key id {rpm_key_id} does not match {cert_key_id}'
                raise RuntimeError(err)
            digest = hashes.Hash(hashes.SHA256())
            with open(file, 'rb') as f:
                digest.update(f.read())
            file_digest = digest.finalize()
            print(hexlify(file_digest).decode('ascii'))

            from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
            ret = public_key.verify(
                sig['signature'],
                file_digest,
                padding.PKCS1v15(),
                Prehashed(hashes.SHA256()),
            )
            print(ret)


def main():
    try:
        filename = sys.argv[1]
    except IndexError:
        print(sys.argv[0] + ' <filename>')
        sys.exit(1)

    if filename.endswith('.pem'):
        print(read_keyid(filename))
    if filename.endswith('.rpm'):
        # pprint(parse_filesignatures(filename))
        verify_signatures(filename)


main()
