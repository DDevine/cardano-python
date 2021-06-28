import base58
import bech32
import re

from .consts import Era


def address(addr, wallet=None):
    if isinstance(addr, Address):
        return addr  # already instatinated and should be of proper class
    elif isinstance(addr, (bytes, bytearray)):
        addr = addr.decode()
    elif not isinstance(addr, str):
        raise TypeError(
            "address() argument must be str, bytes, bytearray or Address instance"
        )
    # validation
    valid = None
    for Klass in (ShelleyAddress, ByronAddress, IcarusAddress):
        try:
            return Klass(addr, wallet=wallet)
        except ValueError:
            pass
    if not valid:
        raise ValueError("String {} is not a valid Cardano address".format(addr))
    return valid


class Address(object):
    """
    Cardano base address class. Does no validation, it is up to child classes.

    Compares with ``str`` and ``bytes`` objects.

    :param addr:    the address as ``str`` or ``bytes`` or ``Address``
    :param wallet:  the ``Wallet`` object if address belongs to
    """

    _address = ""
    wallet = None

    def __init__(self, addr, wallet=None):
        self._address = addr
        self.wallet = wallet or self.wallet
        self._validate()

    def _validate(self):
        pass

    def __repr__(self):
        return str(self._address)

    def __eq__(self, other):
        if isinstance(other, Address):
            return str(self) == str(other)
        elif isinstance(other, str):
            return str(self) == other
        elif isinstance(other, bytes):
            return str(self).encode() == other
        return super(Address, self).__eq__(other)

    def __hash__(self):
        return hash(str(self))

    def __format__(self, spec):
        return format(str(self), spec)


class ByronAddress(Address):
    era = Era.BYRON

    def _validate(self):
        if not self._address.startswith("DdzFF"):
            raise ValueError("{:s} is not a valid Byron address")
        data = base58.b58decode(self._address)

class IcarusAddress(ByronAddress):
    def _validate(self):
        if not self._address.startswith("Ae2"):
            raise ValueError("{:s} is not a valid Icarus/Byron address")
        data = base58.b58decode(self._address)


class ShelleyAddress(Address):
    era = Era.SHELLEY
    _prefix_re = re.compile(r'^(addr|stake)(_test)?')

    def _validate(self):
        if not self._prefix_re.match(self._address):
            raise ValueError("{:s} is not a valid Shelley address")
        addr_prefix, data = bech32.bech32_decode(self._address)
        addr_typ, net_tag = (data[0] & 0xf0) >> 4, data[0] & 0xf
        print(data)
        print(addr_typ, net_tag, addr_prefix)
        #
        # TODO: Perform proper recognition, based on https://github.com/cardano-foundation/CIPs/pull/78
        if addr_typ > 7:
            raise ValueError("Shelley address {:s} is of wrong type ({:x})".format(self._address,
                        addr_typ))
        if net_tag not in (0,1):
            raise ValueError("Shelley address {:s} has unsupported net tag ({:x})".format(self._address, net_tag))
#        if net_tag == 0 and not addr_prefix.endswith("_test"):
#            raise ValueError("Shelley address {:s} has TESTNET tag but the prefix doesn't end with \"_test\"".format(self._address))
#        elif net_tag == 1 and addr_prefix.endswith("_test"):
#            raise ValueError("Shelley address {:s} has MAINNET tag but the prefix ends with \"_test\"".format(self._address))
        #
