import struct

from sgx_structs._sgx_struct import SgxStruct


class SgxAttributes(SgxStruct):
    """
    Provide a wrapper around sgx_attributes_t
    typedef struct _attributes_t
    {
        uint64_t flags; /* 0 */
        uint64_t xfrm;  /* 8 */
    } sgx_attributes_t;
    See: https://01.org/sites/default/files/documentation/
                intel_sgx_sdk_developer_reference_for_linux_os_pdf.pdf
    """

    STRUCT_SIZE = 16

    _format = '<QQ'

    def __init__(self, flags=0, xfrm=0):
        """Initialize SgxAttributes object
        Args:
            flags (int): Bitmask representing SGX flags
            xfrm (int):  Bitmask representing which states are saved
        """
        self.flags = flags
        self.xfrm = xfrm

    def __str__(self):
        return \
            'SGX_ATTRIBUTES: flags={}, xfrm={}'.format(self.flags, self.xfrm)

    def serialize_to_bytes(self):
        """Serializes a object representing an SGX structure to bytes
        laid out in its corresponding C/C++ format.
        NOTE: All integer struct fields are serialized to little endian
            format
        Returns:
            bytes: The C/C++ representation of the object as a struct
        """

        return struct.pack(self._format, self.flags, self.xfrm)

    def parse_from_bytes(self, raw_buffer):
        """Parses a byte array and creates the Sgx* object corresponding
        to the C/C++ struct.
        NOTE: All integer struct fields are parsed as little endian
            format
        Args:
            raw_buffer (bytes): A byte array representing the corresponding
                C/C++ struct used to parse into the object
        Returns:
            None
        Raises:
            TypeError: raw_buffer is not a byte array (aka, bytes)
            ValueError: raw_buffer is not a valid C/C++ struct layout
        """

        try:
            (self.flags, self.xfrm) = struct.unpack(self._format, raw_buffer)
        except struct.error as se:
            raise ValueError('Unable to parse: {}'.format(se))
