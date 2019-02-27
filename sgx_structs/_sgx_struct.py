from abc import ABCMeta
from abc import abstractmethod


class SgxStruct(metaclass=ABCMeta):
    """SgxStruct defines the base class that all Sgx* structures must
    implement
    """

    @abstractmethod
    def serialize_to_bytes(self):
        """Serializes a object representing an SGX structure to bytes
        laid out in its corresponding C/C++ format.
        NOTE: All integer struct fields are serialized to little endian
            format
        Returns:
            bytes: The C/C++ representation of the object as a struct
        """

    @abstractmethod
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
