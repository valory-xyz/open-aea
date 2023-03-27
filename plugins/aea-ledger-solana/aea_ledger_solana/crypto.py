import base64
from solders.hash import Hash
import json

from aea.crypto.base import Crypto, FaucetApi, Helper, LedgerApi
from solders.transaction import Transaction

from .constants import _SOLANA
from typing import Any, Dict, Optional, Tuple, cast, Union
from cryptography.fernet import Fernet  # type: ignore
from solders.keypair import Keypair
from aea.common import Address, JSONLike
from pathlib import Path
import base58
import hashlib
from solders.pubkey import Pubkey as PublicKey


class SolanaCrypto(Crypto[Keypair]):
    """Class wrapping the Account Generation from Solana ledger."""

    identifier = _SOLANA

    def __init__(
        self,
        private_key_path: Optional[str] = None,
        password: Optional[str] = None,
        extra_entropy: Union[str, bytes, int] = "",
    ) -> None:
        """
        Instantiate a solana crypto object.

        :param private_key_path: the private key path of the agent
        :param password: the password to encrypt/decrypt the private key.
        :param extra_entropy: add extra randomness to whatever randomness your OS can provide
        """
        super().__init__(
            private_key_path=private_key_path,
            password=password,
            extra_entropy=extra_entropy,
        )

    @property
    def private_key(self) -> str:
        """
        Return a private key.

        64 random hex characters (i.e. 32 bytes) prefix.

        :return: a private key string in hex format
        """
        key = cast(Keypair, self.entity)
        seed = bytes(self.entity.secret())
        private_key = seed + bytes.fromhex(self.public_key)
        return base58.b58encode(private_key).decode()

    @property
    def public_key(self) -> str:
        """
        Return a public key in hex format.

        :return: a public key string in hex format
        """
        return bytes(self.entity.pubkey()).hex()

    @property
    def address(self) -> str:
        """
        Return the address for the key pair.

        :return: an address string in hex format
        """
        return str(self.entity.pubkey())

    @classmethod
    def load_private_key_from_path(
        cls, file_name: str, password: Optional[str] = None
    ) -> Keypair:
        """
        Load a private key in base58 or bytes format from a file.

        :param file_name: the path to the hex file.
        :param password: the password to encrypt/decrypt the private key.
        :return: the Entity.
        """
        key_path = Path(file_name)
        private_key = cls.load(file_name, password)
        try:
            key = Keypair.from_base58_string(private_key)
        except Exception as e:
            raise KeyIsIncorrect(
                f"Error on key `{key_path}` load! : Error: {repr(e)}.{'try password?' if password is None else ''}"
            ) from e

        return key

    def sign_message(self, message: bytes, is_deprecated_mode: bool = False) -> str:
        """
        Sign a message in bytes string form.

        :param message: the message to be signed
        :param is_deprecated_mode: if the deprecated signing is used
        :return: signature of the message in string form
        """
        if is_deprecated_mode:
            raise ValueError("is_deprecated_mode is not supported at the moment")
        keypair = Keypair.from_base58_string(self.private_key)
        signed_msg = keypair.sign_message(message)
        return str(signed_msg)

    def sign_transaction(
        self, transaction: JSONLike, signers: Optional[list] = None
    ) -> JSONLike:
        """
        Sign a transaction in bytes string form.

        :param transaction: the transaction to be signed
        :param signers: list of signers
        :return: signed transaction
        """
        signers = signers or []
        jsonTx = json.dumps(transaction)

        keypair = Keypair.from_base58_string(self.private_key)
        signers = [Keypair.from_base58_string(signer.private_key) for signer in signers]
        signers.append(keypair)
        recent_hash = Hash.from_string(transaction["recentBlockhash"])
        stxn = Transaction.from_json(jsonTx)
        stxn.sign(keypairs=signers, recent_blockhash=recent_hash)
        return json.loads(stxn.to_json())

    @classmethod
    def generate_private_key(
        cls, extra_entropy: Union[str, bytes, int] = ""
    ) -> Keypair:
        """
        Generate a key pair for Solana network.

        :param extra_entropy: add extra randomness to whatever randomness your OS can provide
        :return: keypair object
        """
        if extra_entropy:
            raise ValueError("extra_entropy is not supported at the moment")
        account = Keypair()  # pylint: disable=no-value-for-parameter
        return account

    def encrypt(self, password: str) -> str:
        """
        Encrypt the private key and return in json.

        :param password: the password to decrypt.
        :return: json string containing encrypted private key.
        """
        try:
            pw = str.encode(password)
            hash_object = hashlib.sha256(pw)
            hex_dig = hash_object.digest()
            base64_bytes = base64.b64encode(hex_dig)
            fernet = Fernet(base64_bytes)
            enc_mac = fernet.encrypt(self.private_key.encode())
        except Exception as e:
            raise Exception("Encryption failed") from e

        return json.dumps(enc_mac.decode())

    @classmethod
    def decrypt(cls, keyfile_json: str, password: str) -> str:
        """
        Decrypt the private key and return in raw form.

        :param keyfile_json: json str containing encrypted private key.
        :param password: the password to decrypt.
        :return: the raw private key.
        """
        try:
            keyfile = json.loads(keyfile_json)
            keyfile_bytes = keyfile.encode()
            pw = str.encode(password)
            hash_object = hashlib.sha256(pw)
            hex_dig = hash_object.digest()
            base64_bytes = base64.b64encode(hex_dig)
            fernet = Fernet(base64_bytes)

            dec_mac = fernet.decrypt(keyfile_bytes).decode()
        except ValueError as e:
            raise DecryptError() from e
        return dec_mac