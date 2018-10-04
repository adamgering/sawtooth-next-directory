# Copyright contributors to Hyperledger Sawtooth
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# -----------------------------------------------------------------------------

import re
import pytest
import unittest
import logging
import sawtooth_signing
from sawtooth_signing.secp256k1 import Secp256k1PrivateKey
from rbac_transaction_creation.common import Key
from tests.transactions.common import PRIVATE_KEY_LENGTH
from tests.transactions.common import PRIVATE_KEY_PATTERN
from tests.transactions.common import PUBLIC_KEY_LENGTH
from tests.transactions.common import PUBLIC_KEY_PATTERN

LOGGER = logging.getLogger(__name__)

@pytest.mark.unit
@pytest.mark.transaction_creation
class TestKeyGenerationAndSigning(unittest.TestCase):

    def test_generate_private_key(self):
        private_key = Secp256k1PrivateKey.new_random()
        self.assertEqual(len(private_key.as_hex()), PRIVATE_KEY_LENGTH)
        self.assertTrue(PRIVATE_KEY_PATTERN.match(private_key.as_hex()))

    def test_gen_private_key_random(self):
        private_key1 = Secp256k1PrivateKey.new_random()
        private_key2 = Secp256k1PrivateKey.new_random()
        self.assertFalse(private_key1.as_hex() == private_key2.as_hex())

    def test_key_class_private_key(self):
        private_key = Secp256k1PrivateKey.new_random()
        txn_key = Key(private_key.as_hex())
        self.assertEqual(len(txn_key.private_key), PRIVATE_KEY_LENGTH)
        self.assertTrue(PRIVATE_KEY_PATTERN.match(txn_key.private_key))
        self.assertEqual(txn_key.private_key, private_key.as_hex())

    def test_key_class_public_key(self):
        private_key = Secp256k1PrivateKey.new_random()
        txn_key = Key(private_key.as_hex())
        self.assertEqual(len(txn_key.public_key), PUBLIC_KEY_LENGTH)
        self.assertTrue(PUBLIC_KEY_PATTERN.match(txn_key.public_key))

