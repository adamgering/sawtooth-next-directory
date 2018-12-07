# Copyright 2018 Contributors to Hyperledger Sawtooth
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
"""User Test Helper"""
# pylint: disable=no-member,too-few-public-methods,invalid-name

import logging

from tests.rbac.common.user.create_user_helper import CreateUserTestHelper
from tests.rbac.common.user.propose_manager_helper import ProposeManagerTestHelper

LOGGER = logging.getLogger(__name__)


class UserManangerTestHelper:
    """User Manager Test Helper"""

    def __init__(self):
        self.propose = ProposeManagerTestHelper()


class UserTestHelper:
    """User Test Helper"""

    def __init__(self):
        """User Test Helper"""
        self.create_user = CreateUserTestHelper()
        self.manager = UserManangerTestHelper()

    def id(self):
        """Returns a random unique identifier"""
        return self.create_user.id()

    def key(self):
        """Returns a random keypair"""
        return self.create_user.key()

    def name(self):
        """Returns a random name"""
        return self.create_user.name()

    def username(self):
        """Returns a random username"""
        return self.create_user.username()

    def email(self):
        """Get a random email"""
        return self.create_user.email()

    def reason(self):
        """Returns a random reason"""
        return self.create_user.reason()

    def message(self):
        """Return a create user message"""
        return self.create_user.message()

    def message_with_manager(self):
        """Return a create user message with manager"""
        return self.create_user.message_with_manager()

    def create(self):
        """Create a test user"""
        return self.create_user.create()

    def create_with_manager(self):
        """Create a test user and their manager"""
        return self.create_user.create_with_manager()

    def create_with_grand_manager(self):
        """Create a test user with their manager and their manager's manager"""
        return self.create_user.create_with_grand_manager()
