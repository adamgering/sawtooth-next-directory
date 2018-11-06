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

from rbac.addressing import addresser as legacy
from rbac.common.addresser.address_base import AddressBase
from rbac.common.addresser.address_space import AddressSpace


class UserAddress(AddressBase):
    def __init__(self):
        AddressBase.__init__(self)

    @property
    def address_type(self):
        """The address type from AddressSpace implemented by this class"""
        return AddressSpace.USER

    def address(self, object_id, target_id=None):
        """Makes a blockchain address of this address type"""
        return legacy.make_user_address(user_id=object_id)


user = UserAddress()

__all__ = ["user"]
