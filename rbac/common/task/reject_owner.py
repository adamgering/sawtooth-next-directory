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

import logging
from rbac.common import addresser
from rbac.common import protobuf
from rbac.common.crypto.keys import Key
from rbac.common.manager.base_message import BaseMessage

LOGGER = logging.getLogger(__name__)


class RejectAddTaskOwner(BaseMessage):
    def __init__(self):
        BaseMessage.__init__(self)

    @property
    def name(self):
        return "proposal"

    @property
    def message_type(self):
        return protobuf.rbac_payload_pb2.RBACPayload.REJECT_ADD_TASK_OWNERS

    @property
    def message_proto(self):
        return protobuf.task_transaction_pb2.RejectAddTaskOwner

    @property
    def container_proto(self):
        return protobuf.proposal_state_pb2.ProposalsContainer

    @property
    def state_proto(self):
        return protobuf.proposal_state_pb2.Proposal

    def address(self, object_id, target_id):
        """Make the blockchain address for the given message"""
        return addresser.proposal.address(object_id=object_id, target_id=target_id)

    # pylint: disable=arguments-differ, not-callable
    def make(self, proposal_id, task_id, user_id, reason=None, metadata=None):
        """Make the message"""
        return self.message_proto(
            proposal_id=proposal_id, task_id=task_id, user_id=user_id, reason=reason
        )

    def make_addresses(self, message, signer_keypair):
        """Makes the appropriate inputs & output addresses for the message"""
        if not isinstance(message, self.message_proto):
            raise TypeError("Expected message to be {}".format(self.message_proto))
        if not isinstance(signer_keypair, Key):
            raise TypeError("Expected signer_keypair to be provided")

        # should be owner not admin
        signer_admin_address = addresser.task.admin.address(
            message.task_id, signer_keypair.public_key
        )
        signer_owner_address = addresser.task.owner.address(
            message.task_id, signer_keypair.public_key
        )

        proposal_address = self.address(
            object_id=message.task_id, target_id=message.user_id
        )

        inputs = [signer_admin_address, signer_owner_address, proposal_address]
        outputs = [proposal_address]

        return inputs, outputs
