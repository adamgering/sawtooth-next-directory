/* Copyright 2019 Contributors to Hyperledger Sawtooth

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
----------------------------------------------------------------------------- */


import React, { Component } from 'react';
import { Checkbox, Segment } from 'semantic-ui-react';
import PropTypes from 'prop-types';
import './RoleList.css';
import Avatar from 'components/layouts/Avatar';
import { Icon } from 'semantic-ui-react';


/**
 *
 * @class         RoleList
 * @description   Displays roles in a list when approving proposals
 *
 */
class RoleList extends Component {

  static propTypes = {
    getRoles:              PropTypes.func,
    getUsers:              PropTypes.func,
    handleChange:          PropTypes.func,
    openProposalsByRole:   PropTypes.object,
    openProposalsByUser:   PropTypes.object,
    roleFromId:            PropTypes.func,
    roles:                 PropTypes.array,
    selectedProposals:     PropTypes.array,
    selectedRoles:         PropTypes.array,
    users:                 PropTypes.array,
  };


  // TODO: Refactor
  /**
   * Entry point to perform tasks required to render
   * component. Get users not loaded in client.
   */
  componentDidMount  () {
    const {
      getRoles,
      getUsers,
      openProposalsByRole,
      openProposalsByUser,
      roles,
      users } = this.props;

    if (!openProposalsByUser) return;
    let collection;
    const newUsers = Object.keys(openProposalsByUser);

    users ?
      collection = newUsers.filter(newUser =>
        !users.find(user => newUser === user.id)) :
      collection = newUsers;

    getUsers(collection);

    const newRoles = Object.keys(openProposalsByRole);
    roles ?
      collection = newRoles.filter(newRole =>
        !roles.find(role => newRole === role.id)) :
      collection = newRoles;

    getRoles(collection);
  }


  /**
   * Called whenever Redux state changes. Get roles and
   * users not loaded in client on state change.
   * @param {object} prevProps Props before update
   * @returns {undefined}
   */
  componentDidUpdate (prevProps) {
    const {
      getRoles,
      getUsers,
      openProposalsByRole,
      openProposalsByUser } = this.props;

    const newRoles = Object.keys(openProposalsByRole);
    const newUsers = Object.keys(openProposalsByUser);
    const oldRoles = Object.keys(prevProps.openProposalsByRole);
    const oldUsers = Object.keys(prevProps.openProposalsByUser);

    if (newUsers.length > oldUsers.length) {
      const diff = newUsers.filter(user => !oldUsers.includes(user));
      getUsers(diff);
    }
    if (newRoles.length > oldRoles.length) {
      const diff = newRoles.filter(role => !oldRoles.includes(role));
      getRoles(diff);
    }
  }


  /**
   * Get role name from role ID
   * @param {string} roleId Role ID
   * @returns {string}
   */
  roleName = (roleId) => {
    const { roleFromId } = this.props;
    const role = roleFromId(roleId);
    return role && role.name;
  };


  /**
   * Render user avatars for a given role
   * @param {string} roleId Role ID
   * @returns {JSX}
   */
  renderUsers (roleId) {
    const { openProposalsByRole } = this.props;
    return (
      <div className='pull-right'>
        { openProposalsByRole[roleId].map((proposal, index) => {
          if (index > 2) return null;
          if (index === 2) {
            return (
              <span
                key={proposal.id}
                className='next-role-list-icon'>
                <Icon
                  color='orange'
                  name='add'
                  size='tiny'/>
                {openProposalsByRole[roleId].length - 2}
              </span>
            );
          }
          return (
            <Avatar
              key={proposal.id}
              userId={proposal.opener}
              size='medium'
              {...this.props}/>
          );
        })}
      </div>
    );
  }


  /**
   * Role item is checked / unchecked based on its presence in
   * selectedRoles state array
   * @param {string} roleId Selected role ID
   * @returns {boolean}
   */
  isRoleChecked = (roleId) => {
    const { selectedRoles } = this.props;
    return selectedRoles.indexOf(roleId) !== -1;
  }


  /**
   * Is checkbox state indeterminate (i.e., should show dot)
   * @param {string} roleId Selected role
   * @returns {boolean}
   */
  // TODO: Indeterminate state not adding class to UI in one scenario
  isIndeterminate = (roleId) => {
    const { selectedProposals, openProposalsByRole } = this.props;
    const selected = openProposalsByRole[roleId].filter(proposal =>
      selectedProposals.includes(proposal.id));

    return selected.length > 0 &&
      selected.length < openProposalsByRole[roleId].length;
  }


  /**
   * Toggle checkbox when segment container clicked
   * @param {string} roleId  Role ID
   */
  handleSegmentClick = (roleId) => {
    const { handleChange } = this.props;
    handleChange(undefined, {
      checked: !this.isRoleChecked(roleId),
      role: roleId,
    });
  }


  /**
   * Render role list item
   * One list item per role with an open request.
   * @param {string} roleId Role ID
   * @returns {JSX}
   */
  renderRoleItem (roleId) {
    const { handleChange } = this.props;
    return (
      <div className='next-role-list-item' key={roleId}>
        <Segment
          className='minimal select cursor-pointer'
          padded
          onClick={() => this.handleSegmentClick(roleId)}>
          <Checkbox
            defaultIndeterminate={this.isIndeterminate(roleId)}
            checked={this.isRoleChecked(roleId)}
            role={roleId}
            label={this.roleName(roleId)}
            onChange={handleChange}/>
          {this.renderUsers(roleId)}
        </Segment>
      </div>
    );
  }


  /**
   * Render entrypoint
   * @returns {JSX}
   */
  render () {
    const { openProposalsByRole } = this.props;
    if (!openProposalsByRole) return null;

    return (
      <div id='next-roles-list-container'>
        { Object.keys(openProposalsByRole).map(roleId => (
          this.renderRoleItem(roleId)
        ))}
      </div>
    );

  }

}


export default RoleList;
