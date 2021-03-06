
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


import React from 'react';
import ReactDOM from 'react-dom';
import { Provider } from 'react-redux';
import { BrowserRouter } from 'react-router-dom';
import { shallow } from 'enzyme';

import * as customStore from 'customStore';
import Individual from './Individual';


const store = customStore.create();
const props = {
  location: {},
  isSocketOpen: () => {},
  getOpenProposals: () => { },
  userFromId: () => { },
  openProposals: [''],
};

const newprops = {
  location: {},
  isSocketOpen: () => {},
  getOpenProposals: () => { },
  userFromId: () => { },
  openProposals: [],
};
const wrapper = shallow(<Individual {...props} store={store}/>);


it('renders without crashing', () => {
  const div = document.createElement('div');

  ReactDOM.render(
    <Provider store={store}>
      <BrowserRouter>
        <Individual {...props}/>
      </BrowserRouter>
    </Provider>, div
  );

  ReactDOM.render(
    <Provider store={store}>
      <BrowserRouter>
        <Individual {...newprops}/>
      </BrowserRouter>
    </Provider>, div
  );

  ReactDOM.unmountComponentAtNode(div);
});

it('calls reset function', () => {
  wrapper.dive().instance().reset();
});

it('calls setFlow function', () => {
  wrapper.dive().instance().setFlow();
});
