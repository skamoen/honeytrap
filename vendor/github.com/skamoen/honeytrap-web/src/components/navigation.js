import React, { Component } from 'react';
import { Link, NavLink } from 'react-router-dom';

class Navigation extends Component {
    render() {
        return (
            <ul className="nav nav-pills nav-stacked">
                <li className="nav-header">Dashboard</li>
                <li>
                <NavLink activeClassName="active" to="/">Overview</NavLink>
                </li>
                <li className="nav-header">Events</li>
                <li>
                <NavLink activeClassName="active" to="/events">Overview</NavLink>
                </li>
                <li className="nav-header">Setup</li>
                <li>
                <NavLink activeClassName="active" to="/configuration/">Instructions</NavLink>
                </li>
            </ul>
        );
    }
}

export default Navigation;
