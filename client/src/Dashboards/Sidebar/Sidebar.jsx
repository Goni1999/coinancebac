import React from 'react';
import { useNavigate } from 'react-router-dom';
import './Sidebar.scss';

const Sidebar = () => {
  const navigate = useNavigate();

  const handleRedirect = (path) => {
    navigate(path);
  };

  return (
    <div className="sidebar">
      <ul className="sidebar-menu">
        <li
          className="sidebar-item"
          onClick={() => handleRedirect('/dashboard')}
        >
          <img src="/images/dashboard.png" alt="Dashboard Icon" className="sidebar-icon" />
          Dashboard
        </li>
        <li
          className="sidebar-item"
          onClick={() => handleRedirect('/exchange')}
        >
          <img src="/images/exchange.png" alt="Exchange Icon" className="sidebar-icon" />
          Exchange
        </li>
        <li
          className="sidebar-item"
          onClick={() => handleRedirect('/prices')}
        >
          <img src="/images/prices.png" alt="Prices Icon" className="sidebar-icon" />
          Prices
        </li>
        <li
          className="sidebar-item"
          onClick={() => handleRedirect('/activities')}
        >
          <img src="/images/activities.png" alt="Activities Icon" className="sidebar-icon" />
          Activities
        </li>
        <li
          className="sidebar-item-2"
          onClick={() => handleRedirect('/')}
        >
          Sign Out
        </li>
      </ul>
    </div>
  );
};

export default Sidebar;
