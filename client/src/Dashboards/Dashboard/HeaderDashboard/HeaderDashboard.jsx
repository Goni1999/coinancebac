import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';
import './HeaderDashboard.scss';

const HeaderDashboard = ({ logoSrc, bellIconSrc, token }) => {
  const navigate = useNavigate();
  const [userName, setUserName] = useState('');

  useEffect(() => {
    // 🔹 Try getting the user name from localStorage first
    const storedUser = JSON.parse(localStorage.getItem('user') || sessionStorage.getItem('user'));
    console.log("Stored User from localStorage:", storedUser);

    if (storedUser && storedUser.name) {
      setUserName(storedUser.name);
      return; // No need to fetch from backend
    }

    // 🔹 If name is missing, fetch from backend using token
    const fetchUserName = async () => {
      try {
        const storedToken = token || localStorage.getItem('token');
        if (!storedToken) {
          console.error("No token found.");
          return;
        }

        const response = await axios.post(
          'http://localhost:3001/getUserName',
          {},
          { headers: { Authorization: `Bearer ${storedToken}` } }
        );

        console.log("Fetched User Name:", response.data.name);
        setUserName(response.data.name);

      } catch (error) {
        console.error('Error fetching user name:', error.response?.data || error.message);
      }
    };

    fetchUserName();
  }, [token]); // 🔹 Ensure useEffect runs when `token` changes

  const handleRedirect = (path) => {
    navigate(path);
  };

  return (
    <header className="header-dashboard">
      <div className="header-left">
        {/* Logo on the left */}
        <img
          src={logoSrc}
          alt="Logo"
          className="logo"
          onClick={() => handleRedirect('/')}
        />
        <h2>Capital Trust</h2>
      </div>

      <div className="header-right">
        <button
          className="notification-button"
          onClick={() => handleRedirect('/activities')}
        >
          <img src={ 'images/notifications24.png' || bellIconSrc } alt="Notifications" className="bell-icon" />
        </button>

        {/* Welcome message with dropdown menu */}
        <div className="dropdown">
          <span className="welcome-text">Welcome, {userName || 'User'}!</span>
          <button className="dropdown-button">▼</button>
          <div className="dropdown-menu">
            <button onClick={() => handleRedirect('/')}>Sign Out</button>
          </div>
        </div>
      </div>
    </header>
  );
};

export default HeaderDashboard;
