import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';
import './UserProfile.scss'; // Create this SCSS file for styling

const UserProfile = () => {
  const [userData, setUserData] = useState(null);
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();

  useEffect(() => {
    const fetchUserData = async () => {
      try {
        const storedUser = JSON.parse(localStorage.getItem('user') || sessionStorage.getItem('user'));
        
        if (!storedUser) {
          navigate('/login');
          return;
        }

        const response = await axios.get(`http://localhost:3001/api/user/${storedUser.email}`, {
          headers: {
            Authorization: `Bearer ${localStorage.getItem('token') || sessionStorage.getItem('token')}`
          }
        });

        setUserData(response.data);
      } catch (error) {
        console.error('Error fetching user data:', error);
        if (error.response?.status === 401) {
          localStorage.clear();
          sessionStorage.clear();
          navigate('/login');
        }
      } finally {
        setLoading(false);
      }
    };

    fetchUserData();
  }, [navigate]);

  const handleLogout = () => {
    localStorage.clear();
    sessionStorage.clear();
    navigate('/login');
  };

  if (loading) {
    return <div className="loading-container">Loading user data...</div>;
  }

  if (!userData) {
    return <div className="error-container">Error loading user data</div>;
  }

  return (
    <div className="user-profile">
      <div className="welcome-message">
        Welcome, <span className="user-name">{userData.name}</span>
      </div>
      <button onClick={handleLogout} className="logout-button">
        Log Out
      </button>
    </div>
  );
};

export default UserProfile;