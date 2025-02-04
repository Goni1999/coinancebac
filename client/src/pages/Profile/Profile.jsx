import React from 'react';
import HeaderDashboard from '../../Dashboards/Dashboard/HeaderDashboard/HeaderDashboard';
import Sidebar from '../../Dashboards/Sidebar/Sidebar';
import './Profile.scss';

const Profile = () => {
  return (
    <div>
    <HeaderDashboard
      logoSrc="./images/Logo.jpg"
      bellIconSrc="/path/to/bell-icon.png"
      userName="User"
    />
    <Sidebar />
    <div style={{ marginLeft: '20%', padding: '0px' }}>
    <div className="profile-card">
      <div className="profile-image-container">
        <img
          src="https://via.placeholder.com/150" // Replace with your user's profile image URL
          alt="Profile"
          className="profile-image"
        />
        <div className="profile-icon">
          <i className="fas fa-camera"></i> {/* Use any icon here */}
        </div>
      </div>
      <div className="profile-info">
        <h2 className="profile-name">John Doe</h2> {/* Replace with dynamic name */}
        <p className="profile-description">
          A passionate web developer who loves building interactive applications.
        </p>
      </div>
    </div>
    </div>
    </div>
  )
}

export default Profile;