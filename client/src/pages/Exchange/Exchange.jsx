import React, { useEffect, useState } from 'react';
import HeaderDashboard from '../../Dashboards/Dashboard/HeaderDashboard/HeaderDashboard';
import Sidebar from '../../Dashboards/Sidebar/Sidebar';
import CryptoCard1 from '../../Dashboards/Dashboard/CryptoCard/CryptoCard1';
import TradeCard from '../../Dashboards/Dashboard/TradeCard/TradeCard';
import { jwtDecode } from 'jwt-decode';
import InvestToday from '../../Dashboards/Dashboard/InvestToday/InvestToday';

const Exchange = () => {
  const [userId, setUserId] = useState(null);
  const [userName, setUserName] = useState("User");

  useEffect(() => {
    const storedToken = localStorage.getItem('token') || sessionStorage.getItem('token');

    if (storedToken) {
      try {
        const decodedToken = jwtDecode(storedToken);
        setUserId(decodedToken.id);
        setUserName(decodedToken.name);
        console.log("🔍 Logged-in User ID:", decodedToken.id);
      } catch (error) {
        console.error("❌ Error decoding token:", error);
      }
    } else {
      console.error("🚨 No token found! Login again.");
    }
  }, []);

  return (
    <div style={{ backgroundColor: '#131720' }}>
      <HeaderDashboard
        logoSrc="./images/logo.png"
        bellIconSrc="/path/to/bell-icon.png"
        userName={userName} 
      />
      <Sidebar />
      <div style={{ marginLeft: '20%', padding: '10px' }}>
        <CryptoCard1 />
        <div style={{ 
          display: 'flex',
          alignItems: 'flex-start',
          marginTop: '20px'
        }}>
          <div style={{ flex: 1 }}>
            {userId ? <TradeCard userId={userId} /> : <p>Loading user data...</p>}
          </div>
          <div style={{ flex: 1 }}>
            <InvestToday />
          </div>
        </div>
      </div>
    </div>
  );
};

export default Exchange;
