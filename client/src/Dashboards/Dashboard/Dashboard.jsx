import React, { useState, useEffect } from 'react';
import HeaderDashboard from '../Dashboard/HeaderDashboard/HeaderDashboard';
import Sidebar from '../Sidebar/Sidebar';
import MonthlyGrowth from './MonthlyGrowth/MonthlyGrowth';
import RecentTransactions from './RecentTransactions/RecentTransactions';
import CryptoCards from './CardCrypto/CryptoCards'; 
import BalanceDonut from './BalanceDonut/BalanceDonut';

const userData = [
  { name: 'Bitcoin', percentage: 40, valueInUSD: 25000, amount: 0.5 },
  { name: 'Ethereum', percentage: 30, valueInUSD: 15000, amount: 10 },
  { name: 'Binance Coin', percentage: 20, valueInUSD: 5000, amount: 12 },
  { name: 'Others', percentage: 10, valueInUSD: 2500, amount: 20 },
];


const DashboardLayout = () => {
  const [userName, setUserName] = useState('');

  useEffect(() => {
    const loggedInUser = JSON.parse(localStorage.getItem('user'));
    if (loggedInUser && loggedInUser.name) {
      setUserName(loggedInUser.name);
    }
  }, []);

  return (
    <div style={{backgroundColor: '#131720'}}>
      <HeaderDashboard
        logoSrc="./images/logo.png"
        bellIconSrc="/path/to/bell-icon.png"
        userName="User"
      />
      <Sidebar />
      <div style={{
        display: "flex",
        flexWrap: "wrap",
        gridTemplateColumns: "1fr 1fr",
        marginLeft: "21%",
        marginTop: "20px",
        
      }}>
    <div>
      <BalanceDonut data={userData} />
    </div>
        <div style={{
          position:'absolute',
          marginLeft:'34%',
          width: "60%",
      }}>
        <MonthlyGrowth />
        </div>
        <CryptoCards />
        <RecentTransactions />

        </div>
      </div>
    
  );
};

export default DashboardLayout;
