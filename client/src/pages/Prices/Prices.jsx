import React from 'react';
import HeaderDashboard from '../../Dashboards/Dashboard/HeaderDashboard/HeaderDashboard';
import Sidebar from '../../Dashboards/Sidebar/Sidebar';
import CryptoCards from '../../Dashboards/Dashboard/CardCrypto/CryptoCards';
import CryptoTable from '../../Dashboards/Dashboard/CryptoTable/CryptoTable';

const Prices = () => {
  return (
    <div>
    <HeaderDashboard
      logoSrc="./images/logo.png"
      bellIconSrc="/path/to/bell-icon.png"
      userName="User"
    />
    <Sidebar />
    <div style={{ marginLeft: '20%', padding: '0px' }}>
        <CryptoCards />
        <CryptoTable />
    </div>
    </div>
  )
}

export default Prices;