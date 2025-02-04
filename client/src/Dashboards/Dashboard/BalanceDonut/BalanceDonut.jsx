import React, { useEffect, useState } from 'react';
import { Doughnut } from 'react-chartjs-2';
import { jwtDecode } from 'jwt-decode';
import axios from 'axios';
import './BalanceDonut.scss';

const BalanceDonut = () => {
  const [data, setData] = useState([]);
  const [totalBalance, setTotalBalance] = useState(0);
  const [userId, setUserId] = useState(null);
  const [exchangeRates, setExchangeRates] = useState({});

  // ✅ Extract userId from token & fetch balances on load
  useEffect(() => {
    const storedToken = localStorage.getItem('token') || sessionStorage.getItem('token');

    if (!storedToken) {
      console.error("🚨 No token found! Login again.");
      return;
    }

    try {
      const decodedToken = jwtDecode(storedToken);
      setUserId(decodedToken.id);
      fetchBalances(decodedToken.id);
      fetchExchangeRates();
    } catch (error) {
      console.error('❌ Error decoding token:', error);
    }
  }, []);

  // ✅ Fetch balances & prices every 10 seconds
  useEffect(() => {
    const interval = setInterval(() => {
      if (userId) {
        fetchBalances(userId);
        fetchExchangeRates();
      }
    }, 10000);

    return () => clearInterval(interval);
  }, [userId]);

  // ✅ Fetch user balances
  const fetchBalances = async (id) => {
    try {
      const token = localStorage.getItem('token') || sessionStorage.getItem('token');
      if (!token) {
        console.error("🚨 No token found! Login again.");
        return;
      }

      const headers = { Authorization: `Bearer ${token}` };
      const response = await axios.get(`http://localhost:3001/api/users/${id}`, { headers });

      console.log("✅ Updated Balance Data:", response.data);

      // ✅ Convert balances into chart data format
      const formattedData = Object.keys(response.data)
        .filter((key) => key !== "total")
        .map((coin) => ({
          name: coin.toUpperCase(),
          amount: parseFloat(response.data[coin]) || 0,
        }));

      setData(formattedData);
    } catch (error) {
      console.error('❌ Error fetching balances:', error.response?.data || error.message);
    }
  };

  // ✅ Fetch real-time exchange rates
  const fetchExchangeRates = async () => {
    try {
      const response = await axios.get('https://api.coinbase.com/v2/exchange-rates?currency=USD');
      setExchangeRates(response.data.data.rates);
      console.log("✅ Live Exchange Rates:", response.data.data.rates);
    } catch (error) {
      console.error("❌ Error fetching exchange rates:", error.message);
    }
  };

  // ✅ Calculate total USD value using live prices
  useEffect(() => {
    if (data.length > 0 && Object.keys(exchangeRates).length > 0) {
      let totalValue = 0;
      
      data.forEach(coin => {
        const coinPrice = exchangeRates[coin.name] ? parseFloat(exchangeRates[coin.name]) : 0;
        totalValue += coin.amount * coinPrice;
      });

      setTotalBalance(totalValue.toFixed(2));
    }
  }, [data, exchangeRates]);

  // ✅ Ensure total balance is not zero before calculating %
  const formattedChartData = data.map(coin => {
    const coinPrice = exchangeRates[coin.name] ? parseFloat(exchangeRates[coin.name]) : 0;
    return {
      name: coin.name,
      amount: coin.amount,
      usdValue: coin.amount * coinPrice,
    };
  });

  const totalUSD = formattedChartData.reduce((acc, coin) => acc + coin.usdValue, 0);

  const chartData = {
    labels: formattedChartData.map(coin => `${coin.name} (${coin.amount})`),
    datasets: [
      {
        data: formattedChartData.map(coin => (totalUSD > 0 ? (coin.usdValue / totalUSD) * 100 : 0)), // ✅ Ensure correct % calculation
        backgroundColor: [
          '#F7931A', '#627EEA', '#00A98F', '#FF4500', '#2A9D8F', '#E63946', '#6A0572', '#F4A261', '#264653'
        ],
        borderWidth: 3,
        hoverOffset: 7,
      },
    ],
  };

  const chartOptions = {
    plugins: {
      legend: {
        display: false, // ✅ Hide the legend to remove values under the chart
      },
      tooltip: {
        callbacks: {
          label: function (tooltipItem) {
            const coin = formattedChartData[tooltipItem.dataIndex];
            return `${coin.name}: $${coin.usdValue.toFixed(2)} (${tooltipItem.raw.toFixed(1)}%)`;
          },
        },
      },
    },
    cutout: '60%', // ✅ Increase inner circle size to restore original chart size
  };
  
  return (
    <div className="balance-donut-card">
      <div className="balance-info">
        <h2>Total Balance</h2>
        <p className="crypto-amount">
          {formattedChartData.map((coin) => `${coin.amount} ${coin.name}`).join(', ')}
        </p>
        <p className="usd-amount">${totalBalance}</p>
      </div>
      <div className="donut-chart-container">
        <Doughnut data={chartData} options={chartOptions} />
      </div>
    </div>
  );
};

export default BalanceDonut;
