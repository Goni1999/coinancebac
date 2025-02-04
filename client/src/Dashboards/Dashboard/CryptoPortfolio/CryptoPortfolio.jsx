import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { Doughnut } from 'react-chartjs-2';
import { Chart, ArcElement, Tooltip, Legend } from 'chart.js';
import './CryptoPortfolio.scss';

Chart.register(ArcElement, Tooltip, Legend);

const CryptoPortfolio = ({ user, isAdmin }) => {
  const [cryptoData, setCryptoData] = useState(user);
  const [prices, setPrices] = useState({});
  const [loading, setLoading] = useState(true);
  const [editMode, setEditMode] = useState(false);

  // Fetch crypto prices from CoinCap API
  useEffect(() => {
    const fetchPrices = async () => {
      try {
        const response = await axios.get('https://api.coincap.io/v2/assets?ids=bitcoin,ethereum,cardano,ripple,dogecoin,binance-coin,solana,polkadot');
        const priceMap = {};
        response.data.data.forEach(asset => {
          priceMap[asset.symbol.toUpperCase()] = parseFloat(asset.priceUsd);
        });
        setPrices(priceMap);
      } catch (error) {
        console.error('Error fetching prices:', error);
      } finally {
        setLoading(false);
      }
    };

    fetchPrices();
  }, []);

  // Calculate total portfolio value
  const calculateTotal = () => {
    return Object.entries(cryptoData).reduce((acc, [key, value]) => {
      if (key === 'total' || key === 'id' || key === 'role') return acc;
      return acc + (value || 0) * (prices[key] || 0);
    }, 0);
  };

  // Handle form input changes
  const handleChange = (e) => {
    const { name, value } = e.target;
    setCryptoData(prev => ({
      ...prev,
      [name]: parseFloat(value) || 0
    }));
  };

  // Save updated data
  const handleSave = async () => {
    try {
      const total = calculateTotal();
      await axios.put(`http://localhost:3001/api/users/${user.id}`, {
        ...cryptoData,
        total
      });
      setEditMode(false);
    } catch (error) {
      console.error('Update failed:', error);
    }
  };

  // Chart configuration
  const chartData = {
    labels: Object.keys(prices),
    datasets: [{
      data: Object.keys(prices).map(symbol => 
        (cryptoData[symbol] || 0) * (prices[symbol] || 0)
      ),
      backgroundColor: [
        '#f7931a', '#627eea', '#0d1e30', '#00a3d9', '#c2a633',
        '#f0b90b', '#66f7d1', '#e6007a'
      ]
    }]
  };

  if (loading) return <div className="loading">Loading crypto data...</div>;

  return (
    <div className="crypto-portfolio">
      <div className="portfolio-header">
        <h2>Crypto Portfolio</h2>
        {isAdmin && (
          <button onClick={() => setEditMode(!editMode)}>
            {editMode ? 'Cancel' : 'Edit'}
          </button>
        )}
      </div>

      {editMode ? (
        <div className="edit-form">
          {Object.keys(prices).map(symbol => (
            <div key={symbol} className="input-group">
              <label>{symbol}</label>
              <input
                type="number"
                name={symbol}
                value={cryptoData[symbol] || 0}
                onChange={handleChange}
                step="0.00000001"
              />
            </div>
          ))}
          <button onClick={handleSave}>Save Changes</button>
        </div>
      ) : (
        <>
          <div className="chart-container">
            <Doughnut data={chartData} />
          </div>
          <div className="portfolio-summary">
            <h3>Total Value: ${calculateTotal().toLocaleString(undefined, {
              minimumFractionDigits: 2,
              maximumFractionDigits: 2
            })}</h3>
            <div className="crypto-list">
              {Object.entries(prices).map(([symbol, price]) => (
                <div key={symbol} className="crypto-item">
                  <span>{symbol}</span>
                  <span>{(cryptoData[symbol] || 0).toFixed(8)}</span>
                  <span>${((cryptoData[symbol] || 0) * price).toFixed(2)}</span>
                </div>
              ))}
            </div>
          </div>
        </>
      )}
    </div>
  );
};

export default CryptoPortfolio;