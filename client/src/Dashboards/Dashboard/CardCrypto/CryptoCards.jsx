import React, { useState, useEffect } from 'react';
import { Line } from 'react-chartjs-2';
import axios from 'axios';
import 'chart.js/auto';
import './CryptoCards.scss';

const CryptoCards = () => {
  const [cryptoData, setCryptoData] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const response = await axios.get('https://api.coinlore.net/api/tickers/');
        const selectedCoins = response.data.data.slice(0, 6); // Get data for 5 coins

        const coinsWithChart = selectedCoins.map((coin) => {
          const prices = Array.from({ length: 12 }, () => Math.random() * coin.price_usd); // Simulate 12 months of price data
          const isIncreasing = prices[prices.length - 1] > prices[0];

          return {
            name: coin.name,
            price: parseFloat(coin.price_usd).toFixed(2),
            logo: `https://www.coinlore.com/img/${coin.nameid}.png`, // Coinlore provides logos
            chartData: {
              labels: Array.from({ length: 12 }, (_, i) => `${i + 1}m`),
              datasets: [
                {
                  data: prices,
                  borderColor: isIncreasing ? 'green' : 'red',
                  borderWidth: 2,
                  fill: false,
                  tension: 0.4,
                },
              ],
            },
          };
        });

        setCryptoData(coinsWithChart);
        setLoading(false);
      } catch (err) {
        setError('Error fetching data');
        setLoading(false);
      }
    };

    fetchData();
  }, []);

  if (loading) return <p>Loading...</p>;
  if (error) return <p>{error}</p>;

  return (
    <div className="crypto-cards-container">
      {cryptoData.map((coin) => (
        <div key={coin.name} className="crypto-card">
          <div className="card-header">
            <span className="coin-name">{coin.name}</span>
            <span className="coin-price">${coin.price}</span>
          </div>
          <div className="card-body">
            <img src={coin.logo} alt={`${coin.name} logo`} className="coin-logo" />
            <Line
              data={coin.chartData}
              options={{
                plugins: { legend: { display: false } },
                scales: { x: { display: false }, y: { display: false } },
                elements: { point: { radius: 0 } },
              }}
            />
          </div>
        </div>
      ))}
    </div>
  );
};

export default CryptoCards;
