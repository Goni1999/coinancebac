import React, { useState, useEffect } from 'react';
import axios from 'axios';
import './CryptoCard1.scss';

const CryptoCard1 = () => {
  const [selectedCoin, setSelectedCoin] = useState('bitcoin'); // Default coin
  const [coinData, setCoinData] = useState(null);
  const [loading, setLoading] = useState(false);

  const coins = [
    'bitcoin', 'ethereum', 'litecoin', 'cardano', 'binancecoin',
    'xrp', 'solana', 'polkadot', 'dogecoin', 'shiba-inu',
  ];

  // Fetch data for the selected coin
  useEffect(() => {
    const fetchData = async () => {
      setLoading(true);
      try {
        const response = await axios.get('https://api.coingecko.com/api/v3/coins/markets', {
          params: {
            vs_currency: 'usd',
            ids: selectedCoin,
          },
        });
        setCoinData(response.data[0]);
      } catch (err) {
        console.error('Error fetching data:', err);
      } finally {
        setLoading(false);
      }
    };

    fetchData();
  }, [selectedCoin]);

  return (
    <div className="crypto-card-1">
      <div className="top-section-1">
        <div className="header-1">
          {loading ? (
            <p>Loading...</p>
          ) : coinData ? (
            <>
              <img className="coin-logo-1" src={coinData.image} alt={coinData.name} />
              <div className="coin-info-1">
                <h3>
                  {coinData.name} ({coinData.symbol.toUpperCase()})
                </h3>
                <select
                  className="coin-dropdown-1"
                  value={selectedCoin}
                  onChange={(e) => setSelectedCoin(e.target.value)}
                >
                  {coins.map((coin) => (
                    <option key={coin} value={coin}>
                      {coin.charAt(0).toUpperCase() + coin.slice(1)} {/* Capitalize */}
                    </option>
                  ))}
                </select>
              </div>
            </>
          ) : (
            <p>Unable to load data. Please try again.</p>
          )}
        </div>
        {!loading && coinData && (
          <div className="price-details-1">
            <p>
              <strong>Current Price:</strong> ${coinData.current_price.toLocaleString()}
            </p>
            <p>
              <strong>24h Change:</strong>{' '}
              {coinData.price_change_percentage_24h > 0 ? (
                <span className="positive-1">
                  ↑ {coinData.price_change_percentage_24h.toFixed(2)}%
                </span>
              ) : (
                <span className="negative-1">
                  ↓ {coinData.price_change_percentage_24h.toFixed(2)}%
                </span>
              )}
            </p>
            <p>
              <strong>24h Volume:</strong> ${coinData.total_volume.toLocaleString()}
            </p>
          </div>
        )}
      </div>

      {!loading && coinData && (
        <div className="bottom-section-1">
          <div className="column-1">
            <p>
              <strong>24h High:</strong> ${coinData.high_24h} <span className="arrow up">↑</span>
            </p>
            <p>
              <strong>24h Low:</strong> ${coinData.low_24h} <span className="arrow down">↓</span>
            </p>
          </div>
          <div className="column-1">
            <p>
              <strong>24h Total:</strong> ${coinData.total_volume.toLocaleString()}
            </p>
            <p>
              <strong>Market Cap:</strong> ${coinData.market_cap.toLocaleString()}
            </p>
          </div>
        </div>
      )}
    </div>
  );
};

export default CryptoCard1;
