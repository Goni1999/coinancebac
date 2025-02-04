// src/components/CryptoData.js
import React, { useState, useEffect } from 'react';
import axios from 'axios';
import './CryptoData.scss';

const CryptoData = () => {
  const [cryptoData, setCryptoData] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  // Function to fetch data from the API
  useEffect(() => {
    const fetchData = async () => {
      try {
        const response = await axios.get('https://api.coingecko.com/api/v3/coins/markets', {
          params: {
            vs_currency: 'usd',
            ids: 'bitcoin,ethereum,litecoin,cardano,binancecoin,xrp,solana,polkadot,dogecoin,shiba-inu,tron,uniswap,chainlink,litecoin,ethereum-classic,vechain,monero,ethereum,stellar,cosmos,terraluna,elrond,bittorrent', // Added 17 more coins
          },
        });
        setCryptoData(response.data);
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
    <div className="crypto-data-2">
      <h2>Cryptocurrency Prices</h2>
      <div className="crypto-cards-2">
        {cryptoData.map((coin) => (
          <div key={coin.id} className="crypto-card-2">
            <img className="coin-logo" src={coin.image} alt={coin.name} />
            <h3>{coin.name}</h3>
            <p>Price: ${coin.current_price}</p>
            <p>Market Cap: ${coin.market_cap}</p>
            <p>24h Change: {coin.price_change_percentage_24h}%</p>
          </div>
        ))}
      </div>
    </div>
  );
};

export default CryptoData;
