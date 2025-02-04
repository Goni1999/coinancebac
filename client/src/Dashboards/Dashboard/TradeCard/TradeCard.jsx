import React, { useEffect, useState } from 'react';
import axios from 'axios';
import { jwtDecode } from 'jwt-decode';
import './TradeCard.scss';

const TradeCard = () => {
    const [userId, setUserId] = useState(null);
    const [balances, setBalances] = useState({});
    const [exchangeRates, setExchangeRates] = useState({});
    const [fromCurrency, setFromCurrency] = useState("");
    const [toCurrency, setToCurrency] = useState("");
    const [amount, setAmount] = useState(0);
    const [conversionRate, setConversionRate] = useState(1);
    const [convertedAmount, setConvertedAmount] = useState(0);

    // 🔥 Automatically load the user from token
    useEffect(() => {
        const storedToken = localStorage.getItem('token') || sessionStorage.getItem('token');
        if (storedToken) {
            try {
                const decoded = jwtDecode(storedToken);
                setUserId(decoded.id);
                fetchBalances(decoded.id);
            } catch (error) {
                console.error("❌ Error decoding token:", error);
            }
        } else {
            console.error("🚨 No token found! Login again.");
        }
    }, []);

    useEffect(() => {
        fetchExchangeRates();
    }, []);

    useEffect(() => {
        if (exchangeRates[fromCurrency] && exchangeRates[toCurrency]) {
            const rate = exchangeRates[toCurrency] / exchangeRates[fromCurrency];
            setConversionRate(rate);
            setConvertedAmount(amount * rate);
        }
    }, [fromCurrency, toCurrency, amount, exchangeRates]);

    // ✅ Automatically fetch balances every 10 seconds to keep data fresh
    useEffect(() => {
        const interval = setInterval(() => {
            if (userId) fetchBalances(userId);
        }, 10000); // Refresh every 10 seconds

        return () => clearInterval(interval); // Cleanup interval
    }, [userId]);

    const fetchBalances = async (id) => {
        try {
            const token = localStorage.getItem('token') || sessionStorage.getItem('token');
            if (!token) {
                console.error("🚨 No token found! Login again.");
                return;
            }

            const headers = { Authorization: `Bearer ${token}` };
            const response = await axios.get(`http://localhost:3001/api/users/${id}`, { headers });

            // Remove 'total' from balance list
            const filteredBalances = Object.fromEntries(
                Object.entries(response.data).filter(([key]) => key !== "total")
            );

            setBalances(filteredBalances);

            // ✅ Ensure different default selections
            const balanceKeys = Object.keys(filteredBalances);
            if (balanceKeys.length >= 2) {
                setFromCurrency(balanceKeys[0]); // First currency
                setToCurrency(balanceKeys[1]); // Second currency
            }
        } catch (error) {
            console.error("❌ Error fetching balances:", error.response?.data || error.message);
        }
    };

    const fetchExchangeRates = async () => {
        try {
            const response = await axios.get('https://api.coinbase.com/v2/exchange-rates?currency=USD');
            setExchangeRates(response.data.data.rates);
        } catch (error) {
            console.error("❌ Error fetching exchange rates:", error.message);
        }
    };

    const handleTrade = async () => {
        if (!amount || amount <= 0) {
            alert("Enter a valid amount to trade.");
            return;
        }
        if (balances[fromCurrency] < amount) {
            alert(`You don't have enough ${fromCurrency} to trade.`);
            return;
        }

        try {
            const token = localStorage.getItem('token') || sessionStorage.getItem('token');
            const headers = { Authorization: `Bearer ${token}` };

            const response = await axios.put('http://localhost:3001/api/trade', {
                userId,
                fromCurrency,
                toCurrency,
                amount,
                conversionRate
            }, { headers });

            alert(response.data.message);
            fetchBalances(userId); // Refresh balances after trade
        } catch (error) {
            console.error("❌ Trade error:", error.response?.data || error.message);
            alert(error.response?.data?.error || "Trade failed.");
        }
    };

    return (
        <div className="trade-card">
            <h2 className="trade-card-title">Crypto Trading</h2>

            <div className="trade-card-row">
                <label>From:</label>
                <select value={fromCurrency} onChange={(e) => setFromCurrency(e.target.value)}>
                    {Object.keys(balances).map((currency) => (
                        <option key={currency} value={currency}>{currency}</option>
                    ))}
                </select>
                <input type="number" value={amount} onChange={(e) => setAmount(parseFloat(e.target.value) || 0)} />
            </div>

            <div className="trade-card-row">
                <label>To:</label>
                <select 
                    value={toCurrency} 
                    onChange={(e) => {
                        setToCurrency(e.target.value);
                        // ✅ Ensure conversion updates immediately
                        const rate = exchangeRates[e.target.value] / exchangeRates[fromCurrency];
                        setConversionRate(rate);
                        setConvertedAmount(amount * rate);
                    }}
                >
                    {Object.keys(balances).map((currency) => (
                        <option key={currency} value={currency}>{currency}</option>
                    ))}
                </select>
                <input type="text" value={convertedAmount.toFixed(6)} disabled />
            </div>

            <p>Rate: 1 {fromCurrency} = {conversionRate.toFixed(6)} {toCurrency}</p>

            <button className="trade-button" onClick={handleTrade}>Trade</button>
        </div>
    );
};

export default TradeCard;
