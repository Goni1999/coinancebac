import React, { useState, useEffect } from 'react';
import './InvestmentForm.scss';

const InvestmentForm = ({ loggedInEmail }) => {
  const [formData, setFormData] = useState({
    first_name: '',
    last_name: '',
    phone_country_code: '',
    phone_number: '',
    email: '',
    investment_amount: 0,
    details: '',
  });

  useEffect(() => {
    if (loggedInEmail) {
        const token = localStorage.getItem('token') || sessionStorage.getItem('token');
        
        fetch(`http://capital-trust.org/api/users/${loggedInEmail}`, {
            headers: { 'Authorization': `Bearer ${token}` }
        })
        .then((response) => response.json())
        .then((data) => {
            if (data.name) {
                setFormData((prevData) => ({
                    ...prevData,
                    first_name: data.name.split(' ')[0] || '',
                    last_name: data.name.split(' ')[1] || '',
                    email: data.email || '',
                }));
            }
        })
        .catch((error) => console.error('Error fetching user data:', error));
    }
}, [loggedInEmail]);


  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData({
      ...formData,
      [name]: value,
    });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();

    try {
        const response = await fetch('http://localhost:3001/api/investments', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(formData),
        });

        // ✅ Check if response is JSON
        const contentType = response.headers.get("content-type");
        if (!response.ok) {
            throw new Error(`Server error: ${response.status}`);
        }
        if (contentType && contentType.includes("application/json")) {
            const data = await response.json();
            alert(data.message || 'Investment submitted successfully!');
        } else {
            throw new Error("Received invalid response (not JSON)");
        }
    } catch (error) {
        console.error('❌ Error submitting investment:', error);
        alert(error.message || 'Failed to submit investment.');
    }
};

  const handleIncreaseInvestment = () => {
    setFormData({
      ...formData,
      investment_amount: formData.investment_amount + 1000,
    });
  };

  return (
    <div className="form-container">
      <div className="investment-form">
        <h2>Investment Form</h2>
        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label>First Name</label>
            <input
              type="text"
              name="first_name"
              value={formData.first_name}
              onChange={handleChange}
              required
            />
          </div>

          <div className="form-group">
            <label>Last Name</label>
            <input
              type="text"
              name="last_name"
              value={formData.last_name}
              onChange={handleChange}
              required
            />
          </div>

          <div className="form-group phone-group">
            <label>Phone Number</label>
            <div className="phone-input">
              <select
                name="phone_country_code"
                value={formData.phone_country_code}
                onChange={handleChange}
                required
              >
                <option value="">+ Country Code</option>
                <option value="+1">+1 (Canada)</option>
<option value="+49">+49 (Germany)</option>
<option value="+1">+1 (USA)</option>
<option value="+44">+44 (UK)</option>
<option value="+91">+91 (India)</option>
<option value="+61">+61 (Australia)</option>
<option value="+33">+33 (France)</option>
<option value="+34">+34 (Spain)</option>
<option value="+39">+39 (Italy)</option>
<option value="+81">+81 (Japan)</option>
<option value="+82">+82 (South Korea)</option>
<option value="+86">+86 (China)</option>
<option value="+7">+7 (Russia)</option>
<option value="+55">+55 (Brazil)</option>
<option value="+27">+27 (South Africa)</option>
<option value="+52">+52 (Mexico)</option>
<option value="+34">+34 (Spain)</option>
<option value="+31">+31 (Netherlands)</option>
<option value="+47">+47 (Norway)</option>
<option value="+46">+46 (Sweden)</option>
<option value="+41">+41 (Switzerland)</option>
<option value="+32">+32 (Belgium)</option>
<option value="+30">+30 (Greece)</option>
<option value="+31">+31 (Netherlands)</option>
<option value="+351">+351 (Portugal)</option>
<option value="+61">+61 (Australia)</option>
<option value="+64">+64 (New Zealand)</option>
<option value="+90">+90 (Turkey)</option>
<option value="+380">+380 (Ukraine)</option>
              </select>
              <input
                type="text"
                name="phone_number"
                value={formData.phone_number}
                onChange={handleChange}
                required
                placeholder="Enter phone number"
              />
            </div>
          </div>

          <div className="form-group">
            <label>Email</label>
            <input
              type="email"
              name="email"
              value={formData.email}
              onChange={handleChange}
              required
            />
          </div>

          <div className="form-group">
            <label>Investment Amount</label>
            <div className="investment-amount-container">
              <input
                type="number"
                name="investment_amount"
                value={formData.investment_amount}
                onChange={handleChange}
                required
                min="0"
              />
              <button type="button" onClick={handleIncreaseInvestment}>
                +1000
              </button>
            </div>
          </div>

          <div className="form-group">
            <label>Additional Details</label>
            <textarea
              name="details"
              value={formData.details}
              onChange={handleChange}
              placeholder="Additional Details (Optional)"
            />
          </div>

          <button type="submit" className="invest-button">
            Invest Now!
          </button>
        </form>
      </div>

      <div className="info-panel">
        <h1>Why Choose CapitalTrust?</h1>
        <ul>
          <li>Expert Guidance: Over a decade of experience providing the best investment advice.</li>
          <li>Advanced Security: Top-notch technology to protect your assets.</li>
          <li>Personalized Service: Tailored investment strategies to meet your unique goals.</li>
        </ul>
        <h2>How It Works</h2>
        <ol>
          <li>Complete the Form: Fill out your details.</li>
          <li>Consult with Advisors: Our experts will discuss your goals.</li>
          <li>Start Investing: Begin with confidence and real-time insights.</li>
        </ol>
        <h2>Secure Investment Options</h2>
        <ul>
          <li>Stocks and Bonds: Diversify your portfolio with our guidance.</li>
          <li>Real Estate: Invest in residential and commercial properties.</li>
          <li>Mutual Funds: Various funds managed by professionals.</li>
          <li>Cryptocurrencies: Securely invest in the future of finance.</li>
        </ul>
        <h2>Ready to Invest?</h2>
        <p>
          Start your journey with CapitalTrust today. Complete the investment form and achieve your financial goals
          securely and confidently.
        </p>
      </div>
    </div>
  );
};

export default InvestmentForm;
