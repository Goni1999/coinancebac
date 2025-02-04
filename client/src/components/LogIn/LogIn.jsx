import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';
import './LogIn.scss';

const Login = () => {
  const [formData, setFormData] = useState({ email: '', password: '' });
  const [rememberMe, setRememberMe] = useState(false);
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const handleChange = (e) => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
  };

  const handleRememberMeChange = (e) => {
    setRememberMe(e.target.checked);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);

    try {
      const response = await axios.post(
        'http://localhost:3001/auth/login',
        formData,
        { validateStatus: (status) => status < 18000 }
      );

      console.log("🔍 Login Response:", response.data); // ✅ Debugging log

      if (!response.data || !response.data.user || !response.data.token) {
        throw new Error('❌ No token received from server');
      }

      const { user, token } = response.data;

      console.log("✅ Received Token:", token);  // ✅ Debugging log

      if (!user.email) throw new Error('User data is missing');

      const normalizedUser = {
        ...user,
        role: user.role?.toLowerCase().trim() || 'user'
      };

      // ✅ Always store token in localStorage
      localStorage.setItem('token', token);
      localStorage.setItem('user', JSON.stringify(normalizedUser));

      console.log("✅ Token Saved in LocalStorage:", localStorage.getItem('token')); // ✅ Debugging log
      console.log("✅ User Data Saved:", localStorage.getItem('user'));

      navigate(normalizedUser.role === 'admin' ? '/admin-dashboard' : '/dashboard');

    } catch (error) {
      console.error('❌ Login error:', error.response?.data || error.message);
      alert(error.response?.data?.error || 'Login failed. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="login-page">
      <form onSubmit={handleSubmit}>
        <div className="login-logo">
          <img src="images/Logo.png" alt="logo" />
        </div>
        <input
          type="email"
          name="email"
          placeholder="Email"
          value={formData.email}
          onChange={handleChange}
          required
          autoComplete="username"
        />
        <input
          type="password"
          name="password"
          placeholder="Password"
          value={formData.password}
          onChange={handleChange}
          required
          autoComplete="current-password"
        />
        <div className="login-links">
          <label className="remember-me">
            <input
              type="checkbox"
              checked={rememberMe}
              onChange={handleRememberMeChange}
              disabled={loading}
            />
            Remember me
          </label>
        </div>
        <div>
          <button type="submit" disabled={loading}>
            {loading ? 'Logging in...' : 'Log In'}
          </button>
        </div>
      </form>
    </div>
  );
};

export default Login;
