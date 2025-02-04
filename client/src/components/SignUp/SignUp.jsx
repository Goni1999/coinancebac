import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';
import './SignUp.scss';

const SignUp = () => {
  const [formData, setFormData] = useState({
    name: '',
    email: '',
    password: '',
    confirmPassword: '',
  });
  const [passwordError, setPasswordError] = useState('');
  const [confirmPasswordError, setConfirmPasswordError] = useState('');
  const navigate = useNavigate();

  const validatePassword = (password) => {
    const errors = [];
    if (password.length < 8) errors.push('at least 8 characters');
    if (!/[A-Z]/.test(password)) errors.push('a capital letter');
    if (!/[!@#$%^&*(),.?":{}|<>]/.test(password)) errors.push('a symbol');
    return errors;
  };

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData((prev) => {
      const newFormData = { ...prev, [name]: value };
      
      if (name === 'password') {
        const errors = validatePassword(value);
        setPasswordError(errors.length > 0 ? `Password must contain ${errors.join(', ')}` : '');
      }
      
      if (name === 'confirmPassword') {
        setConfirmPasswordError(value !== newFormData.password ? 'Passwords do not match' : '');
      }
  
      return newFormData;
    });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
  
    if (passwordError || confirmPasswordError) {
      alert('Please resolve password issues before signing up.');
      return;
    }
  
    try {
      // Updated URL with port 3001
      const response = await axios.post('http://localhost:3001/auth/register', {
        name: formData.name,
        email: formData.email,
        password: formData.password,
      });
  
      alert("Your account is being set up...");

    // Second alert after 3 seconds
    setTimeout(() => {
      alert("Feel free to log in now!");
      navigate('/');
    }, 3000);

  
    } catch (error) {
      const errorMessage = error.response?.data?.error || 
        (error.response?.status === 409 ? 'Email is already registered' : 'Signup failed. Please try again.');
      alert(errorMessage);
    }
  };

  return (
    <div className="signup-page">
      <form onSubmit={handleSubmit}>
        <div className="signup-logo">
          <img src="images/Logo.png" alt="logo" />
        </div>
        <input
          type="text"
          name="name"
          placeholder="Name"
          value={formData.name}
          onChange={handleChange}
          required
        />
        <input
          type="email"
          name="email"
          placeholder="Email"
          value={formData.email}
          onChange={handleChange}
          required
        />
        <input
          type="password"
          name="password"
          placeholder="Password"
          value={formData.password}
          onChange={handleChange}
          required
        />
        {passwordError && <p className="error-message">{passwordError}</p>}
        <input
          type="password"
          name="confirmPassword"
          placeholder="Confirm Password"
          value={formData.confirmPassword}
          onChange={handleChange}
          required
        />
        {confirmPasswordError && <p className="error-message">{confirmPasswordError}</p>}
        <button type="submit">Sign Up</button>
      </form>
    </div>
  );
};

export default SignUp;
