import React from 'react';
import { Navigate } from 'react-router-dom';
import { jwtDecode } from 'jwt-decode';

const ProtectedRoute = ({ children, requiredRole }) => {
  // Get authentication data from storage
  const user = JSON.parse(localStorage.getItem('user')) || JSON.parse(sessionStorage.getItem('user'));
  const token = localStorage.getItem('token') || sessionStorage.getItem('token');

  // Debugging logs
  console.log('ProtectedRoute check - User:', user);
  console.log('ProtectedRoute check - Token:', token);

  // Check if token exists
  if (!token || !user) {
    console.log('Redirecting due to missing token/user');
    return <Navigate to="/" replace />;  // Changed to /login
  }

  // Verify token expiration
  try {
    const decodedToken = jwtDecode(token);
    const currentTime = Date.now() / 1000;

    if (decodedToken.exp < currentTime) {
      console.log('Redirecting due to expired token');
      localStorage.removeItem('user');
      localStorage.removeItem('token');
      sessionStorage.removeItem('user');
      sessionStorage.removeItem('token');
      return <Navigate to="/" replace />;
    }
  } catch (error) {
    console.error('Token validation error:', error);
    return <Navigate to="/" replace />;
  }

  // Debug role check
  console.log('User role:', user.role, 'Required role:', requiredRole);
  
  // Check user role
  if (user.role.toLowerCase() !== requiredRole.toLowerCase()) {  // Case-insensitive check
    console.log('Redirecting due to role mismatch');
    return <Navigate to="/" replace />;
  }

  return children;
};

export default ProtectedRoute;