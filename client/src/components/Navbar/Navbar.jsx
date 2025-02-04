import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import './Navbar.scss';
import SignUp from '../SignUp/SignUp';
import LogIn from '../LogIn/LogIn';
import ReportCaseModal from '../ReportCaseModal/ReportCaseModal';

const Navbar = () => {
    const [user, setUser] = useState(null); // State to manage user authentication
    const [showSignUp, setShowSignUp] = useState(false); // State to toggle SignUp modal
    const [showLogIn, setShowLogIn] = useState(false); // State to toggle LogIn modal
    const [isDarkMode, setIsDarkMode] = useState(
        localStorage.getItem('isDarkMode') === 'true' // Load dark mode state from localStorage
    );

    const toggleSignUp = () => setShowSignUp(!showSignUp); // Toggle SignUp modal
    const toggleLogIn = () => setShowLogIn(!showLogIn); // Toggle LogIn modal

    const toggleDarkMode = () => {
        const newDarkModeState = !isDarkMode;
        setIsDarkMode(newDarkModeState); // Update state
        localStorage.setItem('isDarkMode', newDarkModeState); // Save state to localStorage
    };

    // Apply or remove dark mode class on body
    useEffect(() => {
        if (isDarkMode) {
            document.body.classList.add('dark-mode');
        } else {
            document.body.classList.remove('dark-mode');
        }
    }, [isDarkMode]);

    const handleSignOut = () => {
        setUser(null); // Clear user state on sign-out
        alert("You have successfully signed out.");
    };

    return (
        <>
            <nav className={`navbar ${isDarkMode ? 'dark-mode' : ''}`}>
                <Link to="/">
                <div className="navbar-logo">
                    <img className="img-logo" src="/images/logo.png" alt="Logo" />
                </div>
                </Link>
                <ul className="navbar-links">
                    <li className="navbar-item"><Link to="/">Home</Link></li>
                    <li className="navbar-item"><Link to="/contactus">Inform Us Now</Link></li>
                    <li className="navbar-item"><Link to="/about">About</Link></li>
                    <li className="navbar-item"><a href="/services">Services</a></li>
                    <li className="navbar-item"><a href="/contact">FAQ</a></li>
                    
                </ul>
                <ReportCaseModal />
                <div className="auth-buttons">
                    {user ? (
                        <div className="user-dropdown">
                            <span>{user.name}</span>
                            <div className="dropdown-menu">
                                <button onClick={handleSignOut}>Sign Out</button>
                            </div>
                        </div>
                    ) : (
                        <>
                            <button className="auth-button sign-up" onClick={toggleSignUp}>
                                Sign Up
                            </button>
                            <button className="auth-button log-in" onClick={toggleLogIn}>
                                Log In
                            </button>
                        </>
                    )}
                    {/* Dark Mode Toggle Button */}
                    <button className="theme-toggle" onClick={toggleDarkMode}>
                        {isDarkMode ? '☀️' : '🌙'}
                    </button>
                </div>
            </nav>

            {/* Sign Up Modal */}
            {showSignUp && (
                <div className="modal-overlay" onClick={toggleSignUp}>
                    <div className="modal-content" onClick={(e) => e.stopPropagation()}>
                        <SignUp onSignUpSuccess={setUser} />
                        <button className="close-button" onClick={toggleSignUp}>
                            Close
                        </button>
                    </div>
                </div>
            )}

            {/* Log In Modal */}
            {showLogIn && (
                <div className="modal-overlay" onClick={toggleLogIn}>
                    <div className="modal-content" onClick={(e) => e.stopPropagation()}>
                        <LogIn onLoginSuccess={setUser} />
                        <button className="close-button" onClick={toggleLogIn}>
                            Close
                        </button>
                    </div>
                </div>
            )}
        </>
    );
};

export default Navbar;
