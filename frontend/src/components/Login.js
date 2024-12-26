import { useState, useEffect } from "react";
import { GoogleLogin } from "@react-oauth/google";
import { GoogleOAuthProvider } from '@react-oauth/google'; // Import the GoogleOAuthProvider

import axiosInstance from '../api/axios';
import { useNavigate } from "react-router-dom";

const Login = () => {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const navigate = useNavigate();

  useEffect(() => {
    const token = localStorage.getItem("token");
    if (token) {
      navigate("/dashboard"); // Redirect to dashboard if token exists
    }
  }, [navigate]);


  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      const res = await axiosInstance.post("/api/login", { email, password });
      localStorage.setItem('email', email);
      localStorage.setItem("token", res.data.access_token);
      navigate("/dashboard");
    } catch (err) {
        // Display error message received from Flask backend
        if (err.response && err.response.data.error) {
          alert(err.response.data.error); // Show error message as an alert
      } else {
          alert("An error occurred. Please try again.");
      }
      console.error(err);
    }
  };

  const handleGoogleLogin = async (response) => {
    try {
      const res = await axiosInstance.post("/api/google-login", { token: response.credential });
      localStorage.setItem("token", res.data.access_token);
      navigate("/dashboard");
    } catch (err) {
      console.error(err);
    }
  };

  return (
    <div className="h-screen flex justify-center items-center bg-gray-100">
      <div className="w-full max-w-md bg-white p-8 rounded-lg shadow-md">
        <h2 className="text-2xl font-bold text-center mb-4">Login</h2>
        <form onSubmit={handleSubmit}>
          <div className="mb-4">
            <label htmlFor="email" className="block text-sm font-medium">Email</label>
            <input
              type="email"
              id="email"
              className="w-full p-2 mt-1 border border-gray-300 rounded"
              value={email}
              placeholder="Email"
              onChange={(e) => setEmail(e.target.value)}
              required
            />
          </div>
          <div className="mb-4">
            <label htmlFor="password" className="block text-sm font-medium">Password</label>
            <input
              type="password"
              id="password"
              className="w-full p-2 mt-1 border border-gray-300 rounded"
              value={password}
              placeholder="Password"
              onChange={(e) => setPassword(e.target.value)}
              required
            />
          </div>
          <button type="submit" className="w-full bg-blue-500 text-white p-2 rounded-md hover:bg-blue-600">Login</button>
        </form>

        <div className="my-4 text-center">or</div>

        <GoogleOAuthProvider clientId={ "473085769097-8vte4bgjluisu3at2nbga5h9v17vsi8r.apps.googleusercontent.com"}>
        {/* All components that use Google OAuth should be inside this provider */}
            <div className="App">
                <GoogleLogin 
                onSuccess={handleGoogleLogin} 
                onError={(err) => console.error(err)}
                />
            </div>
        </GoogleOAuthProvider>
        <div className="text-center mt-4">
          <a href="/signup" className="text-blue-500 hover:underline">Don't have an account? Sign up</a>
        </div>
      </div>
    </div>
  );
};

export default Login;
