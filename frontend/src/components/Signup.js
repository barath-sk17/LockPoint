import { useState, useEffect } from "react";
import { GoogleLogin } from "@react-oauth/google";
import { GoogleOAuthProvider } from '@react-oauth/google'; // Import the GoogleOAuthProvider

import axiosInstance from '../api/axios';
import { useNavigate } from "react-router-dom";

const Signup = () => {
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const navigate = useNavigate();

  const [errors,setErrors] = useState({});
  const usernameRegex = /^[a-zA-Z0-9_]{3,15}$/; // Only alphanumeric and underscores, 3-15 characters
  const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[A-Za-z\d@$!%*?&]{8,20}$/; // Minimum 8 characters, 1 uppercase, 1 lowercase, 1 number

  useEffect(() => {
      const token = localStorage.getItem("token");
      if (token) {
        navigate("/dashboard"); // Redirect to dashboard if token exists
      }
    }, [navigate]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    let formErrors = {};

    // Validate username
    if (!usernameRegex.test(username)) {
      formErrors.username = "Username must be 3-15 characters long and can only contain letters, numbers, and underscores.";
    }

    // Validate password
    if (!passwordRegex.test(password)) {
      formErrors.password = "Password must be 8-20 characters long and include at least one uppercase letter, one lowercase letter, and one number.";
    }

    // If there are errors, set the error state and return
    if (Object.keys(formErrors).length > 0) {
      setErrors(formErrors);
      return;
    }

    // Reset errors if validation passes
    setErrors({});

    try {
      const res = await axiosInstance.post("/api/signup", { username, email, password });
      //localStorage.setItem("token", res.data.access_token);
      navigate("/login");
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

  const handleGoogleSignup = async (response) => {
    try {
      const res = await axiosInstance.post("/api/google-signup", { token: response.credential });
      localStorage.setItem("email",res.data.email)
      localStorage.setItem("token", res.data.access_token);
      navigate("/dashboard");
    } catch (err) {
      console.error(err);
    }
  };

  return (
    <div className="h-screen flex justify-center items-center bg-gray-100">
      <div className="w-full max-w-md bg-white p-8 rounded-lg shadow-md">
        <h2 className="text-2xl font-bold text-center mb-4">Sign Up</h2>
        <form onSubmit={handleSubmit}>
          <div className="mb-4">
            <label htmlFor="username" className="block text-sm font-medium">Username</label>
            <input
              type="text"
              id="username"
              className="w-full p-2 mt-1 border border-gray-300 rounded"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
            />
            {errors.username && <p className="text-red-500 text-[12px]">{errors.username}</p>}

          </div>
          <div className="mb-4">
            <label htmlFor="email" className="block text-sm font-medium">Email</label>
            <input
              type="email"
              id="email"
              className="w-full p-2 mt-1 border border-gray-300 rounded"
              value={email}
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
              onChange={(e) => setPassword(e.target.value)}
              required
            />
            {errors.password && <p className="text-red-500 text-[12px]">{errors.password}</p>}

          </div>
          <button type="submit" className="w-full bg-green-500 text-white p-2 rounded-md hover:bg-green-600">Sign Up</button>
        </form>

        <div className="my-4 text-center">or</div>

        <GoogleOAuthProvider clientId={"473085769097-8vte4bgjluisu3at2nbga5h9v17vsi8r.apps.googleusercontent.com"}>
        {/* All components that use Google OAuth should be inside this provider */}
            <div className="App">
                <GoogleLogin 
                onSuccess={handleGoogleSignup} 
                onError={(err) => console.error(err)}
                />
            </div>
        </GoogleOAuthProvider>

        <div className="text-center mt-4">
          <a href="/login" className="text-blue-500 hover:underline">Already have an account? Login</a>
        </div>
      </div>
    </div>
  );
};

export default Signup;
