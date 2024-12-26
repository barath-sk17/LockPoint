// src/api/axios.js
import axios from 'axios';

// Create an Axios instance
const axiosInstance = axios.create({
  baseURL: 'http://localhost:5000',  // Replace with your backend URL
  headers: {
    'Content-Type': 'application/json',
    // You can add more default headers like authorization here
  },
});

// Optionally, you can add interceptors for requests or responses
axiosInstance.interceptors.request.use(
  (config) => {
    // You can add authorization tokens here if needed
    const token = localStorage.getItem('access_token');
    if (token) {
      config.headers['Authorization'] = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

export default axiosInstance;
