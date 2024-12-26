import React, { useEffect, useState } from "react";
import { Navigate } from "react-router-dom";
import axios from "axios";
import axiosInstance from "../api/axios";

// PrivateRoute Component
const PrivateRoute = ({ children }) => {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let isMounted = true; // Track whether the component is still mounted
  
    const verifyToken = async () => {
      const token = localStorage.getItem("token");
  
      if (!token) {
        setIsAuthenticated(false);
        setLoading(false);
        return;
      }
      console.log("Token",token);
      try {
        const res = await axiosInstance.get("/api/verify-token", {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        });
  
        if (isMounted) {
          setIsAuthenticated(res.data.valid); // Update state only if mounted
        }
      } catch (err) {
        console.error("Token verification failed:", err);
        if (isMounted) {
          setIsAuthenticated(false);
        }
      } finally {
        if (isMounted) {
          setLoading(false);
        }
      }
    };
  
    verifyToken();
  
    return () => {
      isMounted = false; // Cleanup on component unmount
    };
  }, []);
  
  if (loading) {
    return <div>Loading...</div>; // Show loading while verifying token
  }

  return isAuthenticated ? children : <Navigate to="/login" />;
};

export default PrivateRoute;
